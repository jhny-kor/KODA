#!/usr/bin/env python3
"""Reject GitLab publication of marketplace assets and excluded document links.

Run as a pre-push hook with Git's remote name/URL arguments and update records on
stdin, or use --check REV to inspect a committed tree before publication.
"""
from __future__ import annotations

import argparse
import html
import re
import subprocess
import sys
from pathlib import PurePosixPath
from urllib.parse import unquote, urlsplit

ZERO_OID = re.compile(r"^0+$")
FORBIDDEN_HOST = re.compile(
    r"(?<![a-z0-9.-])(?:[a-z0-9-]+\.)*"
    r"(?:github\.com|github\.blog|github\.io|githubusercontent\.com|"
    r"githubassets\.com|apps\.apple\.com|itunes\.apple\.com)(?![a-z0-9.-])",
    re.IGNORECASE,
)
MARKETPLACE_TEXT = re.compile(r"app[\s_-]*store|앱\s*스토어", re.IGNORECASE)


def is_gitlab_target(remote_url: str) -> bool:
    """Recognize URL and scp-style GitLab remotes, without matching URL paths."""
    if "://" in remote_url:
        host = urlsplit(remote_url).hostname or ""
    else:
        match = re.fullmatch(r"(?:[^/@:]+@)?([^/:]+):.+", remote_url)
        host = match.group(1) if match else ""
    host = host.lower().rstrip(".")
    return host.startswith("gitlab.")


def excluded_path(path: str) -> bool:
    lower = path.lower()
    parts = PurePosixPath(lower).parts
    name = parts[-1]
    if "store-assets" in parts:
        return True
    if lower in {"docs/store-release.md", "assets/koda-appstore-1024.png"}:
        return True
    if lower.startswith("platforms/macos/packaging/"):
        if name.startswith("readme") or name == "koda-appstore-1024.png":
            return True
        if "archives" in parts or "app-store" in parts or "appstore" in parts:
            return True
    if MARKETPLACE_TEXT.search(name) and (
        "scripts" in parts or "script" in parts or name.endswith(".plist")
    ):
        return True
    return False


def is_document(path: str) -> bool:
    lower = path.lower()
    p = PurePosixPath(lower)
    if p.suffix in {".md", ".markdown"}:
        return True
    if p.suffix not in {".html", ".htm", ".svg", ".txt", ".json"}:
        return False
    return (
        p.parts[0] in {"docs", "dist", "diagrams"}
        or "docs" in p.parts
        or "documentation" in p.parts
        or (p.parts[0] == "platforms" and "packaging" in p.parts)
        or len(p.parts) == 1 and p.stem.startswith(("readme", "privacy", "security"))
    )


def normalized_text(text: str) -> str:
    # Decode nested HTML entities/URL escapes, including escaped separators.
    for _ in range(8):
        decoded = html.unescape(unquote(text))
        if decoded == text:
            break
        text = decoded
    return text


def git(repo: str, *args: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", repo, *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode:
        raise RuntimeError("Git could not inspect the proposed committed tree")
    return result.stdout


def check_revision(repo: str, revision: str) -> list[tuple[str, int | None, str]]:
    # Resolve the object before using it in ls-tree; arbitrary CLI refs cannot
    # become options. Tree records and blob IDs keep unusual paths unambiguous.
    tree = git(repo, "rev-parse", "--verify", "--end-of-options", revision + "^{tree}").strip().decode("ascii")
    records = git(repo, "ls-tree", "-rz", "--full-tree", tree).split(b"\0")
    findings: list[tuple[str, int | None, str]] = []
    for record in records:
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, object_type, object_id = metadata.split(b" ")
        path = raw_path.decode("utf-8", "surrogateescape")
        if excluded_path(path):
            findings.append((path, None, "excluded marketplace publication path"))
            continue
        if object_type != b"blob" or not is_document(path):
            continue
        # Treat document symlinks as publication content as well; do not follow
        # local filesystem links or inspect uncommitted working-tree content.
        content = git(repo, "cat-file", "blob", object_id.decode("ascii")).decode("utf-8", "replace")
        for number, line in enumerate(content.splitlines(), 1):
            normalized = normalized_text(line)
            if FORBIDDEN_HOST.search(normalized):
                findings.append((path, number, "excluded document host"))
            elif MARKETPLACE_TEXT.search(normalized):
                findings.append((path, number, "excluded marketplace document text"))
    return findings


def update_revisions(repo: str, remote_name: str, remote_url: str, local_oid: str, remote_oid: str) -> list[str]:
    """Check newly published history, preserving already published ancestors."""
    commit = git(repo, "rev-parse", "--verify", "--end-of-options", local_oid + "^{commit}").strip().decode("ascii")
    exclusions: list[str] = []
    if not ZERO_OID.fullmatch(remote_oid):
        try:
            old = git(repo, "rev-parse", "--verify", "--end-of-options", remote_oid + "^{commit}")
        except RuntimeError as error:
            raise RuntimeError("remote tip is unavailable locally; fetch the GitLab remote and retry") from error
        exclusions.append(old.strip().decode("ascii"))
    elif re.fullmatch(r"[a-zA-Z0-9._/-]+", remote_name) and not remote_name.startswith("-"):
        # A new branch can share existing GitLab history. Exclude only tracking
        # refs of this same configured push remote, never GitHub tracking refs.
        try:
            configured = git(repo, "remote", "get-url", "--push", "--", remote_name).decode().strip()
        except RuntimeError:
            configured = ""
        if configured == remote_url and is_gitlab_target(configured):
            refs = git(repo, "for-each-ref", "--format=%(objectname)", f"refs/remotes/{remote_name}/")
            exclusions.extend(refs.decode("ascii").splitlines())
    revisions = git(repo, "rev-list", "--reverse", commit, *["^" + oid for oid in exclusions]).decode("ascii").splitlines()
    # Also inspect the final tree on a no-op/re-wind update, where rev-list may
    # produce no new commits. Existing historical commits otherwise stay exempt.
    return list(dict.fromkeys([*revisions, commit]))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("remote_name", nargs="?")
    parser.add_argument("remote_url", nargs="?")
    parser.add_argument("--check", metavar="REV")
    parser.add_argument("--repo", default=".")
    args = parser.parse_args(argv)
    if args.check:
        revisions = [args.check]
    else:
        if not args.remote_url:
            parser.error("provide Git pre-push remote arguments or --check REV")
        if not is_gitlab_target(args.remote_url):
            return 0
        revisions = []
        try:
            for record in sys.stdin:
                fields = record.split()
                if len(fields) != 4:
                    print("KODA GitLab guard: malformed pre-push update record", file=sys.stderr)
                    return 1
                local_ref, local_oid, remote_ref, remote_oid = fields
                if not ZERO_OID.fullmatch(local_oid):
                    revisions.extend(update_revisions(args.repo, args.remote_name, args.remote_url, local_oid, remote_oid))
        except (RuntimeError, ValueError, UnicodeError) as error:
            print(f"KODA GitLab guard: inspection failed: {error}", file=sys.stderr)
            return 1
    failed = False
    try:
        for revision in dict.fromkeys(revisions):
            for path, line, reason in check_revision(args.repo, revision):
                # repr prevents newline/control characters in file names from
                # forging diagnostics, and no document contents are disclosed.
                location = repr(path) + (f":{line}" if line is not None else "")
                print(f"KODA GitLab guard: {location}: {reason}", file=sys.stderr)
                failed = True
    except (RuntimeError, ValueError, UnicodeError) as error:
        print(f"KODA GitLab guard: inspection failed: {error}", file=sys.stderr)
        return 1
    if failed:
        print("Publish a sanitized committed tree to GitLab; the push was rejected.", file=sys.stderr)
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
