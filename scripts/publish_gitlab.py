#!/usr/bin/env python3
"""Prepare a filtered KODA source publication; --push also commits and pushes it."""
from __future__ import annotations

import argparse
import json
import posixpath
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from gitlab_publication_guard import (
    FORBIDDEN_HOST, MARKETPLACE_TEXT, check_revision, excluded_path,
    is_document, is_gitlab_target, normalized_text,
)


def git(repo: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repo), *args])


def tree_files(repo: Path, revision: str) -> dict[str, tuple[str, str]]:
    result = {}
    for item in git(repo, "ls-tree", "-rz", "--full-tree", revision).split(b"\0"):
        if item:
            metadata, name = item.decode("utf-8").split("\t", 1)
            mode, kind, oid = metadata.split()
            if kind != "blob":
                raise ValueError("Publication does not support embedded Git repositories")
            result[name] = (mode, oid)
    return result


def excluded_publication_path(path: str) -> bool:
    p = path.lower()
    return (excluded_path(path) or p.startswith(("dist/", "store-assets/", "icon/", "archive/"))
            or p in {".gitignore", "docs/windows-host-verification.md", "docs/windows-install-verification.md"}
            or p.startswith("docs/assets/readme/") and ("-en." in p or "-en-" in p))


def markdown_map(files: dict, existing: dict) -> dict[str, str]:
    mapping = {}
    for path in files:
        if not path.endswith(".md") or excluded_publication_path(path):
            continue
        if path.endswith(".en.md") or path == "docs/README.en.md":
            continue
        if path.endswith(".ko.md"):
            destination = path if path in existing else path[:-6] + ".md"
        elif path == "docs/gitlab-integration-ko.md":
            destination = "docs/gitlab-integration.md"
        else:
            if path[:-3] + ".ko.md" in files:
                continue
            destination = path
        mapping[path] = destination
    return mapping


def sanitize_document(text: str) -> str:
    # Store installation/promotional links are removed, rather than relabeled.
    text = "\n".join(line for line in text.splitlines()
                     if not re.search(r"(?:apps|itunes)\.apple\.com", normalized_text(line), re.I)) + "\n"
    text = re.sub(r"\[[^\]]*(?:English|영문|🇬🇧)[^\]]*\]\([^)]*\)", "", text, flags=re.I)
    text = re.sub(r"!?\[([^\]]*)\]\(([^)]*)\)",
                  lambda m: m[1] if FORBIDDEN_HOST.search(normalized_text(m[2])) else m[0], text)
    text = re.sub(r'<a\b[^>]*href=["\']([^"\']*)["\'][^>]*>(.*?)</a>',
                  lambda m: m[2] if FORBIDDEN_HOST.search(normalized_text(m[1])) else m[0],
                  text, flags=re.I | re.S)
    text = re.sub(r'https?://[^\s<>"\')`]+',
                  lambda m: "" if FORBIDDEN_HOST.search(normalized_text(m[0])) else m[0], text)
    text = MARKETPLACE_TEXT.sub("정식 배포", text)
    text = text.replace("이번 GitHub 게시", "이번 GitLab 게시").replace("이번 GitHub", "이번 GitLab")
    # A URL-like reference that escaped the common Markdown/HTML cases must not
    # be silently published. The tree guard will reject it with its location.
    return "\n".join(line.rstrip() for line in text.splitlines()
                     if line.strip() not in {"-", "*", "·"}).rstrip() + "\n"


def remap_links(text: str, source_path: str, target_path: str, mapping: dict[str, str]) -> str:
    def replace(match):
        raw = match[2]
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", raw) or raw.startswith("#"):
            return match[0]
        path, marker, fragment = raw.partition("#")
        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(source_path), path))
        if excluded_publication_path(resolved):
            return re.sub(r'^!?\[(.*)\]\($', r'\1', match[1])
        if resolved in mapping:
            new = posixpath.relpath(mapping[resolved], posixpath.dirname(target_path) or ".")
            return match[1] + new + (marker + fragment if marker else "") + ")"
        return match[0]
    return re.sub(r'(!?\[[^\]]*\]\()([^\n]*?)\)', replace, text)


def write_blob(target: Path, name: str, mode: str, content: bytes) -> None:
    path = target / name
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        path.unlink()
    if mode == "120000":
        if path.exists():
            path.unlink()
        path.symlink_to(content.decode())
    else:
        path.write_bytes(content)
        path.chmod(0o755 if mode == "100755" else 0o644)


def sync_committed_tree(source: Path, revision: str, target: Path) -> dict:
    files = tree_files(source, revision)
    existing = tree_files(target, "HEAD")
    mapping = markdown_map(files, existing)
    # Prefer Korean counterparts; an English source README must not replace the
    # GitLab-specific Korean entry point or its publication policy.
    selected = {}
    for path, destination in mapping.items():
        content = git(source, "cat-file", "blob", files[path][1]).decode("utf-8")
        hangul = len(re.findall(r"[가-힣]", content))
        if hangul > 20 and path not in {"README.md", "SECURITY.ko.md", "SECURITY.md", "docs/gitlab-publication.md"}:
            selected[path] = destination
    mapping = {**mapping, **selected}
    written = []
    for path, (mode, oid) in files.items():
        if excluded_publication_path(path) or path in {"README.md", "docs/gitlab-publication.md"}:
            continue
        content = git(source, "cat-file", "blob", oid)
        destination = path
        if path.endswith(".md"):
            if path not in selected:
                continue
            destination = selected[path]
            text = sanitize_document(content.decode("utf-8"))
            text = remap_links(text, path, destination, mapping)
            note = (f"> GitLab 게시 범위: 제품 소스·테스트·빌드 스크립트와 한국어 문서를 "
                    f"원본 `{revision}`에서 반영합니다. 실행 검증 기록은 각 문서의 "
                    "검증 리비전·환경을 따릅니다. 바이너리·데이터·운영 배포는 별도입니다.\n\n")
            text = re.sub(r"^> GitLab (?:문서 )?게시 (?:범위|기준).*\n\n", "", text, flags=re.M)
            heading, separator, rest = text.partition("\n")
            text = heading + separator + "\n" + note + rest.lstrip("\n")
            content = text.encode()
        elif is_document(path):
            if path.startswith("docs/") and path.endswith(".json"):
                payload = json.loads(content)
                if "publication_scope" in payload:
                    payload["publication_scope"] = "GitLab product source, tests, build scripts and Korean documentation; runtime assets and binaries excluded"
                    payload["published_source_revision"] = revision
                def sanitize_value(value):
                    if isinstance(value, str):
                        return sanitize_document(value).strip()
                    if isinstance(value, list):
                        return [sanitize_value(item) for item in value]
                    if isinstance(value, dict):
                        return {key: sanitize_value(item) for key, item in value.items()}
                    return value
                content = (json.dumps(sanitize_value(payload), ensure_ascii=False, indent=2) + "\n").encode()
            elif destination not in existing:
                # Do not import new promotional HTML/SVG or generated output.
                continue
            else:
                content = sanitize_document(content.decode("utf-8")).encode()
        write_blob(target, destination, mode, content)
        written.append(destination)
    # Keep platform-specific GitLab adjustments and its publication tools that
    # do not exist upstream. Do not delete arbitrary GitLab-only source files.
    for path in existing:
        if excluded_path(path) or path.endswith((".en.md", "/README.en.md")):
            (target / path).unlink(missing_ok=True)
    readme = target / "README.md"
    if readme.exists():
        text = readme.read_text()
        block = ("<!-- KODA:GITLAB_PUBLICATION:START -->\n"
                 "## 소스·문서 게시 기준\n\n"
                 f"원본 `{revision}`의 제품 소스·테스트·빌드 스크립트와 한국어 문서를\n"
                 "반영합니다. 실행 검증은 각 문서의 리비전과 환경을 따르며, 바이너리·\n"
                 "취약점 데이터·운영 배포는 별도입니다. 외부 저장소 문서 링크와 앱마켓\n"
                 "홍보·제출 자료는 제외합니다.\n\n"
                 "<!-- KODA:GITLAB_PUBLICATION:END -->\n\n")
        pattern = r"<!-- KODA:GITLAB_PUBLICATION:START -->.*?<!-- KODA:GITLAB_PUBLICATION:END -->\s*"
        if re.search(pattern, text, re.S):
            text = re.sub(pattern, lambda _: block, text, flags=re.S)
        elif re.search(r"^## (?:문서|소스·문서) 현행화", text, re.M):
            text = re.sub(r"^## (?:문서|소스·문서) 현행화.*?(?=^## |\Z)", lambda _: block, text, count=1, flags=re.M | re.S)
        else:
            first, newline, rest = text.partition("\n")
            text = first + newline + "\n" + block + rest
        readme.write_text(sanitize_document(text))
        written.append("README.md")
    return {"source_revision": revision, "written_files": sorted(set(written)), "document_map": selected}


def validate_local_links(target: Path, paths: list[str]) -> list[str]:
    errors = []
    for name in paths:
        if not name.endswith(".md"):
            continue
        text = re.sub(r"```.*?```", "", (target / name).read_text(), flags=re.S)
        for raw in re.findall(r'!?\[[^\]]*\]\(([^\n]*?)\)', text):
            raw = raw.strip().split(' "', 1)[0].strip("<>")
            if not raw or raw.startswith("#") or re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", raw):
                continue
            from urllib.parse import unquote
            route = unquote(raw.partition("#")[0])
            if not (target / Path(name).parent / route).exists():
                errors.append(name + ": " + raw)
    return errors


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source_root = Path(__file__).resolve().parents[1]
    parser.add_argument("--source", type=Path, default=source_root)
    parser.add_argument("--target", type=Path, default=source_root.parent / "koda-gitlab")
    parser.add_argument("--source-ref", default="origin/main")
    parser.add_argument("--remote", default="origin")
    parser.add_argument("--push", action="store_true")
    args = parser.parse_args(argv)
    try:
        # GitLab receives an already-published source revision, never a dirty
        # working tree or a local-only commit. Functional tests belong upstream;
        # this command only filters documents and validates publication policy.
        subprocess.run(["git", "-C", str(args.source), "fetch", "--no-tags", "origin",
                        "main:refs/remotes/origin/main"], check=True)
        revision = git(args.source, "rev-parse", "--verify", "--end-of-options", args.source_ref + "^{commit}").decode().strip()
        subprocess.run(["git", "-C", str(args.source), "merge-base", "--is-ancestor",
                        revision, "refs/remotes/origin/main"], check=True)
        url = git(args.target, "remote", "get-url", "--push", args.remote).decode().strip()
        if not is_gitlab_target(url):
            raise ValueError("Target must be a configured GitLab remote")
        # Never reset the user's checkout. All publication edits use an isolated
        # worktree based on the current GitLab main, preserving its ancestry.
        subprocess.run(["git", "-C", str(args.target), "fetch", "--no-tags", args.remote,
                        "main:refs/remotes/" + args.remote + "/main"], check=True)
        parent = git(args.target, "rev-parse", "refs/remotes/" + args.remote + "/main").decode().strip()
        output = args.source / ".build" / "gitlab-publications"
        output.mkdir(parents=True, exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix="publication-", dir=output)) / "checkout"
        subprocess.run(["git", "-C", str(args.target), "worktree", "add", "--detach", str(work), parent], check=True)
        result = sync_committed_tree(args.source, revision, work)
        missing_links = validate_local_links(work, result["written_files"])
        if missing_links:
            raise ValueError("Missing publication document targets: " + "; ".join(missing_links))
        git(work, "add", "-A")
        tree = git(work, "write-tree").decode().strip()
        findings = check_revision(str(work), tree)
        if findings:
            for path, line, reason in findings:
                print(f"{path!r}:{line or 0}: {reason}", file=sys.stderr)
            raise ValueError("Filtered publication failed validation; nothing was pushed")
        subprocess.run(["git", "-C", str(work), "diff", "--cached", "--check"], check=True)
        result.update(worktree=str(work), parent_revision=parent, pushed=False)
        if args.push and git(work, "diff", "--cached", "--name-only").strip():
            subprocess.run(["git", "-C", str(work), "commit", "-m",
                            "chore: synchronize filtered KODA source and Korean documentation"], check=True)
            subprocess.run(["git", "-C", str(work), "push", "--no-follow-tags", args.remote, "HEAD:main"], check=True)
            result["pushed"] = True
            result["commit"] = git(work, "rev-parse", "HEAD").decode().strip()
        (work.parent / "publication.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
        print(json.dumps({k: v for k, v in result.items() if k != "document_map" and k != "written_files"}, ensure_ascii=False, indent=2))
        return 0
    except (subprocess.CalledProcessError, ValueError, OSError, UnicodeError) as error:
        print(f"KODA GitLab publication failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
