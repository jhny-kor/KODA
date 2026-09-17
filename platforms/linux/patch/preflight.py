#!/usr/bin/env python3
"""Read-only checks before applying a KODA Suite image patch."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


CONTRACT_KEYS = (
    "AUTHORITY", "AUTH_CONTRACT_VERSION", "AUTH_COOKIE_NAME",
    "AUTH_COOKIE_SCHEMA_VERSION", "TRACKER_SESSION_ENDPOINT", "KODA_BASE_PATH",
    "GATEWAY_AUTH_MODE", "KODA_PORTAL_SCHEMA_VERSION",
    "KODA_RBAC_CATALOG_VERSION",
)
SERVICES = (
    "portal-web", "portal-api", "portal-worker", "postgres", "gateway",
    "dtrack-apiserver", "dtrack-frontend",
)
APP_SERVICES = set(SERVICES) - {"postgres"}
ALLOWED_BIND_DESTINATIONS = (
    "/run/secrets/", "/etc/nginx/templates/", "/run/koda/tracker-tokens",
)


class PreflightError(RuntimeError):
    pass


def command(args: list[str], *, input_text: str | None = None) -> str:
    try:
        result = subprocess.run(
            args, input=input_text, text=True, capture_output=True, check=True
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise PreflightError(f"command failed: {args[0]}") from exc
    return result.stdout


def metadata(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise PreflightError(f"invalid metadata entry: {path.name}")
        key, value = line.split("=", 1)
        if key in values:
            raise PreflightError(f"duplicate metadata key: {key}")
        values[key] = value
    return values


def same_file(expected: Path, installed: Path) -> None:
    if not expected.is_file() or not installed.is_file():
        raise PreflightError(f"required contract file is missing: {installed}")
    if hashlib.sha256(expected.read_bytes()).digest() != hashlib.sha256(installed.read_bytes()).digest():
        raise PreflightError(f"installed contract differs: {installed.name}")


def compose_base(contract: Path, prefix: Path) -> list[str]:
    return [
        "docker", "compose", "--project-directory", str(prefix / "tracker"),
        "--env-file", str(prefix / "tracker" / ".env"),
        "-f", str(prefix / "tracker" / "compose.yaml"),
        "-f", str(prefix / "tracker" / "compose.airgap.yaml"),
        "-f", str(prefix / "tracker" / "compose.integration.yaml"),
    ]


def contract_root() -> Path:
    return Path(__file__).resolve().parent / "contract"


def inspect_json(container: str) -> dict:
    try:
        return json.loads(command(["docker", "inspect", container]).strip())[0]
    except (IndexError, json.JSONDecodeError) as exc:
        raise PreflightError("docker inspect returned invalid data") from exc


def inspect_image(reference: str) -> dict:
    try:
        return json.loads(command(["docker", "image", "inspect", reference]).strip())[0]
    except (IndexError, json.JSONDecodeError) as exc:
        raise PreflightError("docker image inspect returned invalid data") from exc


def normalize_digest_map(payload: object) -> dict[str, str]:
    if not isinstance(payload, dict) or not payload:
        raise ValueError
    normalized: dict[str, str] = {}
    for name, digest in payload.items():
        if isinstance(digest, list) and digest and all(isinstance(part, str) for part in digest):
            digest = "".join(digest)
        if not isinstance(name, str) or not isinstance(digest, str):
            raise ValueError
        normalized[name] = digest
    return normalized


def check_backend_hashes(contract: Path, containers: dict[str, str]) -> None:
    path = contract / "tracker-backend-sha256.json"
    if not path.exists():
        raise PreflightError("tracker-backend-sha256.json is missing")
    try:
        normalized = normalize_digest_map(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise PreflightError("invalid tracker-backend-sha256.json") from exc
    script = (
        "import hashlib,json,pathlib,koda_tracker; "
        "root=pathlib.Path(koda_tracker.__file__).parent; "
        "print(json.dumps({str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() "
        "for p in root.rglob('*.py')}))"
    )
    for service in ("portal-api", "portal-worker"):
        output = command(["docker", "exec", containers[service], "python3", "-c", script])
        try:
            actual = json.loads(output)
        except json.JSONDecodeError as exc:
            raise PreflightError(f"{service} backend hash output is invalid") from exc
        if actual != normalized:
            raise PreflightError(f"{service} backend source differs")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="KODA Suite patch read-only preflight")
    parser.add_argument("--prefix", required=True, type=Path)
    args = parser.parse_args(argv)
    prefix = args.prefix.expanduser().resolve()
    contract = contract_root()
    if not (prefix / "metadata.env").is_file() or not (prefix / "tracker" / ".env").is_file():
        raise PreflightError(f"existing suite is missing at {prefix}")
    if not (prefix / "koda-suite").is_file() or not (prefix / "koda" / "koda-docker").is_file():
        raise PreflightError(f"existing suite launcher is missing at {prefix}")
    installed_meta = metadata(prefix / "metadata.env")
    current_meta = metadata(contract / "metadata.env")
    for key in CONTRACT_KEYS:
        if key not in installed_meta or key not in current_meta:
            raise PreflightError(f"patch contract key is missing: {key}")
        if installed_meta[key] != current_meta[key]:
            raise PreflightError(f"patch contract changed: {key}")
    for name in ("compose.yaml", "compose.airgap.yaml", "compose.integration.yaml"):
        same_file(contract / "tracker" / name, prefix / "tracker" / name)
    same_file(contract / "tracker" / "gateway" / "gateway.conf.template", prefix / "tracker" / "gateway" / "gateway.conf.template")
    same_file(contract / "koda" / "koda-docker", prefix / "koda" / "koda-docker")
    same_file(contract / "koda-suite", prefix / "koda-suite")

    rendered = json.loads(command(compose_base(contract, prefix) + ["config", "--format", "json"]))
    project = rendered.get("name") or installed_meta.get("COMPOSE_PROJECT_NAME", "koda-sbom")
    services = rendered.get("services", {})
    refs = {service: services.get(service, {}).get("image", "") for service in APP_SERVICES}
    if any(not ref for ref in refs.values()) or "@sha256:" in refs["portal-web"]:
        raise PreflightError("application image reference is missing or digest-pinned")
    containers: dict[str, str] = {}
    records: dict[str, dict] = {}
    for service in SERVICES:
        ids = command(compose_base(contract, prefix) + ["ps", "-q", service]).splitlines()
        if len(ids) != 1 or not ids[0].strip():
            raise PreflightError(f"service is not uniquely present: {service}")
        containers[service] = ids[0].strip()
        records[service] = inspect_json(ids[0].strip())
        if records[service].get("State", {}).get("Status") != "running":
            raise PreflightError(f"service is not running: {service}")
        if service in APP_SERVICES:
            actual = records[service].get("Config", {}).get("Image", "")
            if actual != refs[service]:
                raise PreflightError(f"running image differs: {service}")
            image = inspect_image(records[service]["Image"])
            if image.get("Os") != "linux" or image.get("Architecture") != "amd64":
                raise PreflightError(f"service is not linux/amd64: {service}")
            for mount in records[service].get("Mounts", []):
                if mount.get("Type") != "bind":
                    continue
                destination = str(mount.get("Destination", ""))
                if not any(destination.startswith(dest) for dest in ALLOWED_BIND_DESTINATIONS):
                    raise PreflightError(f"unexpected app source bind mount: {service}")
                if not Path(str(mount.get("Source", ""))).exists():
                    raise PreflightError(f"bind mount source is missing: {service}")
    dashboard = inspect_json("koda-dashboard")
    if dashboard.get("State", {}).get("Status") != "running":
        raise PreflightError("koda-dashboard is not running linux/amd64")
    image_ref = (prefix / "koda" / "image-ref.txt").read_text(encoding="utf-8").splitlines()[0].strip()
    selected = os.environ.get("KODA_IMAGE", image_ref)
    if "@sha256:" in image_ref or selected != image_ref or dashboard.get("Config", {}).get("Image") != image_ref:
        raise PreflightError("KODA image override or running image differs from image-ref.txt")
    image = inspect_image(dashboard["Image"])
    if image.get("Os") != "linux" or image.get("Architecture") != "amd64":
        raise PreflightError("KODA image is not linux/amd64")
    mounts = dashboard.get("Mounts", [])
    if not any(m.get("Source") == str(prefix / "data" / "koda-portal") and m.get("Destination") == "/var/lib/koda" for m in mounts):
        raise PreflightError("koda-dashboard persistent /var/lib/koda mount is missing")
    if not (prefix / "data" / "koda-portal").exists():
        raise PreflightError("KODA portal data directory is missing")
    for mount in mounts:
        destination = str(mount.get("Destination", ""))
        if destination != "/var/lib/koda" and not any(
            destination == allowed.rstrip("/") or destination.startswith(allowed.rstrip("/") + "/")
            for allowed in ("/run/secrets", "/run/koda/tracker-tokens")
        ):
            raise PreflightError("unexpected KODA mount; inspect custom runtime before patch")
        if mount.get("Type") == "bind" and not Path(str(mount.get("Source", ""))).exists():
            raise PreflightError("KODA bind mount source is missing")
    check_backend_hashes(contract, containers)
    print(f"prefix={prefix}")
    print(f"project={project}")
    print("app_images=" + ",".join(f"{name}={refs[name]}" for name in sorted(refs)))
    print("compatibility=passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (PreflightError, OSError, ValueError, KeyError, IndexError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
