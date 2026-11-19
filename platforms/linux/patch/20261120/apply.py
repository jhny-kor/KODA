#!/usr/bin/env python3
"""Apply or roll back the 2026-11-20 application patch on a native KODA Suite."""
import argparse
import fcntl
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ENV = Path("tracker/.env")
GATEWAY = Path("tracker/gateway/gateway.conf.template")
SCANNER = Path("koda/image-ref.txt")
FILES = (ENV, GATEWAY, SCANNER)
LAUNCHER = "koda-suite"
TRACKER_APPS = {"portal-web", "portal-api", "portal-worker"}
KEYS = {
    "PORTAL_WEB_IMAGE": "local/koda-patch-tracker-web",
    "PORTAL_API_IMAGE": "local/koda-patch-tracker-api",
    "PORTAL_WORKER_IMAGE": "local/koda-patch-tracker-api",
    "PORTAL_IMAGE_TAG": "20261120",
}
IMAGE_REFS = {
    "local/koda-patch-scanner:20261120",
    "local/koda-patch-tracker-api:20261120",
    "local/koda-patch-tracker-web:20261120",
}


def run(*args, capture=False, environment=None):
    return subprocess.run(args, check=True, text=True, env=environment,
                          stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE if capture else None).stdout


def regular(path):
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"일반 파일이 필요합니다 ({path})")
    return path


def digest(path):
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024**2), b""):
            checksum.update(block)
    return checksum.hexdigest()


def verify_archive():
    seen = set()
    for line in regular(ROOT / "manifest.sha256").read_text().splitlines():
        checksum, name = line.split("  ", 1)
        relative = Path(name)
        if (relative.is_absolute() or ".." in relative.parts or name in seen
                or not re.fullmatch(r"[0-9a-f]{64}", checksum)):
            raise ValueError("패치 manifest 항목이 올바르지 않습니다.")
        path = regular(ROOT / relative)
        if not path.resolve().is_relative_to(ROOT) or digest(path) != checksum:
            raise ValueError(f"무결성 검사 실패 ({name})")
        seen.add(name)
    required = {"apply.py", "image-inventory.json", "images.tar", "gateway-upload-locations.conf",
                "README.ko.md", "handover/backup.sh", "handover/verify-backup.sh", "handover/handover.py"}
    if not required <= seen:
        raise ValueError("패치 manifest에 필수 파일이 없습니다.")


def compose_command(prefix):
    tracker = prefix / "tracker"
    command = ["docker", "compose", "--project-directory", str(tracker), "--env-file", str(tracker / ".env")]
    for name in ("compose.yaml", "compose.airgap.yaml", "compose.integration.yaml", "compose.data-key.yaml"):
        path = tracker / name
        if name == "compose.data-key.yaml":
            environment = (prefix / ENV).read_text()
            key_file = None
            for line in environment.splitlines():
                match = ASSIGNMENT.match(line)
                if match is not None and match[1] == "TRACKER_DATA_UPDATE_VERIFY_KEY_FILE":
                    key_file = setting_text(match[2])
            if not key_file:
                continue
        command.extend(("-f", str(regular(path))))
    return command


UPLOAD_DEFAULT = 5 * 1024**3
UPLOAD_PATH = "= /api/v1/sbom-runs"
ROUTES = (
    "= /api/v1/vulnerability-data-bundles/upload",
    "= /api/v1/vulnerability-intelligence/import-csv",
    "= /api/v1/compatibility-data/import",
    "= /api/v1/upgrade-batches/import",
    "~ ^/api/v1/sbom-runs/[^/]+/vex-import$",
    "~ ^/api/v1/(package-metadata/import|vulnerability-intelligence/import)$",
    "= /api/v1/offline-intelligence/import",
    UPLOAD_PATH,
    "^~ /koda/api/",
)
LIMITS = ("client_max_body_size", "client_body_timeout", "proxy_read_timeout", "proxy_send_timeout")
ASSIGNMENT = re.compile(r"^\s*(?:export\s+)?([A-Z_][A-Z0-9_]*)\s*=\s*(.*)$")
SUITE_ENV_PREFIXES = ("COMPOSE_", "POSTGRES_", "TRACKER_", "KODA_", "PORTAL_", "PUBLIC_HTTP_", "APP_NETWORK_", "GATEWAY_")


def installed_environment(prefix):
    declared = {match[1] for line in (prefix / ENV).read_text().splitlines()
                if (match := ASSIGNMENT.match(line)) is not None}
    declared.update({"UPLOAD_MAX_BYTES", "NGINX_IMAGE"})
    return {key: value for key, value in os.environ.items()
            if key not in declared and not key.startswith(SUITE_ENV_PREFIXES)}


def verify_installed_storage(prefix):
    environment = installed_environment(prefix)
    model = json.loads(run(*compose_command(prefix), "config", "--format", "json",
                           capture=True, environment=environment))
    services = model.get("services", {})
    if not (TRACKER_APPS | {"gateway", "postgres"}) <= set(services):
        raise ValueError("설치의 Tracker 서비스 구성이 패치 대상과 일치하지 않습니다.")
    pg = services["postgres"].get("environment", {})
    api = services["portal-api"].get("environment", {})
    targets = (
        ("postgres", "postgres-data", pg.get("PGDATA", "/var/lib/postgresql/data")),
        ("portal-api", "tracker-artifacts", api.get("TRACKER_ARTIFACT_DIR", "/var/lib/sbom-tracker/artifacts")),
        ("portal-api", "vuln-data", api.get("TRACKER_GRYPE_DB_DIR", "/var/lib/sbom-tracker/vuln-data")),
        ("portal-api", "data-updates", api.get("TRACKER_DATA_UPDATE_SPOOL_DIR", "/var/lib/sbom-tracker/data-updates")),
    )
    volumes = set()
    for service, role, target in targets:
        matches = [mount for mount in services[service].get("volumes", [])
                   if mount.get("source") == role or
                   (mount.get("target") and Path(target).is_relative_to(mount["target"]))]
        if len(matches) != 1:
            raise ValueError(f"기존 Suite 데이터 저장소를 확인할 수 없습니다 ({service} {role})")
        mount = matches[0]
        source = mount.get("source")
        if mount.get("type") == "volume" and source in model.get("volumes", {}):
            volumes.add(model["volumes"][source]["name"])
        elif mount.get("type") != "bind" or not source or not Path(source).is_dir():
            raise ValueError(f"기존 Suite 데이터 경로를 확인할 수 없습니다 ({service} {role})")
    if volumes:
        run("docker", "volume", "inspect", "--format", "{{.Name}}", *sorted(volumes),
            capture=True, environment=environment)


def location(config, selector, *, required=False):
    tokens = r"[ \t]+".join(map(re.escape, selector.split()))
    start_pattern = rf"^([ \t]*)location[ \t]+{tokens}[ \t]*\{{"
    matches = list(re.finditer(start_pattern + r"[ \t]*(?:#[^\n]*)?$", config, re.MULTILINE))
    if not matches and not required:
        if re.search(start_pattern, config, re.MULTILINE):
            raise ValueError(f"한 줄로 작성된 게이트웨이 경로는 자동 병합할 수 없습니다 ({selector})")
        return None
    if len(matches) != 1:
        raise ValueError(f"Suite 게이트웨이 경로를 확인할 수 없습니다 ({selector})")
    start = matches[0]
    indent = re.escape(start[1])
    end = re.compile(rf"^{indent}\}}[ \t]*(?:#[^\n]*)?$", re.MULTILINE).search(config, start.end())
    if end is None:
        raise ValueError(f"Suite 게이트웨이 경로의 닫는 괄호가 없습니다 ({selector})")
    return start.start(), end.end()


def directive(block, name):
    pattern = rf"^([ \t]*{re.escape(name)}[ \t]+)([^;\n]+)(;[^\n]*)$"
    matches = list(re.finditer(pattern, block, re.MULTILINE))
    if len(matches) > 1:
        raise ValueError(f"게이트웨이 설정에 중복 지시어가 있습니다 ({name})")
    return matches[0] if matches else None


def quantity(value, size):
    units = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3} if size else {
        "": 1, "ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400,
    }
    match = re.fullmatch(r"([0-9]+)([a-zA-Z]*)", value.strip())
    if not match or match[2].lower() not in units:
        raise ValueError(f"게이트웨이 제한값을 자동 확인할 수 없습니다 ({value.strip()})")
    return int(match[1]) * units[match[2].lower()]


def set_limit(block, name, minimum):
    match = directive(block, name)
    if match is None:
        header, body = block.split("\n", 1)
        return f"{header}\n        {name} {minimum};\n{body}"
    is_size = name == "client_max_body_size"
    old = quantity(match[2], is_size)
    if (is_size and old == 0) or old >= quantity(minimum, is_size):
        return block
    return block[:match.start(2)] + minimum + block[match.end(2):]


def merge_gateway(config, reference, upload_bytes):
    for selector in ROUTES:
        first, last = location(reference, selector, required=True)
        defaults = reference[first:last]
        existing = location(config, selector)
        if existing is None:
            anchor = location(config, "/api/", required=True)[0]
            if selector == "^~ /koda/api/":
                raise ValueError("설치의 KODA 인증 게이트웨이 경로가 없습니다.")
            config = config[:anchor] + defaults + "\n\n" + config[anchor:]
            existing = location(config, selector, required=True)
        first, last = existing
        block = config[first:last]
        for name in LIMITS:
            setting = directive(defaults, name)
            if setting is not None:
                minimum = setting[2].strip()
                if selector == UPLOAD_PATH and name == "client_max_body_size" and upload_bytes > UPLOAD_DEFAULT:
                    minimum = str(upload_bytes + 2 * 1024**2)
                block = set_limit(block, name, minimum)
        buffering = directive(defaults, "proxy_request_buffering")
        if buffering and directive(block, "proxy_request_buffering") is None:
            header, body = block.split("\n", 1)
            block = f"{header}\n        proxy_request_buffering off;\n{body}"
        config = config[:first] + block + config[last:]
    return config


def prepare(prefix):
    for path in (*FILES, Path(LAUNCHER), Path("tracker/deploy/nginx/http-error.html")):
        regular(prefix / path)
    old_environment = (prefix / ENV).read_bytes().decode("utf-8")
    old_gateway = (prefix / GATEWAY).read_text()
    reference = regular(ROOT / "gateway-upload-locations.conf").read_text()
    upload_bytes = UPLOAD_DEFAULT
    lines = []
    for line in old_environment.splitlines(keepends=True):
        assignment = ASSIGNMENT.match(line.rstrip("\r\n"))
        if assignment is not None and assignment[1] == "UPLOAD_MAX_BYTES":
            value = setting_text(assignment[2])
            if value:
                if not value.isascii() or not value.isdecimal():
                    raise ValueError("UPLOAD_MAX_BYTES는 바이트 단위 정수여야 합니다.")
                upload_bytes = max(int(value), UPLOAD_DEFAULT)
            continue
        if assignment is None or assignment[1] not in KEYS:
            lines.append(line)
    if lines and not lines[-1].endswith(("\n", "\r")):
        lines.append("\n")
    lines.extend(f"{key}={value}\n" for key, value in {**KEYS, "UPLOAD_MAX_BYTES": upload_bytes}.items())
    gateway = merge_gateway(old_gateway, reference, upload_bytes)
    return {
        ENV: "".join(lines).encode(),
        GATEWAY: gateway.encode(),
        SCANNER: b"local/koda-patch-scanner:20261120\n",
    }


def setting_text(text):
    pieces = shlex.split(text, comments=True, posix=True)
    return " ".join(pieces)


def write_atomic(path, data):
    mode = regular(path).stat().st_mode & 0o777
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
        try:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
            temporary.chmod(mode)
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def backup_config(prefix):
    root = prefix / "backups" / "patch-20261120"
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    backup = Path(tempfile.mkdtemp(prefix=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-"), dir=root))
    for path in FILES:
        target = backup / path
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.copy2(prefix / path, target)
    return backup


def load_verified_images():
    inventory = json.loads(regular(ROOT / "image-inventory.json").read_text())
    if {image["reference"] for image in inventory} != IMAGE_REFS:
        raise ValueError("이미지 목록이 패치와 일치하지 않습니다.")
    for image in inventory:
        prior = subprocess.run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", image["reference"]],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=False,
        )
        if prior.returncode == 0 and prior.stdout.strip() not in {image["id"], image["configId"]}:
            raise ValueError(f"같은 이름의 다른 이미지가 이미 있습니다 ({image['reference']})")
    run("docker", "load", "--input", str(ROOT / "images.tar"))
    for image in inventory:
        output = run("docker", "image", "inspect", "--format", "{{.Os}}/{{.Architecture}} {{.Id}}",
                     image["reference"], capture=True).strip().split()
        if len(output) != 2 or output[0] != "linux/amd64" or output[1] not in {image["id"], image["configId"]}:
            raise ValueError(f"이미지 검사 실패 ({image['reference']})")


def restart(prefix):
    commands = compose_command(prefix)
    environment = installed_environment(prefix)
    # Reload the mounted template after the new API and KODA container have
    # addresses. The normal Suite launcher starts the gateway in that order.
    run(*commands, "stop", "gateway", environment=environment)
    run(*commands, "rm", "--force", "gateway", environment=environment)
    run(str(prefix / LAUNCHER), "start", "--prefix", str(prefix), environment=environment)
    run(*commands, "exec", "-T", "gateway", "nginx", "-t", environment=environment)
    run(str(prefix / LAUNCHER), "status", "--prefix", str(prefix), environment=environment)


def restore(prefix, backup):
    paths = {path: regular(backup / path).read_bytes() for path in FILES}
    for path, data in paths.items():
        write_atomic(prefix / path, data)
    restart(prefix)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, required=True)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true")
    action.add_argument("--apply", action="store_true")
    action.add_argument("--rollback", type=Path, metavar="BACKUP")
    args = parser.parse_args()
    if sys.version_info < (3, 10):
        raise ValueError("Python 3.10 이상이 필요합니다.")
    prefix = args.prefix.resolve(strict=True)
    if os.uname().sysname != "Linux" or os.uname().machine not in {"x86_64", "amd64"}:
        raise ValueError("패치 대상은 Linux x86_64입니다.")
    if prefix.stat().st_uid != os.geteuid():
        raise ValueError("설치 디렉터리의 소유자 계정으로 실행하세요.")
    with (prefix / ".koda-suite-operation.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.rollback:
            backup = args.rollback.resolve(strict=True)
            if backup.parent != (prefix / "backups" / "patch-20261120").resolve():
                raise ValueError("이 설치에 대해 생성한 패치 설정 백업 경로를 지정하세요.")
            restore(prefix, backup)
            return
        updates = prepare(prefix)
        verify_installed_storage(prefix)
        verify_archive()
        if args.check:
            print("파일 무결성, 설치 구조, Compose 서비스 검사 통과")
            return
        load_verified_images()
        backup = backup_config(prefix)
        print(f"설정 복구 경로 {backup}", flush=True)
        try:
            for path, data in updates.items():
                write_atomic(prefix / path, data)
            restart(prefix)
        except (ValueError, OSError, subprocess.CalledProcessError) as exc:
            print(f"서비스 기동 실패, 보관한 설정으로 복구합니다 ({exc})", file=sys.stderr)
            restore(prefix, backup)
            raise


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        sys.exit(str(exc))
