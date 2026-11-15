#!/usr/bin/env python3
"""Recover a missing Suite gateway proof from the two running containers."""
import argparse
import fcntl
import hmac
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import tempfile

KEY = "KODA_GATEWAY_PROOF"
PROOF = re.compile(r"[A-Za-z0-9_-]{32,128}")
ASSIGNMENT = re.compile(rb"^[ \t]*(?:export[ \t]+)?KODA_GATEWAY_PROOF[ \t]*=(.*)$")


class RecoveryError(Exception):
    pass


def docker(*args):
    try:
        return subprocess.run(
            ["docker", *args], check=True, capture_output=True, text=True, timeout=20,
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise RecoveryError("Docker에서 대상 컨테이너를 읽을 수 없습니다. 기존 설치 계정과 Docker 접근을 확인하세요.") from exc


def live_proof(prefix):
    tracker = prefix / "tracker"
    portal_data = prefix / "data" / "koda-portal"
    if not portal_data.is_dir():
        raise RecoveryError("대상 경로에서 기존 KODA 데이터 폴더를 찾을 수 없습니다.")
    ids = docker("ps", "-q", "--filter", "label=com.docker.compose.service=gateway").split()
    gateways = json.loads(docker("inspect", "--type", "container", *ids)) if ids else []
    owned = []
    for container in gateways:
        labels = container["Config"].get("Labels") or {}
        workdir = labels.get("com.docker.compose.project.working_dir")
        if (workdir and Path(workdir).resolve() == tracker and container["State"]["Running"]
                and labels.get("com.docker.compose.service") == "gateway"):
            owned.append(container)
    if len(owned) != 1:
        raise RecoveryError("대상 설치의 실행 중인 gateway를 하나로 확인할 수 없습니다.")
    dashboard, = json.loads(docker("inspect", "--type", "container", "koda-dashboard"))
    if not dashboard["State"]["Running"] or not any(
        mount["Type"] == "bind" and Path(mount["Source"]).resolve() == portal_data.resolve()
        for mount in dashboard.get("Mounts", [])
    ):
        raise RecoveryError("대상 설치의 실행 중인 koda-dashboard를 확인할 수 없습니다.")

    values = []
    for name, container in (("gateway", owned[0]), ("koda-dashboard", dashboard)):
        entries = [entry.partition("=")[2] for entry in container["Config"].get("Env") or []
                   if entry.startswith(KEY + "=")]
        if len(entries) > 1 or entries and entries[0] and not PROOF.fullmatch(entries[0]):
            raise RecoveryError(f"{name}에서 기존 gateway proof의 형식을 확인할 수 없습니다.")
        values.append(entries[0] if entries else "")
    if not any(values):
        raise RecoveryError("gateway와 koda-dashboard 모두에 복구할 기존 값이 없습니다. 구버전 전환 절차가 필요합니다.")
    if not all(values) or not hmac.compare_digest(*values):
        raise RecoveryError("gateway와 koda-dashboard에서 같은 기존 값을 확인할 수 없습니다.")
    return values[0]


def patched_environment(raw, proof):
    lines = raw.splitlines(keepends=True)
    assignments = [(index, match[1]) for index, line in enumerate(lines)
                   if (match := ASSIGNMENT.fullmatch(line.rstrip(b"\r\n")))]
    if len(assignments) > 1:
        raise RecoveryError("운영 .env에 gateway proof가 중복 선언되어 있습니다.")
    ending = b"\r\n" if b"\r\n" in raw else b"\n"
    setting = KEY.encode("ascii") + b"=" + proof.encode("ascii")
    if assignments:
        index, value = assignments[0]
        try:
            words = shlex.split(value.decode("utf-8"), comments=True)
        except (UnicodeError, ValueError) as exc:
            raise RecoveryError("운영 .env의 기존 gateway proof 선언을 해석할 수 없습니다.") from exc
        line = lines[index]
        original_setting = line.rstrip(b"\r\n")
        if original_setting == setting:
            return None
        if any(words) and words != [proof]:
            raise RecoveryError("운영 .env에 실행 중인 값과 다른 gateway proof가 이미 있습니다.")
        lines[index] = setting + line[len(original_setting):]
        return b"".join(lines)
    if lines and lines[-1].rstrip(b"\r\n").endswith(b"\\"):
        raise RecoveryError("운영 .env 마지막 줄이 줄 연속 문자로 끝납니다.")
    return raw + (ending if raw and not raw.endswith(b"\n") else b"") + setting + ending


def read_environment(env):
    fd = os.open(env, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as file:
        info = os.fstat(file.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise RecoveryError("기존 .env 파일의 소유 계정으로 실행하세요.")
        return file.read(), info


def write_private(directory, prefix, raw, group=None):
    with tempfile.NamedTemporaryFile(dir=directory, prefix=prefix, delete=False) as file:
        path = Path(file.name)
        try:
            if group is not None and os.fstat(file.fileno()).st_gid != group:
                os.fchown(file.fileno(), -1, group)
            file.write(raw)
            file.flush()
            os.fsync(file.fileno())
        except BaseException:
            path.unlink(missing_ok=True)
            raise
    return path


def recover(prefix, apply):
    prefix = prefix.resolve(strict=True)
    env = prefix / "tracker" / ".env"
    if env.parent.resolve(strict=True) != env.parent:
        raise RecoveryError("대상 tracker 경로가 심볼릭 링크입니다.")
    raw, info = read_environment(env)
    updated = patched_environment(raw, live_proof(prefix))
    if updated is None:
        print("운영 .env와 두 컨테이너의 기존 값이 일치합니다.")
        return
    if not apply:
        print("복구 가능: 실행 중인 두 컨테이너의 기존 값이 일치합니다.")
        return

    lock_path = prefix / ".handover-operation.lock"
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, "r+b") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RecoveryError("다른 Suite 작업이 진행 중입니다.") from exc
        current, current_info = read_environment(env)
        if current != raw or (current_info.st_dev, current_info.st_ino) != (info.st_dev, info.st_ino):
            raise RecoveryError("운영 .env가 확인 도중 변경되었습니다. 다시 확인하세요.")
        if patched_environment(current, live_proof(prefix)) != updated:
            raise RecoveryError("확인 도중 실행 중인 gateway proof가 변경되었습니다. 다시 확인하세요.")
        backup = write_private(env.parent, ".env.gateway-proof-backup.", raw)
        temporary = write_private(env.parent, ".env.gateway-proof-new.", updated, info.st_gid)
        try:
            latest, latest_info = read_environment(env)
            if latest != raw or (latest_info.st_dev, latest_info.st_ino) != (info.st_dev, info.st_ino):
                raise RecoveryError("운영 .env가 복구 도중 변경되었습니다. 다시 확인하세요.")
            os.replace(temporary, env)
        finally:
            temporary.unlink(missing_ok=True)
        print(f"기존 gateway proof를 복구했습니다. 비공개 .env 백업: {backup}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, required=True, help="기존 KODA Suite 설치 경로")
    parser.add_argument("--apply", action="store_true", help="검증한 기존 값을 .env에 저장")
    args = parser.parse_args()
    try:
        recover(args.prefix, args.apply)
    except RecoveryError as exc:
        parser.exit(2, f"복구 중단: {exc}\n")
    except (OSError, ValueError, TypeError, KeyError):
        parser.exit(2, "복구 중단: 대상 파일 또는 Docker 응답을 확인할 수 없습니다. 설정 값은 출력하지 않습니다.\n")


if __name__ == "__main__":
    main()
