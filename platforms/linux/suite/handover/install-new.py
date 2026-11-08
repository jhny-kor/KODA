#!/usr/bin/env python3
"""Fresh installation only; existing installations must use update.sh."""
import argparse
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import handover as h


def require_empty_prefix(prefix):
    if prefix.is_symlink() or (prefix.exists() and (not prefix.is_dir() or any(prefix.iterdir()))):
        raise h.Failure('새 설치 경로는 없거나 빈 디렉터리여야 합니다. 기존 설치는 update.sh를 사용하세요.')


def main(argv=None, runner=None):
    parser = argparse.ArgumentParser(description='기존 데이터를 덮어쓰지 않는 신규 Suite 설치 (공개키 자동 검증)')
    parser.add_argument('--prefix', type=Path, default=h.DEFAULT_PREFIX)
    parser.add_argument('--env-file', type=Path, required=True, help='직접 준비한 실제 운영 설정 파일')
    args = parser.parse_args(argv)
    runner = runner or h.Runner()
    try:
        if sys.platform != 'linux':
            raise h.Failure('Linux 서버에서 실행하세요.')
        prefix = args.prefix.absolute()
        require_empty_prefix(prefix)
        env_file = args.env_file.resolve(strict=True)
        if not env_file.is_file() or env_file.is_relative_to(prefix):
            raise h.Failure('운영 설정은 새 설치 경로 밖의 일반 파일로 준비하세요.')
        env, _ = h.source_environment(env_file, runner)
        host = SimpleNamespace(prefix=prefix, env_file=env_file, env=env, runner=runner)
        release_args = SimpleNamespace(archive=None, release_public_key=h.HERE/'release-public.pem')
        with h.release(release_args, host) as (suite, release_env):
            require_empty_prefix(prefix)
            runner.run(['bash', suite, 'install', '--prefix', prefix, '--env-file', env_file], env=release_env)
        print('신규 설치 완료. 기존 설치·데이터 경로는 사용하지 않았습니다.')
        return 0
    except (h.Failure, OSError, ValueError, EOFError) as error:
        # Never expose env values or command output.
        print('신규 설치 중단: '+(str(error) if isinstance(error,h.Failure) else type(error).__name__), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
