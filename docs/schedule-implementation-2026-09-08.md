# 예약 원격 디렉터리 점검 구현 보고서 — 2026-09-08

## 판정

승인된 계획의 KODA·worker 구현 범위를 소스에 반영했다. KODA 기존 수동 점검
경로와 데이터베이스를 worker가 직접 공유하지 않도록 제한된 인증 내부 API를
추가했고, 실제 운영 서버에 연결하거나 GitLab에 게시하는 작업은 수행하지 않았다.

## 구현 범위

- `schedule_api.py`: worker 전용 Bearer 인증 API, 단일 lease, 중복 요청 재생,
  결과·SBOM 영속 저장, 취소/heartbeat, 정리 확인, 90일 예약 결과 정리
- `schedule_api_worker.py`: 별도 worker 프로세스, 순차 대상 처리, 전체/변경분 선택,
  durable result outbox, 재시작 복구, 재전송, 임시 수집물의 성공·실패·취소 후 정리
- `schedule_transport.py`: 읽기 전용 SSH 수집, known-host 검증, 원격 목록·파일
  수·전송량·디스크·속도·시간 제한, 제외 경로와 부분 파일 제거
- `process_limits.py`: Linux CPU affinity, 주소공간 제한, 부모 사망 신호와 분석
  프로세스 그룹 감시
- `schedule_settings.py`, `portal_views.py`, `linux_portal.py`: 관리자 연동 설정의
  대상·규칙·GitLab 매핑과 worker 자원 설정, 예약 결과 탭과 상태 표시, 관리자 취소
- `koda-docker.sh`, Suite 설정: `koda-schedule-worker` 별도 컨테이너, 포털 DB·입력·
  보고서·게시 secret 미마운트, 기본 비활성, read-only rootfs와 CPU/메모리/PID 제한.
  worker 전용 outbound SSH bridge와 포털 API bridge를 사용하며 기존 포털 egress 정책은 유지

## 데이터와 게시 흐름

`원격 임시 수집 → 분석 → 결과/SBOM 저장 → 임시 원본 전체 삭제 → Tracker 전송 →
GitLab 게시` 순서다. 정리 확인 전에는 정상 완료가 되지 않으며, downstream 장애는
원본 재수집 없이 저장된 결과 outbox로 재전송한다. GitLab 예약 경로는
`koda/scheduled/<target-id>/<run-id>`와
`.koda/scheduled-results/<target-id>/<run-id>.json`을 사용한다. 예약 결과는 KODA와
Tracker에서 90일 보관하고 GitLab 파일·MR·Issue는 자동 삭제하지 않는다.

## 검증 범위

로컬 테스트에는 내부 API 인증·lease 경쟁·결과 idempotency·outbox 재생·재시작 및
정리 실패 복구·실제 analyzer 호출·취소/시간 초과·합성 입력의 원본 삭제 방지,
SSH 목록/전송 제한·제외·속도·설정 저장·Linux 프로세스 종료·기존 포털 회귀가
포함된다. Linux amd64의 기존 이미지에 현재 코드를 마운트한 제한 실행도 수행했다.
최신 실행 결과는 아래 검증 기록에 정리했다.

다음 항목은 이 소스 및 로컬 대역 테스트로 확정하지 않는다.

- 실제 원격 서버의 SSH 인증, known_hosts, 권한 오류, 연결 단절 및 대용량 운영 부하
- 실제 GitLab/Tracker 권한, MR·Issue 재사용과 네트워크 장애 복구
- 새 오프라인 배포 이미지의 빌드·서명·운영 호스트 실행
- 브라우저의 실제 시각 회귀와 서버 1대 시범 운영의 CPU·메모리·응답시간 측정

## 검증 기록

| 실행 | 결과 |
| --- | --- |
| `PYTHONPATH=platforms/shared/python python3 -m unittest discover -s tests` | 465개 실행, 실패 0, 환경별 2개 skip |
| 마지막 대기 중 정책 변경 보완 후 API·설정·worker·게시 테스트 | 36개 통과 |
| Linux amd64: API·전송·프로세스 제한 (`--network none --cpus 1 --memory 4g --read-only`) | 24개 통과 |
| Docker/Suite 가짜 Docker 실행 회귀 | 19개 통과, 실행 중 포털 보존·worker 마운트 및 전용 SSH 네트워크 검증 |
| Tracker 전체 백엔드 (`uv run --project apps/api pytest -vv`) | 80개 통과, 외부 Dependency-Track live integration 1개 skip |
| Tracker 예약/RBAC/API 집중 테스트 | 32개 통과 |
| Tracker 웹 전체 테스트 및 빌드 | 29개 통과, production build 성공 |
| Python 구문 검사·쉘 `bash -n`·`git diff --check` | 통과 |

전체 회귀 뒤 추가한 정책 변경 테스트는 후속 집중 테스트와 Linux 테스트에 포함한다.
macOS에서 Linux 전용 Playwright wheel을 설치하는 기존 패키징 경로는 실행할 수
없어, Linux 컨테이너 안에서 동일 `platforms/linux/package.sh`를 실행했다.
Playwright/Chromium을 포함한 소스 패키지 생성에 성공했으며 현재 worker 코드와
패키지 파일 일치 검사도 통과했다. 검증용 산출물은
`/tmp/koda-schedule-package-20260908/koda-linux-x86_64-scheduled-20260908.tar.gz`다. 이 패키지 검증에는 운영 취약점 DB 자산이나
최종 배포용 Docker 이미지 생성·서명은 포함하지 않는다.

Linux 프로세스 제약 구현은 [PR_SET_PDEATHSIG](https://www.man7.org/linux/man-pages/man2/PR_SET_PDEATHSIG.2const.html),
[Python OS API](https://docs.python.org/3.11/library/os.html),
[resource API](https://docs.python.org/3/library/resource.html)를 기준으로 확인했다.

## 배포와 롤백

예약 기능은 `KODA_SCHEDULE_ENABLED=0`으로 배포한 뒤 대상 1개에서 단계적으로
활성화한다. 롤백은 예약 기능을 비활성화하고 `koda-schedule-worker`를 중지하는
것부터 시작하며, 기존 포털 데이터·결과·볼륨은 삭제하지 않는다. 운영 배포와
실제 게시는 이번 작업에 포함하지 않았다.

## 이전 보고서

이 문서가 현재 구현 상태의 기준이다. [2026-09-07 검증 보고서](schedule-verification-2026-09-07.md)는
API 격리·worker 복구 보완 전의 상태를 기록한 역사 문서이며, [2026-09-08 소스 감사](schedule-source-audit-2026-09-08.md)는
이번 구현 전의 잔여 항목을 기록한 역사 문서다. 두 문서의 “미구현” 판정은 현재
구현 상태의 결론으로 사용하지 않는다.
