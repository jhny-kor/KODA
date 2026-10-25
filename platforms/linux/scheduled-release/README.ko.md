# KODA Linux 예약 기능 이미지 패치

**이미 현행 native 두 제품 구성으로 전환한 Linux x86_64 KODA Suite**를 위한 이미지 패치입니다. 구형 외부 분석 스택과 과거 launcher·backend baseline은 지원하지 않습니다. Compose·gateway·인증 계약·소스 해시가 다르면 전체 통합 설치·갱신 절차로 먼저 전환합니다.

Docker Engine, Compose v2, Python 3, Bash, sha256sum, flock이 필요합니다. 새 패키지는 검증된 KODA·Tracker 이미지 3종, 현재 launcher와 native 호환 계약, 대응 소스·법적 고지·이미지 목록·manifest를 포함합니다. `provenance.json`과 이미지 목록을 실제 전달물의 증거로 사용하며 이 디렉터리의 과거 검증 숫자를 새 이미지의 검증 결과로 간주하지 않습니다.

## 보존과 사전 검사

- KODA SQLite WAL을 반영한 백업, PostgreSQL 논리 덤프, 설정·gateway·취약점 자료 백업을 만든 뒤 이미지를 교체합니다.
- 기존 `.env`, 계정·프로젝트·결과·SBOM 원본·데이터 volume과 자원 한도·예약 SSH 설정을 보존합니다.
- 이미지 적재와 해시 검증은 서비스 중지 전에 수행합니다. 백업 실패 시 이미지 교체로 진행하지 않습니다.
- 현재 native 서비스 7개가 정확히 존재해야 합니다. 임의 서비스 추가·앱 소스 bind mount·알 수 없는 launcher는 중단합니다.
- LDAP를 위한 portal-api 전용 egress network와 기존 설정의 literal IP DNS 1~4개만 제한적으로 허용합니다. 기관별 주소를 코드에 고정하지 않으며 다른 Compose 변경은 전체 텍스트 비교로 거절합니다.

새 전달물을 푼 디렉터리에서 기존 데이터 소유자로 실행합니다.

```bash
PREFIX=/opt/koda-suite
sha256sum -c manifest.sha256
python3 preflight.py --prefix "$PREFIX"
bash apply.sh --prefix "$PREFIX"
"$PREFIX/koda-suite" status --prefix "$PREFIX"
```

`apply.sh`는 Linux x86_64 대상입니다. 현재 데이터의 소유자가 아닌 계정으로 임의 전환하지 않습니다. 백업은 설치 경로의 `backups/scheduled-release/<UTC>`에 보관하며 이전 이미지도 복구용 태그로 유지합니다.

## 예약 점검과 자원 설정

예약 기능은 기본 비활성입니다. 활성화할 때에는 승인한 대상의 읽기 전용 SSH 키와 검증된 `known_hosts`를 준비합니다. 키·토큰은 패키지에 포함하지 않습니다.

```bash
bash apply.sh --prefix /opt/koda-suite \
  --enable-schedule --ssh-dir /opt/koda-schedule-ssh
```

예약 worker 기동과 관리자 설정의 전역 점검 활성화는 별개입니다. 기존 활성화와 SSH 경로는 재적용 시 보존합니다. `KODA_SCHEDULE_CPUS`, `KODA_SCHEDULE_MEMORY`, 전송률·간격·디스크 여유 설정은 호스트의 실제 여유 범위에서 조정합니다. SSH 연결·대상 권한과 실제 예약 실행은 해당 서버에서 검증합니다.

KODA 웹·수동 분석·전달 worker의 이미지가 일치하는지 확인합니다. Tracker 분석·데이터 갱신 worker도 기동 상태와 해당 분석·반입 작업을 확인합니다. 이미지 패치는 취약점 피드의 신규 반입을 대신하지 않습니다.

## 실패와 롤백

서비스를 중지하기 전 계약·이미지 검증이 실패하면 원인을 해결하고 다시 검사합니다. 백업 실패나 부분 태그 교체 실패는 그대로 보존한 백업과 이전 이미지로 복구합니다. `rollback.sh --help`에서 해당 전달물의 복구 인자를 확인하고 기록된 백업 디렉터리를 사용합니다.

롤백은 선택한 패치 백업의 이미지·launcher·설정 복구입니다. 데이터 전체 파기나 신규 설치 초기화가 아닙니다. KODA SQLite·Tracker DB·SBOM 원본 해시·과거 리비전·활성 취약점 자료와 자원 한도를 확인한 뒤 운영을 재개합니다.

[현행 통합 설치·전환](../suite/README.ko.md), [설치·로그인·worker 장애 대응](../suite/TROUBLESHOOTING.ko.md)을 함께 참고합니다. 이 문서 개정 과정에서는 실제 운영 서버 적용이나 현재 Mac의 기존 자원 삭제를 수행하지 않았습니다.
