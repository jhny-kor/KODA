# KODA·KODA SBOM Tracker 현행 포털 패치

이 경로의 사전 검사는 **현행 두 제품 설치**에만 사용합니다. 설치된 Compose·gateway·launcher·인증 계약과 Tracker 백엔드의 정확한 소스 해시가 전달물의 native contract와 일치해야 합니다. 필수 서비스는 gateway·portal-web·portal-api·portal-worker·portal-data-updater·portal-metadata-collector·postgres입니다.

구형 외부 분석 서비스가 포함된 스택이나 알 수 없는 파일·이미지·mount가 있으면 부분 패치를 중단합니다. 이 경우 새 통합 전달물의 전체 설치·갱신 절차로 먼저 전환합니다. 검사 파일·설치 계약·백엔드 해시를 편집해 이전 스택에 부분 패치를 적용하지 않습니다.

## 적용 순서

1. 운영 데이터 소유자로 새 전달물의 서명·manifest·체크섬과 이미지 아키텍처를 검증합니다.
2. KODA 이력·입력·설정, Tracker DB·artifact와 취약점 자료를 백업하고 격리된 복원 경로를 준비합니다.
3. 전달물의 `preflight.py --prefix <설치경로>`로 계약을 검사합니다. contract 디렉터리가 포함된 정식 전달물을 사용합니다.
4. 호환되는 이미지 패치는 현행 `koda-suite patch`로 적용합니다. 지원 그룹은 `koda`, `gateway`, `portal-web`, `portal-api-worker`입니다.
5. 전체 상태, 로그인·권한, 알려진 샘플 SBOM의 Grype 분석, 원본 artifact 해시와 과거 이력 보존을 확인합니다.

```bash
PREFIX=/opt/koda-suite
"$PREFIX/koda-suite" status --prefix "$PREFIX"
# 새 전달물을 푼 디렉터리에서 실행
python3 preflight.py --prefix "$PREFIX"
./koda-suite patch --group portal-web --prefix "$PREFIX"
"$PREFIX/koda-suite" status --prefix "$PREFIX"
```

KODA 웹·분석·전달 worker는 같은 릴리스의 이미지를 사용합니다. CPU·메모리·PID 한도, 예약 SSH 경로·전역 활성화, 읽기 전용 취약점 volume은 현재 설정을 보존합니다. 임의의 앱 소스 bind mount나 쓰기 가능한 취약점 데이터 mount는 허용하지 않습니다.

## 실패와 복구

호환성 실패는 서비스를 변경하기 전에 해결합니다. 백업 실패·이미지 해시 불일치·정책 미평가를 정상 완료로 바꾸지 않습니다. 이미지 적용 후 문제가 발생하면 해당 전달물이 보존한 백업·이미지·launcher로 복구하고, 데이터 복원은 필요한 경우에만 격리 검증 후 수행합니다. 전체 볼륨 삭제는 패치 복구 절차가 아닙니다.

[현행 통합 설치](../suite/README.ko.md), [장애 대응](../suite/TROUBLESHOOTING.ko.md), [예약 기능 이미지 패치](../scheduled-release/README.ko.md)를 참고합니다. 기존 외부 분석 서비스의 폐기 자원 정리는 전체 설치·갱신이 소유권 확인 후 수행하며 이 부분 패치는 그 작업을 대신하지 않습니다.
