# KODA와 KODA SBOM Tracker Linux 운영 안내

현재 Linux 통합 전달물은 KODA와 KODA SBOM Tracker 두 제품으로 구성합니다. 각 프로젝트의 소스·데이터베이스·배포 이력은 따로 유지합니다.

이 경로의 이전 통합본 설치·업데이트 명령은 폐기했습니다. 신규 설치와 기존 환경 전환은 아래 현재 운영 문서를 사용합니다.

- [통합 설치·운영](../../platforms/linux/suite/README.ko.md)
- [설치 장애 진단과 복구](../../platforms/linux/suite/TROUBLESHOOTING.ko.md)
- [폐쇄망 운영과 외부 호출 통제](../security/OFFLINE-OPERATIONS.ko.md)
- [오프라인 반입 데이터](../security/OFFLINE-DATASETS.ko.md)
- [개별·통합 전달물 생성](offline-delivery.md)

업데이트 전에는 KODA 프로젝트·분석 이력과 입력, Tracker PostgreSQL 데이터와 SBOM 원본, 취약점 데이터 릴리스, 설정 및 복구에 필요한 키를 백업합니다. 사용하지 않는 이전 서비스의 데이터 정리는 현행 전환 절차의 대상 확인과 백업을 먼저 수행합니다.
