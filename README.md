# KODA

<p align="center">
  <img src="docs/assets/readme/koda-capabilities-architecture-outcomes-ko.png" alt="KODA 기능과 구현 구조" width="760">
</p>

KODA는 소스 코드, 설정, 의존성, 호스트와 웹 보안 상태를 로컬에서 점검하는
오프라인 우선 보안·품질 스캐너입니다. 기본 동작은 로컬 파일과 로컬 대시보드에
머무르며, 웹·ZAP 점검은 명시적으로 권한을 받은 대상에만 사용해야 합니다.

## 빠른 시작

Python 3.10 이상이 필요합니다. 공통 엔진은 표준 라이브러리만 사용하므로 별도
패키지 설치가 필요하지 않습니다.

```bash
git clone https://gitlab.aigov.go.kr/y2kthr/koda.git
cd koda
export PYTHONPATH="$PWD/platforms/shared/python"
python3 -m security_scanner app
```

대시보드는 `http://127.0.0.1:8765`에서 열립니다. 프로젝트를 점검하려면 예제
설정을 복사해 대상 경로를 지정한 뒤 다음 명령을 실행합니다.

```bash
cp platforms/shared/python/scanner_config.example.json my-config.json
python3 -m security_scanner scan --config my-config.json
```

## 목적별 한국어 문서

| 목적 | 문서 |
| --- | --- |
| 전체 문서와 기능별 시작점 | [한국어 문서 인덱스](docs/README.md) |
| CLI·설정·보고서·CI 사용법 | [CLI 및 로컬 사용법](docs/usage.md) |
| macOS 설치 | [macOS 설치](docs/install/macos.md) |
| Linux 설치·운영 | [Linux 설치·운영](docs/install/linux.md) |
| Windows 설치·빌드 | [Windows 설치](docs/install/windows.md) |
| 폐쇄망 배포 | [폐쇄망 배포 개요](docs/install/offline-delivery.md) |
| Java SBOM·취약점 점검 | [Java SBOM 점검 런북](docs/security/java-sbom-vulnerability-scan.md) |
| 보안 연동·VEX·ZAP | [한국어 문서 인덱스의 보안 연동](docs/README.md#보안-점검연동-security) |

## 지원 범위

- 소스 코드·설정·의존성·비밀 값·보안 예방 점검
- JAR/WAR/EAR 오프라인 SBOM 및 취약점 비교
- macOS 네이티브 앱과 Linux·Windows·CI용 공통 Python 엔진
- 호스트 보안 상태와 승인된 웹·ZAP 점검
- HTML, JSON, SARIF, CycloneDX 보고서와 선택형 CI 게이트

## 안전 및 정책

일반 스캔은 읽기 전용입니다. `fix --apply`, 예방 템플릿 생성, 웹·ZAP 능동
점검은 파일을 변경하거나 대상에 접속할 수 있으므로 권한과 범위를 확인한 뒤
사용하세요.

- [개인정보 보호정책](PRIVACY.md)
- [보안 정책](SECURITY.md)
- [라이선스](LICENSE)
