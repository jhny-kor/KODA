# 2026-10-11 KODA 수정·빌드·실행 검증

[English](verification-2026-10-11.md) · [현재 상태](current-status.ko.md) · [기계 판독 요약](verification-2026-10-11.json)

GitHub 소스 기준 `4efb0bce1e0f5a00a078c77d9f91608d5127a757`와 로컬 미커밋·신규
소스를 합친 개발 작업 트리를 점검하고 오류를 수정했다. **이번 게시에는 문서만
포함한다. 수정 코드·신규 테스트·자산·빌드 산출물·원시 로그는 로컬에 보존한다.**
이 문서의 결과는 기존 설치본·App Store·GitHub 신규 clone의 검증 결과가 아니다.

## 수정한 실행·오류 처리

- Windows SourceOnly 대시보드가 import하는 Grype adapter를 보존하고, 완성 GUI EXE의 시작 smoke 검사를 빌드 단계에 추가했다.
- Syft의 Windows 비소켓 파이프를 두 reader thread와 제한된 queue로 수집한다. stdout 32MiB·stderr 1MiB를 유지하며 EOF 이후에도 원래 deadline을 적용한다.
- 없는 소스 대상은 경고/0건 성공 대신 오류를 전달한다. Java `--fail-on`/`--fail-on-kev` 요청에서 Grype 부재·비활성화는 exit 2이며, gate 없는 명시적 SBOM-only는 exit 0을 유지한다.
- macOS 정상 빈 DEFLATE ZIP/GZIP을 허용하면서 손상·잘린·후행 데이터와 확장 한도를 검사한다.
- macOS Java runner는 실행 중 양쪽 출력을 소비하고 프로세스당 30분 deadline·TERM/KILL 정리를 적용한다.
- macOS helper의 필수 JSON/보고서 자산·명시적 아키텍처·checksum 형식을 보완했다. 영어 UI와 한국어 전용 Java 보고서 인자를 분리했다.
- Linux 그룹 종료 실패는 실행 소유자를 중단하고 workspace·비종결 슬롯·오류를 보존하며 다음 실행을 차단한다. 이전 일시적 권한 오류의 정확한 원인은 확정하지 않았다.
- 반복 문자 비밀값 fixture 및 Linux 설치/롤백 fixture를 현재 계약에 맞추고 미사용 코드 경고를 정리했다. 제품의 탐지·안전 검사를 완화하지 않았다.

## 검증 결과

| 검증 | 결과 | 범위 |
| --- | --- | --- |
| Linux 전체 unittest | **768개: 767 통과, 0 실패, 1 skip** / 198.051초 | Debian 12, Python 3.12.15, amd64 |
| macOS 호스트 전체 unittest | **768개: 760 통과, 0 실패, 8 skip** / 142.730초 | Python 3.14.6, 앞선 수정 단계 |
| Python 3.12 집중 unittest | **214 통과** | CLI·Java·웹·네트워크·Syft·패키징·worker |
| macOS harness | **10개 스크립트 모두 성공** | 압축 8개, Java process 4개, 자산 staging 2개 및 AI fixture 7종 포함; 중복 합산하지 않음 |
| macOS 전체 앱 | **Java 포함 universal Release build/analyze 성공** | arm64+x86_64, 개발자 서명·공증 없음 |
| macOS 실제 Java | **ARM 앱 두 실행 exit 0** | 영어 UI 설정, 전체 네트워크 접근 거부 한국어 설정 |
| Linux 설치 | **실제 install.sh·설치 CLI·PDF·포털 성공** | 비 root 사용자, network none, 준비된 wheels/Chromium 재사용 |
| Linux 실제 포털 | **ZIP 업로드→외부 worker 검사→JSON/PDF 성공** | web/scan/delivery 3개, 두 worker healthy, 잔여 workspace 0 |
| Linux 실제 Java | **DB import exit 0, `--fail-on high` exit 1** | 실제 Syft/Grype, network none, 4GiB 제한 |
| 소스 일치 | **설치된 제품 소스·자산 106개 hash 일치** | Finder metadata/Python cache 제외 |
| 정적 검사 | **Ruff F/E9·수정 shell 문법·diff 통과** | 실행·배포 검증과 별개 |

Linux는 Apple Silicon의 Docker LinuxKit VM에서 **amd64 사용자 공간을 에뮬레이션**했다.
실제 ELF x86-64 Python·도구와 Linux 프로세스/파일 시스템을 실행한 결과이며,
물리 x86_64 CPU·네이티브 x86_64 커널의 검증이나 성능 인증은 아니다.

## Java 자산과 합성 입력

- Syft 1.46.0 / Grype 0.115.0.
- Grype DB schema v6.1.10, built `2026-10-10T06:30:01Z`.
- NVD 2002~2026 및 recent/modified 27개 feed, CISA KEV.
- release checksum·DB 공식 SHA-256·자산 팩 manifest 검증 통과.
- 앱과 helper/tools의 아키텍처 확인, 양쪽 helper 규칙/보고서 자산 해시 일치, 외부 임시 Python 경로 없는 링크 확인.

실행 코드 없는 `log4j-core 2.14.1` Maven 메타데이터 JAR을 사용했다. 양쪽에서
구성요소 1개, 고유 취약점 7개(Critical 2 / High 1 / Medium 4), KEV 1개,
경고 0개로 일치했으며 `CVE-2021-44228`을 확인했다. Linux gate의 exit 1은
예상한 취약점 차단이다. macOS Java 보고서는 UI locale과 관계없이 한국어다.

실제 설치 검증은 `platforms/linux/install.sh --no-link`의 소스 설치 경로다.
`platforms/linux/docker/install.sh`로 전체 Docker 전달물을 반입한 결과는 아니다.
검증 이미지 ID는 기계 판독 요약에 기록했다. 이 이미지는 일반 배포본이나 운영
Suite 전체를 재패키징한 릴리스가 아니다. 테스트 컨테이너는 종료·제거했고 검증
앱·이미지·시험 데이터·로그는 로컬에 보존했다. 기존 App Store 앱은 교체하지 않았다.

## 초기 실패와 최종 결과

초기 전체 실행의 누락된 samples/Git metadata·작업 디렉터리 조건과 오래된 Linux
설치 테스트 fixture를 보완했다. 해당 테스트를 skip하지 않고 최종 전체 실행을
통과했다. Git 관련 계약에는 별도 합성 metadata만 사용했고 호스트 인증 설정은
이미지에 복사하지 않았다. 설치/롤백 unittest의 Docker double과 실제 설치·포털
실행을 구분한다.

## 남은 검증

Windows 실기 실행은 사용자 지시로 제외했다. Intel helper는 빌드·링크 검증 후
실행을 시도했지만 이 호스트에서 `Bad CPU type in executable`이 발생했다.
개발자 서명·공증·App Store 제출, 실제 외부 웹/LLM 품질, 물리 x86_64 서버,
운영 Nginx 로그인·Tracker/GitLab 전송·Suite 업그레이드/복구는 검증하지 않았다.

[OS별 전체 기능 구현표](platform-feature-matrix.ko.md) · [문서 인덱스](README.md)
