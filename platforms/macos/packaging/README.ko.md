# KODA macOS App Store 패키징

이 폴더는 KODA 네이티브 SwiftUI 앱의 App Store 패키징 경로를 담습니다.

기준일 **2026-10-11**. 미커밋 개발 변경을 포함한 로컬 소스 기준입니다.
Java 포함 universal Release 빌드·분석, ARM 앱 시작·오프라인 Java 검사를
통과했습니다. Intel 실행·배포 서명·공증·스토어 제출은 미검증입니다.
[검증 요약](../../../docs/verification-2026-10-11.ko.md)을 확인하세요.

## 포함 항목

- App Store 아이콘·샌드박스 entitlements
- `platforms/macos/app/KODA/KODA.xcodeproj` 네이티브 프로젝트
- 오프라인 Java 스캐너 자산을 포함하는 Xcode 빌드 스크립트
- App Store 아카이브 및 서명 검증 스크립트

## 로컬 빌드

```zsh
platforms/macos/scripts/build-koda-xcode-app.command
```

결과는 `dist/macos/KODA.app`에 생성됩니다. Java 메뉴는 내장 Python helper,
Syft, Grype, Grype DB, NVD, CISA KEV를 사용하며 앱 실행 중 다운로드하지
않습니다. 빌드에는 전체 Xcode와 대상 아키텍처를 지원하는 Python이 필요합니다.

기본 앱 아키텍처는 arm64입니다. 자산은 `KODA_MACOS_ARCH=arm64` 또는
`KODA_MACOS_ARCH=x86_64`로 한 번에 한 아키텍처씩 준비합니다. Intel helper는
Intel Mac 또는 x86_64 Python을 제공하는 교차 빌드 환경에서 만들 수 있습니다.
아키텍처별 venv와 명시적 PyInstaller target architecture를 사용하며 규칙 JSON과
보고서 자산을 포함합니다. 양쪽 자산을 준비한 뒤
`KODA_MACOS_ARCHS="arm64 x86_64"`로 universal 앱을, `KODA_MACOS_ARCHS=x86_64`로
Intel 전용 앱을 만듭니다. staging은 helper·Syft·Grype의 실제 Mach-O 아키텍처를
확인하고 하나라도 없거나 다르면 실패합니다. `manifest.sha256`은 준비 자산 팩
루트에서 확인하며 재배치된 앱 내부 경로에 그대로 적용하지 않습니다.

자산 준비 스크립트는 `platforms/linux/package-offline.sh`로 만든 오프라인 데이터
캐시가 필요하며 기본 NVD 범위는 2002년부터 현재 연도입니다. Java 탐색의 기본
안전 상한은 중첩 깊이 8, 선택 루트 전체 외부 아카이브 10,000개·ZIP 항목 10,000개,
외부 아카이브당 256MiB, 중첩 확장 데이터 256MiB, 보유 데이터 512MiB,
아카이브당 central directory 4MiB, 압축비 1,000입니다. CLI에서는 `--max-depth`로
깊이를 조정할 수 있고 모든 상한을 옵션으로 제공하지는 않습니다. 상한 경고는
검사 범위가 불완전함을 뜻합니다. macOS wrapper는 helper·도구 프로세스마다
1,800초를 적용하고 공유 Java CLI의 Syft·Grype 기본 제한 시간은 300초입니다.
Java HTML·Markdown 보고서는 영어 UI에서도 현재 한국어로 생성됩니다.

App Store용 Java helper에는 명령줄 스캔 경로만 포함하며 대시보드 서버와
Tk 폴더 선택기 모듈은 제외합니다. 이 제외 설정은 공유 Python, Windows,
Linux 및 레거시 macOS 앱 빌드에는 적용되지 않습니다.

App Store 제출은 다음 경로를 사용합니다.

```zsh
platforms/macos/scripts/archive-koda-app-store.command
```

App Store 아카이브는 `KODA_APP_STORE` Swift 조건으로 빌드됩니다. 네이티브 웹
점검은 GET/HEAD 기반 read-only만 허용하고, 로그인 POST·능동 probe·ZAP·상태 변경
시나리오는 실행하지 않습니다. 전체 21개 프로필 점검은 별도의 공유 Python CLI에서
실행해야 합니다. 네이티브 직접배포 앱에는 이 CLI 프로필 엔진이 없습니다.
App Store판의 미지원 항목은 PASS가 아닌
`UNSUPPORTED`/검토 상태로 남깁니다.

배포 경계는 다음과 같습니다.

| 배포판 | 웹 21개 항목 | 실행 경계 |
| --- | --- | --- |
| macOS 공유 Python CLI | 지원 | 네이티브 앱과 별도 실행; `web-audit`의 profile·approval·nonce 게이트 적용 |
| macOS 네이티브 직접배포 앱 | 부분 지원 | 네이티브 웹 점검; 공유 CLI 프로필·oracle 엔진 없음 |
| App Store판 | 부분 지원 | GET/HEAD native read-only만 허용; POST·능동 probe·ZAP·상태 변경은 실행하지 않음 |

공유 Python CLI로 점검할 때는 저장소 루트에서 `PYTHONPATH`를 지정하고 먼저
`web-audit run --dry-run`을 실행하세요. ZAP/Playwright/BOAST는 앱이 자동으로
내려받지 않으며 사전 설치·digest·manifest가 없으면 PASS 대신 capability 상태가
반환됩니다. App Store판에서 `state_change` 또는 GET/HEAD 이외 메서드를 프로필에
선언하면 프로필 검증 단계에서 거부됩니다.

서명된 앱의 App Sandbox와 오프라인 JAR 스모크 테스트를 제출 전에 확인하세요.

- [한국어 문서 인덱스](../../../docs/README.md)
- [English macOS packaging guide](README.md)
