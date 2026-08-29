# KODA macOS 설치

macOS에는 네이티브 SwiftUI 앱과 로컬 Python 도우미 경로가 있습니다.
개발·검증 환경에서는 저장소의 Xcode 프로젝트와 빌드 스크립트를 사용할 수
있습니다.

## 설치

- 소스 빌드: `platforms/macos/scripts/build-koda-xcode-app.command`

Java 아카이브 메뉴는 앱에 포함된 오프라인 helper, Syft, Grype, NVD, CISA KEV
자료를 사용합니다. 실행 중 자동 다운로드는 하지 않습니다. 앱 언어를 명시해
호출하면 해당 언어로 고정된 HTML을 생성합니다.

- [한국어 문서 인덱스](../README.md)
