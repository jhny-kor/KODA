# KODA macOS 설치

> 기준일: **2026-10-11**. 아래 소스 동작은 로컬 작업 트리를 기준으로 합니다.
> 미커밋 개발 변경이 포함되어 있으며, 문서 현행화가 App Store 업데이트·공증·
> 운영 릴리스 검증 완료를 의미하지 않습니다. 설치된 앱의 기능은 배포 버전에 따라 확인하세요.

macOS에는 네이티브 SwiftUI 앱과 로컬 Python 도우미 경로가 있습니다. 일반
사용자는 Mac App Store 앱을 설치하고, 개발·검증 환경에서는 저장소의 Xcode
프로젝트와 빌드 스크립트를 사용할 수 있습니다.

## 설치

- [KODA Mac App Store](https://apps.apple.com/kr/app/koda/id6770264012?mt=12)
- 소스 빌드: `platforms/macos/scripts/build-koda-xcode-app.command`

소스 빌드는 기본적으로 오프라인 Java 자산을 준비하고 Release 앱을
`dist/macos/KODA.app`에 만듭니다. Apple Development 인증서가 있는 개발자는
다음처럼 서명 빌드와 로컬 실행을 확인합니다.

```zsh
CODE_SIGNING_ALLOWED=YES platforms/macos/scripts/build-koda-xcode-app.command
codesign --verify --deep --strict --verbose=2 dist/macos/KODA.app
open -n dist/macos/KODA.app
```

`/Applications/KODA.app`에 복사할 때 기존 Mac App Store 설치본이 root 소유이면
관리자 인증이 필요합니다. 기존 앱을 먼저 백업하고 새 앱의 코드서명과 실행 경로를
확인하세요. 소스 빌드의 Apple Development 서명은 로컬 검증용이며 App Store
배포·공증 완료를 의미하지 않습니다.

Java 아카이브 메뉴는 앱에 포함된 오프라인 helper, Syft, Grype, NVD, CISA KEV
자료를 사용합니다. 실행 중 자동 다운로드는 하지 않습니다. Java HTML·Markdown
보고서는 현재 한국어로 생성됩니다. 영어 UI에서도 Java helper에는 지원되는
`--language ko`를 전달하므로 보고서 언어는 UI 언어와 별개입니다.

## 2026-10-11 검증 범위

현재 로컬 소스의 Java 포함 arm64+x86_64 universal Release 빌드와 Xcode 분석을
통과했습니다. ARM 실제 앱을 실행하고 앱의 headless 진입점으로 번들 Java 검사를
완료했으며, 네트워크를 차단한 검사도 통과했습니다. 영어 UI·한국어 UI 설정 모두
정상 종료했습니다. GUI 버튼으로 Java 검사를 시작하는 경로는 별도로 시험하지
않았습니다. Intel 바이너리는 생성·아키텍처 검증까지 완료했고 실제 Intel 실행은
미검증입니다. 개발자 서명 없는 로컬 검증이며 스토어 배포 완료를 뜻하지 않습니다.
[검증 요약](../verification-2026-10-11.ko.md)을 확인하세요.

## 설정 및 호스트 보안 상태

앱은 규칙 카탈로그를 설정 화면 진입 전에 백그라운드에서 선로딩하고, 설정 화면은
캐시된 결과를 사용합니다. App Sandbox에서는 `fdesetup`, `csrutil`, `defaults`
등의 시스템 명령 결과를 신뢰성 있게 확정할 수 없습니다. 이 경우 FileVault,
자동 로그인, 화면 잠금 등 9개 호스트 항목을 임의의 PASS/FAIL로 판정하지 않고
`미확인(Unverified)`과 다음 조치 위치를 표시합니다. 지원되는 항목은 시스템 설정을
바로 열고, SIP는 명령과 복구 모드 경로를 안내합니다.

- FileVault: 시스템 설정 > 개인정보 보호 및 보안 > FileVault
- 자동 로그인·게스트 사용자: 시스템 설정 > 사용자 및 그룹
- 화면 잠금: 시스템 설정 > 잠금 화면
- 자동 업데이트: 시스템 설정 > 일반 > 소프트웨어 업데이트
- 방화벽: 시스템 설정 > 네트워크 > 방화벽
- Gatekeeper: 시스템 설정 > 개인정보 보호 및 보안 > 보안
- SIP: `csrutil status`로 확인하고 변경은 macOS 복구 모드에서 수행

## 네이티브 웹 점검

웹 점검의 `전체 선택`은 웹 옵션 10개만 선택·해제하며 ZAP 설정과 섞이지 않습니다.
전체 선택에는 능동 XSS/SQLi/리다이렉트 검증이 포함되므로 승인된 대상에서만
사용하세요. 네이티브 크롤은 기본 50페이지·깊이 3이며 크롤 frontier 처리는 최대
100개 URL로 제한됩니다. 능동 검증·자산·호스트 probe 요청은 이 frontier 한도와
별도입니다. 네이티브 능동 검증은 URL 쿼리 매개변수만 확인하고 HTML 폼은 제출하지
않습니다. 상한, 자산 읽기, WebKit 렌더링 실패로 확인하지 못한 범위는 경고로
남깁니다. `KODA_APP_STORE` 빌드 조건은 GET/HEAD 기반 read-only 범위를 유지합니다.
이는 현재 소스의 분기 설명이며 설치된 스토어 버전의 실기 검증 결과는 아닙니다.

- [한국어 문서 인덱스](../README.md)
- [English macOS install](macos.md)

## 로컬 AI 개발 경로

현재 로컬 작업 트리에는 저장된 모델 연결·AI 설명·오탐 검토·Python/Java/XML/
JavaScript 수정본 미리보기·회귀 계획·Python 영향 분석·별도 AI 보고서가 있습니다.
AI 요청은 이 Mac의 loopback 서버에만 보내며 원본 소스를 자동 변경하지 않습니다.
미게시 개발 파일과 별도 ad-hoc 개발 빌드가 필요한 기능으로, 스토어 설치 안내와
구분합니다. 실행 명령·전송 범위·도구 요구사항·검증 한계는
[로컬 AI 개발 가이드](../macos-local-ai.ko.md)를 확인하세요.
