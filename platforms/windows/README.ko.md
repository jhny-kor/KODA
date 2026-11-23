# KODA Windows EXE 설치본 빌드

> 기준일 **2026-10-11**. 미커밋 개발 변경을 포함한 로컬 소스 기준입니다.
> Mac 호스트에서 Windows 패키징·프로세스 회귀 및 PowerShell 문법 검사를
> 통과했습니다. Windows EXE·설치본·WebView2·네이티브 Syft 실기 실행은
> 사용자 지시로 제외했습니다. [검증 요약](../../docs/verification-2026-10-11.ko.md)을 확인하세요.

이 폴더는 Windows 직접 배포용 Inno Setup 설치본을 만드는 경로입니다.
실제 `.exe`는 Windows PC에서 PyInstaller와 Inno Setup으로 빌드해야 합니다.

## HAR 기록과 로컬 TCP 수신 포트

Full 대시보드의 **HAR 기록 검토**에서 브라우저가 내보낸 HAR 파일을 읽고
저장된 보안 응답 헤더와 쿠키 속성을 확인합니다. 인증 헤더가 기록된
쓰기 요청과 평문 HTTP 요청을 집계해 JSON으로 저장할 수 있습니다.

대시보드의 **이 PC의 TCP 수신 포트** 또는
`KODA-CLI.exe local-listeners --format markdown`으로 수신 주소와 포트를
확인합니다. `KODA-CLI.exe approval-review --help`는 기존 웹 점검 승인
문서의 서명·만료와 이 PC에 기록된 사용 여부를 확인하는 옵션을 보여 줍니다.

**인증서와 JWT 키 길이 검토**에서 PEM·DER 인증서 파일의 유효 기간과
SHA-256 지문을 확인하고 HS256·HS384·HS512의 최소 키 길이를 대조합니다.
명령줄에서도 `KODA-CLI.exe tls-cert-review --certificate server.cer`와
`KODA-CLI.exe jwt-key-review --algorithm HS256 --key-bits 256`을 사용할 수
있습니다.

## 로컬 SpotBugs와 Semgrep CE

대시보드의 **SpotBugs · Semgrep CE** 또는 `KODA-CLI.exe scan`에서 로컬 Java
바이트코드와 소스를 검사할 수 있습니다. 각 분석기는 별도로 설치합니다.
[도구 설정과 사용법](../../docs/usage.ko.md#로컬-spotbugs와-semgrep-ce)

## 로컬 AI 수정 후보

개인용 대시보드에서 **로컬 AI 수정 후보**를 열고 같은 PC의 OpenAI 호환 서버 주소와 모델을 선택합니다. **모델 목록**은 서버에 설치된 모델을 조회합니다. **연결 저장**은 서버·모델 조합을 사용자 프로필에 저장하고, 입력한 API 키는 Windows 자격 증명 관리자에 보관합니다.

12 KiB 이하의 UTF-8 Python, Java, XML 또는 JavaScript 파일을 선택하면 KODA가 수정 가능한 점검 항목을 표시합니다. 항목을 선택해 후보 생성을 실행하면 구문·인터페이스와 해당 규칙을 다시 검사합니다. 최대 세 번 시도하며 통과한 후보의 차이, 변경 영향 초안, 테스트 계획을 보여 줍니다. **후보 파일 다운로드**는 변경본을 새 파일로 저장합니다.

JavaScript 검증에는 Node.js가 필요합니다. Java 검증에는 PATH의 JDK 도구 `javac`·`javap`와 단일 파일로 컴파일할 수 있는 소스가 필요합니다.

## 결과물과 요구사항

결과물은 `dist\\KODA\\KODA.exe`와 `dist\\Windows\\KODASetup.exe`입니다.
빌드 PC에는 Windows, Python 3.10 이상, Inno Setup 6이 필요합니다. 사용자는
저장소를 복제하지 않고 `KODASetup.exe`만 설치하면 됩니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\platforms\windows\scripts\build-koda-windows-installer.ps1
```

버전은 `-Version 0.1.1`, Inno Setup 경로는
`-InnoCompilerPath "C:\\Path\\To\\ISCC.exe"`로 지정할 수 있습니다.

소스코드 SW49 기능만 빠르게 반복 점검할 때는 다음과 같이 빌드합니다.
최초 1회는 `-SkipDependencyInstall`을 빼서 PyInstaller를 설치하고, 이후
반복 빌드부터 아래처럼 사용합니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\platforms\windows\scripts\build-koda-windows-installer.ps1 `
  -SourceOnly -SkipDependencyInstall
```

이 프로파일은 같은 `KODASetup.exe`를 만들지만 Java/라이브러리·실시간 웹
점검, Playwright/Chromium, Syft·Grype·Grype DB를 포함하지 않습니다. 대시보드,
`koda scan --standard sw-dev-security-49`, 소스 HTML/JSON/Markdown 리포트와
패키지 SW49 스모크 테스트는 유지됩니다. 대시보드 import에 필요한 경량 Python
`grype_adapter` 모듈은 유지하고 Grype 실행 파일·DB는 제외합니다. 빌더는 완성된
`KODA.exe --smoke-test`로 실제 로컬 대시보드 HTTP 응답을 확인하며, 비정상 종료나
30초 제한 시간 초과 시 빌드를 중단합니다. 이 검사는 WebView2 화면을 시험하지
않습니다. `jar-scan`, `web-scan`, `web-audit`이 필요할
때는 `-SourceOnly` 없이 정식 설치본을 다시 빌드해야 합니다.
`web-audit`의 21개 항목은 SourceOnly에서 자동 실행하지 않고
`UNSUPPORTED(package_capability_missing)`으로 보고합니다.

정식 Full 설치본은 공유 Python 엔진과 웹 점검 모듈을 포함합니다.
Full 빌드는 빌드 PC에 Playwright를 설치하고 Chromium을 내려받아 GUI 번들에
포함하며 CLI도 이 브라우저 자산을 재사용합니다. Docker·digest로 고정한 ZAP 이미지·
add-on manifest·BOAST는 별도로 준비해야 합니다. 설치된 스캐너는 실행 중 외부
도구·브라우저를 자동 다운로드하지 않습니다. 먼저
다음처럼 무트래픽 사전 검증을 수행한 뒤 승인된 staging origin으로 실행하세요.

```powershell
$env:KODA_APPROVAL_KEY = "operator-managed-secret"
koda web-audit run `
  --profile .\profile.json `
  --approval .\approval.json `
  --confirm-origin https://staging.example.com `
  --dry-run
```

`PASS`는 모든 필수 시나리오·oracle·cleanup이 완료된 경우에만 의미가 있습니다.
SourceOnly의 `UNSUPPORTED`와 승인/인증 실패의 `NOT_SCANNED`를 구분하여 릴리스
게이트에서 확인하세요.

Microsoft Store 배포에는 Inno 설치본이 아니라 MSIX 또는 `.msixupload`를
사용해야 합니다.

설치 후 `koda scan --target C:\src\project --format html --output reports\source.html`을
실행하면 소스 메인 리포트와 `source-detail.html` 상세 리포트가 함께 생성됩니다.
Java 아카이브는 `koda jar-scan --target C:\deploy\apps --format html`을 사용하며,
`server-library-report.html`과 `server-library-report-detail.html`을 생성합니다.
Windows 프로그램에서는 **보고서 → HTML (메인 + 상세)**를 선택하면 소스 두 파일이
상대 링크를 유지한 ZIP으로 저장됩니다.

여러 배포 폴더를 하나의 라이브러리 리포트로 합치려면 `--target`을 반복 지정합니다.
모든 폴더의 아카이브·컴포넌트·취약점·SBOM이 중복 제거되어 하나의 메인/상세 리포트로
생성됩니다.

```bat
koda jar-scan ^
  --target C:\deploy\api ^
  --target C:\deploy\worker ^
  --output-dir reports\java-scan
```

- [한국어 문서 인덱스](../../docs/README.md)
- [English Windows installer guide](README.md)

## 검사 종료 코드

없는 소스 `--target`은 정상 보고서를 만들지 않고 `2`로 종료합니다. Java의
`--fail-on`·`--fail-on-kev`는 실제 사용 가능한 Grype 비교가 필요합니다.
Grype가 없거나 `--no-grype`로 꺼진 상태에서 게이트를 요청하면 `2`로 종료합니다.
정상 평가한 게이트는 기준에 해당하는 취약점이 있으면 `1`, 없으면 `0`입니다.
게이트 없는 명시적 `--no-grype` SBOM 생성은 지원하지만 이때의 `0`은 취약점이
없다는 판정이 아닙니다. KEV 게이트는 CISA 자료가 없어 평가할 수 없을 때도 `2`입니다.
