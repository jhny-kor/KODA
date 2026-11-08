# macOS Swift 웹 정밀 점검 검증 기록

검증일: 2026-10-22. 대상: 현재 작업 폴더의 macOS arm64 개발 소스.
Xcode 27.0, Swift 6.4.0을 사용했습니다.

## 구현

- `NativeWebAuditModels.swift`: 버전 있는 JSON 프로필, 엄격한 필드 검증,
  21개 통제 항목의 상태, 증거 ID·결과 모델.
- `NativeWebAuditTransport.swift`: 단일 origin·경로·메서드, 계정별 인증·쿠키,
  streaming 응답 제한, 요청·시간·RPS 예산, 취소와 예약된 정리 예산.
- `NativeWebAuditRules.swift`: 수동 신호, 제한된 능동 query 차등,
  내장 노출 규칙. 사용자 정의 matcher는 검토 필요 후보로 유지.
- `NativeWebAuditAPI.swift`: OpenAPI/Swagger JSON 입력 표본, 음성 표본,
  로컬 참조, 제한된 JSON/form 입력과 응답 상태·required/type 검사.
- `NativeWebAuditor.swift`: 크롤링·규칙·API·권한 행렬·업무 시나리오를
  공통 정책으로 실행하고 JSON/HTML/Markdown 보고서 생성.
- `NativeWebAuditView.swift`, `ContentView.swift`: 앱의 동적 점검 메뉴,
  권한 확인·계정·API·프로필·실행 한도·중지·결과·보고서 UI.
- `KODAApp.swift`: GUI와 같은 검사 경로를 실행하는 환경변수 자동화 진입점.

## 실제 검증 결과

| 검사 | 결과 |
|---|---|
| `tests.test_native_web_transport`, `tests.test_native_web_rules` | 3개 테스트 메서드 통과. 실제 production Swift 컴파일, 루프백 HTTP와 19개 규칙/API subcase 포함 |
| `platforms/macos/tests/test_native_web_audit.py` | 23개 테스트 메서드 통과, skip 없음, 10.502초 |
| 실제 빌드한 앱 실행 파일 | 정상 종료 0, 확정 취약점 1, 요청 한도 미완료 2의 세 경우 확인 |
| 보고서 | JSON·HTML·Markdown 생성, 21개 상태, 증거 ID 연결, 계정 정보 제거와 출력 escape 확인 |
| 직접 배포용 전체 앱 | Java 검사 자산을 포함한 Debug 빌드 통과 |
| App Store 제한 | GET/HEAD·능동/상태 변경 제한을 적용한 앱 빌드와 analyze 통과 |
| Swift 6 엄격 검사 | 생산 핵심 5파일 `-warnings-as-errors -typecheck` 통과 |
| 변경 파일 공백 검사 | `git diff --check` 통과 |

전체 자동 검사 메서드는 **26개**입니다. 실제 앱 세 경우는 위 23개 테스트의
한 메서드에 포함된 subcase이며 별도의 테스트 수로 중복 합산하지 않았습니다.

오탐과 실행 정책의 회귀에는 다음을 포함합니다.

- 로그인 HTML의 HTTP 200, 보호 데이터 marker 없는 200, 경로별 SPA/soft404는
  권한 우회나 파일 노출로 자동 확정하지 않음.
- 익명·기본·추가 계정의 헤더와 쿠키 격리, 계정 세션 쿠키 지속.
- 외부 origin·redirect·API 외부 server/$ref에 접근하지 않음.
- 응답 크기·요청 예산·기간·취소를 실제 통신에서 강제.
- 상태 변경 뒤 취소해도 예약된 예산으로 실제 정리 요청 수행. 정리 500은 미완료.
- 좁게 지정한 경로 밖의 내장 규칙을 실행하지 않음.
- 능동 검사 해제 시 API 음성 표본과 필수 입력 제거 요청을 전송하지 않음.
- 프로필 오타·빈 oracle·빈 시나리오·중복 ID·규칙 충돌을 전송 전에 거부.
- 증거가 없는 통제 항목을 PASS로 올리지 않음.

## 재현과 증거

```bash
python3 -m unittest tests.test_native_web_transport tests.test_native_web_rules -v
KODA_TEST_APP_BINARY="$PWD/.build/macos-web-full/Build/Products/Debug/KODA.app/Contents/MacOS/KODA" \
  python3 platforms/macos/tests/test_native_web_audit.py
```

이 작업 폴더의 `.build/macos-web-verification/`에 통합 검사 로그, 단위 검사 로그,
빌드·분석 로그와 `summary.json`을 보관했습니다. 검증한 앱 실행 파일 SHA-256:

```text
3cb446810ea87e5931a6e217d6bede3c99d6ef52e37dc4fb19f132013101c280
```

## 남은 검증 공백

Mac이 잠겨 있고 UI 도구의 자동 잠금 해제가 중지된 상태여서, 실제 창의 배치와
클릭·파일 선택·중지 버튼을 통한 화면 조작은 검증하지 못했습니다. 앱 프로세스의
실행과 동일 생산 코드의 검사·보고서 생성은 별도로 검증했습니다.

이 결과는 로컬 HTTP fixture와 macOS arm64 개발 빌드에 대한 것입니다.
실제 외부 서비스 탐지율, 실제 HTTPS 대상·프록시 환경, Intel Mac 실행,
배포 서명·공증·App Store 심사 완료를 의미하지 않습니다. API와 규칙의 지원
범위·미지원 사항은 [사용 안내](MACOS-WEB-AUDIT.ko.md)를 따릅니다.
