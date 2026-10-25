# 개인정보·회사 식별정보·내부주소 읽기 전용 조사

감사일: 2026-10-19. 두 저장소의 현재 파일 시스템을 조사했습니다. 소스·설정·실행 자료는 수정하지 않았습니다. 아래 값은 마스킹되었으며, 후보가 실제로 유효한 비밀번호인지 외부 시스템에 인증해 확인하지 않았습니다.

## 최종 변경 후 제한 재점검: 기관 DNS 하드코딩 해소

최종 소스 변경 뒤 최근 변경된/새 파일 중 Git ignored를 제외한 텍스트 **453개(KODA 322개, Tracker 131개)**를 제한적으로 다시 검사했습니다. 전체 4.80GB 검사를 반복하지 않았습니다. 별도 작업에서 설정 기반 검증으로 바꾼 다음 3개 tracked 경로를 Git HEAD의 이전 리터럴과 대조했습니다.

|경로|이전 실제 기관 DNS 리터럴|현재 원본 소스|처리 상태|
|---|---:|---:|---|
|security/platforms/linux/scheduled-release/apply.sh|2개|0개|설치 설정 기반 검증으로 변경되어 해소|
|security/platforms/linux/scheduled-release/support-ldap-compose.py|2개|0개|설치 설정 기반 검증으로 변경되어 해소|
|security/tests/test_ldap_compose_compat.py|2개|0개|RFC5737 테스트 주소로 변경되어 해소|

이 두 실제 DNS 값은 `.hostmap`의 실제값 매핑과 별도로 확인된 항목입니다. **기존 매핑으로 확인한 Tracker tracked 4개 파일·24개 행은 계속 남아 있으며, 위 KODA 3개 경로는 해소된 항목**으로 구분합니다. 단일 비밀/실제 주소 재유입 검사 결과 위 두 주소가 해당 3개 소스/테스트에 다시 들어오지 않았습니다. 엄격 한국 휴대전화 형식 후보도 0개입니다. 현재 공공 공급자·정상 라이선스/법적 참조 정보는 정리 대상으로 분류하지 않았습니다.

과거 산출물 `security/dist/linux-update-20260916-final/repair-ldap-compose.sh.txt:36`에는 같은 두 DNS 값이 남아 있습니다. 이 파일은 현재 **untracked**, Git ignore에는 걸리지 않는 과거 로컬 배포 자료입니다. GitHub 게시 대상으로 확정되지 않았으므로 사용자 지시에 따라 삭제하지 않고 보존했습니다. 추후 강제로/일괄 Git 추가하거나 이 과거 자료를 별도 배포할 경우에는 다시 검토할 항목입니다. 이 추가 잔존 항목은 `.hostmap` 매핑 59건/49행 통계에 포함되지 않습니다.

이 후속 점검은 실제값 비교와 최근 변경 파일에 한정합니다. 기존 보고서의 OCR·대형 Grype·Git 이력·바이너리·최종 전달 패키지에 대한 한계는 유지합니다.

## 사용자 최신 범위: GitHub 게시 대상만 우선 검토

**GitHub에 게시하지 않는 ignored/local 자료는 삭제 대상에서 제외하고 보존합니다.** `.env`·runtime 인증응답·세션·`.hostmap`·브라우저 기록·과거 빌드 후보는 개인정보/자격 자료가 존재한다는 사실을 기록했으며 삭제하지 않았습니다.

판정은 각 저장소 `git ls-files`와 `git check-ignore --no-index`를 사용했습니다. 현재 tracked 파일은 게시 검토 대상, ignored는 로컬 보존, 무시되지 않은 untracked 새 소스·문서는 게시 후보입니다. **GitLab 게시 필터를 GitHub에 적용하지 않았습니다.** 아래는 현재 checkout 기준이며, 이미 GitHub에 공개되어 있는지 원격 커밋 이력까지 대조한 결과는 아닙니다. 강제 추가(`git add -f`)나 별도 패키징은 ignored도 포함할 수 있으므로 이 구분과 별도로 전달 산출물을 검토해야 합니다.

|저장소|범위|파일 수|중복 제외 행 위치|매핑 일치 건수|
|---|---|---:|---:|---:|
|security|ignored-local / GitHub 비게시 보존|4|4|4|
|security-sbom-dependecy|ignored-local / GitHub 비게시 보존|8|17|19|
|security-sbom-dependecy|tracked-current / GitHub 게시 검토 대상|4|24|32|
|security-sbom-dependecy|untracked / GitHub 게시 후보|2|4|4|

게시 검토 대상의 확정 내부값은 **Tracker tracked 4개 파일의 24개 행(매핑 중복 포함 32건)**입니다. 추가로 무시되지 않은 untracked HTML 가이드 2개 파일·4개 행이 게시 후보입니다. KODA에서 같은 실제값을 확인한 4개 파일은 모두 `.build` 아래 ignored 과거 게시 후보로, GitHub 비게시 로컬 보존 범위입니다.

Tracked 우선 위치:

- `security-sbom-dependecy/docs/operations-ko.md`: 내부 서비스 도메인 및 사설 IP.
- `security-sbom-dependecy/docs/troubleshooting-ko.md`: 내부 서비스 도메인 및 사설 IP.
- `security-sbom-dependecy/docs/presentations/koda-suite-user-briefing.html:494,495`: 내부 서비스 도메인.
- `security-sbom-dependecy/apps/web/src/App.tsx:1039`: LDAP 입력 예시에 실제 조직 메일/도메인.

실제값 매핑의 최종 개별 위치와 게시 구분:

|위치|분류|마스킹값|GitHub 게시 구분|
|---|---|---|---|
|security/.build/gitlab-publications/publication-n6qti1ma/checkout/docs/install/koda-tracker-linux-operations.md:749|internal mapping row 3|k***.kr|ignored-local / GitHub 비게시 보존|
|security/.build/gitlab-publications/publication-k1lpavuv/checkout/docs/install/koda-tracker-linux-operations.md:749|internal mapping row 3|k***.kr|ignored-local / GitHub 비게시 보존|
|security/.build/gitlab-publications/publication-dxstadqw/checkout/docs/install/koda-tracker-linux-operations.md:749|internal mapping row 3|k***.kr|ignored-local / GitHub 비게시 보존|
|security/.build/gitlab-publications/publication-jxj5ri2l/checkout/docs/install/koda-tracker-linux-operations.md:749|internal mapping row 3|k***.kr|ignored-local / GitHub 비게시 보존|
|security-sbom-dependecy/.hostmap:3|internal mapping row 3|k***.kr|ignored-local / GitHub 비게시 보존|
|security-sbom-dependecy/.hostmap:4|internal mapping row 4|1***147|ignored-local / GitHub 비게시 보존|
|security-sbom-dependecy/.hostmap:5|internal mapping row 5|s***.kr|ignored-local / GitHub 비게시 보존|
|security-sbom-dependecy/.hostmap:5|internal mapping row 6|s***.kr|ignored-local / GitHub 비게시 보존|
|security-sbom-dependecy/.hostmap:6|internal mapping row 6|s***.kr|ignored-local / GitHub 비게시 보존|
|security-sbom-dependecy/output/previews/koda-robot-globe.html:980|internal mapping row 3|k***.kr|ignored-local / GitHub 비게시 보존|
|security-sbom-dependecy/output/previews/koda-robot-globe.html:981|internal mapping row 3|k***.kr|ignored-local / GitHub 비게시 보존|
|security-sbom-dependecy/output/previews/koda-guide-before-robot-9e1ad4eb37.html:980|internal mapping row 3|k***.kr|ignored-local / GitHub 비게시 보존|
|security-sbom-dependecy/output/previews/koda-guide-before-robot-9e1ad4eb37.html:981|internal mapping row 3|k***.kr|ignored-local / GitHub 비게시 보존|
|security-sbom-dependecy/output/previews/koda-guide-before-feedback-517d9fd184.html:980|internal mapping row 3|k***.kr|ignored-local / GitHub 비게시 보존|
|security-sbom-dependecy/output/previews/koda-guide-before-feedback-517d9fd184.html:981|internal mapping row 3|k***.kr|ignored-local / GitHub 비게시 보존|
|security-sbom-dependecy/docs/troubleshooting-ko.md:136|internal mapping row 3|k***.kr|tracked-current / GitHub 게시 검토 대상|
|security-sbom-dependecy/docs/troubleshooting-ko.md:140|internal mapping row 3|k***.kr|tracked-current / GitHub 게시 검토 대상|
|security-sbom-dependecy/docs/troubleshooting-ko.md:147|internal mapping row 3|k***.kr|tracked-current / GitHub 게시 검토 대상|
|security-sbom-dependecy/docs/troubleshooting-ko.md:147|internal mapping row 4|1***147|tracked-current / GitHub 게시 검토 대상|
|security-sbom-dependecy/docs/troubleshooting-ko.md:154|internal mapping row 3|k***.kr|tracked-current / GitHub 게시 검토 대상|
|security-sbom-dependecy/docs/troubleshooting-ko.md:154|internal mapping row 4|1***147|tracked-current / GitHub 게시 검토 대상|
|security-sbom-dependecy/docs/troubleshooting-ko.md:161|internal mapping row 3|k***.kr|tracked-current / GitHub 게시 검토 대상|
|security-sbom-dependecy/docs/troubleshooting-ko.md:161|internal mapping row 4|1***147|tracked-current / GitHub 게시 검토 대상|
|security-sbom-dependecy/docs/troubleshooting-ko.md:205|internal mapping row 4|1***147|tracked-current / GitHub 게시 검토 대상|
|security-sbom-dependecy/docs/troubleshooting-ko.md:206|internal mapping row 3|k***.kr|tracked-current / GitHub 게시 검토 대상|
|security-sbom-dependecy/docs/troubleshooting-ko.md:211|internal mapping row 3|k***.kr|tracked-current / GitHub 게시 검토 대상|
|security-sbom-dependecy/docs/operations-ko.md:146|internal mapping row 3|k***.kr|tracked-current / GitHub 게시 검토 대상|
|security-sbom-dependecy/docs/operations-ko.md:146|internal mapping row 4|1***147|tracked-current / GitHub 게시 검토 대상|
|security-sbom-dependecy/docs/operations-ko.md:158|internal mapping row 3|k***.kr|tracked-current / GitHub 게시 검토 대상|
|security-sbom-dependecy/docs/operations-ko.md:160|internal mapping row 3|k***.kr|tracked-current / GitHub 게시 검토 대상|
|security-sbom-dependecy/docs/operations-ko.md:162|internal mapping row 3|k***.kr|tracked-current / GitHub 게시 검토 대상|
|security-sbom-dependecy/docs/operations-ko.md:166|internal mapping row 3|k***.kr|tracked-current / GitHub 게시 검토 대상|
|security-sbom-dependecy/docs/operations-ko.md:175|internal mapping row 4|1***147|tracked-current / GitHub 게시 검토 대상|
|security-sbom-dependecy/docs/operations-ko.md:176|internal mapping row 3|k***.kr|tracked-current / GitHub 게시 검토 대상|
|security-sbom-dependecy/docs/operations-ko.md:195|internal mapping row 3|k***.kr|tracked-current / GitHub 게시 검토 대상|
|security-sbom-dependecy/docs/operations-ko.md:195|internal mapping row 4|1***147|tracked-current / GitHub 게시 검토 대상|
|security-sbom-dependecy/docs/operations-ko.md:196|internal mapping row 3|k***.kr|tracked-current / GitHub 게시 검토 대상|
|security-sbom-dependecy/docs/operations-ko.md:197|internal mapping row 3|k***.kr|tracked-current / GitHub 게시 검토 대상|
|security-sbom-dependecy/docs/operations-ko.md:197|internal mapping row 4|1***147|tracked-current / GitHub 게시 검토 대상|
|security-sbom-dependecy/docs/operations-ko.md:198|internal mapping row 3|k***.kr|tracked-current / GitHub 게시 검토 대상|
|security-sbom-dependecy/docs/operations-ko.md:216|internal mapping row 3|k***.kr|tracked-current / GitHub 게시 검토 대상|
|security-sbom-dependecy/docs/operations-ko.md:216|internal mapping row 4|1***147|tracked-current / GitHub 게시 검토 대상|
|security-sbom-dependecy/docs/operations-ko.md:217|internal mapping row 3|k***.kr|tracked-current / GitHub 게시 검토 대상|
|security-sbom-dependecy/docs/presentations/KODA 사용자 가이드.html:1043|internal mapping row 3|k***.kr|untracked / GitHub 게시 후보|
|security-sbom-dependecy/docs/presentations/KODA 사용자 가이드.html:1044|internal mapping row 3|k***.kr|untracked / GitHub 게시 후보|
|security-sbom-dependecy/docs/presentations/KODA 사용자 가이드 (로봇 포함).html:1043|internal mapping row 3|k***.kr|untracked / GitHub 게시 후보|
|security-sbom-dependecy/docs/presentations/KODA 사용자 가이드 (로봇 포함).html:1044|internal mapping row 3|k***.kr|untracked / GitHub 게시 후보|
|security-sbom-dependecy/docs/presentations/koda-suite-user-briefing.html:494|internal mapping row 3|k***.kr|tracked-current / GitHub 게시 검토 대상|
|security-sbom-dependecy/docs/presentations/koda-suite-user-briefing.html:495|internal mapping row 3|k***.kr|tracked-current / GitHub 게시 검토 대상|
|security-sbom-dependecy/.playwright-cli/page-2026-09-17T06-58-50-890Z.yml:216|internal mapping row 3|k***.kr|ignored-local / GitHub 비게시 보존|
|security-sbom-dependecy/.playwright-cli/page-2026-09-17T06-58-50-890Z.yml:221|internal mapping row 3|k***.kr|ignored-local / GitHub 비게시 보존|
|security-sbom-dependecy/.playwright-cli/page-2026-09-17T07-00-38-067Z.yml:216|internal mapping row 3|k***.kr|ignored-local / GitHub 비게시 보존|
|security-sbom-dependecy/.playwright-cli/page-2026-09-17T07-00-38-067Z.yml:221|internal mapping row 3|k***.kr|ignored-local / GitHub 비게시 보존|
|security-sbom-dependecy/.playwright-cli/page-2026-09-17T06-59-52-747Z.yml:216|internal mapping row 3|k***.kr|ignored-local / GitHub 비게시 보존|
|security-sbom-dependecy/.playwright-cli/page-2026-09-17T06-59-52-747Z.yml:221|internal mapping row 3|k***.kr|ignored-local / GitHub 비게시 보존|
|security-sbom-dependecy/apps/web/dist/assets/index-PGuTnXV5.js:12|internal mapping row 5|s***.kr|ignored-local / GitHub 비게시 보존|
|security-sbom-dependecy/apps/web/dist/assets/index-PGuTnXV5.js:12|internal mapping row 6|s***.kr|ignored-local / GitHub 비게시 보존|
|security-sbom-dependecy/apps/web/src/App.tsx:1039|internal mapping row 5|s***.kr|tracked-current / GitHub 게시 검토 대상|
|security-sbom-dependecy/apps/web/src/App.tsx:1039|internal mapping row 6|s***.kr|tracked-current / GitHub 게시 검토 대상|

## 사람이 우선 검토할 결과

1. **실제 내부값 매핑이 현재 문서와 UI에도 반영되어 있습니다.** Tracker `.hostmap:3~6`의 우변을 실제 값으로 명시한 파일을 기준으로 정확히 역검색했습니다. 총 59개 매핑 일치(중복 제외 49개 행), 그중 현재 Git tracked 32건(24개 행)이며 나머지는 숨김 설정·빌드·미리보기·브라우저 기록입니다. 아래 상세 위치를 참조하세요.
2. **로컬 검증용 자격 증명 및 세션 자료가 남아 있습니다.** `security-sbom-dependecy/runtime/native-verification-20261017/.env:7,17,47,49,67,95`에 DB 비밀번호, DB URL 내 비밀번호, 관리자 초기 비밀번호, LDAP 암호화 키, 웹훅 비밀값이 존재합니다. 생성된 로컬 검증값으로 보이며 사용 범위·재사용 여부는 확인이 필요합니다. `runtime/migration-verification-20261018/source-bootstrap.json:1`, 같은 폴더 `source-auth.json:1`, `runtime/java-regex-verification-20261018/source-auth.json:1`, `runtime/literal-verification-20261018/source-auth.json:1`에도 세션/CSRF/JWT 또는 초기 자격 자료 후보가 존재합니다. 배포·공유 대상에서 분리하고, 다른 환경에 재사용한 값은 교체를 권고합니다.
3. **사용자 홈 경로가 코드·스크립트·로그·배포/검증 자료에 반복됩니다.** `/Users/<user>/...` 형태이며 개인정보 재유입을 막기 위해 보고서에서도 사용자명을 가렸습니다. 절대 경로는 실행 위치에 따라 환경 변수·상대 경로로 전환 가능한지 검토하세요.
4. **정상 저작권·라이선스 정보는 구분합니다.** SSVC 라이선스의 저자 이름/메일, 제3자 패키지 저자·회사, 공공 보안기관·표준·공급자 이름은 정상 출처 정보입니다. 일괄 삭제하면 라이선스 의무와 출처가 손상될 수 있습니다. 자체 `security/platforms/macos/app/KODA/KODA/Info.plist:28`의 회사 저작권 표기와 `KODA.xcodeproj/project.pbxproj:356,381`의 개발팀 식별자 `4***U`는 제품/배포 식별정보로 별도 검토할 항목이며 비밀번호는 아닙니다.
5. **현재 소스·문서 재검사에서는 실제 휴대전화/주민번호로 확정한 항목이 없습니다.** 휴대전화 광범위 후보는 크기 상수·해시·날짜·버전의 숫자 조각이 다수였습니다. 현재 plain-text 1,676개 파일을 엄격한 한국 휴대전화 형식으로 재확인한 결과 후보 0개입니다. 실제 주민번호 전체임을 입증한 항목도 없습니다. 이는 부재의 완전한 보증이 아닙니다. 개인 이름과 회사명은 자연어·이미지·바이너리 전체에 대해 완전 식별이 어렵습니다.
6. **IP는 용도를 구분합니다.** 루프백/미지정 바인드, RFC5737 및 IPv6 문서 예제, Docker 사설 서브넷, 알려진 공용 DNS는 운영 예시 또는 표준 구성입니다. `.hostmap`에 실제값으로 대응시킨 사설 IP는 내부 환경 정보입니다. 현재 plain-text에서 공인 IP가 네트워크 접속 주소로 쓰인 추가 후보는 발견되지 않았으며, 광범위 숫자 패턴에는 버전 문자열 오탐이 많습니다.

## 실제값 매핑으로 확인한 위치

`internal mapping row 3`: 내부 서비스 도메인, row4: 실제 사설 IP, row5: 실제 메일, row6: 기관/회사 도메인. `.hostmap` 좌변은 예시/자리표시자이며 우변이 실제값으로 설명되어 있습니다.

|위치|분류|마스킹값|파일 상태|
|---|---|---|---|
|security/.build/gitlab-publications/publication-n6qti1ma/checkout/docs/install/koda-tracker-linux-operations.md:749|internal mapping row 3|k***.kr|local/generated|
|security/.build/gitlab-publications/publication-k1lpavuv/checkout/docs/install/koda-tracker-linux-operations.md:749|internal mapping row 3|k***.kr|local/generated|
|security/.build/gitlab-publications/publication-dxstadqw/checkout/docs/install/koda-tracker-linux-operations.md:749|internal mapping row 3|k***.kr|local/generated|
|security/.build/gitlab-publications/publication-jxj5ri2l/checkout/docs/install/koda-tracker-linux-operations.md:749|internal mapping row 3|k***.kr|local/generated|
|security-sbom-dependecy/.hostmap:3|internal mapping row 3|k***.kr|local/generated|
|security-sbom-dependecy/.hostmap:4|internal mapping row 4|1***147|local/generated|
|security-sbom-dependecy/.hostmap:5|internal mapping row 5|s***.kr|local/generated|
|security-sbom-dependecy/.hostmap:5|internal mapping row 6|s***.kr|local/generated|
|security-sbom-dependecy/.hostmap:6|internal mapping row 6|s***.kr|local/generated|
|security-sbom-dependecy/output/previews/koda-robot-globe.html:980|internal mapping row 3|k***.kr|local/generated|
|security-sbom-dependecy/output/previews/koda-robot-globe.html:981|internal mapping row 3|k***.kr|local/generated|
|security-sbom-dependecy/output/previews/koda-guide-before-robot-9e1ad4eb37.html:980|internal mapping row 3|k***.kr|local/generated|
|security-sbom-dependecy/output/previews/koda-guide-before-robot-9e1ad4eb37.html:981|internal mapping row 3|k***.kr|local/generated|
|security-sbom-dependecy/output/previews/koda-guide-before-feedback-517d9fd184.html:980|internal mapping row 3|k***.kr|local/generated|
|security-sbom-dependecy/output/previews/koda-guide-before-feedback-517d9fd184.html:981|internal mapping row 3|k***.kr|local/generated|
|security-sbom-dependecy/docs/troubleshooting-ko.md:136|internal mapping row 3|k***.kr|tracked|
|security-sbom-dependecy/docs/troubleshooting-ko.md:140|internal mapping row 3|k***.kr|tracked|
|security-sbom-dependecy/docs/troubleshooting-ko.md:147|internal mapping row 3|k***.kr|tracked|
|security-sbom-dependecy/docs/troubleshooting-ko.md:147|internal mapping row 4|1***147|tracked|
|security-sbom-dependecy/docs/troubleshooting-ko.md:154|internal mapping row 3|k***.kr|tracked|
|security-sbom-dependecy/docs/troubleshooting-ko.md:154|internal mapping row 4|1***147|tracked|
|security-sbom-dependecy/docs/troubleshooting-ko.md:161|internal mapping row 3|k***.kr|tracked|
|security-sbom-dependecy/docs/troubleshooting-ko.md:161|internal mapping row 4|1***147|tracked|
|security-sbom-dependecy/docs/troubleshooting-ko.md:205|internal mapping row 4|1***147|tracked|
|security-sbom-dependecy/docs/troubleshooting-ko.md:206|internal mapping row 3|k***.kr|tracked|
|security-sbom-dependecy/docs/troubleshooting-ko.md:211|internal mapping row 3|k***.kr|tracked|
|security-sbom-dependecy/docs/operations-ko.md:146|internal mapping row 3|k***.kr|tracked|
|security-sbom-dependecy/docs/operations-ko.md:146|internal mapping row 4|1***147|tracked|
|security-sbom-dependecy/docs/operations-ko.md:158|internal mapping row 3|k***.kr|tracked|
|security-sbom-dependecy/docs/operations-ko.md:160|internal mapping row 3|k***.kr|tracked|
|security-sbom-dependecy/docs/operations-ko.md:162|internal mapping row 3|k***.kr|tracked|
|security-sbom-dependecy/docs/operations-ko.md:166|internal mapping row 3|k***.kr|tracked|
|security-sbom-dependecy/docs/operations-ko.md:175|internal mapping row 4|1***147|tracked|
|security-sbom-dependecy/docs/operations-ko.md:176|internal mapping row 3|k***.kr|tracked|
|security-sbom-dependecy/docs/operations-ko.md:195|internal mapping row 3|k***.kr|tracked|
|security-sbom-dependecy/docs/operations-ko.md:195|internal mapping row 4|1***147|tracked|
|security-sbom-dependecy/docs/operations-ko.md:196|internal mapping row 3|k***.kr|tracked|
|security-sbom-dependecy/docs/operations-ko.md:197|internal mapping row 3|k***.kr|tracked|
|security-sbom-dependecy/docs/operations-ko.md:197|internal mapping row 4|1***147|tracked|
|security-sbom-dependecy/docs/operations-ko.md:198|internal mapping row 3|k***.kr|tracked|
|security-sbom-dependecy/docs/operations-ko.md:216|internal mapping row 3|k***.kr|tracked|
|security-sbom-dependecy/docs/operations-ko.md:216|internal mapping row 4|1***147|tracked|
|security-sbom-dependecy/docs/operations-ko.md:217|internal mapping row 3|k***.kr|tracked|
|security-sbom-dependecy/docs/presentations/KODA 사용자 가이드.html:1043|internal mapping row 3|k***.kr|local/generated|
|security-sbom-dependecy/docs/presentations/KODA 사용자 가이드.html:1044|internal mapping row 3|k***.kr|local/generated|
|security-sbom-dependecy/docs/presentations/KODA 사용자 가이드 (로봇 포함).html:1043|internal mapping row 3|k***.kr|local/generated|
|security-sbom-dependecy/docs/presentations/KODA 사용자 가이드 (로봇 포함).html:1044|internal mapping row 3|k***.kr|local/generated|
|security-sbom-dependecy/docs/presentations/koda-suite-user-briefing.html:494|internal mapping row 3|k***.kr|tracked|
|security-sbom-dependecy/docs/presentations/koda-suite-user-briefing.html:495|internal mapping row 3|k***.kr|tracked|
|security-sbom-dependecy/.playwright-cli/page-2026-09-17T06-58-50-890Z.yml:216|internal mapping row 3|k***.kr|local/generated|
|security-sbom-dependecy/.playwright-cli/page-2026-09-17T06-58-50-890Z.yml:221|internal mapping row 3|k***.kr|local/generated|
|security-sbom-dependecy/.playwright-cli/page-2026-09-17T07-00-38-067Z.yml:216|internal mapping row 3|k***.kr|local/generated|
|security-sbom-dependecy/.playwright-cli/page-2026-09-17T07-00-38-067Z.yml:221|internal mapping row 3|k***.kr|local/generated|
|security-sbom-dependecy/.playwright-cli/page-2026-09-17T06-59-52-747Z.yml:216|internal mapping row 3|k***.kr|local/generated|
|security-sbom-dependecy/.playwright-cli/page-2026-09-17T06-59-52-747Z.yml:221|internal mapping row 3|k***.kr|local/generated|
|security-sbom-dependecy/apps/web/dist/assets/index-BzarVW1U.js:12|internal mapping row 5|s***.kr|local/generated|
|security-sbom-dependecy/apps/web/dist/assets/index-BzarVW1U.js:12|internal mapping row 6|s***.kr|local/generated|
|security-sbom-dependecy/apps/web/src/App.tsx:1039|internal mapping row 5|s***.kr|tracked|
|security-sbom-dependecy/apps/web/src/App.tsx:1039|internal mapping row 6|s***.kr|tracked|

## Git 현재 설정 추가 확인

Git object/과거 이력은 조사하지 않았습니다. 현재 `.git/config`의 원격 URL은 확인했으며 URL 내 비밀번호 패턴은 발견되지 않았습니다. 원격 저장소 소유자/프로젝트명은 실제 조직 식별자가 될 수 있습니다.

- security/.git/config:9: remote URL configuration, no-embedded-password-pattern
- security/.git/config:12: remote URL configuration, no-embedded-password-pattern
- security-sbom-dependecy/.git/config:9: remote URL configuration, no-embedded-password-pattern
- security-sbom-dependecy/.git/config:16: remote URL configuration, no-embedded-password-pattern


## 조사 범위·확인 수준

- 두 저장소 현재 파일: tracked/untracked/ignored, 숨김 설정, `.build`·`dist`·runtime·output·배포 자산을 inventory했습니다. 최초 전체 조사 기준 수치이며 병행 작업으로 파일 수가 달라질 수 있습니다.
- Git object/과거 이력은 제외하고 현재 `.git/config` 원격 URL 설정만 추가 확인했습니다.
- 텍스트·HTML·로그·JSON·설정·원본 소스와 ZIP/TAR/GZIP/BZIP2 안의 파일, PDF 텍스트, 작은 SQLite 복사본을 읽기 전용으로 확인했습니다. Office ZIP/XML 형식 파싱 경로는 제공되지만 현재 Office 원본 파일은 발견되지 않았습니다.
- 바이너리는 ASCII 문자열 후보를 확인한 수준이며 완전한 역공학·해석이 아닙니다. 중복된 제3자 Go 실행 파일/패키지의 이메일·버전 문자열이 대량 후보로 검출되므로 이를 개인정보 확정 건수로 집계하지 않습니다.
- 정규식 전체 후보 3,242,733건은 중복/버전/라이브러리 문자열이 대부분입니다. 전체 부록을 무한히 늘리는 대신 실제 매핑·로컬 자격·현재 소스 근거와 유형별 통계로 제한했습니다.

|저장소|tracked|untracked|ignored|원본 파일 수|총 바이트|
|---|---:|---:|---:|---:|---:|
|security|502|2124|12562|15188|1840331035|
|security-sbom-dependecy|218|48|18309|18575|3800890043|

실제 검사 단위(압축 내부·중복 포함): {"bytes-examined": 4795685714, "text-units": 26332, "binary-units": 6034, "zip-containers": 19, "sqlite-databases": 1, "tar-containers": 5, "pdf-documents": 2}

## 최종 소스·문서 재검사

병행 소스 변경 후 현재 텍스트 1676개(KODA 1182, Tracker 494)를 재검사했습니다. 제3자 의존성/대형 빌드 캐시/bytecode는 최종 재검사에서 제외하고 최초 전체 inventory와 묶어 해석합니다.

### 사용자 홈 절대 경로: 주요 위치 예시

|위치|유형|마스킹 값|
|---|---|---|
|security/AGENTS.md:6|local-home-path|/Users/<user>|
|security/platforms/macos/app/KODA/KODA/ScannerBridge.swift:2752|local-home-path|/Users/<user>|
|security/platforms/shared/python/security_scanner/.omc/state/last-tool-error.json:3|local-home-path|/Users/<user>|
|security/platforms/shared/python/.omc/state/last-tool-error.json:3|local-home-path|/Users/<user>|
|security/platforms/linux/install.sh:4|local-home-path|/home/<user>|
|security/platforms/linux/README-offline.md:14|local-home-path|/home/<user>|
|security/platforms/linux/README-offline.ko.md:26|local-home-path|/home/<user>|
|security/platforms/linux/scheduled-release/README.ko.md:13|local-home-path|/home/<user>|
|security/platforms/linux/docker/README.en.md:96|local-home-path|/home/<user>|
|security/platforms/linux/docker/Dockerfile:36|local-home-path|/home/<user>|
|security/platforms/linux/docker/install.sh:9|local-home-path|/home/<user>|
|security/platforms/linux/docker/README.md:91|local-home-path|/home/<user>|
|security/platforms/linux/patch/README.ko.md:5|local-home-path|/home/<user>|
|security/dist/diagrams/koda-remote-daily-delta.visual-check.json:9|local-home-path|/Users/<user>|
|security/dist/linux-update-20260916-final/repair-ldap-compose.sh.txt:5|local-home-path|/home/<user>|
|security/dist/linux-update-20260916-final/closed-network-install-guide.ko.md:5|local-home-path|/home/<user>|
|security/dist/linux-update-20260916-final/koda-apply-hotfix-20260917/README.ko.md:12|local-home-path|/home/<user>|
|security/docs/linux-update-2026-09-16.md:14|local-home-path|/home/<user>|
|security/docs/closed-network-install-2026-09-16.ko.md:5|local-home-path|/home/<user>|
|security/docs/linux-update-2026-09-14.md:43|local-home-path|/home/<user>|
|security/docs/install/offline-delivery.md:65|local-home-path|/home/<user>|
|security/docs/install/linux.md:75|local-home-path|/home/<user>|
|security/scripts/publish_gitlab.py:213|local-home-path|/Users/<user>|
|security/.omx/logs/turns-2026-05-18.jsonl:1|local-home-path|/Users/<user>|
|security/.omx/logs/turns-2026-07-17.jsonl:2|local-home-path|/Users/<user>|
|security/.omx/logs/turns-2026-07-15.jsonl:3|local-home-path|/Users/<user>|
|security/.omx/logs/turns-2026-07-08.jsonl:1|local-home-path|/Users/<user>|
|security/.omx/logs/turns-2026-05-07.jsonl:1|local-home-path|/Users/<user>|
|security/.omx/logs/turns-2026-07-13.jsonl:2|local-home-path|/Users/<user>|
|security/.omx/logs/turns-2026-05-05.jsonl:1|local-home-path|/Users/<user>|
|security/.omx/logs/turns-2026-07-14.jsonl:1|local-home-path|/Users/<user>|
|security/.omx/logs/turns-2026-07-16.jsonl:6|local-home-path|/Users/<user>|
|security/.omx/logs/turns-2026-07-12.jsonl:5|local-home-path|/Users/<user>|
|security/.omx/logs/turns-2026-05-04.jsonl:5|local-home-path|/Users/<user>|
|security/.omx/logs/turns-2026-05-08.jsonl:2|local-home-path|/Users/<user>|
|security/.omx/logs/turns-2026-07-07.jsonl:3|local-home-path|/Users/<user>|
|security/.omx/logs/turns-2026-07-23.jsonl:5|local-home-path|/Users/<user>|
|security/.omx/logs/turns-2026-06-27.jsonl:2|local-home-path|/Users/<user>|
|security/.omx/logs/turns-2026-05-15.jsonl:1|local-home-path|/Users/<user>|
|security/.omx/logs/turns-2026-07-03.jsonl:3|local-home-path|/Users/<user>|
|security/.omx/logs/turns-2026-05-17.jsonl:1|local-home-path|/Users/<user>|
|security/.omx/logs/turns-2026-07-25.jsonl:2|local-home-path|/Users/<user>|
|security/.omx/logs/turns-2026-07-06.jsonl:6|local-home-path|/Users/<user>|
|security/.omx/logs/turns-2026-05-09.jsonl:1|local-home-path|/Users/<user>|
|security/.omx/logs/turns-2026-07-22.jsonl:2|local-home-path|/Users/<user>|

같은 사용자 홈 경로가 검사 보고서·원본 manifest·브라우저 로그에도 반복됩니다. 경로에 등장한 사용자명을 실제 실명으로 확정하지는 않습니다.

## 검사 제외·부분 확인 목록

|범위|파일 수|확인 수준|
|---|---:|---|
|file larger than128MiB; content not parsed|3|전체 의미 해석 제외|
|media/font: no OCR/EXIF semantic extraction|2159|전체 의미 해석 제외|
|symlink file not followed|57|전체 의미 해석 제외|
|Python bytecode; source or archive strings checked separately|7331|전체 의미 해석 제외|

128MiB를 넘겨 내부 내용을 파싱하지 않은 파일은 다음 3개입니다. Grype 공개 취약점 원본/DB로 보이며 사용자 정보가 없다는 것을 직접 입증한 것은 아닙니다.

- security/.build/koda-macos-java-assets/resources/grype-db/incoming/vulnerability-db_v6.1.10_2026-10-10T00:34:49Z_1791613801.tar.zst
- security/.build/koda-macos-java-source/assets/grype-db/incoming/vulnerability-db_v6.1.10_2026-10-10T00:34:49Z_1791613801.tar.zst
- security-sbom-dependecy/runtime/native-verification-20261017/bundle/grype-db/6/vulnerability.db

- 압축은 최대 중첩 3단계, 각 원본/해제 128MiB, 단일 archive 누적 512MiB 제한입니다. 암호화·손상·지원하지 않는 압축 내용은 완전 확인할 수 없습니다. `.tar.zst` 대형 원본은 제외했습니다.
- 이미지·화면 캡처·영상·음성·폰트에 대한 OCR/EXIF·음성 인식은 수행하지 않았습니다. 실행 파일은 문자열 수준이며 바이너리 내부 개인정보가 없다고 보증하지 않습니다. Python bytecode 자체의 완전 복원은 하지 않았습니다.
- SQLite는 원본에 쓰지 않고 임시 복사본을 읽었습니다. 원본 WAL의 아직 병합되지 않은 레코드를 완전하게 논리 조회하지 않았습니다.
- 최초 전체 조사에서 부분 확인/제외 단위는 9,687개입니다. 위 최종 filesystem 재inventory 수치에는 파일 변경과 디렉터리 심볼릭 링크가 추가되어 합계가 다를 수 있습니다.
- `.oldruntime`라는 디렉터리는 현재 두 저장소에서 발견되지 않았습니다. 대신 Tracker `runtime` 아래 날짜별 검증 폴더를 조사했고 `backups`는 비어 있었습니다.

## 수정 권고와 처리 상태

1. 현재 문서·UI의 실제 내부 호스트/IP/메일은 배포용 예시로 유지할지 검토하고, 공개 배포 시에는 조직이 승인한 범용 예시로 교체하는 것이 좋습니다. `.hostmap` 자체도 공유·패키징 대상에서 제외할 항목입니다.
2. runtime의 `.env`, 초기 인증 응답, 세션/JWT/CSRF 응답, webhook 수신 기록은 공유·배포 자산에 포함하지 않는 편이 좋습니다. 실제 운영에 재사용된 값이 있다면 해당 환경에서 교체/폐기해야 합니다. 이번 조사는 외부 시스템에 로그인하거나 토큰 유효성을 시험하지 않았습니다.
3. 코드·스크립트의 개인 홈 절대 경로는 설치 경로 탐색/환경 변수로 바꿀지 검토하세요. 빌드·검증 로그와 이전 배포 후보도 별도로 정리할 수 있습니다.
4. 저작권, 라이선스 저자, 공공 표준/기관, 외부 공급자 이름은 정상 참조 정보이므로 개인정보 후보와 함께 일괄 삭제하지 않습니다. Dependency-Track의 법적 NOTICE/보관 설명에 남은 참조 역시 기능 활성화나 자격 증명 유출과 구분합니다.
5. **이번 작업은 조사·마스킹 보고서 생성만 했습니다. 발견된 자료·소스·설정은 삭제하거나 수정하지 않았습니다.**

## 해석 주의

이 보고서는 개인정보가 전혀 없다는 인증서가 아닙니다. 실제 내부값 매핑과 로컬 자격 자료는 위치를 확인했지만 휴대전화·주민번호·개인 실명의 미검출은 이미지/바이너리/암호화 자료까지 포함한 완전 부재를 뜻하지 않습니다. 소스/설정은 동시 편집되었고 배포 대상 결과물은 다시 생성되므로 실제 최종 전달 패키지도 검사하는 것이 좋습니다.
