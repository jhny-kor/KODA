# KODA Linux 설치·운영

Linux는 `platforms/shared/python/`의 공통 엔진을 사용하며 사용자 소유 경로에
설치할 수 있습니다. 폐쇄망에서는 Syft·Grype·로컬 DB·NVD·CISA KEV 자료를
승인된 절차로 반입합니다.

```bash
export PYTHONPATH=/opt/koda/platforms/shared/python
python3 -m security_scanner jar-scan \
  --target /deploy/apps --target /deploy/worker-apps --output-dir reports/java-scan \
  --syft-bin /opt/koda/tools/syft --grype-bin /opt/koda/tools/grype \
  --nvd-data /opt/koda/vuln-data/nvd \
  --cisa-kev /opt/koda/vuln-data/known_exploited_vulnerabilities.json
```

JAR 보고서는 현재 HTML과 Markdown 모두 한국어로 생성되며 `--language`는
`ko`만 지원합니다.
`--target`은 반복 지정할 수 있으며, 여러 폴더의 결과를 하나의 라이브러리
메인/상세 리포트와 SBOM으로 통합합니다.

## 인증 Linux 포털

Linux 서버 화면은 KODA와 KODA SBOM Tracker를 묶은 폐쇄망 통합본으로 설치합니다.
동일한 HTTPS 오리진에서 Tracker가 계정과 세션을 관리하고 KODA는 별도의 프로젝트
역할·화면 권한을 적용합니다. 한쪽에서 로그아웃하면 중앙 세션이 폐기되어 두
사이트에서 모두 다시 로그인해야 합니다.

```text
https://<서버>/          # KODA SBOM Tracker
https://<서버>/koda/     # KODA
```

KODA의 보안·품질 점검 규칙은 시스템 관리자만 바꾸고, 일반 사용자는 프로젝트에서
검사 기준과 기준 범위만 선택합니다. 사용자가 가입을 신청하면 Tracker 관리자가
역할을 확인하고 활성화합니다. 승인된 계정은 KODA에도 자동 활성화되며 KODA
프로젝트 역할은 별도로 배정합니다.
LDAP 로그인은 Tracker 관리자 설정에서 LDAP 서버·TLS·검색 속성·그룹 매핑을 저장한 뒤
사용합니다. KODA 로그인 화면은 Tracker의 LDAP 인증과 동일한 세션을 사용하므로 별도
KODA 계정을 만들 필요가 없습니다. LDAP이 구성되지 않았거나 연결에 실패하면
`503`으로 거부되며 로컬 비밀번호 인증으로 자동 전환하지 않습니다.

### 포털 화면과 분석 결과

실제 결과 화면과 라이브러리·소스코드·품질 탭, 전체 기능 흐름은
[KODA 웹 포털 화면과 기능](../koda-web-portal.md)에서 확인할 수 있습니다.

- `대시보드`: 점검 이력이 있는 프로젝트별 최신 상태와 심각도 분포를 확인합니다.
- `라이브러리 취약점`: SBOM·manifest·lockfile·JAR/WAR 입력을 CVE 기준으로 점검하고 CVE가 연결된 결과만 표시합니다.
- `소스코드 취약점`: 소스 입력을 `전체` 또는 코드·비밀정보·보안설정·예방통제 기준으로 점검합니다.
- `프로젝트`: 입력 메타데이터와 회차를 프로젝트별로 보관합니다. 점검이 끝나면
  원본 입력 파일은 삭제되고 결과 회차·스냅샷만 남습니다.
- `점검 결과`: 두 점검 유형의 회차를 검색하고, 각 결과에서 기존 분류 탭과 불변
  스냅샷을 조회합니다. 새 점검은 입력 파일을 다시 등록해야 하며 기존 `/koda/scans/new` 경로는
  호환성을 위해 전체 점검 화면으로 유지합니다.
- `비교`: 같은 프로젝트의 회차 결과를 비교합니다.
- `관리자 설정`: KODA 접근·시스템 관리자, 사용자별 프로젝트 역할, 전역 역할 정책,
  보안·품질 규칙과 감사 기록을 관리합니다.
- `사용 가이드`: 모든 활성 KODA 사용자가 기능·보안 용어·지원 기준을 확인합니다.

포털 분석은 정확한 버전·PURL을 얻을 수 있는 manifest/lockfile에 대해 번들된 로컬
Grype DB를 사용합니다. 완료 회차에서는 Windows/Linux 공통 CLI 렌더러와 같은
메인·상세 HTML, HTML ZIP, PDF, Excel, JSON, Markdown 보고서를 내려받고 CycloneDX 1.6
또는 국정원 NIS-SBOM 1.0 CSV를 내려받을 수 있습니다. 라이브러리 회차의 HTML은
구성요소·버전·취약점 식별자 중심의 라이브러리 취약점 보고서로 표시됩니다.
JAR/WAR/EAR 내부 라이브러리는
CLI의 `jar-scan`을 사용합니다.

통합 압축파일 생성·검증·설치와 최초 관리자 지정은
[KODA + KODA SBOM Tracker 폐쇄망 통합본](../../platforms/linux/suite/README.md)을
따릅니다. KODA 컨테이너의 8765 포트는 직접 공개하지 않습니다.
설치·주소·로그인·Dependency-Track 오류는
[폐쇄망 설치 장애 대응서](../../platforms/linux/suite/TROUBLESHOOTING.md)를
따릅니다.

- [한국어 문서 인덱스](../README.md)
- [English Linux install](linux.md)
