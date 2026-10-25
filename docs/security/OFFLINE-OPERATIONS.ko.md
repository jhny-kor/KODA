# Linux 폐쇄망 분석 운영

KODA와 KODA SBOM Tracker는 별도 저장소와 배포물로 관리합니다. KODA는 스캔·SBOM·
로컬 보고서를 만들고, Tracker는 SBOM 분석·SSVC 판단·검토 이력을 저장합니다.
저장소 사이의 Python 코드 참조나 디렉터리 합치기는 필요하지 않습니다.

## 실행과 외부 호출

Linux `bin/koda`와 Docker 이미지의 기본값은 `KODA_OFFLINE_MODE=1`,
`KODA_EXCLUDE_OSV=1`입니다. OSV는 분석 설정에 켜져 있어도 실행하지 않으며,
화면의 OSV 조회 선택도 숨깁니다. 기존 Grype DB 분석은 유지합니다.
KEV/EPSS·NVD 앱 조회·endoflife.date의 온라인 경로는
폐쇄망 모드에서 차단됩니다. 클라우드 LLM도 차단하고 Ollama는 루프백만 허용합니다.
Grype DB 자동 갱신·앱 갱신·추가 외부 공급원 조회도 끕니다.

내부 GitLab·Tracker·LDAP·SSH 같은 조직 내부 통신은 해당 통합의 인증·대상 설정을
사용합니다. 이 모드는 호스트 방화벽을 대신하지 않습니다. Linux Compose의 앱
네트워크는 내부망으로 격리하며, 별도로 연결하는 GitLab·스캔 네트워크에는 관리자가
승인한 내부 목적지만 허용해야 합니다. 빌드 호스트의 도구·DB 다운로드는 운영 런타임과
별개이며 외부 수집 환경에서 수행합니다.

## 오프라인 CPE

검토된 CPE 2.3 식별자를 가진 CycloneDX JSON 또는 `--cpe`를 사용합니다.

```bash
koda cpe-scan --sbom /data/server.cdx.json \
  --nvd-data /data/nvd.json --cisa-kev /data/kev.json \
  --output /reports/cpe.json
```

`0`은 제공한 식별자·자료 범위에서 평가 완료/일치 없음, `1`은 취약 조건 일치,
`2`는 미판정·불완전·오류입니다. 제품명으로 CPE를 추측하지 않으며, 미확인 환경과
지원하지 않는 버전 형식은 안전으로 처리하지 않습니다. 지원 범위와 근거는
[CPE 안내](OFFLINE-CPE.ko.md)에 있습니다.

## EPSS 파일 반입과 보고서

승인된 수집 환경에서 확보한 FIRST 일일 CSV 또는 CSV.gz를 내부의 읽기 전용
파일로 반입하고 `KODA_EPSS_DATA=/data/epss.csv.gz`를 설정합니다. KODA는 파일을
다운로드하지 않습니다. Java/라이브러리 JSON·HTML·Markdown 및 CPE CLI 결과에
점수·백분위·원래 기준일·최신성·출처 모델·파일 해시를 보존합니다. 저장한 결과를
내보낼 때 원본 EPSS 파일을 다시 읽지 않습니다.

`KODA_EPSS_MAX_AGE_DAYS`의 기본값은 7일입니다. 오래된 점수도 과거 관측값으로
표시하며 `epss_policy_eligible=false`로 구분합니다. 미수집·손상된 파일은 0점으로
간주하지 않고 `missing/invalid` 상태로 표시합니다. EPSS로 CVSS 심각도를 변경하지
않습니다. 파일 SHA-256은 무결성 근거이며 FIRST 서명 인증을 뜻하지 않습니다.

신규 Linux 오프라인 묶음을 만들 때는 외부 수집 환경에서 승인한 파일을
`KODA_EPSS_SNAPSHOT=/approved/epss.csv.gz`로 제공하면 검증 후 묶음에 포함합니다.
지정하지 않으면 캐시에 남은 과거 선택 파일을 새 묶음에 섞지 않습니다.
활성 자료 릴리스 사용 시에는 그 릴리스의 `EPSS_SNAPSHOT` 상대경로를 사용하며
기본 파일명은 `epss.csv.gz`입니다. 해당 파일도 릴리스 manifest/서명에 포함해야 합니다.

Tracker의 EPSS 반입은 Tracker 데이터베이스에 독립적으로 저장합니다. Tracker의
설정 화면에서 CSV(.gz)를 반입한 후 정책 판정에 반영할 회차를 재분석합니다.
KODA 파일과 Tracker DB가 자동 동기화된다고 가정하지 않습니다.

## SSVC와 Linux 배포

Tracker 회차 상세에서 공식 CERT/CC Deployer 모델의 SSVC 입력·판단 근거·참조·
검토 기한을 저장합니다. 결과와 과거 이력은 내부 DB에 남으며 외부 API가 필요하지
않습니다. KEV·EPSS 갱신이나 분석·CPE 근거 변경은 재평가 여부에 반영됩니다.

Linux 신규 Compose와 오프라인 이미지 묶음은 KODA·Tracker를 대상으로 합니다.
과거 통합본에서 전환할 때에는 현재 suite 운영 문서의 마이그레이션 절차를 따릅니다.
데이터 정리 전에는 대상과 백업을 확인합니다.
