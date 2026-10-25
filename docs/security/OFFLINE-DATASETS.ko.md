# 폐쇄망 보강 자료와 SPDX SBOM

KODA와 KODA SBOM Tracker는 독립 저장소·배포·DB를 유지한다. 공통 전송 규격 `koda-offline-intelligence-v1`만 공유하며 런타임에 상대 저장소 코드를 가져오지 않는다. OSV 직접 연동은 제외하며 Linux 운영은 두 제품으로 구성한다.

## 데이터 흐름

1. 연결망의 수집 도구에서 공식 자료 또는 승인된 로컬 파일을 정규화한다.
2. `intelligence.json`과 `intelligence-sources/` 원본들을 함께 보관한다. 원본 기준일, 수집 시각, SHA-256, 허용 기간을 자료마다 기록한다.
3. 원본에서 정규화한 레코드를 다시 생성해 대조하고, 기존 서명된 취약점 업데이트 번들로 반입한다. JSON 직접 반입은 원본 바이트를 포함하는 형식을 사용한다.
4. KODA는 점검 시 활성 릴리스를 고정하고, Tracker는 반입 이력과 분석 회차에 사용한 스냅샷을 보관한다.
5. 새 자료로 재평가한 결과와 과거 점검 결과를 구분한다. 기존 결과를 내보낼 때 최신 외부 자료를 다시 조회하지 않는다.

## 보강 자료

| 자료 | 활용 | 권장 수집 주기 |
|---|---|---|
| EPSS | CVE별 관측 점수·백분위·기준일, 별도 정책 허용 기간 | 매일 |
| CISA Vulnrichment | SSVC 입력 근거와 검토용 추천값 | 매일 |
| CSAF/VEX | 정확한 제품 식별자가 일치하는 공급자 영향·수정 설명 | 매일 |
| Ubuntu OVAL | 배포판·패키지 조건을 보존한 평가 근거 | 매일 |
| endoflife.date v1 | 제품 사이클별 지원 종료·최신 릴리스 | 매주 |
| 패키지 메타데이터 | 기존 Tracker export/import 규격의 버전·릴리스 시각 | 매일 또는 매주 |
| NVD CPE Dictionary / Match Criteria | 식별자·폐기 여부·CVE 적용 조건 참조 | 매주 |
| CWE / SPDX License List | 취약점 유형과 라이선스 식별자 참조 | 새 버전 발표 시 |

전체 레지스트리와 모든 CPE 매칭 정보를 무조건 복제하지 않는다. 실제 사용하는 제품·패키지의 자료를 수집하고 수집 범위와 누락을 기록한다. 대형 NVD 자료는 수집 도구가 허용하는 크기 안에서 대상 API 페이지별로 반입한다. 참조 목록에 없는 제품·라이선스·취약점은 안전 또는 허용으로 판정하지 않는다.

## KODA 번들에 넣기

연결망에서 생성한 승인된 스냅샷을 지정한다. `intelligence.json` 옆에 원본 디렉터리가 있어야 한다.

```sh
KODA_INTELLIGENCE_SNAPSHOT=/approved/intelligence/intelligence.json \
KODA_EPSS_SNAPSHOT=/approved/epss_scores-current.csv.gz \
bash platforms/linux/package-offline.sh
```

지정하지 않은 선택 자료는 이전 빌드 캐시에서 새 번들로 자동 포함하지 않는다. Linux 실행기는 번들의 `vuln-data/intelligence.json`을 사용한다. 별도 설치에서는 `KODA_INTELLIGENCE_DATA`로 같은 파일을 지정할 수 있다. 활성 취약점 릴리스가 있으면 그 릴리스 내부 경로를 우선하며 경로 탈출을 허용하지 않는다.

`scripts/stage-offline-intelligence.py`는 포장용 캐시 준비 도구다. 실행 중인 앱의 활성 데이터 경로에 직접 사용하지 않는다. 활성 데이터 전환은 기존 불변 릴리스 갱신 경로로 수행한다. Tracker에서 더 최신인 수동 보강 자료는 과거 번들 롤백으로 강등하지 않는다.

KODA 번들로 Tracker 초기 데이터를 만들 때도 보강 자료와 EPSS를 전달한다.

```sh
KODA_LINUX_BUNDLE=/approved/koda-linux.tar.gz \
bash platforms/linux/build-suite-vuln-bundle.sh /approved/suite-vulnerability-data
```

실행 시 외부 호출은 하지 않는다. 외부 수집 도구는 연결망 전용이며 폐쇄망 앱의 요청 처리나 작업자에서 호출하지 않는다.

## 판정 원칙

- EPSS 예측값을 실제 악용 증거로 변환하지 않는다.
- CISA Coordinator 모델의 최종 결정을 Deployer SSVC 결정으로 복사하지 않는다. 호환되는 입력 근거만 추천하고 운영 노출도·업무 영향은 별도 확인한다.
- 공급자 VEX는 CVE와 정확한 PURL 또는 검토된 CPE가 일치할 때 연결한다. 자동으로 취약점을 숨기거나 Grype 심각도를 바꾸지 않는다.
- OVAL 파일에 CVE가 들어 있다는 사실만으로 설치 시스템이 취약하다고 판단하지 않는다. 지원하지 않는 조건·불완전한 인벤토리·평가 도구 부재는 미판정이다.
- 지원 종료 정보는 기관의 연장 지원 계약을 대신하지 않는다.
- 최신 버전은 취약점이 해결되었거나 기관에서 반입 승인된 버전이라는 뜻이 아니다.
- 자료별 기준일과 최신성 상태를 보존한다. 오래되거나 없는 자료를 위험 없음으로 처리하지 않는다.

## SPDX

KODA CVE 점검과 보고서에서 SPDX 2.3 JSON 출력을 선택할 수 있다. CycloneDX와 NIS 출력도 유지한다. SPDX의 패키지·PURL·확인된 해시·라이선스·관계를 보존하고, 분석하지 않은 라이선스 결론은 `NOASSERTION`으로 표시한다. 생성한 SPDX는 Tracker 입력 정규화를 거쳐 기존 분석 흐름으로 전달한다.

```sh
koda scan --target /srv/application --format spdx --output application.spdx.json
koda jar-scan --target /srv/application --sbom-format spdx-2.3 --output-dir reports
```

샘플 기반 검증과 실제 Linux의 전체 규모 자료 반입·배포판별 운영 검증은 구분해야 한다. 폐쇄망 반입 파일 자체는 운영자가 승인한 최신 스냅샷을 사용한다.
