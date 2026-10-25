# 폐쇄망 CPE 점검

KODA는 검토된 CPE 2.3 식별자 또는 CycloneDX JSON의 `cpe`로 로컬 NVD
적용 조건을 점검합니다. 외부 조회와 제품명 추정은 수행하지 않습니다.

```sh
koda cpe-scan \
  --sbom /data/product.cdx.json \
  --nvd-data /data/nvd \
  --cisa-kev /data/kev.json \
  --output /data/reports/cpe.json
```

`--cpe`를 여러 번 지정할 수도 있습니다. `--nvd-data` 생략 시 활성 취약점
자료 경로를 사용합니다. `--cisa-kev`는 선택 사항입니다. 원본 NVD 2.0 JSON·JSON.gz
파일/디렉터리 또는 새 Tracker NVD 인덱스를 사용할 수 있습니다. 두 저장소는 각각
자체 구현을 보유하며 런타임에 서로의 소스 폴더를 참조하지 않습니다.

종료 코드는 `0`: 제공된 식별자/조건 범위에서 평가 완료·일치 없음,
`1`: 평가 완료·취약 조건 일치, `2`: 오류 또는 미판정/커버리지 부족입니다.
입력이 없거나 환경 전제가 빠졌거나 자료에 해당 제품의 적용 조건이 없으면
안전 판정을 하지 않습니다. 발견이 있어도 다른 입력이 미판정이면 종료 코드는 2입니다.
JSON에는 발견·경고·입력/평가/미판정 수와 자료 SHA-256·기준일이 포함됩니다.

`koda-offline-cpe-v1`은 정확한 vendor/product, CPE escape, AND/OR·negate,
환경 조건과 숫자 점 구분 버전 경계를 평가합니다. 벤더별 알파벳 버전 범위나
식별자 부족은 미판정입니다. 문자열만 남은 과거 NVD 요약 자료로 적용 조건을
추정하지 않습니다. 기존 Grype의 배포판별 취약점·백포트 판정은 계속 사용합니다.
