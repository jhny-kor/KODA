# SPDX 2.3 JSON 내보내기

KODA는 기존 CycloneDX와 NIS SBOM CSV에 더해 SPDX 2.3 JSON을 생성합니다. 외부 서비스나 추가 패키지가 필요하지 않습니다.

```sh
koda scan --target ./project --category dependencies --format spdx --output sbom.spdx.json
koda jar-scan --target ./application.jar --sbom-format spdx-2.3 --output-dir ./report
koda cpe-scan --sbom ./sbom.spdx.json --nvd-data ./nvd.json
```

Java 점검 결과는 `server-sbom.spdx.json`과 분석 원본 `server-sbom.cdx.json`을 함께 보관합니다. 대시보드 SBOM 형식 선택과 Linux 포털 실행 결과의 SBOM 다운로드에서도 SPDX를 선택할 수 있습니다. 저장형 HTML ZIP에는 `sbom.cdx.json`과 `sbom.spdx.json`을 함께 넣습니다. 다운로드 권한은 기존 실행 결과 내보내기 권한을 따릅니다.

## 보존 범위

- 구성 요소 이름·버전·공급자, PURL/CPE, 유효한 해시, 명시된 라이선스를 변환합니다. 원본 구성 요소와 메타데이터는 SPDX annotation에 보존합니다.
- 명시적 CycloneDX 의존 관계는 `DEPENDS_ON`, 중첩 구성은 `CONTAINS`로 표현합니다. 원본 참조가 중복되거나 대상을 찾을 수 없는 관계는 근거로 보존하고 연결을 추측하지 않습니다.
- 출처가 없는 다운로드 위치·저작권·판정 라이선스 등은 `NOASSERTION`으로 표시합니다. `filesAnalyzed=false`이며 실제 파일 분석이나 라이선스 적합성 판정을 주장하지 않습니다.
- 라이선스 표현식은 구조를 검사하고 원본 식별자를 유지합니다. 전체 SPDX 라이선스 목록 검증은 수행하지 않습니다. 여러 라이선스가 나열되었지만 AND/OR가 명시되지 않으면 선언은 `NOASSERTION`이며 원본 목록을 보존합니다. 이름만 있는 사용자 라이선스는 `LicenseRef`와 출처 텍스트를 사용합니다.

별도 프로젝트인 KODA SBOM Tracker는 SPDX 2.3 JSON 반입을 지원합니다. 내부 분석용 CycloneDX로 정규화하고 원본 업로드와 SPDX 근거를 보존합니다. 두 프로젝트는 서로의 Python 모듈을 실행 시 참조하지 않습니다.

## 검증 자료

회귀 테스트는 공식 [SPDX 2.3 JSON Schema](https://github.com/spdx/spdx-spec/blob/v2.3/schemas/spdx-schema.json)를 로컬 fixture로 사용합니다. fixture SHA-256은 `239208b7ac287b3cf5d9a9af23f9d69863971102a5e1587a27a398b43490b89b`입니다. 기존 `jsonschema`가 설치된 검증 환경에서는 실제 스키마 검증도 수행합니다. 운영 실행에는 해당 패키지가 필요하지 않습니다.
