# SW49 소스 분석 검토 fixture

`manifest.json`은 공식 항목 49개를 모두 색인합니다. 자동 규칙 예시는 빌드 가능한
프로젝트가 아니라 작은 소스 조각입니다. 수동·미지원 항목은 목록과 보고서 동작을
검증하기 위한 제한된 placeholder를 사용하며, 실제 기준 데이터가 아니므로 측정된
탐지 정확도를 주장하는 데 사용하면 안 됩니다.

`c01_cross_file/`은 프로젝트 문맥 회귀 쌍입니다. 취약 fixture는 nullable source를
`Provider.java`에, 역참조를 `Consumer.java`에 배치하고, 안전한 쌍은 파일 간 명시적
null guard를 포함합니다.
