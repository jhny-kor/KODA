# 보안 대시보드 설계 조사

현재 대시보드는 특정 공급업체의 화면을 복제하지 않고 취약점 관리 도구의
정보 구조만 참고합니다.

## 채택한 패턴

- 여러 로컬 대상의 결과를 한 화면에서 요약
- 치명적·높음 심각도 우선 표시
- 대상별 finding 수와 위험 상태 비교
- 심각도·카테고리·대상·검색어 전역 필터
- SARIF·CycloneDX·JSON 등 외부 연동 형식 유지

이 문서는 설계 근거와 한계를 설명하며, 실제 사용법은 한국어 CLI 문서를
기준으로 확인합니다.

- [한국어 문서 인덱스](README.md)
- [English dashboard research](security-dashboard-research.md)
