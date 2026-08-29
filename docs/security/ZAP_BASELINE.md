# OWASP ZAP Baseline

소유하거나 명시적 권한을 받은 시스템만 대상으로 사용하세요. 기본
`zap-run`은 ZAP Baseline 모드이며, 활성·전체·API 점검은 별도 승인과
`--authorize-active`가 필요합니다.

```bash
python3 -m security_scanner zap-run \
  --url https://example.com --mode baseline
```

세션·비밀번호를 명령행에 직접 입력하지 말고 header와 환경변수 옵션을
사용하세요. 결과는 대상·권한·실행 시각과 함께 보관합니다.

- [한국어 보안 문서 인덱스](../README.md#보안-점검연동-security)
- [English ZAP baseline guide](ZAP_BASELINE.md)
