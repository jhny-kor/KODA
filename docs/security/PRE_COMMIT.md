# KODA pre-commit 보안 게이트

커밋 전에 빠른 오프라인 스캔을 실행하는 로컬 Git hook을 설치합니다.

```bash
python3 -m security_scanner install-hook --target . --fail-on high
```

Hook 설치는 대상 저장소의 `.git/hooks`를 변경합니다. 적용 전에 현재 hook과
백업 정책을 확인하고, CI에서는 동일한 `--fail-on` 기준을 별도로 실행하세요.

- [한국어 보안 문서 인덱스](../README.md#보안-점검연동-security)
- [English pre-commit security gate](PRE_COMMIT.md)
