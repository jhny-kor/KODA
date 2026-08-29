# Dependency-Track SBOM 업로드

KODA에서 CycloneDX SBOM을 만든 뒤 Dependency-Track 서버에 업로드합니다.

```bash
export PYTHONPATH="$PWD/platforms/shared/python"
export DEPENDENCY_TRACK_API_KEY='operator-managed-secret'
python3 -m security_scanner scan --target . --format cyclonedx --output reports/sbom.cdx.json
python3 -m security_scanner upload-sbom \
  --server-url https://dependency-track.example.com \
  --api-key-env DEPENDENCY_TRACK_API_KEY \
  --project-name security --project-version main \
  --sbom reports/sbom.cdx.json --auto-create
```

API 키 환경변수가 비었거나 SBOM 파일이 없거나 프로젝트 이름·버전이 비었으면
업로드는 실패합니다. API 키는 셸 기록에 남을 수 있는 `--api-key` 대신 환경변수로
전달하세요.

- [한국어 보안 문서 인덱스](../README.md#보안-점검연동-security)
- [English Dependency-Track guide](DEPENDENCY_TRACK.md)
