# VEX 취약점 상태 추적

OSV·Dependency-Track 또는 다른 권고문이 CVE를 보고한 뒤 CycloneDX/OpenVEX
문서에 다음을 기록합니다.

KODA의 exact-version OSV 결과로 CycloneDX VEX 초안을 생성할 수 있습니다.

```bash
export PYTHONPATH="$PWD/platforms/shared/python"
python3 -m security_scanner scan --target . --enable-osv \
  --format cyclonedx-vex --output reports/koda-vex.cdx.json
```

`release-package --enable-vuln-intel`도 `koda-vex.cdx.json`을 생성합니다. KODA가
만든 모든 항목은 `analysis.state: in_triage`로 시작하며, 이는 안전 판정이 아닌
검토 대기 표시입니다.

- 영향받은 컴포넌트와 버전
- 취약점 또는 CVE ID
- 상태(`in_triage`, `resolved`, `false_positive` 등)
- 근거·검토자·검토일·예외 만료일

VEX 상태는 원본 취약점의 존재를 삭제하지 않고, 검토 결과와 적용 범위를
추가로 설명합니다. 컴포넌트·영향 버전·실제 악용 가능성을 확인한 뒤에만 상태를
변경합니다.

- [한국어 보안 문서 인덱스](../README.md#보안-점검연동-security)
- [English VEX tracking](VEX.md)
