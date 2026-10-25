# VEX Tracking

Use VEX to record reviewed dependency vulnerabilities after Grype, NVD, or another advisory source reports a CVE.

Generate KODA's CycloneDX VEX draft from exact-version OSV findings with:

```bash
export PYTHONPATH="$PWD/platforms/shared/python"
python3 -m security_scanner scan --target . --enable-osv \
  --format cyclonedx-vex --output reports/koda-vex.cdx.json
```

`release-package --enable-vuln-intel` also writes `koda-vex.cdx.json`. Every
KODA-generated entry starts with `analysis.state: in_triage`; it is a review
placeholder, not an exploitability or remediation decision.

Create `docs/security/vex.cdx.json` or another CycloneDX/OpenVEX document with:

- the affected component and version
- the vulnerability or CVE ID
- status such as `not_affected`, `affected`, `fixed`, or `under_investigation`
- impact statement and expiry/review date

KODA treats VEX as a prevention artifact. It does not claim a vulnerability is safe automatically; review and change each placeholder only after confirming the component, affected version, and exploitability.
