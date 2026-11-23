from __future__ import annotations

import sys

from security_scanner.cli import main


if __name__ == "__main__":
    local_commands = {
        "-h", "--help", "approval-review", "correlate", "cpe-scan", "dashboard",
        "diff-reports", "discover", "har-review", "host-scan", "jar-scan",
        "jwt-key-review", "local-listeners", "manifest", "sbom-verify", "scan",
        "tls-cert-review",
    }
    if len(sys.argv) > 1 and sys.argv[1] not in local_commands:
        print("This executable supports KODA desktop tools only.", file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(main())
