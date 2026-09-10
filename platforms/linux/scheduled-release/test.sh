#!/usr/bin/env bash
# Packaging-side guard checks; does not contact Docker or a production host.
set -euo pipefail
here="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
bash -n "$here/apply.sh" "$here/rollback.sh"
grep -q 'sqlite3.connect(destination)' "$here/apply.sh"
grep -q 'pg_dumpall -U "\$POSTGRES_USER"' "$here/apply.sh"
grep -q 'service_refs=' "$here/apply.sh"
grep -q 'duplicate=0' "$here/apply.sh"
grep -q -- '--no-deps --force-recreate portal-web portal-api portal-worker' "$here/apply.sh"
grep -q -- '--no-deps gateway' "$here/apply.sh"
grep -q 'could not preserve current image' "$here/apply.sh"
grep -q 'compatibility contract is missing' "$here/apply.sh"
echo "scheduled-release script guards passed"
