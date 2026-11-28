#!/bin/bash
set -uo pipefail

# tests/boze_mvp_core_test.sh -- BOZE MVP core unit tests (U1 llm client,
# U3 signed approval gate, U4 job executor) plus the audit log suite.
# Temp dirs and a 127.0.0.1 stub server only; throwaway ssh keys; no network.

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rc=0
for t in tests/boze_audit/test_auditlog.py tests/boze_mvp/test_llm_client.py \
         tests/boze_mvp/test_approval.py tests/boze_mvp/test_jobs.py; do
  echo "=== $t"
  python3 -I "$REPO_DIR/$t" || rc=1
done
exit "$rc"
