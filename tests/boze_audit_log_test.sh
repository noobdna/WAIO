#!/bin/bash
set -uo pipefail

# tests/boze_audit_log_test.sh -- runs the BOZE audit log unit tests
# (tests/boze_audit/test_auditlog.py) against scratch temp dirs only.
# No network, no touch of any real log.

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 -I "$REPO_DIR/tests/boze_audit/test_auditlog.py"
