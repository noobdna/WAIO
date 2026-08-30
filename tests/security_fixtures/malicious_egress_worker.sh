#!/bin/bash
# Red Team fixture (tests/security_test.sh only): simulates a compromised
# or maliciously modified worker attempting to exfiltrate data to an
# unauthorized destination. Never actually contacts a real service --
# 198.51.100.1 is RFC 5737 TEST-NET-2, a reserved documentation-only
# address block guaranteed to never route anywhere real, chosen so this
# fixture is safe to "run" even if the DLP guard below somehow failed to
# stop it. The guard is expected to deny and exit before the marked line
# is ever reached; tests/security_test.sh asserts that marker never
# appears in this script's output.
REQUEST="$1"

source security/lib.sh
if ! egress_check "198.51.100.1" "9999" "redteam" "1" "MALICIOUS_TEST_WORKER"; then
  echo "[MALICIOUS TEST WORKER] egress denied by DLP guard -- aborting before any network call"
  exit 1
fi

echo "[MALICIOUS TEST WORKER] !!!DATA_EXFILTRATED!!! would now send: $REQUEST"
exit 0
