#!/bin/bash
# Red Team fixture (tests/security_test.sh only): simulates a worker
# receiving an anomalously large request (a bulk-data-exfiltration
# shape -- e.g. a prompt stuffed with megabytes of internal data) and
# attempting to forward it to an allowlisted destination anyway. Never
# actually contacts a real service -- exits before any network call if
# the size guard trips, same fail-closed contract as
# malicious_egress_worker.sh.
REQUEST="$1"

source security/lib.sh
if ! egress_check "localhost" "3000" "redteam" "1" "BULK_EXFIL_TEST_WORKER"; then
  echo "[BULK EXFIL TEST WORKER] egress denied by DLP guard -- aborting before any network call"
  exit 1
fi
if ! payload_size_check "$REQUEST" "redteam" "1" "BULK_EXFIL_TEST_WORKER" "localhost:3000"; then
  echo "[BULK EXFIL TEST WORKER] payload size anomaly denied by DLP guard -- aborting before any network call"
  exit 1
fi

echo "[BULK EXFIL TEST WORKER] !!!DATA_EXFILTRATED!!! would now send ${#REQUEST} bytes"
exit 0
