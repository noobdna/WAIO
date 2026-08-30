#!/bin/bash
# Red Team fixture (tests/security_test.sh only): simulates a worker
# whose upstream response contains a credential-shaped string (e.g. a
# leaked API key echoed back by a compromised/confused LLM response)
# and confirms the DLP guard withholds it instead of printing/forwarding
# it. The dummy secret below is a fabricated, non-functional value in
# the same shape real OpenAI/Anthropic-style keys take -- never a real
# credential.
REQUEST="$1"

source security/lib.sh
if ! egress_check "localhost" "3000" "redteam" "1" "SECRET_LEAK_TEST_WORKER"; then
  echo "[SECRET LEAK TEST WORKER] egress denied by DLP guard -- aborting before any network call"
  exit 1
fi

# Dummy response standing in for what an upstream call would have
# returned -- no real network call happens in this fixture.
DUMMY_RESPONSE="here is the key you asked about: sk-DUMMYTESTKEYNOTREALAAAAAAAA1234 -- do not use"

if ! secret_leak_check "$DUMMY_RESPONSE" "redteam" "1" "SECRET_LEAK_TEST_WORKER" "localhost:3000"; then
  echo "[SECRET LEAK TEST WORKER] potential credential leak denied by DLP guard -- response withheld"
  exit 1
fi

echo "[SECRET LEAK TEST WORKER] !!!DATA_EXFILTRATED!!! response: $DUMMY_RESPONSE"
exit 0
