#!/bin/bash
set -uo pipefail

# tests/hunt_for_red_test.sh -- HUNT FOR RED P1 (Evidence Ledger +
# Source Registry checks).
#   U-series: tests/hunt_for_red_unittest.py (fabricated data, temporary
#     HFR_HOME outside any git tree).
#   D-series: static guards for the P1 decisions (D-2 no case data in
#     the repo, D-3 passive only / no network code, D-1 no coupling to
#     the Incident Learning Engine's writable parts).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR" || exit 1

PASS=0
FAIL=0
ok()   { PASS=$((PASS + 1)); echo "  PASS: $1"; }
bad()  { FAIL=$((FAIL + 1)); echo "  FAIL: $1"; }

echo "== U-series (python unittest)"
u_out="$(python3 -I -W error::ResourceWarning tests/hunt_for_red_unittest.py 2>&1)"; u_rc=$?
printf '%s\n' "$u_out" | tail -n 5
if [ "$u_rc" -eq 0 ]; then ok "U-series unittest suite"; else printf '%s\n' "$u_out"; bad "U-series unittest suite"; fi

HFR_PY=(security/hunt_for_red/*.py)

echo "== D1: no network modules in security/hunt_for_red (D-3, fetching is P3)"
if grep -nE '^\s*(import|from)\s+(urllib|http|socket|requests|ftplib|smtplib|ssl|asyncio)\b' "${HFR_PY[@]}"; then
  bad "D1 network import found"
else
  ok "D1 no network imports"
fi

echo "== D2: subprocess used only for git rev-parse"
if grep -nE 'subprocess\.' "${HFR_PY[@]}" | grep -v 'rev-parse' | grep -vE 'subprocess\.(TimeoutExpired)'; then
  bad "D2 unexpected subprocess use"
else
  ok "D2 subprocess limited to git rev-parse"
fi

echo "== D3: no real case data in the repo (D-2)"
if find security/hunt_for_red -type f ! -name '*.py' ! -name '*.md' ! -name '*.example' | grep .; then
  bad "D3 non-code, non-example file in security/hunt_for_red"
else
  ok "D3 only code, docs and *.example"
fi
if [ -d security/hunt_for_red/cases ] || [ -d security/hunt_for_red/registry ]; then
  bad "D3 data directory inside the repo"
else
  ok "D3 no cases/ or registry/ inside the repo"
fi

echo "== D4: no coupling to Incident Learning write paths (D-1)"
if grep -nE 'knowledge_manager|incident_human_gate|security/knowledge|candidate_transition|km advance' "${HFR_PY[@]}"; then
  bad "D4 reference to an Incident Learning write path"
else
  ok "D4 Incident Learning referenced by id only"
fi

echo "== D5: METHODS holds only the passive set (D-3)"
m="$(python3 -I -c "import sys; sys.path.insert(0,'security/hunt_for_red'); import hfr_lib; print(','.join(hfr_lib.METHODS))")"
if [ "$m" = "feed,manual_browse,web_search_result,owner_provided" ]; then ok "D5 METHODS=$m"; else bad "D5 METHODS=$m"; fi

echo "== D6: examples use documentation-only values"
if grep -hoE '([0-9]{1,3}\.){3}[0-9]{1,3}|([0-9]{1,3}\[\.\]){3}[0-9]{1,3}' security/hunt_for_red/*.example 2>/dev/null | sed 's/\[\.\]/./g' | grep -vE '^(198\.51\.100|192\.0\.2|203\.0\.113)\.'; then
  bad "D6 non-documentation IP in examples"
else
  ok "D6 example IPs are RFC 5737"
fi

echo
echo "hunt_for_red_test: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
