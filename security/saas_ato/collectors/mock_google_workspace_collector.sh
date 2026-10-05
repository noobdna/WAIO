#!/bin/bash
set -uo pipefail

# security/saas_ato/collectors/mock_google_workspace_collector.sh -- a
# fixed, no-network Collector for exercising the SaaS ATO Monitor
# without any real Google Workspace connection or credential. Same
# RawSignal Collector contract as
# security/saas_ato/collectors/mock_m365_collector.sh's own header --
# see that file for the full shape documentation; this file only
# differs in `source`/`tenant`/sample content.
#
# A future real Collector for this platform (a Google Workspace Admin
# SDK Reports API / Alert Center poller) is a separate, later,
# deliberately out-of-scope task -- see
# security/saas_ato/saas_ato_monitor.sh's own header for the explicit
# P1 boundary this repeats from the dashboard's SND@HOME/Takomachi
# System Overview panel.
#
# All sample records below are entirely fictional (example.invalid
# tenant/account) -- this file makes no real network call and reports
# no real incident.

NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

emit() {
  python3 -c "
import json, sys
d = json.loads(sys.argv[1])
print(json.dumps(d, ensure_ascii=False))
" "$1"
}

# Sample: a new mail-forwarding rule to an address OUTSIDE the
# account's own domain -- HIGH risk, HIGH confidence (a direct config
# read, same certainty class as an sshd_config read).
emit '{
  "id": "GWS-MOCK-1",
  "source": "mock_google_workspace_collector",
  "tenant": "fabrikam.example.invalid",
  "account": "bob@fabrikam.example.invalid",
  "signal_type": "new_forwarding_rule",
  "detected_at": "'"$NOW"'",
  "forwards_to": "collector@external-mail.example.invalid"
}'

# Sample: an impossible-travel sign-in -- HIGH risk, MEDIUM confidence
# (geo-IP heuristics are known to false-positive on VPN/mobile NAT).
emit '{
  "id": "GWS-MOCK-2",
  "source": "mock_google_workspace_collector",
  "tenant": "fabrikam.example.invalid",
  "account": "bob@fabrikam.example.invalid",
  "signal_type": "impossible_travel_signin",
  "detected_at": "'"$NOW"'",
  "location_from": "Tokyo, JP",
  "location_to": "Warsaw, PL",
  "minutes_between": 11
}'
