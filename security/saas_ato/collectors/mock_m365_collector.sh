#!/bin/bash
set -uo pipefail

# security/saas_ato/collectors/mock_m365_collector.sh -- a fixed,
# no-network Collector for exercising the SaaS ATO Monitor without any
# real Microsoft 365 connection or credential.
#
# RawSignal Collector contract (any future real Collector -- a
# Microsoft Graph API `security/alerts_v2` or sign-in-log poller --
# must conform to this same shape, so saas_ato_lib.py and everything
# downstream never needs to know which Collector produced a given
# record):
#   - emit one JSON object per line on stdout (JSONL), nothing else on
#     stdout (diagnostics go to stderr)
#   - each object has at least: id, source, tenant, account,
#     signal_type, detected_at (security/saas_ato/saas_ato_lib.py's own
#     parse_signal_line() silently skips any record missing one of
#     these -- see its own header)
#   - signal_type is one of: mass_send (recipient_count, window_minutes),
#     impossible_travel_signin (location_from, location_to,
#     minutes_between), new_forwarding_rule (forwards_to),
#     oauth_grant (app_name, scopes) -- see saas_ato_lib.py's own
#     classify_signal() header for exactly how each is scored
#   - id must be stable and collision-resistant across repeated runs
#     of the SAME collector (this mock uses a fixed id per sample, so
#     re-running it is idempotent)
#   - never fabricates risk/confidence itself -- a Collector only
#     reports what it saw and where; classify_signal() in
#     saas_ato_lib.py is entirely responsible for scoring it
#
# All sample records below are entirely fictional (example.invalid
# tenant/account, invented app names) -- this file makes no real
# network call and reports no real incident, same posture as
# security/incident_learning/collectors/mock_collector.sh.

NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

emit() {
  python3 -c "
import json, sys
d = json.loads(sys.argv[1])
print(json.dumps(d, ensure_ascii=False))
" "$1"
}

# Sample 1: an ordinary, small internal mailing -- LOW risk, included
# so this mock collector also demonstrates the non-alarming common
# case, not only a suspected-takeover scenario.
emit '{
  "id": "M365-MOCK-1",
  "source": "mock_m365_collector",
  "tenant": "contoso.example.invalid",
  "account": "newsletter@contoso.example.invalid",
  "signal_type": "mass_send",
  "detected_at": "'"$NOW"'",
  "recipient_count": 12,
  "window_minutes": 10
}'

# Sample 2: a single suspicious OAuth grant to an unfamiliar app
# requesting a sensitive scope -- HIGH risk on its own, MEDIUM
# confidence (a grant is a fact, "sensitive" is this module's own
# judgment call).
emit '{
  "id": "M365-MOCK-2",
  "source": "mock_m365_collector",
  "tenant": "contoso.example.invalid",
  "account": "alice@contoso.example.invalid",
  "signal_type": "oauth_grant",
  "detected_at": "'"$NOW"'",
  "app_name": "Invoice Helper Pro (example.invalid)",
  "scopes": ["Mail.ReadWrite", "Mail.Send"]
}'
