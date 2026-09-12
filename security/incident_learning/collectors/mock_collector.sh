#!/bin/bash
set -uo pipefail

# security/incident_learning/collectors/mock_collector.sh -- Incident
# Learning Engine, Step 2: a fixed, no-network Collector for exercising
# the pipeline without any real external dependency.
#
# Collector contract (any future real Collector -- CISA KEV, CERT,
# NVD, a vendor advisory feed -- must conform to this same shape, so
# incident_normalizer.sh and everything downstream never needs to know
# which Collector produced a given record):
#   - emit one JSON object per line on stdout (JSONL), nothing else on
#     stdout (diagnostics go to stderr)
#   - each object has at least: id, source, source_type, source_url,
#     collected_at, raw_text
#   - id must be stable and collision-resistant across repeated runs
#     of the SAME collector (this mock uses a fixed id per sample, so
#     re-running it is idempotent from incident_normalizer.sh's own
#     point of view -- see that file's own "already exists" handling)
#   - never fabricates confidence/verification -- a Collector only
#     reports what it saw and where it saw it; Evidence/Confidence is
#     incident_evidence.sh's and incident_analyzer.sh's job entirely
#
# All three sample records below are entirely fictional (example.invalid
# domains, CVE ids in an unassigned range) -- this file makes no real
# network call and reports no real incident.

COLLECTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

emit() {
  python3 -c "
import json, sys
print(json.dumps({
    'id': sys.argv[1],
    'source': 'mock_collector',
    'source_type': sys.argv[2],
    'source_url': sys.argv[3],
    'collected_at': sys.argv[4],
    'raw_text': sys.argv[5],
}, ensure_ascii=False))
" "$1" "$2" "$3" "$COLLECTED_AT" "$4"
}

# A single-source, vendor-published advisory -- the shape most likely
# to eventually score high enough to reach the human gate.
emit "MOCK-2026-0001" "vendor_advisory" "https://example.invalid/advisory/0001" \
"Threat actor tracked as APT-EXAMPLE exploited CVE-2026-10001 in WidgetCorp VPN appliances via crafted authentication requests, achieving remote code execution. Observed indicators include outbound connections to 203.0.113.10 and 203.0.113.11. Detection point: unusual outbound traffic from the VPN appliance subnet immediately following authentication. Recommended mitigation: apply vendor patch 4.2.1, restrict outbound egress from the VPN appliance subnet."

# A news report describing a phishing campaign -- no CVE, but real IOC
# and mitigation content to normalize.
emit "MOCK-2026-0002" "news" "https://example.invalid/news/0002" \
"Widespread phishing campaign impersonating shipping notifications observed delivering malicious macro-enabled documents. Indicator: sender domain notify-shipping-example.invalid. Detection point: macro execution from a document opened directly from an email attachment. Mitigation: disable Office macros from internet-sourced documents by default."

# An unverified, single-source forum claim -- deliberately the
# low-confidence case for later steps (incident_evidence.sh /
# incident_analyzer.sh) to catch; this step normalizes it just like
# the others (extraction doesn't judge trustworthiness).
emit "MOCK-2026-0003" "unknown" "https://example.invalid/forum/0003" \
"Unverified forum post claims a supply-chain compromise of a popular open-source logging library, allegedly CVE-2026-99999. No vendor confirmation. Single source. No corroboration found."
