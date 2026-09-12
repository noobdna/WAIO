#!/bin/bash
set -uo pipefail

# security/incident_learning/incident_normalizer.sh -- Incident
# Learning Engine, Step 2: COLLECTED -> NORMALIZED.
#
# Reads RawIncident JSONL (a Collector's own stdout -- see
# collectors/mock_collector.sh's header for the shape contract) from
# stdin or a file argument. For each record:
#   1. creates a Knowledge Candidate via knowledge_manager.sh if this
#      id hasn't been seen before (idempotent: re-feeding the same
#      RawIncident is a no-op for an id that already exists, never a
#      duplicate/overwritten candidate)
#   2. only acts on candidates currently at COLLECTED -- anything
#      already further along the pipeline is left untouched (skipped,
#      logged), never re-normalized
#   3. extracts a small, deliberately simple set of structured fields
#      via pattern matching -- CVE ids, IPv4-shaped strings as
#      candidate IOCs, and a fixed detection-point/mitigation keyword
#      scan -- NOT real NLP. This is intentionally conservative: a
#      later step (incident_evidence.sh) is what actually establishes
#      trust in any of this, so over-engineering extraction here would
#      be effort spent before the safety-relevant part of the pipeline
#      even runs.
#   4. advances the candidate to NORMALIZED, attaching the extracted
#      fields, via knowledge_manager.sh advance's own KEY=VALUE
#      mechanism -- never any other status.
#
# This file never reads/writes any Control Plane file (same DuCoPA
# boundary as knowledge_manager.sh itself) and makes no network call.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$SCRIPT_DIR"
KM_SCRIPT="security/incident_learning/knowledge_manager.sh"
km() { bash "$KM_SCRIPT" "$@"; }

INPUT="${1:-/dev/stdin}"

# extract_fields RAW_TEXT -- prints one JSON object with cve_list,
# ioc_list, detection_points, mitigations -- all arrays, all possibly
# empty. Pure function of the input text, no side effects.
extract_fields() {
  python3 -c "
import json, re, sys

raw = sys.argv[1]

cves = sorted(set(re.findall(r'CVE-\d{4}-\d{4,7}', raw)))
iocs = sorted(set(re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', raw)))

detection_points = []
for sentence in re.split(r'(?<=[.])\s+', raw):
    if sentence.strip().lower().startswith('detection point'):
        detection_points.append(sentence.strip())

mitigations = []
for sentence in re.split(r'(?<=[.])\s+', raw):
    s = sentence.strip()
    if s.lower().startswith('mitigation') or s.lower().startswith('recommended mitigation'):
        mitigations.append(s)

print(json.dumps({
    'cve_list': cves,
    'ioc_list': iocs,
    'detection_points': detection_points,
    'mitigations': mitigations,
}))
" "$1"
}

while IFS= read -r line; do
  [ -n "$line" ] || continue

  id="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['id'])" "$line")"
  source_name="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['source'])" "$line")"
  source_type="$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('source_type','unknown'))" "$line")"
  source_url="$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('source_url',''))" "$line")"
  raw_text="$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('raw_text',''))" "$line")"
  collected_at="$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('collected_at',''))" "$line")"
  corroborating_sources="$(python3 -c "import json,sys; print(json.dumps(json.loads(sys.argv[1]).get('corroborating_sources', [])))" "$line")"

  if ! km status "$id" >/dev/null 2>&1; then
    # Each of these values (source_type, a URL, a free-text sentence)
    # is passed as-is: none of them are valid JSON syntax on their own,
    # so _km_parse_extras' own try/json.loads-else-string fallback
    # stores them as plain strings automatically -- no manual
    # JSON-quoting needed (and manually wrapping in literal quotes here
    # would break the moment raw_text itself ever contains a `"`).
    # collected_at/corroborating_sources are threaded through here too
    # (rather than left to default on the candidate's own created_at /
    # an absent field) so incident_evidence.sh's age/corroboration
    # computations reflect what the Collector actually reported, not
    # "now" and "none".
    km create "$id" "$source_name" "source_type=$source_type" "source_url=$source_url" "raw_text=$raw_text" \
      "collected_at=$collected_at" "corroborating_sources=$corroborating_sources" >/dev/null
    echo "[NORMALIZER] $id: new candidate created (COLLECTED)"
  fi

  current="$(km status "$id" 2>/dev/null)"
  if [ "$current" != "COLLECTED" ]; then
    echo "[NORMALIZER] $id: skipping (status=$current, not COLLECTED)"
    continue
  fi

  fields_json="$(extract_fields "$raw_text")"
  cve_list="$(python3 -c "import json,sys; print(json.dumps(json.loads(sys.argv[1])['cve_list']))" "$fields_json")"
  ioc_list="$(python3 -c "import json,sys; print(json.dumps(json.loads(sys.argv[1])['ioc_list']))" "$fields_json")"
  detection_points="$(python3 -c "import json,sys; print(json.dumps(json.loads(sys.argv[1])['detection_points']))" "$fields_json")"
  mitigations="$(python3 -c "import json,sys; print(json.dumps(json.loads(sys.argv[1])['mitigations']))" "$fields_json")"

  cve_count="$(python3 -c "import json,sys; print(len(json.loads(sys.argv[1])))" "$cve_list")"
  ioc_count="$(python3 -c "import json,sys; print(len(json.loads(sys.argv[1])))" "$ioc_list")"
  reason="normalized: $cve_count CVE(s), $ioc_count IOC(s) extracted"

  km advance "$id" NORMALIZED "$reason" \
    "cve_list=$cve_list" "ioc_list=$ioc_list" \
    "detection_points=$detection_points" "mitigations=$mitigations" >/dev/null
  echo "[NORMALIZER] $id: NORMALIZED ($reason)"
done < "$INPUT"
