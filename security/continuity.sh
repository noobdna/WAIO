#!/bin/bash
set -uo pipefail

# security/continuity.sh -- WAIO Pre-Disconnect Cache (PDC).
#
# User-facing name: WAIO Pre-Disconnect Cache (PDC). This file's own
# internal name, "Continuity Engine" (function/variable prefix
# `continuity_`, state dir `security/state/continuity/`), predates that
# name and is kept as the implementation-level name only -- nothing
# user-facing should say "continuity" instead of "PDC".
#
# Purpose (stated narrowly, matching the request this was built from):
# let WAIO keep operating from local state/cached context when the
# external network, an external AI API, or a cloud service it depends
# on (Takomachi, a third-party HTTP API) becomes unreachable -- NOT to
# predict or detect *why* connectivity was lost. The reference concept
# is TERN's GPS-denied navigation design *at the conceptual level
# only*: keep a continuously-updated local reference while the
# external signal is available, so operation can continue by
# dead-reckoning on that reference if the signal drops, and reconcile
# once it returns. No jamming-detection/avoidance/counter-signal
# concept is implemented or in scope here -- this file only ever reads
# already-existing local state and TCP-reachability results.
#
# Lifecycle this file implements, all of it a read/derive layer on top
# of already-existing WAIO subsystems (deliberately -- see "Reused, not
# rebuilt" below):
#   PREPARE  -- security/continuity_prepare_cron.sh (opt-in, periodic,
#               not wired into any dispatch path): refreshes
#               segments.conf-derived reachability via the existing
#               health_checker.sh, then continuity_update_state +
#               continuity_write_snapshot below.
#   OPERATE  -- unchanged existing dispatch, whenever continuity_assess
#               reports CONNECTED. This file makes no behavior change
#               on that path.
#   RECOVER  -- when a dependency is DEGRADED/OFFLINE, workers/
#               orchestrate_worker.sh (the only integration point --
#               see its own PDC comments) may, opt-in only
#               (WAIO_PDC_FALLBACK=1), serve continuity_cache_get's
#               last-known-good content instead of a live dispatch.
#               Actual reconnection attempts are NOT reimplemented here
#               -- security/recovery_engine.sh (Phase 49) already does
#               this safely (whitelisted actions, dry-run default, no
#               automatic infinite retry) and is reused as-is.
#   RESYNC   -- continuity_update_state logs a continuity_resync event
#               the moment every monitored dependency is reachable
#               again. MVP scope, explicit: no automatic replay of
#               requests skipped/served-from-cache during the outage --
#               matching this codebase's existing posture (Phase 40-A/
#               recovery_engine.sh) that no automated component may
#               declare its own recovery complete or silently
#               reconstruct what a human would want re-run.
#
# Reused, not rebuilt (per the explicit instruction to keep new code
# minimal and respect the existing architecture):
#   - Connectivity / dependency state: security/segments.conf +
#     security/health_checker.sh, completely unmodified. Its TCP
#     `nc -z` probe was never SSH-specific -- registering Takomachi
#     (localhost:3000) or a keyless third-party API (e.g.
#     api.open-meteo.com:443) as an ordinary segments.conf entry works
#     today with zero code change; see security/segments.conf.example's
#     new PDC section. This file only ever READS segment status
#     (segment_get_status, via security/segment_manager.sh) -- it never
#     calls segment_transition and is not a second source of truth.
#   - Recovery: security/recovery_engine.sh, completely unmodified.
#   - Policy Cache: registry.conf/pipeline.conf/egress_allowlist.conf/
#     segments.conf are already always read from local disk, never
#     fetched -- nothing new was needed for this MVP item; this file's
#     snapshot below only records a SHA-256 of each, to flag drift.
#   - Local Knowledge: security/knowledge/*.json (Incident Learning
#     Engine) is untouched by this file and by PDC generally -- it is a
#     different kind of local knowledge (curated threat intel via a
#     human-gated promotion pipeline), not an operational response
#     cache. PDC's Context Cache below is new and distinct from it.
#
# New in this file: Context Cache (continuity_cache_put/get), overall
# CONNECTED/DEGRADED/OFFLINE state derivation (continuity_assess),
# PREPARE's local snapshot (continuity_write_snapshot), this
# subsystem's own JSONL audit log (continuity_audit_log), and a
# read-only SND@HOME snapshot (continuity_snd_snapshot_refresh/get --
# see that section below for its own, more detailed header; it reuses
# dashboard/collect_snd_status.sh as-is and never modifies SND@HOME or
# that script).
#
# Security constraint (explicit, load-bearing): neither the Context
# Cache nor the SND@HOME snapshot ever stores an API key, secret,
# private key, or password. Every write path (continuity_cache_put,
# continuity_snd_snapshot_refresh) runs security/lib.sh's existing
# secret_leak_check() (the same pattern-based check every worker
# already runs on Takomachi response content) before writing anything,
# and refuses (logs, does not write) on a match. Nothing in this file
# ever reads Keychain, TAKOMACHI_API_KEY, SND_HOME_API_TOKEN's value
# beyond passing it through unread to collect_snd_status.sh's own
# Authorization header, or any other credential -- it only ever
# persists RESPONSE/STATUS TEXT that has already passed a check once at
# its own source (the worker, or collect_snd_status.sh, neither of
# which ever writes a token into what PDC reads), and checks it again
# here independently.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
source security/lib.sh
source security/segment_manager.sh

CONTINUITY_STATE_DIR="${WAIO_CONTINUITY_STATE_DIR:-$SECURITY_LIB_DIR/state/continuity}"
CONTINUITY_CACHE_DIR="${WAIO_CONTINUITY_CACHE_DIR:-$CONTINUITY_STATE_DIR/context_cache}"
CONTINUITY_STATE_FILE="${WAIO_CONTINUITY_STATE_FILE:-$CONTINUITY_STATE_DIR/CONTINUITY_STATE}"
CONTINUITY_SNAPSHOT_FILE="${WAIO_CONTINUITY_SNAPSHOT_FILE:-$CONTINUITY_STATE_DIR/last_known_good.json}"
CONTINUITY_SND_SNAPSHOT_FILE="${WAIO_CONTINUITY_SND_SNAPSHOT_FILE:-$CONTINUITY_STATE_DIR/snd_snapshot.json}"
CONTINUITY_AUDIT_LOG="${WAIO_CONTINUITY_AUDIT_LOG:-$SECURITY_LIB_DIR/../logs/continuity-audit.jsonl}"

mkdir -p "$CONTINUITY_STATE_DIR" "$CONTINUITY_CACHE_DIR" "$(dirname "$CONTINUITY_AUDIT_LOG")" 2>/dev/null || true

# continuity_audit_log EVENT WORKER REASON RESULT -- appends one JSON
# line. Same "metadata only, never a secret/credential/raw payload"
# discipline as security/lib.sh's audit_log() and
# security/segment_manager.sh's segment_audit_log() -- kept as its own
# separate file/function for the same reason segment_audit_log is
# separate from lib.sh's audit_log: a distinct, fixed field set for
# this domain (event/worker/reason/result) that should never have to
# drift either existing log's own frozen shape.
continuity_audit_log() {
  local event="$1" worker="$2" reason="$3" result="$4"
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  python3 -c "
import json, sys
print(json.dumps({
    'timestamp': sys.argv[1],
    'event': sys.argv[2],
    'worker': sys.argv[3],
    'reason': sys.argv[4],
    'result': sys.argv[5],
}, ensure_ascii=False))
" "$ts" "$event" "$worker" "$reason" "$result" >> "$CONTINUITY_AUDIT_LOG"
}

# continuity_worker_dependency_status WORKER_NAME -- cross-references
# security/segments.conf's WORKER_NAME field (already how each segment
# documents which workers/registry.conf worker it corresponds to,
# Phase 49) and returns that segment's current Incident State Machine
# status (normal/suspicious/isolated/recovering/recovered/failed) via
# segment_get_status. A worker with no matching segments.conf entry --
# not registered for dependency monitoring at all -- reads as
# "unmonitored", deliberately distinct from "normal": PDC must never
# claim a dependency is healthy that it never actually checked. If more
# than one segments.conf entry names the same WORKER_NAME (e.g. a
# worker with several distinct dependencies -- see
# segments.conf.example's PDC section for EARTHWEATHER's two), the
# WORST (most severe) of their statuses is returned, so a single failed
# dependency is never masked by another healthy one.
continuity_worker_dependency_status() {
  local worker="$1" i st worst="unmonitored" found="false"
  load_segments || { echo "unmonitored"; return 0; }
  for i in "${!SEG_WORKERS[@]}"; do
    if [ "${SEG_WORKERS[$i]}" = "$worker" ]; then
      found="true"
      st="$(segment_get_status "${SEG_IDS[$i]}")"
      if [ "$worst" = "unmonitored" ]; then
        worst="$st"
      else
        worst="$(_continuity_worse_status "$worst" "$st")"
      fi
    fi
  done
  [ "$found" = "true" ] || { echo "unmonitored"; return 0; }
  echo "$worst"
}

# _continuity_worse_status A B -- prints whichever of two Incident
# State Machine statuses is more severe, by the same ranking
# continuity_assess uses below (isolated/recovering/failed count as
# "down"; normal/suspicious/recovered do not). Ties keep A.
_continuity_worse_status() {
  local a="$1" b="$2"
  case "$b" in
    isolated|recovering|failed)
      case "$a" in
        isolated|recovering|failed) echo "$a" ;;
        *) echo "$b" ;;
      esac
      ;;
    *) echo "$a" ;;
  esac
}

# continuity_is_degraded WORKER_NAME -- true (exit 0) iff PDC should
# treat this worker's dependency as currently down enough to justify
# falling back to the Context Cache. "suspicious" (a first failed
# check, unconfirmed) deliberately does NOT count -- matching
# health_checker.sh's own debounce posture, a single flaky check must
# never itself change behavior. "unmonitored" also does not count: PDC
# only ever substitutes a call for a dependency it has positive
# evidence is down, never guesses.
continuity_is_degraded() {
  local status
  status="$(continuity_worker_dependency_status "$1")"
  case "$status" in
    isolated|recovering|failed) return 0 ;;
    *) return 1 ;;
  esac
}

# continuity_assess -- derives one overall PDC state from Emergency
# Shutdown plus every security/segments.conf entry's current status.
# Prints exactly one of CONNECTED / DEGRADED / OFFLINE, never fails.
#   OFFLINE   -- Emergency Shutdown is active (no egress is possible at
#                all, by definition), OR at least one segment is
#                registered and every one of them is currently
#                isolated/recovering/failed.
#   DEGRADED  -- at least one, but not every, registered segment is
#                isolated/recovering/failed.
#   CONNECTED -- no segments.conf entries at all (nothing to be
#                offline from -- same "empty is a safe state" posture
#                segments.conf.example already documents), or every
#                entry is normal/suspicious/recovered.
continuity_assess() {
  if is_shutdown_active; then
    echo "OFFLINE"
    return 0
  fi
  load_segments || { echo "CONNECTED"; return 0; }
  if [ "${#SEG_IDS[@]}" -eq 0 ]; then
    echo "CONNECTED"
    return 0
  fi
  local id st total=0 down=0
  for id in "${SEG_IDS[@]}"; do
    total=$((total + 1))
    st="$(segment_get_status "$id")"
    case "$st" in
      isolated|recovering|failed) down=$((down + 1)) ;;
    esac
  done
  if [ "$down" -eq 0 ]; then
    echo "CONNECTED"
  elif [ "$down" -eq "$total" ]; then
    echo "OFFLINE"
  else
    echo "DEGRADED"
  fi
}

# continuity_state_get -- the last value continuity_update_state
# persisted, or CONNECTED if PDC has never run yet (fresh checkout --
# must not read as an incident by default, same fail-safe-default
# posture as security/guardian.sh's absent-state-file case).
continuity_state_get() {
  if [ -f "$CONTINUITY_STATE_FILE" ]; then
    cat "$CONTINUITY_STATE_FILE" 2>/dev/null || echo "CONNECTED"
  else
    echo "CONNECTED"
  fi
}

# continuity_update_state -- PREPARE's own entry point: assesses
# current state, persists it, and logs an audit event only when the
# value actually CHANGES (so the log records enter-degraded/
# enter-offline/resync transitions, not one identical line per cron
# tick). Prints the newly assessed state.
continuity_update_state() {
  local new_state previous_state
  new_state="$(continuity_assess)"
  previous_state="$(continuity_state_get)"
  if [ "$new_state" != "$previous_state" ]; then
    local event="continuity_state_changed"
    if [ "$new_state" = "CONNECTED" ] && [ "$previous_state" != "CONNECTED" ]; then
      event="continuity_resync"
    fi
    continuity_audit_log "$event" "n/a" "$previous_state -> $new_state" "$new_state"
  fi
  printf '%s' "$new_state" > "$CONTINUITY_STATE_FILE"
  echo "$new_state"
}

# continuity_write_snapshot -- PREPARE's "keep a fresh local reference
# while still online" step (State Snapshot / Last-known State). Writes
# CONTINUITY_SNAPSHOT_FILE with: the current PDC state, every
# segments.conf entry's status, and a SHA-256 of each policy file's
# CONTENTS (registry.conf/pipeline.conf/egress_allowlist.conf/
# segments.conf) -- never the file's own text, never any cached
# response content, never a credential. The hash exists only so a
# human reviewing a RESYNC can notice "a policy file changed while PDC
# was degraded/offline" -- this never diffs or restores anything
# itself.
continuity_write_snapshot() {
  local state seg_jsonl tmp rc
  state="$(continuity_state_get)"
  load_segments || true
  seg_jsonl="$(mktemp)"
  local id
  for id in "${SEG_IDS[@]:-}"; do
    [ -n "$id" ] || continue
    python3 -c "
import json, sys
print(json.dumps({'segment_id': sys.argv[1], 'status': sys.argv[2]}))
" "$id" "$(segment_get_status "$id")" >> "$seg_jsonl"
  done

  tmp="$CONTINUITY_SNAPSHOT_FILE.tmp.$$"
  python3 -c "
import hashlib, json, os, sys
generated_at, seg_jsonl_path, state, out_path = sys.argv[1:5]
policy_paths = sys.argv[5:]

segments = []
with open(seg_jsonl_path) as f:
    for line in f:
        line = line.strip()
        if line:
            segments.append(json.loads(line))

policy_hashes = {}
for p in policy_paths:
    if os.path.isfile(p):
        with open(p, 'rb') as fh:
            policy_hashes[p] = hashlib.sha256(fh.read()).hexdigest()

json.dump({
    'generated_at': generated_at,
    'continuity_state': state,
    'segments': segments,
    'policy_file_sha256': policy_hashes,
}, open(out_path, 'w'), indent=2, ensure_ascii=False)
" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$seg_jsonl" "$state" "$tmp" \
    workers/registry.conf workers/pipeline.conf security/egress_allowlist.conf security/segments.conf
  rc=$?
  rm -f "$seg_jsonl"
  if [ "$rc" -eq 0 ] && [ -s "$tmp" ]; then
    mv -f "$tmp" "$CONTINUITY_SNAPSHOT_FILE"
    return 0
  fi
  rm -f "$tmp"
  return 1
}

# continuity_cache_path WORKER_NAME -- PDC caches the latest
# known-good result PER WORKER NAME, not per distinct request (an
# explicit MVP scope decision): it answers "what did this worker last
# successfully say", for offline fallback continuity, not a
# general-purpose request/response cache. See
# workers/orchestrate_worker.sh's own PDC comments for the one
# integration point that reads/writes this.
continuity_cache_path() {
  echo "$CONTINUITY_CACHE_DIR/$1.json"
}

# continuity_cache_put WORKER_NAME CONTENT -- writes CONTENT (already-
# COLLECT'd stage result text) as WORKER_NAME's latest cached context.
# Runs security/lib.sh's existing secret_leak_check() first and refuses
# to write (logs, no file written) on a match -- see this file's own
# header for why this is load-bearing, not defense-in-depth-for-its-
# own-sake. CONTENT is written to disk (state/, already gitignored),
# never to the audit log.
continuity_cache_put() {
  local worker="$1" content="$2"
  if ! secret_leak_check "$content" "n/a" "pdc_cache" "$worker" "n/a"; then
    continuity_audit_log "pdc_cache_write_denied" "$worker" "secret_leak_check flagged this content" "denied"
    return 1
  fi
  local path tmp
  path="$(continuity_cache_path "$worker")"
  tmp="$path.tmp.$$"
  if ! python3 -c "
import json, sys
json.dump({'worker': sys.argv[1], 'cached_at': sys.argv[2], 'content': sys.argv[3]}, open(sys.argv[4], 'w'), ensure_ascii=False)
" "$worker" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$content" "$tmp"; then
    rm -f "$tmp"
    return 1
  fi
  mv -f "$tmp" "$path"
  continuity_audit_log "pdc_cache_write" "$worker" "stage result cached" "ok"
  return 0
}

# continuity_cache_get WORKER_NAME -- prints the cached content, or
# nothing + returns 1 if no cache entry exists yet (or it's
# unreadable/corrupt -- never fabricates a fallback answer).
continuity_cache_get() {
  local worker="$1" path
  path="$(continuity_cache_path "$worker")"
  [ -f "$path" ] || return 1
  python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['content'])" "$path" 2>/dev/null
}

# continuity_cache_age_seconds WORKER_NAME -- prints how old the cached
# entry is, in seconds, or nothing + returns 1 if there is none. Exists
# so a caller (workers/orchestrate_worker.sh's fallback path) can
# always label a served cache entry with its real age -- PDC never
# lets a stale answer look indistinguishable from a fresh one.
continuity_cache_age_seconds() {
  local worker="$1" path cached_at
  path="$(continuity_cache_path "$worker")"
  [ -f "$path" ] || return 1
  cached_at="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['cached_at'])" "$path" 2>/dev/null)" || return 1
  [ -n "$cached_at" ] || return 1
  python3 -c "
import datetime, sys
cached_at = datetime.datetime.strptime(sys.argv[1], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc)
now = datetime.datetime.now(datetime.timezone.utc)
print(int((now - cached_at).total_seconds()))
" "$cached_at" 2>/dev/null
}

# --- SND@HOME read-only snapshot integration -------------------------
# PDC's Last Known State for SND@HOME (independent security monitoring
# project; per its own CLAUDE.md, "他の一切のプロジェクトとは無関係で
# あり、混在させません" -- WAIO only ever consumes its JSON/API output,
# never merges code, never starts/stops it, never calls a mutating
# route). This is deliberately NOT the per-worker Context Cache above:
# SND@HOME is not a workers/registry.conf worker and is never dispatched
# through ORCHESTRATE, so there is no worker NAME to key it by.
#
# Reuses dashboard/collect_snd_status.sh AS-IS (Phase 76) -- never
# duplicates its HTTP/auth logic, never modifies it. That script
# already: is fully opt-in (no-op unless SND_HOME_API_URL is set, shell
# env or ~/.waio.env), never sends SND_HOME_API_TOKEN anywhere but an
# Authorization header, and never writes it into its own output JSON
# (logs/snd-status-latest.json). The one gap this section exists to
# close: that script unconditionally OVERWRITES its own output on every
# run, including a failed one (available:false, all fields null) --
# exactly the moment PDC's "last known good" state is needed most.
# CONTINUITY_SND_SNAPSHOT_FILE is therefore a separate file, updated
# ONLY on a verified-successful refresh; a failed refresh (SND_HOME
# unreachable, non-200, etc.) leaves whatever was last written there
# completely untouched.

# continuity_snd_snapshot_refresh -- no-op (returns 0, touches nothing)
# unless SND_HOME_API_URL resolves to a non-empty value (same
# resolution order as dashboard/collect_snd_status.sh's own: shell env,
# then ~/.waio.env) -- PDC never causes an SND_HOME network attempt
# that would not already happen from running that script by hand.
# Never invoked automatically by security/continuity_prepare_cron.sh or
# any other schedule -- manual/on-demand only, matching
# dashboard/collect_snd_status.sh's own existing posture for itself.
#
# On a configured URL: runs dashboard/collect_snd_status.sh (exit
# status ignored beyond "did logs/snd-status-latest.json get written",
# since that script itself always exits 0 and reports failure via its
# own JSON, never a nonzero exit), then commits the result into
# CONTINUITY_SND_SNAPSHOT_FILE only if ALL of: the refresh produced
# output, that output's own "available" field is true, and its full
# serialized content passes secret_leak_check() (the same check
# continuity_cache_put runs on worker results, applied here
# independently a second time even though collect_snd_status.sh never
# writes a token into this JSON in the first place). Any other outcome
# logs a skip/denial event and returns non-zero, leaving the previous
# snapshot (if any) exactly as it was.
continuity_snd_snapshot_refresh() {
  local url=""
  url="${SND_HOME_API_URL:-}"
  if [ -z "$url" ] && [ -f "$HOME/.waio.env" ]; then
    url="$(sed -n 's/^\s*export\s\+SND_HOME_API_URL=//p' "$HOME/.waio.env" | tail -1)"
  fi
  [ -n "$url" ] || return 0

  export SND_HOME_API_URL="$url"
  if ! dashboard/collect_snd_status.sh >/dev/null 2>&1; then
    continuity_audit_log "pdc_snd_snapshot_refresh_skipped" "SND" "dashboard/collect_snd_status.sh exited non-zero" "skipped"
    return 1
  fi

  local snd_out="logs/snd-status-latest.json"
  if [ ! -f "$snd_out" ]; then
    continuity_audit_log "pdc_snd_snapshot_refresh_skipped" "SND" "$snd_out not found after refresh" "skipped"
    return 1
  fi

  local available=""
  available="$(python3 -c "
import json
try:
    print('true' if json.load(open('$snd_out')).get('available') else 'false')
except Exception:
    print('false')
" 2>/dev/null)" || available="false"
  if [ "$available" != "true" ]; then
    continuity_audit_log "pdc_snd_snapshot_refresh_skipped" "SND" "collect_snd_status.sh reported unavailable -- last known good snapshot preserved" "skipped"
    return 1
  fi

  local content=""
  content="$(cat "$snd_out" 2>/dev/null)"
  if ! secret_leak_check "$content" "n/a" "pdc_snd_snapshot" "SND" "n/a"; then
    continuity_audit_log "pdc_snd_snapshot_write_denied" "SND" "secret_leak_check flagged this content" "denied"
    return 1
  fi

  local tmp
  tmp="$CONTINUITY_SND_SNAPSHOT_FILE.tmp.$$"
  if ! python3 -c "
import json, sys
snd_out_path, ts, out_path = sys.argv[1:4]
snd = json.load(open(snd_out_path))
json.dump({'pdc_cached_at': ts, 'snd_status': snd}, open(out_path, 'w'), indent=2, ensure_ascii=False)
" "$snd_out" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$tmp"; then
    rm -f "$tmp"
    return 1
  fi
  mv -f "$tmp" "$CONTINUITY_SND_SNAPSHOT_FILE"
  continuity_audit_log "pdc_snd_snapshot_refresh" "SND" "SND@HOME snapshot updated" "ok"
  return 0
}

# continuity_snd_snapshot_get -- prints the last successfully-cached
# SND@HOME snapshot (the whole {'pdc_cached_at', 'snd_status'} object,
# as JSON text), or nothing + returns 1 if none exists yet. Purely a
# local file read -- no network call, no dependency on SND_HOME_API_URL
# being set right now. This is PDC's Last Known State for SND@HOME:
# what a caller reads while SND_HOME/the network is unreachable.
continuity_snd_snapshot_get() {
  [ -f "$CONTINUITY_SND_SNAPSHOT_FILE" ] || return 1
  cat "$CONTINUITY_SND_SNAPSHOT_FILE"
}

# Only run the CLI dispatch when executed directly -- every other
# sourcing caller (workers/orchestrate_worker.sh,
# security/continuity_prepare_cron.sh, tests/continuity_engine_test.sh)
# only ever wants this file's functions.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  case "${1:-}" in
    state)
      continuity_state_get
      ;;
    assess)
      continuity_assess
      ;;
    update)
      continuity_update_state
      ;;
    snapshot)
      continuity_write_snapshot
      ;;
    dep-status)
      [ -n "${2:-}" ] || { echo "Usage: $0 dep-status WORKER_NAME" >&2; exit 1; }
      continuity_worker_dependency_status "$2"
      ;;
    cache-get)
      [ -n "${2:-}" ] || { echo "Usage: $0 cache-get WORKER_NAME" >&2; exit 1; }
      continuity_cache_get "$2"
      ;;
    snd-snapshot)
      continuity_snd_snapshot_refresh
      ;;
    snd-get)
      continuity_snd_snapshot_get
      ;;
    *)
      echo "Usage: $0 {state|assess|update|snapshot|dep-status WORKER_NAME|cache-get WORKER_NAME|snd-snapshot|snd-get}" >&2
      exit 1
      ;;
  esac
fi
