#!/bin/bash
set -uo pipefail

# security/shadow_ai_attack_graph_cron.sh -- scheduled entry point for
# the Shadow AI Monitor + Attack Graph pair (security/shadow_ai/,
# security/attack_graph/), left as a manual-invocation-only pipe by
# both modules' own design until now (see each script's own header:
# neither ever documented a scheduling path, unlike
# incident_learning_cron.sh/global_patrol_cron.sh/
# segment_monitor_cron.sh, all of which do).
#
# Deliberately thin, same posture as security/segment_monitor_cron.sh
# (Phase 51): adds no new logic, no new state file, no new lock. It
# only runs the exact pipe both modules' own headers already document
# as "the intended real-world invocation" --
#   security/shadow_ai/shadow_ai_monitor.sh scan | security/attack_graph/attack_graph.sh build
# -- and logs when it ran. shadow_ai_monitor.sh's own "scan" writes
# security/state/shadow_ai/inventory.json; attack_graph.sh's own
# "build" (reading the scan's JSONL stdout via stdin, the "-" default)
# writes security/state/attack_graph/latest_graph.json. Both already
# write their own state atomically (tmp file + mv, see each script's
# own header) -- this wrapper adds no locking of its own, same
# reasoning segment_monitor_cron.sh's own header gives for why it
# doesn't either.
#
# Preserves both modules' own explicit scope boundary, unchanged:
# neither script is modified by this file, neither sources
# security/lib.sh, neither is wired into DuCoPA/Guardian/Decision
# Engine/any containment action. This file does not call either
# module any differently than a human running the same pipe by hand --
# it only adds a timer and a log line.
#
# Meant to be invoked periodically by a per-user launchd agent -- see
# security/com.waio.shadow-ai-attack-graph.plist.example. Safe to also
# run by hand at any time; running it twice back-to-back is a no-op
# beyond repeating the same two idempotent, read-only-of-the-outside-
# world calls (ps/lsof locally, no network, no SSH, no Control Plane
# file touched).
#
# 2026-10-18 additions (both default-safe):
#   - Overlap lock: a run that finds another run still in progress logs
#     "skipped" and exits 0 instead of interleaving with it. Reuses
#     security/incident_learning/lock.sh (mkdir-based, PID-liveness-gated
#     stale-lock reclaim -- a lock left by a crashed run is reclaimed on
#     the next tick). Override: SHADOW_AI_ATTACK_GRAPH_CRON_LOCK_DIR.
#   - Optional evidence + decision stages, OFF unless
#     WAIO_DETECTION_DECIDE=1: also runs the Intelligence Layer and the
#     Decision Engine on this run's own output, so a fresh decision
#     report exists every tick. Still proposal-only -- the Decision
#     Engine never executes anything and nothing here calls Guardian,
#     DuCoPA or any containment/recovery tool.
#   2026-10-19: size-based rotation of this script's own log (5 MiB cap,
#   5 gzip archives kept, 0600), done under the overlap lock -- see
#   rotate_log below.
#   launchd StartInterval does not back-fill intervals missed while the
#   machine was asleep or the agent unloaded; every run is a fresh,
#   stateless scan, so the next run simply covers the gap.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

LOG_FILE="${SHADOW_AI_ATTACK_GRAPH_CRON_LOG:-logs/shadow-ai-attack-graph-cron.log}"
mkdir -p "$(dirname "$LOG_FILE")"

log() {
  printf '%s %s\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$1" >>"$LOG_FILE"
}

source security/incident_learning/lock.sh
LOCK_DIR="${SHADOW_AI_ATTACK_GRAPH_CRON_LOCK_DIR:-security/state/shadow_ai/.cron.lock}"
mkdir -p "$(dirname "$LOCK_DIR")" 2>/dev/null || true
if ! il_lock_acquire "$LOCK_DIR" 0; then
  log "skipped: another run is already in progress (lock held at $LOCK_DIR)"
  exit 0
fi
RUN_TMP=""
trap 'il_lock_release "$LOCK_DIR"; [ -n "$RUN_TMP" ] && rm -rf "${RUN_TMP:?}"' EXIT

# Size-based log rotation, done only by the lock holder so two runs can
# never rotate at once. Disk use is bounded by MAX_BYTES (plus one run's
# output) for the live log and LOG_KEEP archives. Archives and the fresh
# log are 0600 (the log names local processes). A rotation that fails is
# logged and the run carries on -- rotation must never stop detection.
# Overrides: SHADOW_AI_ATTACK_GRAPH_CRON_LOG_MAX_BYTES / _LOG_KEEP.
LOG_MAX_BYTES="${SHADOW_AI_ATTACK_GRAPH_CRON_LOG_MAX_BYTES:-5242880}"  # 5 MiB
LOG_KEEP="${SHADOW_AI_ATTACK_GRAPH_CRON_LOG_KEEP:-5}"
case "$LOG_MAX_BYTES" in ''|*[!0-9]*) LOG_MAX_BYTES=5242880 ;; esac
case "$LOG_KEEP" in ''|*[!0-9]*) LOG_KEEP=5 ;; esac

rotate_log() {
  local size arc old
  [ -f "$LOG_FILE" ] && [ ! -L "$LOG_FILE" ] || return 0
  size="$(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE" 2>/dev/null)"
  [ -n "$size" ] && [ "$size" -gt "$LOG_MAX_BYTES" ] || return 0
  arc="$LOG_FILE.$(date -u +%Y%m%dT%H%M%SZ)"
  if [ -e "$arc" ] || [ -e "$arc.gz" ]; then arc="$arc.$$"; fi
  if ! mv -f -- "$LOG_FILE" "$arc" 2>/dev/null; then
    log "log rotation failed: could not rename $LOG_FILE ($size bytes); continuing without rotating"
    return 0
  fi
  ( umask 077; : >>"$LOG_FILE" )
  chmod 600 "$arc" 2>/dev/null
  if gzip -n -- "$arc" 2>/dev/null; then
    arc="$arc.gz"
  else
    rm -f -- "$arc.gz"
    log "log rotation: gzip failed, archive kept uncompressed"
  fi
  log "log rotated: previous log ($size bytes) archived as $(basename "$arc")"
  # Prune the oldest archives (compressed or not) beyond LOG_KEEP. The
  # UTC timestamp in each name sorts chronologically.
  set -- "$LOG_FILE".2[0-9][0-9][0-9][0-9][0-9][0-9][0-9]T[0-9]*Z*
  [ -e "$1" ] || return 0
  while [ "$#" -gt "$LOG_KEEP" ]; do
    old="$1"; shift
    rm -f -- "$old" && log "log retention: removed oldest archive $(basename "$old")"
  done
}
rotate_log

log "run start"

if [ "${WAIO_DETECTION_DECIDE:-}" != "1" ]; then
  if ./security/shadow_ai/shadow_ai_monitor.sh scan 2>>"$LOG_FILE" | ./security/attack_graph/attack_graph.sh build >>"$LOG_FILE" 2>&1; then
    log "shadow_ai_monitor.sh scan | attack_graph.sh build: ok"
  else
    log "shadow_ai_monitor.sh scan | attack_graph.sh build: exited non-zero (see log above for which stage)"
  fi
else
  RUN_TMP="$(mktemp -d "${TMPDIR:-/tmp}/waio-detect.XXXXXX")" || { log "could not create a temp dir; run aborted"; exit 1; }
  stage() {  # stage NAME OUTFILE CMD... -- runs one stage, logs its outcome
    local name="$1" out="$2"; shift 2
    if "$@" > "$out" 2>>"$LOG_FILE"; then log "$name: ok"; return 0; fi
    log "$name: exited non-zero; later stages skipped this run"; return 1
  }
  stage "shadow_ai_monitor.sh scan" "$RUN_TMP/shadow_ai.jsonl" ./security/shadow_ai/shadow_ai_monitor.sh scan &&
  stage "attack_graph.sh build" "$RUN_TMP/attack_graph.json" ./security/attack_graph/attack_graph.sh build "$RUN_TMP/shadow_ai.jsonl" &&
  stage "intelligence_layer.sh ingest" "$RUN_TMP/intelligence.json" ./security/intelligence/intelligence_layer.sh ingest --shadow-ai "$RUN_TMP/shadow_ai.jsonl" --attack-graph "$RUN_TMP/attack_graph.json" &&
  stage "decision_engine.sh decide (proposal only)" "$RUN_TMP/decisions.json" ./security/decision_engine/decision_engine.sh decide "$RUN_TMP/intelligence.json"
fi

log "run end"
