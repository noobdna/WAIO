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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

LOG_FILE="${SHADOW_AI_ATTACK_GRAPH_CRON_LOG:-logs/shadow-ai-attack-graph-cron.log}"
mkdir -p "$(dirname "$LOG_FILE")"

log() {
  printf '%s %s\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$1" >>"$LOG_FILE"
}

log "run start"

if ./security/shadow_ai/shadow_ai_monitor.sh scan 2>>"$LOG_FILE" | ./security/attack_graph/attack_graph.sh build >>"$LOG_FILE" 2>&1; then
  log "shadow_ai_monitor.sh scan | attack_graph.sh build: ok"
else
  log "shadow_ai_monitor.sh scan | attack_graph.sh build: exited non-zero (see log above for which stage)"
fi

log "run end"
