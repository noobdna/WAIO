#!/bin/bash
set -uo pipefail

# taco-control/taco_control_dispatch.sh -- 750 (management) side
# trigger for the minimal 750->800 control channel (see
# taco_control_executor.sh's own header for the full picture and its
# deliberate scope limits).
#
# NOT YET FUNCTIONAL end-to-end: this script's ssh call will fail with
# "Host key verification failed" until 192.168.1.80's SSH host key is
# independently verified and deliberately added to this machine's own
# known_hosts (see this repo's own session notes) -- this file
# intentionally does NOT pass -o StrictHostKeyChecking=no or otherwise
# bypass that check itself, per explicit instruction not to touch
# known_hosts/SSH config from this side. Once that trust is
# established through whatever separate, deliberate process the
# operator chooses, this script works as-is with no changes needed.
#
# Command-injection fix (Red Team finding #2, 2026-09-13): $COMMAND
# used to be embedded into the remote SSH command line inside a bare
# `'$COMMAND'` -- a single quote in COMMAND broke out of that quoting
# once the LOCAL shell substituted it into the text actually sent to
# the remote shell (`ssh host "..."` always re-parses its one trailing
# command-line argument on the far end -- see security/lib.sh's
# shell_quote() own header for why that one layer of re-parsing can
# never be skipped). Fixed with two independent layers, matching this
# repo's existing defense-in-depth posture elsewhere (e.g.
# security/recovery_engine.sh's whitelisted-actions-only plus a
# separate post-action health check):
#   1. Shape validation, first, before anything else runs: COMMAND
#      must look like a plain command keyword (^[A-Z][A-Z0-9_]*$).
#      taco_control_executor.sh's own `case` statement on the OTHER
#      end remains the single source of truth for which specific
#      commands are actually valid (today just PING) -- this dispatch
#      script never invents or duplicates that whitelist, it only
#      refuses input that could not possibly BE a legitimate command
#      keyword (a space, quote, `;`, backtick, `$()`, `|`, `&&`, a
#      newline -- all refused here, before SSH is ever attempted, with
#      a clear local error instead of a raw remote failure).
#   2. security/lib.sh's shell_quote() (already used and tested for
#      the same class of bug in workers/rpi_worker.sh, Red Team finding
#      #1) safely embeds COMMAND into the remote command line
#      regardless, as defense in depth.
# See tests/taco_control_injection_test.sh for the attack-simulation
# regression tests (same fake-ssh-on-PATH technique as
# tests/rpi_command_injection_test.sh -- no real network, no real
# host-key trust needed).
#
# DLP/audit-bypass fix (Red Team finding #4, 2026-09-13): this file
# used to make its real outbound SSH connection with NO egress_check
# and NO audit trail at all, a complete bypass of the DLP/Emergency
# Shutdown layer -- fixed by calling egress_check immediately before
# the real ssh call (security/lib.sh was already sourced here for
# shell_quote() above; this reuses that same source, no new
# dependency). Operational consequence, expected and intentional: this
# channel's destination (192.168.1.80, distinct from 800号機's own
# 192.168.1.91) was never checked before this fix and so is not yet in
# a real deployment's security/egress_allowlist.conf -- egress_check
# will deny it (fail closed, same "unlisted destination is refused,
# not silently allowed" policy every other destination already
# follows) until an operator adds the real entry (see
# security/egress_allowlist.conf.example's new line). See
# tests/jobs_taco_control_dlp_test.sh for the regression tests.
#
# Usage: taco_control_dispatch.sh COMMAND
#   e.g. taco_control_dispatch.sh PING

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/security/lib.sh"

TACO_HOST="${TACO_CONTROL_HOST:-192.168.1.80}"
TACO_USER="${TACO_CONTROL_USER:-masa}"
TACO_REMOTE_DIR="${TACO_CONTROL_REMOTE_DIR:-taco-control}"

# Host-collision guard (security audit finding, 2026-09-17): this
# channel's destination is DESIGNED to be distinct from 800号機's own
# host (workers/800.json) -- see this file's own "DLP/audit-bypass fix"
# note above, which explicitly relies on that distinction to keep
# egress_check() failing closed until an operator deliberately adds a
# real allowlist entry for THIS channel. If workers/800.json's real
# host is ever reassigned to the same address TACO_HOST resolves to
# (whether via this script's own hardcoded default or an explicit
# TACO_CONTROL_HOST override), that fail-closed design is silently
# defeated: egress_allowlist.conf's pre-existing HOST800 entry now
# matches this channel's destination too, purely by coincidence, with
# no operator ever having reviewed or approved taco-control reaching
# that address. Refuses loudly here instead of letting egress_check
# report a misleading "allowed."
#
# Reads workers/800.json's own host the same way workers/host800_worker.sh
# already does (python3 json.load, CWD-relative, read-only, no state
# written). Fails safe toward NOT blocking: a missing, unreadable, or
# malformed workers/800.json means there is nothing to collide with, so
# this check is silently skipped -- egress_check below remains the
# real, primary gate either way; this is an additional collision guard
# layered in front of it, not a replacement for it.
TACO_800_HOST="$(python3 -c '
import json
try:
    print(json.load(open("workers/800.json")).get("host", ""))
except Exception:
    print("")
' 2>/dev/null)"
if [ -n "$TACO_800_HOST" ] && [ "$TACO_800_HOST" = "$TACO_HOST" ]; then
  echo "ERROR: TACO_HOST ($TACO_HOST) is identical to workers/800.json's own host ($TACO_800_HOST) -- refusing to proceed." >&2
  echo "ERROR: this channel is designed to be a destination distinct from 800号機 (see this file's own header); a collision here means either workers/800.json's real host changed without this script/its allowlist entry being reviewed, or TACO_CONTROL_HOST was set to 800号機's own address by mistake." >&2
  echo "ERROR: resolve explicitly -- set TACO_CONTROL_HOST to the actually-intended, distinct destination, or confirm workers/800.json and this deployment's documentation (see ARCHITECTURE.md) agree on 800号機's real address before proceeding." >&2
  audit_log "taco_control_host_collision_detected" "n/a" "dispatch" "TACO_CONTROL" "$TACO_HOST:22" "denied" "TACO_HOST collides with workers/800.json's own host ($TACO_800_HOST) -- refusing, see script header"
  exit 1
fi

COMMAND="${1:-}"
if [ -z "$COMMAND" ]; then
  echo "Usage: $0 COMMAND" >&2
  exit 1
fi

if ! [[ "$COMMAND" =~ ^[A-Z][A-Z0-9_]*$ ]]; then
  echo "ERROR: COMMAND must look like a plain command keyword (^[A-Z][A-Z0-9_]*\$), got '$COMMAND' -- refusing before attempting SSH" >&2
  exit 1
fi

QUOTED_COMMAND="$(shell_quote "$COMMAND")"

# DLP / Emergency Shutdown layer: last check before the real SSH call.
if ! egress_check "$TACO_HOST" "22" "" "" "TACO_CONTROL"; then
  echo "ERROR: egress denied by DLP guard, emergency shutdown triggered -- SSH not attempted" >&2
  exit 1
fi

ssh -o BatchMode=yes "${TACO_USER}@${TACO_HOST}" "
  mkdir -p \"\$HOME/$TACO_REMOTE_DIR/commands\"
  echo $QUOTED_COMMAND > \"\$HOME/$TACO_REMOTE_DIR/commands/next.command\"
  bash \"\$HOME/$TACO_REMOTE_DIR/taco_control_executor.sh\"
  echo '--- state/control.status ---'
  cat \"\$HOME/$TACO_REMOTE_DIR/state/control.status\"
  echo '--- state/last.result ---'
  cat \"\$HOME/$TACO_REMOTE_DIR/state/last.result\"
"
