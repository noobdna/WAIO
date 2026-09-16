#!/bin/bash
set -uo pipefail

# security/recover.sh -- the ONLY way to clear an Emergency Shutdown.
# Deliberately manual and explicit (requirement: no auto-recovery, a
# human must confirm the cause has been investigated). Requires
# --confirm "<non-empty reason>"; refuses to run otherwise.
#
# --guardian-confirm "<reason>" is the same gate, reserved for the
# Guardian SSH path (see security/guardian_recover_wrapper.sh and
# ARCHITECTURE.md Phase 34/35) -- identical validation and effect, only
# the audit_log event_type differs, so the audit trail can tell which
# party recovered the system.
#
# Usage: ./security/recover.sh --confirm "investigated: <what you found>"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
source security/lib.sh
_reconcile_recovery_audit
_handle_audit_log_integrity_alert

if [ ! -f "$SHUTDOWN_LOCK" ]; then
  echo "[RECOVER] No active shutdown (no $SHUTDOWN_LOCK). Nothing to do."
  exit 0
fi

MODE="${1:-}"
CONFIRM_REASON="${2:-}"
case "$MODE" in
  --confirm) EVENT_TYPE="recovery_confirmed" ;;
  --guardian-confirm) EVENT_TYPE="recovery_confirmed_guardian" ;;
  *) EVENT_TYPE="" ;;
esac

# Minimum reason strength (recovery-hardening item 1): a non-empty
# reason alone used to be sufficient -- "x" would clear any shutdown.
# Two language-agnostic checks, both overridable for tests/tuning:
#   - trimmed length >= WAIO_RECOVER_MIN_REASON_LENGTH (default 20,
#     chosen to match this repo's own shortest pre-existing recovery
#     reason in tests/security_test.sh's cleanup calls, e.g.
#     "phase40b1 K2 cleanup" -- so no existing caller needed to change)
#   - distinct-character count >= WAIO_RECOVER_MIN_REASON_DISTINCT_CHARS
#     (default 8) instead of a word-count minimum: word-count would
#     reject a perfectly good Japanese reason with no spaces (this
#     codebase's own comments are bilingual), so a low-entropy/padding
#     check ("aaaaaaaaaaaaaaaaaaaa") is used instead, which works the
#     same regardless of language.
# Deliberately NOT validated: whether the reason is actually true, or
# related to this specific incident -- that remains an honor-system
# boundary (see ARCHITECTURE.md Phase 31/32: no new authentication
# mechanism was authorized). This only raises the bar against a
# one-keystroke, contentless clear.
MIN_REASON_LENGTH="${WAIO_RECOVER_MIN_REASON_LENGTH:-20}"
MIN_REASON_DISTINCT_CHARS="${WAIO_RECOVER_MIN_REASON_DISTINCT_CHARS:-8}"
REASON_ERROR=""
TRIMMED_REASON=""
if [ -n "$EVENT_TYPE" ] && [ -n "$CONFIRM_REASON" ]; then
  # Trim/length/distinct-character-count done in python3, decoding stdin
  # as raw bytes -> UTF-8 explicitly (sys.stdin.buffer, not sys.stdin) --
  # NOT bash's ${#var}/fold/sort/wc, which silently mis-measure
  # multi-byte text (e.g. Japanese) whenever the process locale is
  # unset/C, which this repo's own launchd-invoked cron wrappers already
  # run under. Confirmed during implementation: under an empty locale,
  # ${#var} counts bytes and `fold -w1 | sort -u` degenerates to ~3
  # "characters" for a real Japanese sentence -- python3's str type
  # counts actual characters regardless of the process locale once
  # decoded this way, so the check works the same in any environment.
  # \x1f (unit separator) joins the status and payload -- a reason is
  # free-form human text and must not be split on a byte a real reason
  # could plausibly contain (unlike a tab or comma).
  REASON_CHECK="$(printf '%s' "$CONFIRM_REASON" | python3 -c "
import sys
raw = sys.stdin.buffer.read().decode('utf-8', errors='replace')
trimmed = raw.strip()
min_len = int(sys.argv[1])
min_distinct = int(sys.argv[2])
sep = '\x1f'
if not trimmed:
    print('EMPTY')
elif len(trimmed) < min_len:
    print(f'TOO_SHORT{sep}{len(trimmed)}')
elif len(set(trimmed)) < min_distinct:
    print(f'LOW_VARIETY{sep}{len(set(trimmed))}')
else:
    print(f'OK{sep}{trimmed}')
" "$MIN_REASON_LENGTH" "$MIN_REASON_DISTINCT_CHARS")"

  REASON_STATUS="${REASON_CHECK%%$'\x1f'*}"
  REASON_PAYLOAD="${REASON_CHECK#*$'\x1f'}"
  case "$REASON_STATUS" in
    EMPTY) REASON_ERROR="reason is empty after trimming whitespace" ;;
    TOO_SHORT) REASON_ERROR="reason is $REASON_PAYLOAD character(s), minimum is $MIN_REASON_LENGTH -- describe what you investigated and why it's safe to resume" ;;
    LOW_VARIETY) REASON_ERROR="reason has too little variety ($REASON_PAYLOAD distinct characters, minimum $MIN_REASON_DISTINCT_CHARS) -- looks like padding, not a real explanation" ;;
    OK) TRIMMED_REASON="$REASON_PAYLOAD" ;;
    *) REASON_ERROR="internal error validating reason (unexpected validator output)" ;;
  esac
fi

if [ -z "$EVENT_TYPE" ] || [ -z "$CONFIRM_REASON" ] || [ -n "$REASON_ERROR" ]; then
  echo "[RECOVER] ERROR: refusing to clear an active shutdown without a sufficiently descriptive confirmation."
  [ -n "$REASON_ERROR" ] && echo "[RECOVER]   reason rejected: $REASON_ERROR"
  echo "[RECOVER] Usage: $0 --confirm \"<reason: what you investigated and why it's safe to resume>\""
  echo "[RECOVER]    or: $0 --guardian-confirm \"<reason>\"  (reserved for the Guardian SSH path)"
  echo "[RECOVER] Current shutdown record:"
  sed 's/^/  /' "$SHUTDOWN_LOCK"
  exit 1
fi
CONFIRM_REASON="$TRIMMED_REASON"

echo "[RECOVER] Current shutdown record:"
sed 's/^/  /' "$SHUTDOWN_LOCK"

RUN_ID="recover-$(date -u +%Y%m%dT%H%M%SZ)"
rm -f "$SHUTDOWN_LOCK"
audit_log "$EVENT_TYPE" "$RUN_ID" "n/a" "n/a" "n/a" "cleared" "$CONFIRM_REASON"

# DuCoPA: this is also the one place that clears a Guardian-side SHUTDOWN
# mirror (see security/guardian.sh's guardian_request_waio_shutdown /
# WAIO_AUTO_GUARDIAN_NOTIFY) -- deliberately the same recovery authority
# and the same confirmation gate as the real lock it mirrors, never a
# second, separate way to release it. A Guardian state of BLOCKED/WARNING/
# HUMAN_APPROVAL_REQUIRED unrelated to this shutdown is left untouched;
# only SHUTDOWN is reset here.
if [ "$(guardian_get_state)" = "SHUTDOWN" ]; then
  guardian_set_state "NORMAL" "$CONFIRM_REASON" "$RUN_ID" "$([ "$EVENT_TYPE" = "recovery_confirmed_guardian" ] && echo "guardian" || echo "operator")"
fi

echo "[RECOVER] Shutdown cleared. Reason recorded: $CONFIRM_REASON"
echo "[RECOVER] Audit event written to $SECURITY_AUDIT_LOG"
