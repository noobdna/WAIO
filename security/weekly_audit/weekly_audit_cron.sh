#!/bin/bash
set -uo pipefail

# security/weekly_audit/weekly_audit_cron.sh -- WAIO WEEKLY SECURITY AUDIT
# v1.0. Driven by launchd every Monday 08:00 JST
# (com.waio.weekly-audit.plist.example); safe to run by hand.
#
# What it does: collects read-only observations of this host and its LAN
# into a private work directory, then hands them to weekly_audit_lib.py,
# which compares them with the previous audit, grades findings
# (CRITICAL/HIGH/MEDIUM/LOW) and writes WEEKLY_AUDIT_YYYYMMDD.md.
#
# Reuses, never duplicates:
#   - dashboard/collect_snd_status.sh  SND@HOME API read (GET only), with
#     SND_STATUS_OUT_PATH pointing into the private work dir so the
#     dashboard's own SND panel is not touched.
#   - security/ssh_exposure/ssh_exposure_monitor.sh  SSH exposure +
#     firewall state (its macOS adapter), with its state/audit log
#     redirected into the private audit dir.
#   - security/ssh_exposure/ssh_exposure_lib.py  lsof parsing and
#     listener scope classification (imported by weekly_audit_lib.py).
#   - security/incident_learning/lock.sh  the repo's mkdir lock, so two
#     runs never overlap (fail closed: a second run logs and exits 0).
#
# Execution policy (grep-guarded by tests/weekly_audit_test.sh):
#   read-only; no sudo; no blocking, deleting, restarting, firewall or
#   API_KEY change; no active network scan (only this host's own ARP
#   cache/routing table and SND_HOME's own GET API). Findings that need
#   action are listed in the report for a human to approve.
#
# Data placement: reports, snapshots and the device ledger contain MAC
# and IP addresses, and this repo is public. Everything is written under
# WEEKLY_AUDIT_DIR (default ~/waio-ops/weekly-audit), created mode 0700
# with umask 077 so files are 0600. The script refuses to run if that
# directory resolves inside this repository. Wrong permissions on an
# existing directory are reported (HIGH), never silently changed.
#
# Environment:
#   WEEKLY_AUDIT_DIR            private output dir (default above)
#   WEEKLY_AUDIT_WAIO_LOG_DIR   WAIO logs read for HTTP/backup/error
#                               trends (default <repo>/logs)
#   WEEKLY_AUDIT_LAUNCH_AGENTS  LaunchAgents dir (default ~/Library/LaunchAgents)
#   WEEKLY_AUDIT_CMD_TIMEOUT    per-command cap in seconds (default 60)
#   SND_HOME_API_URL            passed through to collect_snd_status.sh
#                               (unset = SND section "not configured")

umask 077
export TZ="${TZ:-Asia/Tokyo}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$SCRIPT_DIR" || exit 1

AUDIT_DIR="${WEEKLY_AUDIT_DIR:-$HOME/waio-ops/weekly-audit}"
WAIO_LOG_DIR="${WEEKLY_AUDIT_WAIO_LOG_DIR:-$SCRIPT_DIR/logs}"
LAUNCH_AGENTS_DIR="${WEEKLY_AUDIT_LAUNCH_AGENTS:-$HOME/Library/LaunchAgents}"
CMD_TIMEOUT="${WEEKLY_AUDIT_CMD_TIMEOUT:-60}"

# Refuse an output dir inside the (public) repository -- audit data must
# never be one `git add` away from being published.
AUDIT_DIR_REAL="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$AUDIT_DIR")" || exit 1
case "$AUDIT_DIR_REAL/" in
  "$SCRIPT_DIR"/*)
    echo "[WEEKLY AUDIT] REFUSED: WEEKLY_AUDIT_DIR ($AUDIT_DIR_REAL) is inside the repository ($SCRIPT_DIR)" >&2
    exit 2 ;;
esac
AUDIT_DIR="$AUDIT_DIR_REAL"

if [ ! -d "$AUDIT_DIR" ]; then
  mkdir -p -m 700 "$AUDIT_DIR" || { echo "[WEEKLY AUDIT] cannot create $AUDIT_DIR" >&2; exit 1; }
fi
for sub in snapshots work state; do
  [ -d "$AUDIT_DIR/$sub" ] || mkdir -m 700 "$AUDIT_DIR/$sub" || exit 1
done

LOG_FILE="$AUDIT_DIR/weekly-audit.log"
log() { printf '%s %s\n' "$(date +%Y-%m-%dT%H:%M:%S%z)" "$1" >>"$LOG_FILE"; }

# shellcheck source=../incident_learning/lock.sh
source security/incident_learning/lock.sh
LOCK_DIR="$AUDIT_DIR/.weekly_audit.lock"
if ! il_lock_acquire "$LOCK_DIR" 0; then
  log "another weekly audit holds $LOCK_DIR -- skipping this run (no overlap)"
  echo "[WEEKLY AUDIT] another run is in progress -- skipped" >&2
  exit 0
fi
trap 'il_lock_release "$LOCK_DIR"' EXIT

RUN_ID="$(date +%Y%m%dT%H%M%S)"
NOW_ISO="$(date +%Y-%m-%dT%H:%M:%S%z | sed -E 's/([0-9]{2})([0-9]{2})$/\1:\2/')"
# Two runs inside the same second (a manual run right after the
# scheduled one) get distinct ids instead of failing on mkdir.
[ -e "$AUDIT_DIR/work/$RUN_ID" ] && RUN_ID="${RUN_ID}_$$"
WORK="$AUDIT_DIR/work/$RUN_ID"
mkdir -m 700 "$WORK" || { log "cannot create work dir $WORK"; exit 1; }
ERRS="$WORK/collector_errors.txt"
: >"$ERRS"
log "run start $RUN_ID"

# capture OUTFILE CMD... -- run one read-only command with a hard time
# cap (perl alarm survives exec; macOS has no timeout(1)). A failure is
# recorded and the audit continues with whatever else it can see.
capture() {
  local out="$1" rc
  shift
  perl -e 'alarm shift; exec @ARGV or exit 127' "$CMD_TIMEOUT" "$@" >"$WORK/$out" 2>>"$WORK/stderr.txt"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    printf '%s exited %s\n' "$1" "$rc" >>"$ERRS"
  fi
  return 0
}

# A. network (this host's own tables only -- no probing)
capture arp.txt arp -an
capture ifconfig.txt ifconfig
capture route_default.txt route -n get default
IFACE="$(sed -nE 's/^[[:space:]]*interface:[[:space:]]*//p' "$WORK/route_default.txt" | head -1)"
case "$IFACE" in
  ''|*[!A-Za-z0-9]*) printf 'no usable default interface for DHCP lookup\n' >>"$ERRS" ;;
  *) capture dhcp.txt ipconfig getpacket "$IFACE" ;;
esac

# B. security
capture netstat_listen.txt netstat -an -p tcp
capture lsof.txt lsof -i -P -n
capture dscl_users.txt dscl . -list /Users UniqueID
capture dscl_admin.txt dscl . -read /Groups/admin GroupMembership
SSH_EXPOSURE_STATE_DIR="$AUDIT_DIR/state/ssh_exposure" \
SSH_EXPOSURE_AUDIT_LOG="$AUDIT_DIR/state/ssh-exposure-audit.jsonl" \
  capture ssh_exposure.json ./security/ssh_exposure/ssh_exposure_monitor.sh scan

# C. system
capture df.txt df -kl
capture vm_stat.txt vm_stat
capture memsize.txt sysctl -n hw.memsize
capture loadavg.txt sysctl -n vm.loadavg
capture ncpu.txt sysctl -n hw.ncpu
capture uptime.txt uptime
capture launchctl.txt launchctl list
capture sw_vers.txt sw_vers
capture softwareupdate_history.txt softwareupdate --history
capture tmutil_latest.txt tmutil latestbackup

# D. SND@HOME -- GET-only read through the existing collector. An
# unreachable/unconfigured SND is recorded in snd.json and the audit
# carries on.
SND_STATUS_OUT_PATH="$WORK/snd.json" capture snd_collector.txt ./dashboard/collect_snd_status.sh
[ -s "$WORK/snd.json" ] || printf '{"configured": false, "available": false, "reason": "collector produced no output"}\n' >"$WORK/snd.json"

RESULT="$(python3 security/weekly_audit/weekly_audit_lib.py run \
  --work "$WORK" --audit-dir "$AUDIT_DIR" --run-id "$RUN_ID" --now "$NOW_ISO" \
  --waio-log-dir "$WAIO_LOG_DIR" --launch-agents-dir "$LAUNCH_AGENTS_DIR" 2>>"$WORK/stderr.txt")"
rc=$?
if [ "$rc" -ne 0 ]; then
  log "run $RUN_ID: report generation FAILED (python exit $rc, see $WORK/stderr.txt)"
  echo "[WEEKLY AUDIT] report generation failed (exit $rc) -- see $WORK/stderr.txt" >&2
  exit 1
fi
log "run end $RUN_ID $RESULT"
echo "[WEEKLY AUDIT] $RESULT"
exit 0
