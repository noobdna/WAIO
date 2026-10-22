#!/bin/bash
set -uo pipefail

# tests/wsr_backup_test.sh -- regression suite for WAIO Local Survival
# & Recovery (WSR) Phase A: security/wsr_backup.sh.
#
# Everything here runs against scratch fixtures under a temp dir --
# same isolation pattern as tests/continuity_engine_test.sh
# (WAIO_CONTINUITY_*) and tests/segment_recovery_test.sh
# (SEGMENT_MANAGER_*): this suite never reads or writes this
# deployment's real workers/*.json, security/*.conf, security/state/,
# logs/security-audit.jsonl, logs/continuity-audit.jsonl, or the real
# /Volumes/Backup HD. WAIO_WSR_BACKUP_SOURCE_ROOT and
# WAIO_WSR_BACKUP_DEST are both redirected under the fixture sandbox,
# and wsr_device_of (security/wsr_backup.sh's own "is this really a
# separate disk?" check) is overridden after sourcing to simulate two
# physically distinct disks without actually needing two disks.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

PASS=0
FAIL=0
declare -a FAILURES=()

assert_eq() {
  local label="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    PASS=$((PASS + 1)); echo "  PASS: $label"
  else
    FAIL=$((FAIL + 1)); FAILURES+=("$label (expected='$expected' actual='$actual')")
    echo "  FAIL: $label (expected='$expected' actual='$actual')"
  fi
}

assert_contains() {
  local label="$1" haystack="$2" needle="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    PASS=$((PASS + 1)); echo "  PASS: $label"
  else
    FAIL=$((FAIL + 1)); FAILURES+=("$label (expected to contain '$needle')")
    echo "  FAIL: $label (expected to contain '$needle', got: $haystack)"
  fi
}

# --- fixture sandbox --------------------------------------------------
FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-wsr-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT

SOURCE_ROOT="$FIXTURE_DIR/fake_repo"
mkdir -p "$SOURCE_ROOT/confdir" "$SOURCE_ROOT/statedir"
echo '{"host":"fixturehost"}' > "$SOURCE_ROOT/confdir/a.json"
echo 'plain config line' > "$SOURCE_ROOT/confdir/b.conf"
echo 'state entry' > "$SOURCE_ROOT/statedir/state.txt"

DEST_MOUNT="$FIXTURE_DIR/fake_backup_volume"
mkdir -p "$DEST_MOUNT"

export WAIO_WSR_BACKUP_SOURCE_ROOT="$SOURCE_ROOT"
export WAIO_WSR_BACKUP_SOURCES="confdir/a.json confdir/b.conf statedir"
export WAIO_WSR_BACKUP_DEST="$DEST_MOUNT/WAIO-WSR-Backups"
export WAIO_WSR_BACKUP_AUDIT_LOG="$FIXTURE_DIR/wsr-backup-audit.jsonl"
export WAIO_WSR_BACKUP_RETAIN_COUNT=2
export WAIO_WSR_BACKUP_MIN_FREE_MULTIPLIER=3
export WAIO_SHUTDOWN_LOCK="$FIXTURE_DIR/SHUTDOWN.lock"
export WAIO_AUDIT_LOG="$FIXTURE_DIR/security-audit.jsonl"
export WAIO_AUDIT_LOG_CHECKPOINT="$FIXTURE_DIR/audit-checkpoint"
export WAIO_AUDIT_INTEGRITY_ALERTS="$FIXTURE_DIR/audit-alerts.jsonl"
export WAIO_AUDIT_LOG_LOCK_DIR="$FIXTURE_DIR/audit-lock"

source security/wsr_backup.sh

# Make "same disk?" deterministic under test: two distinct fake device
# ids for source vs. destination by default -- real disk devices are
# not under test here, only wsr_check_destination's own comparison
# logic. Individual tests below temporarily collapse this to the same
# value to exercise the refusal path, then restore it.
wsr_device_of() {
  case "$1" in
    "$SOURCE_ROOT") echo "/dev/fake-source" ;;
    "$DEST_MOUNT") echo "/dev/fake-dest" ;;
    *) echo "/dev/fake-other" ;;
  esac
}

echo "=== WAIO Local Survival & Recovery (WSR) Phase A regression suite ==="
echo

# --- destination safety gates ----------------------------------------
echo "--- wsr_check_destination: safety gates ---"

echo "[B1] destination volume not mounted -> refused, nothing created"
ORIG_DEST="$WSR_BACKUP_DEST"
WSR_BACKUP_DEST="$FIXTURE_DIR/not_mounted/WAIO-WSR-Backups"
B1_OUT="$(wsr_check_destination 2>&1)"; B1_RC=$?
assert_eq "B1 check fails" "1" "$B1_RC"
assert_contains "B1 error mentions not mounted" "$B1_OUT" "not mounted"
assert_eq "B1 nothing created at the unmounted path" "false" "$([ -e "$FIXTURE_DIR/not_mounted" ] && echo true || echo false)"
WSR_BACKUP_DEST="$ORIG_DEST"

echo
echo "[B2] destination on same device as source -> refused"
wsr_device_of() { echo "/dev/same-everywhere"; }
B2_OUT="$(wsr_check_destination 2>&1)"; B2_RC=$?
assert_eq "B2 check fails" "1" "$B2_RC"
assert_contains "B2 error mentions same device" "$B2_OUT" "same device"
wsr_device_of() {
  case "$1" in
    "$SOURCE_ROOT") echo "/dev/fake-source" ;;
    "$DEST_MOUNT") echo "/dev/fake-dest" ;;
    *) echo "/dev/fake-other" ;;
  esac
}

echo
echo "[B3] insufficient free space -> refused"
ORIG_MULT="$WSR_BACKUP_MIN_FREE_MULTIPLIER"
WSR_BACKUP_MIN_FREE_MULTIPLIER=999999999999
B3_OUT="$(wsr_check_destination 2>&1)"; B3_RC=$?
assert_eq "B3 check fails" "1" "$B3_RC"
assert_contains "B3 error mentions free space" "$B3_OUT" "insufficient free space"
WSR_BACKUP_MIN_FREE_MULTIPLIER="$ORIG_MULT"

echo
echo "[B4] every gate passes with the fixture's real (separate-dir) layout"
B4_RC=0
wsr_check_destination >/dev/null 2>&1 || B4_RC=$?
assert_eq "B4 check passes" "0" "$B4_RC"

# --- successful backup + manifest -------------------------------------
echo
echo "--- wsr_backup_create: happy path ---"

echo "[B5] first backup succeeds and its manifest matches the fixture tree"
B5_OUT="$(wsr_backup_create 2>&1)"; B5_RC=$?
assert_eq "B5 backup succeeds" "0" "$B5_RC"
SNAP1="$(wsr_list_snapshot_dirs | head -1)"
assert_eq "B5 exactly one snapshot exists" "1" "$(wsr_list_snapshot_dirs | wc -l | tr -d ' ')"
assert_eq "B5 manifest file_count is 3" "3" "$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['file_count'])" "$SNAP1/MANIFEST.json")"
EXPECTED_HASH="$(shasum -a 256 "$SOURCE_ROOT/confdir/a.json" | awk '{print $1}')"
MANIFEST_HASH="$(python3 -c "
import json, sys
m = json.load(open(sys.argv[1]))
print([f['sha256'] for f in m['files'] if f['path'] == sys.argv[2]][0])
" "$SNAP1/MANIFEST.json" "confdir/a.json")"
assert_eq "B5 manifest sha256 matches independently computed hash" "$EXPECTED_HASH" "$MANIFEST_HASH"

echo
echo "[B6] wsr_verify_snapshot reports OK on an untouched snapshot"
B6_OUT="$(wsr_verify_snapshot "$SNAP1" 2>&1)"; B6_RC=$?
assert_eq "B6 verify passes" "0" "$B6_RC"
assert_contains "B6 verify reports OK" "$B6_OUT" "OK:"

echo
echo "[B7] a second backup creates a distinct snapshot and never modifies the first"
HASH_BEFORE="$(shasum -a 256 "$SNAP1/MANIFEST.json" | awk '{print $1}')"
sleep 1.1
B7_OUT="$(wsr_backup_create 2>&1)"; B7_RC=$?
assert_eq "B7 second backup succeeds" "0" "$B7_RC"
assert_eq "B7 two distinct snapshots now exist" "2" "$(wsr_list_snapshot_dirs | wc -l | tr -d ' ')"
HASH_AFTER="$(shasum -a 256 "$SNAP1/MANIFEST.json" | awk '{print $1}')"
assert_eq "B7 first snapshot's own manifest is byte-identical after the second run" "$HASH_BEFORE" "$HASH_AFTER"

# --- secret-leak exclusion ---------------------------------------------
echo
echo "--- secret_leak_check integration ---"

echo "[B8] a file containing a credential-shaped string is excluded, not backed up, and the run still succeeds for the rest"
echo "sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAA" > "$SOURCE_ROOT/confdir/secretlike.conf"
export WAIO_WSR_BACKUP_SOURCES="confdir/a.json confdir/b.conf confdir/secretlike.conf statedir"
WSR_SOURCES=(confdir/a.json confdir/b.conf confdir/secretlike.conf statedir)
rm -f "$FIXTURE_DIR/SHUTDOWN.lock"
sleep 1.1
B8_OUT="$(wsr_backup_create 2>&1)"; B8_RC=$?
assert_eq "B8 backup still succeeds overall" "0" "$B8_RC"
SNAP3="$(wsr_list_snapshot_dirs | head -1)"
assert_eq "B8 excluded_count is 1" "1" "$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['excluded_count'])" "$SNAP3/MANIFEST.json")"
assert_eq "B8 excluded file not actually present in the snapshot" "false" "$([ -e "$SNAP3/confdir/secretlike.conf" ] && echo true || echo false)"
assert_contains "B8 excluded_files lists its path" "$(cat "$SNAP3/MANIFEST.json")" "confdir/secretlike.conf"
assert_contains "B8 audit log records the exclusion" "$(cat "$WAIO_WSR_BACKUP_AUDIT_LOG")" "wsr_backup_file_excluded"
assert_eq "B8 secret_leak_check's own Emergency Shutdown also tripped (same as every other call site)" "true" "$([ -f "$FIXTURE_DIR/SHUTDOWN.lock" ] && echo true || echo false)"
rm -f "$FIXTURE_DIR/SHUTDOWN.lock"
export WAIO_WSR_BACKUP_SOURCES="confdir/a.json confdir/b.conf statedir"
WSR_SOURCES=(confdir/a.json confdir/b.conf statedir)
rm -f "$SOURCE_ROOT/confdir/secretlike.conf"

# --- tamper detection ----------------------------------------------------
echo
echo "--- wsr_verify_snapshot: tamper detection ---"

echo "[B9] a byte changed in a backed-up file after the fact is detected as a MISMATCH"
echo "tampered" >> "$SNAP3/statedir/state.txt"
B9_OUT="$(wsr_verify_snapshot "$SNAP3" 2>&1)"; B9_RC=$?
assert_eq "B9 verify fails" "1" "$B9_RC"
assert_contains "B9 reports which file" "$B9_OUT" "MISMATCH: statedir/state.txt"
rm -rf "$SNAP3"

# --- retention / pruning ------------------------------------------------
echo
echo "--- wsr_prune_old_snapshots: retention ---"

echo "[B10] with retain=2 and 4 valid snapshots created in sequence, pruning keeps exactly the 2 newest"
rm -rf "$WSR_BACKUP_DEST"
for i in 1 2 3 4; do
  wsr_backup_create >/dev/null 2>&1
  sleep 1.1
done
assert_eq "B10 exactly 2 snapshots remain" "2" "$(wsr_list_snapshot_dirs | wc -l | tr -d ' ')"
ALL_OK=true
while IFS= read -r d; do
  [ -n "$d" ] || continue
  wsr_verify_snapshot "$d" >/dev/null 2>&1 || ALL_OK=false
done <<< "$(wsr_list_snapshot_dirs)"
assert_eq "B10 both remaining snapshots verify OK" "true" "$ALL_OK"

echo
echo "[B11] if the newest snapshot fails verification, pruning aborts entirely (nothing deleted)"
NEWEST="$(wsr_list_snapshot_dirs | head -1)"
OLDEST="$(wsr_list_snapshot_dirs | tail -1)"
FIRST_FILE="$(python3 -c "
import json, sys
m = json.load(open(sys.argv[1]))
print(m['files'][0]['path'])
" "$NEWEST/MANIFEST.json")"
echo "corrupt" >> "$NEWEST/$FIRST_FILE"
ORIG_RETAIN="$WSR_BACKUP_RETAIN_COUNT"
WSR_BACKUP_RETAIN_COUNT=1
B11_RC=0
wsr_prune_old_snapshots >/dev/null 2>&1 || B11_RC=$?
WSR_BACKUP_RETAIN_COUNT="$ORIG_RETAIN"
assert_eq "B11 prune reports failure" "1" "$B11_RC"
assert_eq "B11 newest (corrupted) snapshot still present" "true" "$([ -d "$NEWEST" ] && echo true || echo false)"
assert_eq "B11 oldest snapshot still present too (nothing deleted)" "true" "$([ -d "$OLDEST" ] && echo true || echo false)"

echo
echo "[B12] retain-count misconfigured to 0 is coerced to a floor of 1, never deletes everything"
rm -rf "$WSR_BACKUP_DEST"
ORIG_RETAIN="$WSR_BACKUP_RETAIN_COUNT"
WSR_BACKUP_RETAIN_COUNT=0
for i in 1 2 3; do
  wsr_backup_create >/dev/null 2>&1
  sleep 1.1
done
WSR_BACKUP_RETAIN_COUNT="$ORIG_RETAIN"
B12_COUNT="$(wsr_list_snapshot_dirs | wc -l | tr -d ' ')"
assert_eq "B12 at least one snapshot survives" "true" "$([ "$B12_COUNT" -ge 1 ] && echo true || echo false)"

# --- static safety self-check -------------------------------------------
echo
echo "--- static safety self-check ---"

echo "[B13] no forbidden operational verb appears as an actual command, and no restore-capable function was defined"
FORBIDDEN_FOUND="false"
for verb in "launchctl load" "launchctl bootstrap" "sudo " "chmod " "chown " "brew install" "npm install" "pip install"; do
  if grep -qF "$verb" security/wsr_backup.sh security/wsr_backup_cron.sh; then
    FORBIDDEN_FOUND="true"
    echo "    found forbidden verb: $verb" >&2
  fi
done
if grep -qE '^[a-zA-Z_]*restore[a-zA-Z_]*\(\)' security/wsr_backup.sh security/wsr_backup_cron.sh; then
  FORBIDDEN_FOUND="true"
  echo "    found a restore-capable function definition" >&2
fi
assert_eq "B13 no forbidden verb or restore function present" "false" "$FORBIDDEN_FOUND"

echo
echo "[B14] bash -n syntax check passes on both new scripts"
B14_RC=0
bash -n security/wsr_backup.sh || B14_RC=1
bash -n security/wsr_backup_cron.sh || B14_RC=1
assert_eq "B14 syntax check passes" "0" "$B14_RC"

echo
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
