#!/bin/bash
set -uo pipefail

# security/wsr_backup.sh -- WAIO Local Survival & Recovery (WSR),
# Phase A: Local Asset Backup.
#
# Purpose (stated narrowly, matching the request this was built from):
# periodically copy WAIO's own critical, gitignored, deployment-real
# state -- the config files and audit/recovery metadata that exist
# ONLY on this machine's disk, never in git (see .gitignore) -- to a
# physically separate local disk, with an integrity-verified manifest.
# This is about surviving a LOCAL disk failure, not a Cloudflare/DNS/
# external-cloud outage: WAIO's Pre-Disconnect Cache (security/
# continuity.sh, Phase 87-89) already handles "an external dependency
# is unreachable, keep operating from local state" -- that is a
# different problem from "the local state itself is gone" and is not
# duplicated here.
#
# Explicitly NOT in scope / not implemented here (by design, not an
# oversight):
#   - No restore. This file can create and verify backups; it has no
#     "restore"/"apply" subcommand at all. Restoring from a WSR backup
#     is a separate, later, explicitly human-gated phase, matching this
#     codebase's existing posture that no automated component may
#     silently undo or reconstruct state a human should review first
#     (security/recover.sh, security/recovery_engine.sh).
#   - No launchd registration. Nothing in this file installs or
#     schedules anything; security/wsr_backup_cron.sh (the periodic
#     entry point meant to eventually be launchd-driven) is not wired
#     into any plist this phase.
#   - No service restart, no chmod/chown, no package install, no sudo.
#
# What gets backed up (critical config / audit history / recovery
# metadata only -- deliberately NOT a full-repo mirror; results/,
# general logs/*.log, earth_weather/data/, fx_validation/data/, and
# backups/ itself are regenerable/non-critical and excluded, same
# judgment call PDC's own snapshot made for "what's worth persisting"):
#   workers/750.json, workers/800.json                -- real host metadata
#   security/egress_allowlist.conf                    -- DLP allowlist
#   security/ssh_management_allowlist.conf            -- SSH allowlist
#   security/segments.conf                            -- segment registry
#   security/knowledge/*.json                          -- promoted Incident Learning entries
#   security/shadow_ai/known_ai_allowlist.conf         -- Shadow AI allowlist
#   security/state/                                    -- continuity/guardian/segment/incident-learning state
#   logs/security-audit.jsonl                          -- DLP audit trail
#   logs/continuity-audit.jsonl                        -- PDC audit trail
# A missing source file/dir is silently skipped (not an error) -- same
# "optional, not fail-closed" posture security/segments.conf.example
# documents for its own optional entries.
#
# Destination (overridable via WAIO_WSR_BACKUP_DEST, default confirmed
# live on this machine: a physically separate internal disk from the
# boot volume, HFS+, already this user's established personal-backup
# volume): /Volumes/Backup HD/WAIO-WSR-Backups. Before any write,
# wsr_check_destination verifies (1) the volume's mount point already
# exists (never auto-created -- a missing mount means "not plugged
# in"/"not mounted", not "create it"), (2) the destination's device
# differs from the WAIO repo's own device (refuses a same-disk "backup"
# outright), (3) free space >= WAIO_WSR_BACKUP_MIN_FREE_MULTIPLIER
# (default 3) times the current source-file set's total size. Any
# check failing aborts cleanly -- nothing is written, no partial
# directory is left, and this never silently falls back to writing
# inside the repo itself.
#
# Snapshot format: each run creates its own timestamped, self-contained
# directory (WAIO-WSR-<UTC timestamp>/) containing a mirrored copy of
# every included source file (relative paths preserved) plus
# MANIFEST.json (path/size/mtime/SHA-256 per file, machine-readable --
# same hashlib.sha256-over-python3 convention as security/
# continuity.sh's continuity_write_snapshot) and MANIFEST.txt (human-
# readable, same style as backups/A-800-node-prep-*/MANIFEST.txt). A
# run is written to a "<name>.partial" directory first and only
# renamed to its final name after this file's own self-verification
# (re-hashing every file against the manifest it just wrote) passes --
# a failed/partial run is discarded (rm -rf) and never touches any
# prior snapshot. Retention keeps the last WAIO_WSR_BACKUP_RETAIN_COUNT
# snapshots (default 7, hard floor 1 -- see wsr_prune_old_snapshots):
# pruning only ever deletes older snapshots that themselves still pass
# verification, only after confirming the newest one verifies, and
# never the newest, so "the only valid backup" can never be deleted or
# overwritten.
#
# Secret-leak prevention: before copying each source file's bytes,
# this file reuses security/lib.sh's existing secret_leak_check() (the
# SAME function and pattern-based check every worker already runs on
# Takomachi response content, and the same one security/continuity.sh
# already reuses for its own Context Cache / SND@HOME snapshot writes
# -- not a second, drifting reimplementation of the credential-shape
# regex). A match excludes just that one file from this run (recorded
# as a path only -- never its content -- in MANIFEST.{json,txt} and
# wsr_audit_log) and the run continues with the rest; this also trips
# the same Emergency Shutdown secret_leak_check() always triggers on a
# match (first-trip-only, matching every other call site -- a
# credential-shaped string turning up in supposedly-secret-free
# deployment config is itself a severity event worth a human's
# attention, not something to silently work around). Manifests and
# this file's own JSONL audit log (logs/wsr-backup-audit.jsonl, same
# "metadata only" discipline as security/continuity.sh's
# continuity_audit_log) never carry file content, only
# path/size/hash/counts.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
source "$SCRIPT_DIR/security/lib.sh"

WSR_BACKUP_DEST="${WAIO_WSR_BACKUP_DEST:-/Volumes/Backup HD/WAIO-WSR-Backups}"
WSR_BACKUP_RETAIN_COUNT="${WAIO_WSR_BACKUP_RETAIN_COUNT:-7}"
WSR_BACKUP_MIN_FREE_MULTIPLIER="${WAIO_WSR_BACKUP_MIN_FREE_MULTIPLIER:-3}"
WSR_BACKUP_AUDIT_LOG="${WAIO_WSR_BACKUP_AUDIT_LOG:-$SCRIPT_DIR/logs/wsr-backup-audit.jsonl}"

# WSR_SOURCE_ROOT -- the root every WSR_SOURCES entry is resolved
# against, and the path wsr_check_destination compares the
# destination's device to. Defaults to the repo root itself (SCRIPT_DIR,
# production behavior, unchanged). tests/wsr_backup_test.sh overrides
# this to a scratch fixture tree via WAIO_WSR_BACKUP_SOURCE_ROOT, the
# same reason security/segment_manager.sh exposes SEGMENT_MANAGER_CONF
# as its own override -- so this suite never reads or writes this
# deployment's real workers/*.json, security/*.conf, or security/state/.
WSR_SOURCE_ROOT="${WAIO_WSR_BACKUP_SOURCE_ROOT:-$SCRIPT_DIR}"

# Default source set -- see this file's header for what each entry is
# and why. Overridable wholesale via WAIO_WSR_BACKUP_SOURCES (a space-
# separated list of paths relative to the repo root) -- used by
# tests/wsr_backup_test.sh to point at a scratch fixture tree instead
# of this deployment's real files; relies on simple word-splitting, the
# same "no spaces in a config value" convention every other WAIO *.conf
# file already assumes.
WSR_DEFAULT_SOURCES=(
  "workers/750.json"
  "workers/800.json"
  "security/egress_allowlist.conf"
  "security/ssh_management_allowlist.conf"
  "security/segments.conf"
  "security/knowledge"
  "security/shadow_ai/known_ai_allowlist.conf"
  "security/state"
  "logs/security-audit.jsonl"
  "logs/continuity-audit.jsonl"
)
if [ -n "${WAIO_WSR_BACKUP_SOURCES:-}" ]; then
  # shellcheck disable=SC2206
  WSR_SOURCES=($WAIO_WSR_BACKUP_SOURCES)
else
  WSR_SOURCES=("${WSR_DEFAULT_SOURCES[@]}")
fi

mkdir -p "$(dirname "$WSR_BACKUP_AUDIT_LOG")" 2>/dev/null || true

# wsr_audit_log EVENT RESULT REASON -- appends one JSON line. Same
# "metadata only, never a secret/credential/raw payload" discipline as
# security/continuity.sh's continuity_audit_log -- kept as its own
# separate file/function for the same reason continuity_audit_log is
# separate from security/lib.sh's own audit_log: a distinct, fixed
# field set for this domain that should never have to drift either
# existing log's own frozen shape.
wsr_audit_log() {
  local event="$1" result="$2" reason="$3"
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  python3 -c "
import json, sys
print(json.dumps({
    'timestamp': sys.argv[1],
    'event': sys.argv[2],
    'result': sys.argv[3],
    'reason': sys.argv[4],
}, ensure_ascii=False))
" "$ts" "$event" "$result" "$reason" >> "$WSR_BACKUP_AUDIT_LOG"
}

# wsr_enumerate_source_files -- prints the absolute path of every real
# file under every configured source (expanding directories
# recursively), one per line. A source entry that does not exist on
# disk is silently skipped -- not an error, same "optional, not fail-
# closed" posture as an unconfigured security/segments.conf entry.
wsr_enumerate_source_files() {
  local src full
  for src in "${WSR_SOURCES[@]}"; do
    full="$WSR_SOURCE_ROOT/$src"
    if [ -d "$full" ]; then
      find "$full" -type f 2>/dev/null
    elif [ -f "$full" ]; then
      echo "$full"
    fi
  done
}

# wsr_device_of PATH -- the filesystem device PATH lives on (macOS
# `df -P` first column), used to confirm the backup destination is a
# physically separate disk from the WAIO repo's own, never a stand-in
# for a stronger identity check.
wsr_device_of() {
  df -P "$1" 2>/dev/null | awk 'NR==2{print $1}'
}

# wsr_check_destination -- every safety gate that must pass before
# wsr_backup_create writes a single byte. See this file's header for
# what each check means and why a failure here must never fall back to
# writing inside the repo.
wsr_check_destination() {
  local vol_mount
  vol_mount="$(dirname "$WSR_BACKUP_DEST")"
  if [ ! -d "$vol_mount" ]; then
    echo "[WSR] ERROR: backup destination volume not mounted: $vol_mount" >&2
    wsr_audit_log "wsr_backup_aborted" "denied" "destination volume not mounted: $vol_mount"
    return 1
  fi

  local src_device dest_device
  src_device="$(wsr_device_of "$WSR_SOURCE_ROOT")"
  dest_device="$(wsr_device_of "$vol_mount")"
  if [ -z "$src_device" ] || [ -z "$dest_device" ]; then
    echo "[WSR] ERROR: could not determine filesystem device for source or destination" >&2
    wsr_audit_log "wsr_backup_aborted" "denied" "could not determine filesystem device"
    return 1
  fi
  if [ "$src_device" = "$dest_device" ]; then
    echo "[WSR] ERROR: backup destination is on the same device as the WAIO repo ($src_device) -- refusing (not a separate disk)" >&2
    wsr_audit_log "wsr_backup_aborted" "denied" "destination on same device as source: $src_device"
    return 1
  fi

  mkdir -p "$WSR_BACKUP_DEST" 2>/dev/null || {
    echo "[WSR] ERROR: could not create $WSR_BACKUP_DEST" >&2
    wsr_audit_log "wsr_backup_aborted" "denied" "could not create destination directory"
    return 1
  }

  local avail_kb source_kb required_kb
  avail_kb="$(df -Pk "$WSR_BACKUP_DEST" 2>/dev/null | awk 'NR==2{print $4}')"
  source_kb="$(wsr_enumerate_source_files | xargs -I{} du -k {} 2>/dev/null | awk '{s+=$1} END{print s+0}')"
  [ -n "$source_kb" ] || source_kb=0
  required_kb=$(( source_kb * WSR_BACKUP_MIN_FREE_MULTIPLIER ))
  [ "$required_kb" -ge 1024 ] || required_kb=1024
  if [ -z "$avail_kb" ] || [ "$avail_kb" -lt "$required_kb" ]; then
    echo "[WSR] ERROR: insufficient free space at $WSR_BACKUP_DEST (available=${avail_kb:-0}KB, required=${required_kb}KB)" >&2
    wsr_audit_log "wsr_backup_aborted" "denied" "insufficient free space: available=${avail_kb:-0}KB required=${required_kb}KB"
    return 1
  fi

  return 0
}

# wsr_copy_sources SNAPSHOT_DIR EXCLUDED_FILE -- reads absolute source
# paths from stdin (one per line, as wsr_enumerate_source_files
# prints), runs each through secret_leak_check() first, and copies
# (cp -p, preserving mtimes) everything that passes into SNAPSHOT_DIR
# under its path relative to the repo root. A file that fails
# secret_leak_check() is appended to EXCLUDED_FILE (path only) instead
# of copied; the run continues.
wsr_copy_sources() {
  local snapshot_dir="$1" excluded_file="$2"
  local f rel content

  while IFS= read -r f; do
    [ -n "$f" ] && [ -f "$f" ] || continue
    rel="${f#"$WSR_SOURCE_ROOT"/}"
    content="$(cat "$f" 2>/dev/null)"
    if ! secret_leak_check "$content" "n/a" "wsr_backup" "$rel" "n/a"; then
      echo "$rel" >> "$excluded_file"
      wsr_audit_log "wsr_backup_file_excluded" "excluded" "secret_leak_check flagged this file's content: $rel"
      continue
    fi
    mkdir -p "$snapshot_dir/$(dirname "$rel")"
    cp -p "$f" "$snapshot_dir/$rel"
  done
}

# wsr_write_manifest SNAPSHOT_DIR EXCLUDED_FILE -- walks SNAPSHOT_DIR
# (the files wsr_copy_sources actually wrote, not the original source
# list -- re-deriving from the filesystem is more robust than trusting
# an intermediate list) and writes MANIFEST.json (machine-readable:
# path/size_bytes/mtime/sha256 per file, plus excluded_files -- paths
# only, never content) and MANIFEST.txt (human-readable, same
# "created_at/host/purpose/files" shape as backups/A-800-node-prep-*/
# MANIFEST.txt).
wsr_write_manifest() {
  local snapshot_dir="$1" excluded_file="$2"
  python3 -c "
import hashlib, json, os, sys, socket, datetime

snapshot_dir, excluded_file = sys.argv[1], sys.argv[2]

excluded = []
if os.path.isfile(excluded_file):
    with open(excluded_file) as f:
        excluded = [line.strip() for line in f if line.strip()]

files = []
total_bytes = 0
for root, dirs, names in os.walk(snapshot_dir):
    for name in sorted(names):
        if name in ('MANIFEST.json', 'MANIFEST.txt'):
            continue
        p = os.path.join(root, name)
        rel = os.path.relpath(p, snapshot_dir)
        st = os.stat(p)
        with open(p, 'rb') as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        files.append({
            'path': rel,
            'size_bytes': st.st_size,
            'mtime': datetime.datetime.utcfromtimestamp(st.st_mtime).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'sha256': digest,
        })
        total_bytes += st.st_size

manifest = {
    'generated_at': datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
    'host': socket.gethostname(),
    'tool': 'security/wsr_backup.sh',
    'file_count': len(files),
    'total_bytes': total_bytes,
    'excluded_count': len(excluded),
    'excluded_files': excluded,
    'files': files,
}
with open(os.path.join(snapshot_dir, 'MANIFEST.json'), 'w') as f:
    json.dump(manifest, f, indent=2, ensure_ascii=False)

lines = []
lines.append('created_at: ' + manifest['generated_at'])
lines.append('host: ' + manifest['host'])
lines.append('purpose: WAIO Local Survival & Recovery (WSR) Phase A -- critical config/audit-history/recovery-metadata backup')
lines.append('file_count: ' + str(manifest['file_count']))
lines.append('total_bytes: ' + str(manifest['total_bytes']))
lines.append('excluded_count: ' + str(manifest['excluded_count']))
lines.append('files:')
for fe in files:
    lines.append('  - ' + fe['path'] + '  (' + str(fe['size_bytes']) + ' bytes, sha256=' + fe['sha256'][:16] + '...)')
if excluded:
    lines.append('excluded (secret_leak_check flagged -- content NOT backed up):')
    for e in excluded:
        lines.append('  - ' + e)
with open(os.path.join(snapshot_dir, 'MANIFEST.txt'), 'w') as f:
    f.write('\n'.join(lines) + '\n')
" "$snapshot_dir" "$excluded_file"
}

# wsr_verify_snapshot SNAPSHOT_DIR -- re-hashes every file
# MANIFEST.json lists and compares against the recorded SHA-256.
# Prints one MISSING/MISMATCH line per problem and returns non-zero if
# any are found; prints a one-line OK summary and returns 0 otherwise.
# Used both as this file's own post-write self-verification and as the
# standalone `verify` CLI subcommand.
wsr_verify_snapshot() {
  local snapshot_dir="$1"
  if [ ! -f "$snapshot_dir/MANIFEST.json" ]; then
    echo "[WSR] ERROR: no MANIFEST.json in $snapshot_dir" >&2
    return 1
  fi
  python3 -c "
import hashlib, json, os, sys

snapshot_dir = sys.argv[1]
manifest = json.load(open(os.path.join(snapshot_dir, 'MANIFEST.json')))
missing = []
mismatches = []
for fe in manifest['files']:
    p = os.path.join(snapshot_dir, fe['path'])
    if not os.path.isfile(p):
        missing.append(fe['path'])
        continue
    with open(p, 'rb') as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    if digest != fe['sha256']:
        mismatches.append(fe['path'])

for m in missing:
    print('MISSING: ' + m)
for m in mismatches:
    print('MISMATCH: ' + m)
if missing or mismatches:
    sys.exit(1)
print('OK: ' + str(len(manifest['files'])) + ' files verified')
" "$snapshot_dir"
}

# wsr_list_snapshot_dirs -- every WAIO-WSR-* snapshot directory under
# WSR_BACKUP_DEST, newest first, excluding any still-in-progress
# "*.partial" directory.
wsr_list_snapshot_dirs() {
  find "$WSR_BACKUP_DEST" -maxdepth 1 -mindepth 1 -type d -name 'WAIO-WSR-*' ! -name '*.partial' 2>/dev/null | sort -r
}

# wsr_prune_old_snapshots -- deletes snapshots beyond
# WSR_BACKUP_RETAIN_COUNT (default 7, hard floor 1 -- a misconfigured
# 0 or negative value is coerced up to 1, never down to zero). Verifies
# the newest snapshot first and aborts all pruning if it fails (never
# deletes anything on the strength of an unverified "newest"); each
# older candidate is independently re-verified immediately before its
# own deletion, and anything that fails verification is left in place
# for a human to inspect rather than destroyed. The newest snapshot is
# never a deletion candidate, by construction (the loop only considers
# indices at or beyond the retain count).
wsr_prune_old_snapshots() {
  local retain="$WSR_BACKUP_RETAIN_COUNT"
  case "$retain" in
    ''|*[!0-9]*) retain=7 ;;
  esac
  [ "$retain" -ge 1 ] || retain=1

  local -a snapshots=()
  while IFS= read -r d; do
    [ -n "$d" ] && snapshots+=("$d")
  done < <(wsr_list_snapshot_dirs)

  local count="${#snapshots[@]}"
  [ "$count" -gt "$retain" ] || return 0

  local newest="${snapshots[0]}"
  if ! wsr_verify_snapshot "$newest" >/dev/null 2>&1; then
    echo "[WSR] WARNING: newest snapshot ($newest) failed verification -- skipping pruning this run" >&2
    wsr_audit_log "wsr_backup_prune_skipped" "warning" "newest snapshot failed verification: $(basename "$newest")"
    return 1
  fi

  local i victim
  for ((i = retain; i < count; i++)); do
    victim="${snapshots[$i]}"
    if wsr_verify_snapshot "$victim" >/dev/null 2>&1; then
      rm -rf "$victim"
      wsr_audit_log "wsr_backup_pruned" "ok" "removed old snapshot: $(basename "$victim")"
    else
      echo "[WSR] WARNING: not pruning $victim -- it fails verification (kept for inspection)" >&2
      wsr_audit_log "wsr_backup_prune_skipped" "warning" "snapshot fails verification, kept: $(basename "$victim")"
    fi
  done
}

# wsr_backup_create -- the one top-level entry point security/
# wsr_backup_cron.sh and tests/wsr_backup_test.sh call. Checks the
# destination, copies everything that passes secret_leak_check() into
# a fresh "<name>.partial" directory, writes its manifest, self-
# verifies, and only then renames it to its final name and prunes old
# snapshots. A failure at any step discards only this run's own
# partial directory -- no prior snapshot is ever touched.
wsr_backup_create() {
  wsr_check_destination || return 1

  local ts snapshot_name snapshot_dir partial_dir
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  snapshot_name="WAIO-WSR-$ts"
  snapshot_dir="$WSR_BACKUP_DEST/$snapshot_name"
  partial_dir="$snapshot_dir.partial"

  if [ -e "$snapshot_dir" ] || [ -e "$partial_dir" ]; then
    echo "[WSR] ERROR: snapshot path already exists: $snapshot_name" >&2
    wsr_audit_log "wsr_backup_aborted" "denied" "snapshot path collision: $snapshot_name"
    return 1
  fi

  mkdir -p "$partial_dir" || return 1

  local excluded_file verify_out
  excluded_file="$(mktemp)"
  verify_out="$(mktemp)"

  wsr_enumerate_source_files | wsr_copy_sources "$partial_dir" "$excluded_file"
  wsr_write_manifest "$partial_dir" "$excluded_file"

  if ! wsr_verify_snapshot "$partial_dir" > "$verify_out" 2>&1; then
    echo "[WSR] ERROR: newly-created backup failed self-verification -- discarding this run, prior snapshots untouched" >&2
    cat "$verify_out" >&2
    rm -f "$excluded_file" "$verify_out"
    rm -rf "$partial_dir"
    wsr_audit_log "wsr_backup_failed" "failed" "self-verification failed, snapshot discarded: $snapshot_name"
    return 1
  fi
  rm -f "$verify_out"

  mv "$partial_dir" "$snapshot_dir"

  local file_count excluded_count total_bytes
  file_count="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['file_count'])" "$snapshot_dir/MANIFEST.json")"
  excluded_count="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['excluded_count'])" "$snapshot_dir/MANIFEST.json")"
  total_bytes="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['total_bytes'])" "$snapshot_dir/MANIFEST.json")"

  echo "[WSR] Backup created: $snapshot_dir (files=$file_count, excluded=$excluded_count, bytes=$total_bytes)"
  wsr_audit_log "wsr_backup_created" "ok" "$snapshot_name files=$file_count excluded=$excluded_count bytes=$total_bytes"

  rm -f "$excluded_file"

  wsr_prune_old_snapshots
  return 0
}

# wsr_cmd_verify [SNAPSHOT_NAME_OR_PATH] -- defaults to the newest
# snapshot when no argument is given.
wsr_cmd_verify() {
  local target="${1:-}"
  if [ -z "$target" ]; then
    target="$(wsr_list_snapshot_dirs | head -1)"
    if [ -z "$target" ]; then
      echo "[WSR] No snapshots found in $WSR_BACKUP_DEST" >&2
      return 1
    fi
  elif [ ! -d "$target" ]; then
    target="$WSR_BACKUP_DEST/$target"
  fi
  wsr_verify_snapshot "$target"
}

# wsr_cmd_list -- one summary line per snapshot, newest first.
# Read-only.
wsr_cmd_list() {
  local d
  wsr_list_snapshot_dirs | while IFS= read -r d; do
    if [ -f "$d/MANIFEST.json" ]; then
      python3 -c "
import json, sys
m = json.load(open(sys.argv[1]))
print(sys.argv[2] + ': files=' + str(m['file_count']) + ' bytes=' + str(m['total_bytes']) + ' excluded=' + str(m['excluded_count']) + ' generated_at=' + m['generated_at'])
" "$d/MANIFEST.json" "$(basename "$d")"
    else
      echo "$(basename "$d"): (no MANIFEST.json -- incomplete/corrupt)"
    fi
  done
}

# Only run the CLI dispatch when executed directly -- every sourcing
# caller (security/wsr_backup_cron.sh, tests/wsr_backup_test.sh) only
# ever wants this file's functions, same guard security/continuity.sh
# already uses for the identical reason.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  case "${1:-}" in
    backup)
      wsr_backup_create
      ;;
    verify)
      wsr_cmd_verify "${2:-}"
      ;;
    list)
      wsr_cmd_list
      ;;
    *)
      echo "Usage: $0 {backup|verify [snapshot]|list}" >&2
      exit 1
      ;;
  esac
fi
