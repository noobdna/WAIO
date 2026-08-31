#!/bin/bash
set -uo pipefail

# security/generate_ssh_guardian_config.sh -- generates 750号機's
# /etc/ssh/sshd_config.d/50-waio-guardian.conf drop-in from
# security/ssh_management_allowlist.conf instead of hand-editing it.
#
# Post-incident background (2026-08-31): the previous drop-in was
# hand-written with a single `Match Address 192.168.1.91` exception to
# a global `PubkeyAuthentication no` default. Only 800号機 was ever
# added to that exception, so every other legitimate management client
# (iPad Pro, Raspberry Pi) lost SSH access the moment
# PasswordAuthentication/KbdInteractiveAuthentication were hardened to
# no alongside it -- a self-inflicted lockout, not an attack. This
# script exists so the Match Address list is generated from an
# allowlist (security/ssh_management_allowlist.conf, same pattern as
# security/egress_allowlist.conf) and checked for lockout risk before
# anything is written, instead of hand-edited and hoped correct.
#
# Modes (default: --check):
#   --check     Render the config from the allowlist into a local
#               staging file, run the lockout-detection and sshd syntax
#               checks, and report the result. Never touches
#               /etc/ssh/sshd_config.d. Safe to run anytime, no sudo.
#   --apply     Same checks as --check; on success, back up the
#               currently deployed drop-in (if any) and install the
#               staged config in its place, then re-verify with a real
#               `sshd -t` against the live config tree before leaving
#               it in place -- reverting to the backup automatically if
#               that fails. Requires sudo.
#   --rollback  Restore the most recent backup over the currently
#               deployed drop-in. Requires sudo.
#
# Fail-closed on generation: a missing or empty allowlist refuses to
# generate anything (matches egress_allowlist.conf's fail-closed
# posture) -- it never produces an empty Match Address (which would
# lock out every management client) and never falls back to a wide-open
# config either. See check_lockout() below for the "management lockout
# detected" gate required on top of that.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
source security/lib.sh

# DEFAULT_DEPLOYED_CONFIG is the real system path. Every other path
# below can be overridden by env var so the test suite can point the
# whole pipeline at scratch fixtures and never touch /etc/ssh or this
# deployment's real allowlist -- see tests/ssh_guardian_config_test.sh.
DEFAULT_DEPLOYED_CONFIG="/etc/ssh/sshd_config.d/50-waio-guardian.conf"
ALLOWLIST="${SSH_GUARDIAN_ALLOWLIST:-$SECURITY_LIB_DIR/ssh_management_allowlist.conf}"
DEPLOYED_CONFIG="${SSH_GUARDIAN_DEPLOYED_CONFIG:-$DEFAULT_DEPLOYED_CONFIG}"
STAGE_DIR="${SSH_GUARDIAN_STATE_DIR:-$SECURITY_LIB_DIR/state}"
STAGED_CONFIG="$STAGE_DIR/50-waio-guardian.conf.staged"
BACKUP_DIR="${SSH_GUARDIAN_BACKUP_DIR:-$SCRIPT_DIR/backups/ssh_guardian}"
RUN_ID="ssh-guardian-$(date -u +%Y%m%dT%H%M%SZ)"

mkdir -p "$STAGE_DIR" "$BACKUP_DIR" 2>/dev/null || true

MODE="${1:---check}"

# privileged_cp SRC DST -- plain `cp` when DST's directory is
# user-writable (test fixtures, e.g. under /tmp), `sudo cp` only when
# it isn't (the real /etc/ssh/sshd_config.d, root:wheel). Lets the same
# backup/apply/rollback code path run against fixtures with no sudo
# prompt in tests, while still using sudo for the one real target.
privileged_cp() {
  local src="$1" dst="$2"
  if [ -w "$(dirname "$dst")" ] && { [ ! -e "$dst" ] || [ -w "$dst" ]; }; then
    cp "$src" "$dst"
  else
    sudo cp "$src" "$dst"
  fi
}

# post_install_check -- the real deployment target gets a real,
# live-tree `sudo sshd -t` (the strongest available proof the whole
# installed config tree, not just this drop-in, still parses). Any
# overridden/fixture target reuses sshd_syntax_check's ephemeral-hostkey
# `sshd -T -f` probe instead, since there is no real live tree to check
# and no sudo available/desired for a fixture path.
post_install_check() {
  if [ "$DEPLOYED_CONFIG" = "$DEFAULT_DEPLOYED_CONFIG" ]; then
    sudo /usr/sbin/sshd -t
  else
    sshd_syntax_check
  fi
}

# --- load_allowlist: populate ALLOWLIST_IPS/ALLOWLIST_LABELS, or fail
# closed. Every non-comment/non-blank line must be IP|LABEL with both
# fields non-empty. ------------------------------------------------
ALLOWLIST_IPS=()
ALLOWLIST_LABELS=()

load_allowlist() {
  if [ ! -f "$ALLOWLIST" ]; then
    echo "[SSH-GUARDIAN] ERROR: management allowlist missing: $ALLOWLIST" >&2
    echo "[SSH-GUARDIAN] Refusing to generate any config (fail closed on generation -- see README.md Setup)." >&2
    audit_log "ssh_guardian_generate_denied" "$RUN_ID" "generate" "ssh_guardian" "n/a" "denied" "allowlist missing: $ALLOWLIST"
    return 1
  fi

  local ip label
  while IFS='|' read -r ip label; do
    case "$ip" in ""|\#*) continue ;; esac
    if [ -z "$ip" ] || [ -z "${label:-}" ]; then
      echo "[SSH-GUARDIAN] ERROR: malformed allowlist line (need IP|LABEL): '$ip|${label:-}'" >&2
      audit_log "ssh_guardian_generate_denied" "$RUN_ID" "generate" "ssh_guardian" "n/a" "denied" "malformed allowlist line"
      return 1
    fi
    ALLOWLIST_IPS+=("$ip")
    ALLOWLIST_LABELS+=("$label")
  done < "$ALLOWLIST"

  if [ "${#ALLOWLIST_IPS[@]}" -eq 0 ]; then
    echo "[SSH-GUARDIAN] ERROR: management allowlist is empty: $ALLOWLIST" >&2
    echo "[SSH-GUARDIAN] Refusing to generate a config with no management client (would lock out every admin)." >&2
    audit_log "ssh_guardian_generate_denied" "$RUN_ID" "generate" "ssh_guardian" "n/a" "denied" "allowlist empty"
    return 1
  fi
  return 0
}

# join ALLOWLIST_IPS with commas, for the Match Address line
join_ips() {
  local IFS=,
  echo "${ALLOWLIST_IPS[*]}"
}

# --- render_config: write the drop-in to STAGED_CONFIG. ------------
render_config() {
  local match_ips
  match_ips="$(join_ips)"
  cat > "$STAGED_CONFIG" <<EOF
# Generated by security/generate_ssh_guardian_config.sh -- DO NOT EDIT
# BY HAND. Source of truth: security/ssh_management_allowlist.conf
# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication no

Match Address $match_ips
    PubkeyAuthentication yes
EOF
}

# extract_match_addresses FILE -- prints the comma-separated address
# list of FILE's `Match Address` line (one line, space-joined), or
# nothing if FILE doesn't exist or has no such line.
extract_match_addresses() {
  local file="$1"
  [ -f "$file" ] || return 0
  local line
  line="$(grep -E '^[[:space:]]*Match[[:space:]]+Address[[:space:]]+' "$file" | head -1)"
  [ -n "$line" ] || return 0
  echo "$line" | sed -E 's/^[[:space:]]*Match[[:space:]]+Address[[:space:]]+//' | tr ',' ' '
}

# --- check_lockout: refuse (exit 2, no apply) if the newly generated
# config would drop any address that (a) is in the allowlist itself
# (self-consistency -- catches the generator silently dropping an
# entry, the exact class of bug that caused the incident) or (b) is
# currently live in the deployed drop-in (regression -- catches an
# allowlist edit that accidentally removes a currently-working client).
# This is "management lockout detected", not fail-closed: on lockout,
# nothing is written to /etc/ssh at all -- the previously deployed
# config (however open or closed) is left exactly as it was. ---------
check_lockout() {
  local generated_ips missing=()
  generated_ips=" $(extract_match_addresses "$STAGED_CONFIG") "

  local i ip label
  for i in "${!ALLOWLIST_IPS[@]}"; do
    ip="${ALLOWLIST_IPS[$i]}"; label="${ALLOWLIST_LABELS[$i]}"
    case "$generated_ips" in
      *" $ip "*) ;;
      *) missing+=("$ip ($label) [allowlist entry missing from generated config]") ;;
    esac
  done

  if [ -f "$DEPLOYED_CONFIG" ]; then
    local live_ips live_ip
    live_ips="$(extract_match_addresses "$DEPLOYED_CONFIG")"
    for live_ip in $live_ips; do
      case "$generated_ips" in
        *" $live_ip "*) ;;
        *) missing+=("$live_ip [currently live in deployed config, absent from new config]") ;;
      esac
    done
  fi

  if [ "${#missing[@]}" -gt 0 ]; then
    echo "[SSH-GUARDIAN] management lockout detected -- refusing to proceed. Missing management path(s):" >&2
    local m
    for m in "${missing[@]}"; do echo "  - $m" >&2; done
    echo "[SSH-GUARDIAN] No file was written to /etc/ssh. Fix security/ssh_management_allowlist.conf and re-run." >&2
    audit_log "ssh_guardian_lockout_detected" "$RUN_ID" "generate" "ssh_guardian" "$(join_ips)" "denied" "management lockout detected: ${missing[*]}"
    return 2
  fi
  return 0
}

# --- sshd_syntax_check: validate STAGED_CONFIG with the real sshd
# binary using a throwaway, ephemeral host key -- never touches or
# reads any real host key, never requires sudo. Proves the generated
# file is actually valid sshd_config syntax on this machine's installed
# OpenSSH, not just "looks right". --------------------------------
sshd_syntax_check() {
  local tmpkey
  # Explicit XXXXXX template (not `mktemp -t prefix`): GNU mktemp
  # (Linux) and BSD/macOS mktemp disagree on `-t` with no XXXXXX in
  # the template -- this form is the one both implementations handle
  # identically.
  tmpkey="$(mktemp "${TMPDIR:-/tmp}/waio-guardian-hostkey.XXXXXX")"
  rm -f "$tmpkey"
  if ! ssh-keygen -q -t ed25519 -N "" -f "$tmpkey" >/dev/null 2>&1; then
    echo "[SSH-GUARDIAN] ERROR: could not generate throwaway host key for syntax check" >&2
    return 1
  fi

  local probe_config
  probe_config="$(mktemp "${TMPDIR:-/tmp}/waio-guardian-probe.XXXXXX")"
  {
    echo "Port 22"
    echo "HostKey $tmpkey"
    cat "$STAGED_CONFIG"
  } > "$probe_config"

  local out rc
  out="$(/usr/sbin/sshd -T -f "$probe_config" 2>&1)"
  rc=$?
  rm -f "$tmpkey" "$tmpkey.pub" "$probe_config"

  if [ "$rc" -ne 0 ]; then
    echo "[SSH-GUARDIAN] ERROR: generated config failed sshd syntax check:" >&2
    echo "$out" | sed 's/^/  /' >&2
    return 1
  fi
  return 0
}

# --- backup_existing: copy the currently deployed drop-in into
# BACKUP_DIR with a timestamp, if one exists. Requires sudo to read
# /etc/ssh (root-owned). ---------------------------------------------
backup_existing() {
  [ -f "$DEPLOYED_CONFIG" ] || { echo "[SSH-GUARDIAN] No existing deployed config to back up."; return 0; }
  local backup_path="$BACKUP_DIR/50-waio-guardian.conf.$(date -u +%Y%m%dT%H%M%SZ).bak"
  if ! privileged_cp "$DEPLOYED_CONFIG" "$backup_path"; then
    echo "[SSH-GUARDIAN] ERROR: backup of $DEPLOYED_CONFIG failed -- aborting apply." >&2
    return 1
  fi
  echo "[SSH-GUARDIAN] Backed up $DEPLOYED_CONFIG -> $backup_path"
  echo "$backup_path"
}

latest_backup() {
  ls -1t "$BACKUP_DIR"/50-waio-guardian.conf.*.bak 2>/dev/null | head -1
}

# --- apply_config: check -> backup -> install -> re-verify with a
# real `sshd -t`, reverting automatically on failure. Requires sudo,
# never invoked by --check. -------------------------------------------
apply_config() {
  load_allowlist || return 1
  render_config
  check_lockout || return 2
  sshd_syntax_check || return 1

  local backup_path
  backup_path="$(backup_existing)" || return 1

  if ! privileged_cp "$STAGED_CONFIG" "$DEPLOYED_CONFIG"; then
    echo "[SSH-GUARDIAN] ERROR: failed to install $DEPLOYED_CONFIG" >&2
    return 1
  fi

  if ! post_install_check; then
    echo "[SSH-GUARDIAN] ERROR: post-install syntax check failed -- reverting." >&2
    if [ -n "$backup_path" ] && [ -f "$backup_path" ]; then
      privileged_cp "$backup_path" "$DEPLOYED_CONFIG"
    else
      rm -f "$DEPLOYED_CONFIG" 2>/dev/null || sudo rm -f "$DEPLOYED_CONFIG"
    fi
    audit_log "ssh_guardian_apply_failed" "$RUN_ID" "apply" "ssh_guardian" "$(join_ips)" "denied" "sshd -t failed post-install, reverted"
    return 1
  fi

  audit_log "ssh_guardian_applied" "$RUN_ID" "apply" "ssh_guardian" "$(join_ips)" "applied" "installed to $DEPLOYED_CONFIG, backup at $backup_path"
  echo "[SSH-GUARDIAN] Applied. Reload sshd for it to take effect, e.g.:"
  echo "  sudo launchctl kickstart -k system/com.openssh.sshd"
  echo "[SSH-GUARDIAN] Rollback available: $0 --rollback"
  return 0
}

rollback() {
  local backup_path
  backup_path="$(latest_backup)"
  if [ -z "$backup_path" ]; then
    echo "[SSH-GUARDIAN] ERROR: no backup found in $BACKUP_DIR" >&2
    return 1
  fi
  echo "[SSH-GUARDIAN] Restoring $backup_path -> $DEPLOYED_CONFIG"
  if ! privileged_cp "$backup_path" "$DEPLOYED_CONFIG"; then
    echo "[SSH-GUARDIAN] ERROR: rollback copy failed" >&2
    return 1
  fi
  if [ "$DEPLOYED_CONFIG" = "$DEFAULT_DEPLOYED_CONFIG" ] && ! sudo /usr/sbin/sshd -t; then
    echo "[SSH-GUARDIAN] ERROR: sshd -t failed after rollback -- manual intervention required." >&2
    return 1
  fi
  audit_log "ssh_guardian_rolled_back" "$RUN_ID" "rollback" "ssh_guardian" "n/a" "applied" "restored $backup_path"
  echo "[SSH-GUARDIAN] Rolled back. Reload sshd for it to take effect, e.g.:"
  echo "  sudo launchctl kickstart -k system/com.openssh.sshd"
  return 0
}

check_only() {
  load_allowlist || return 1
  render_config
  check_lockout || return 2
  sshd_syntax_check || return 1
  audit_log "ssh_guardian_check_ok" "$RUN_ID" "generate" "ssh_guardian" "$(join_ips)" "ok" "staged config passed lockout and syntax checks"
  echo "[SSH-GUARDIAN] OK: staged config at $STAGED_CONFIG passed lockout and sshd syntax checks."
  echo "[SSH-GUARDIAN] Not applied (dry run). Run with --apply (requires sudo) to deploy."
  return 0
}

# Only run the CLI dispatch when executed directly. tests/ can
# `source` this file (after exporting the SSH_GUARDIAN_* overrides
# above) to unit-test load_allowlist/render_config/check_lockout/
# sshd_syntax_check/backup_existing/rollback individually, against
# fixtures, without ever invoking this dispatch.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  case "$MODE" in
    --check) check_only ;;
    --apply) apply_config ;;
    --rollback) rollback ;;
    *)
      echo "Usage: $0 [--check|--apply|--rollback]" >&2
      exit 1
      ;;
  esac
fi
