#!/bin/bash
# launchd wrapper for the WAIO-dedicated Cloudflare Tunnel
# (com.waio.cloudflared-tunnel).
#
# The token is passed via the $TUNNEL_TOKEN environment variable, NOT
# the --token command-line flag -- cloudflared's own --help documents
# --token as backed by $TUNNEL_TOKEN ("--token value ... [$TUNNEL_TOKEN]").
# A command-line argument is visible to any local process via
# `ps aux`/`ps -ef`; an environment variable set only for this
# process's own exec is not exposed the same way.
#
# Fails closed: if the Keychain item is missing, refuses to start
# rather than silently doing nothing. Never echoes $TUNNEL_TOKEN --
# do not add `set -x` to this script, which would print it to the log.
#
# `run-waio-tunnel.sh --check` validates the binary and the stored
# token's format, reports what is wrong (never the token itself) and
# exits without starting the tunnel -- for the operator to run by hand
# after storing a new token.

set -euo pipefail

CHECK_ONLY=false
if [ "${1:-}" = "--check" ]; then
  CHECK_ONLY=true
fi

KEYCHAIN_ACCOUNT="$(whoami)"

# Overridable only for test isolation (WAIO_TUNNEL_CLOUDFLARED_BIN) --
# a real deployment never sets it and always execs the real installed
# cloudflared binary. Lets tests/launchd_scripts_test.sh point this at
# a fixture script (to capture argv/env without ever running the real
# tunnel binary) without touching production behavior.
#
# Default is Cloudflare's own official release binary
# (github.com/cloudflare/cloudflared, Developer ID: Cloudflare Inc.
# 68WVV388M8) installed at /usr/local/bin. The previous default,
# /Users/masa/.npm-global/bin/cloudflared, disappeared when the npm
# global prefix moved to ~/.npm-global-v2, and launchd then respawned
# this job every ThrottleInterval with "No such file or directory".
CLOUDFLARED_BIN="${WAIO_TUNNEL_CLOUDFLARED_BIN:-/usr/local/bin/cloudflared}"

# Fails closed on a missing binary too, and checks it BEFORE touching
# the Keychain, so a broken install never reads the token at all.
# --check reads the token even without a binary: the operator asked for
# it, and both problems are worth reporting in one pass.
BIN_OK=true
if [ ! -x "$CLOUDFLARED_BIN" ]; then
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) [run-waio-tunnel.sh] ERROR: cloudflared binary not found or not executable at $CLOUDFLARED_BIN. Refusing to start." >&2
  if [ "$CHECK_ONLY" != true ]; then
    exit 1
  fi
  BIN_OK=false
fi

TUNNEL_TOKEN="$(security find-generic-password -a "$KEYCHAIN_ACCOUNT" -s "com.waio.tunnel-token" -w 2>/dev/null || true)"

if [ -z "$TUNNEL_TOKEN" ]; then
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) [run-waio-tunnel.sh] ERROR: WAIO tunnel token not found in Keychain (service: com.waio.tunnel-token, account: $KEYCHAIN_ACCOUNT). Refusing to start." >&2
  exit 1
fi

# cloudflared's "Provided Tunnel token is not valid." is a LOCAL parse
# failure, not a rejection by Cloudflare: it base64-decodes the token
# and expects JSON with the account tag ("a"), tunnel ID ("t") and
# tunnel secret ("s"). The same shape is checked here, so the log says
# which way the stored value is wrong instead of cloudflared exiting
# with a usage error on every respawn. Prints a reason, never the value;
# the token reaches base64 on stdin from the printf builtin, never argv.
token_format_problem() {
  local token="$1" decoded=""
  case "$token" in
    *[[:space:]]*)
      echo "it contains whitespace (was the whole 'cloudflared service install ...' command, or a quoted or multi-line value, stored?)"
      return 0 ;;
  esac
  if [[ "$token" != eyJ* ]]; then
    if [[ "$token" =~ ^[0-9a-f]+$ ]]; then
      echo "it is hex-encoded: 'security -w' prints an item as hex when it contains non-printable bytes, usually a trailing newline from the paste"
    else
      echo "it does not start with 'eyJ', so it is not a base64-encoded JSON tunnel token (a tunnel ID, API token or certificate is not the run token)"
    fi
    return 0
  fi
  decoded="$(printf '%s' "$token" | base64 -d 2>/dev/null)" || decoded=""
  if [ -z "$decoded" ]; then
    echo "it does not base64-decode (truncated or altered while copying?)"
    return 0
  fi
  if [[ ! "$decoded" =~ \"a\"[[:space:]]*: ]] || [[ ! "$decoded" =~ \"t\"[[:space:]]*: ]] || [[ ! "$decoded" =~ \"s\"[[:space:]]*: ]]; then
    echo "it decodes, but not to a tunnel token: the account tag, tunnel ID or secret field is missing (truncated?)"
    return 0
  fi
  return 0
}

TOKEN_PROBLEM="$(token_format_problem "$TUNNEL_TOKEN")"
if [ -n "$TOKEN_PROBLEM" ]; then
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) [run-waio-tunnel.sh] ERROR: WAIO tunnel token in Keychain (service: com.waio.tunnel-token, account: $KEYCHAIN_ACCOUNT) is malformed: $TOKEN_PROBLEM. Refusing to start." >&2
  exit 1
fi

if [ "$CHECK_ONLY" = true ]; then
  if [ "$BIN_OK" != true ]; then
    exit 1
  fi
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) [run-waio-tunnel.sh] OK: $CLOUDFLARED_BIN is executable and the Keychain token has the tunnel token's format. Not started (--check)."
  exit 0
fi

export TUNNEL_TOKEN
exec "$CLOUDFLARED_BIN" tunnel run
