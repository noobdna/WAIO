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

set -euo pipefail

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
if [ ! -x "$CLOUDFLARED_BIN" ]; then
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) [run-waio-tunnel.sh] ERROR: cloudflared binary not found or not executable at $CLOUDFLARED_BIN. Refusing to start." >&2
  exit 1
fi

TUNNEL_TOKEN="$(security find-generic-password -a "$KEYCHAIN_ACCOUNT" -s "com.waio.tunnel-token" -w 2>/dev/null || true)"

if [ -z "$TUNNEL_TOKEN" ]; then
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) [run-waio-tunnel.sh] ERROR: WAIO tunnel token not found in Keychain (service: com.waio.tunnel-token, account: $KEYCHAIN_ACCOUNT). Refusing to start." >&2
  exit 1
fi

export TUNNEL_TOKEN
exec "$CLOUDFLARED_BIN" tunnel run
