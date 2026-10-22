#!/bin/bash
# Weekly log rotation for cloudflared-tunnel-launchd.log. launchd keeps
# the same file descriptor open for the life of the tunnel process, so
# simply renaming the file does not create a fresh one on its own --
# this script renames+gzips the old log, then uses `launchctl kickstart`
# to restart the tunnel job, which both reopens a fresh log file and
# forces cloudflared to reconnect (a brief, expected reconnect blip,
# scheduled off-hours by the companion plist).

set -euo pipefail

# Both overridable only for test isolation (WAIO_TUNNEL_LOG /
# WAIO_TUNNEL_LOG_MAX_BYTES) -- a real deployment never sets either
# and gets the same hardcoded path/threshold as before. Lets
# tests/launchd_scripts_test.sh exercise rotation against a throwaway
# fixture log (and a small threshold, so a test run doesn't need to
# generate a real 10MB file) without touching production behavior.
LOG="${WAIO_TUNNEL_LOG:-/Users/masa/WAIO/logs/cloudflared-tunnel-launchd.log}"
MAX_BYTES="${WAIO_TUNNEL_LOG_MAX_BYTES:-10485760}"  # 10MB

LOG_SIZE="$(stat -f%z "$LOG" 2>/dev/null || stat -c%s "$LOG" 2>/dev/null)"
if [ -f "$LOG" ] && [ -n "$LOG_SIZE" ] && [ "$LOG_SIZE" -gt "$MAX_BYTES" ]; then
  TS="$(date -u +%Y%m%dT%H%M%SZ)"
  mv "$LOG" "${LOG}.${TS}"
  gzip "${LOG}.${TS}"
  launchctl kickstart -k "gui/$(id -u)/com.waio.cloudflared-tunnel"
fi

# `|| true`: with no rotated .gz yet (every run until the log first
# exceeds MAX_BYTES), the unmatched glob makes ls exit non-zero, and
# pipefail turned that into this whole script exiting 1 -- launchd then
# showed com.waio.cloudflared-tunnel-rotate as failed on every weekly
# run even though there was simply nothing to prune.
{ ls -t "${LOG}".*.gz 2>/dev/null || true; } | tail -n +9 | xargs -r rm -f
