#!/bin/bash
set -uo pipefail

REQUEST="${1:-}"

if [ -z "$REQUEST" ]; then
  echo "[RPI DISPATCH] ERROR: empty request"
  exit 1
fi

# DLP / Emergency Shutdown layer: last check before the real SSH call.
source security/lib.sh
if ! egress_check "192.168.1.150" "22" "" "" "RPI"; then
  echo "[RPI DISPATCH] ERROR: egress denied by DLP guard, emergency shutdown triggered -- SSH not attempted"
  exit 1
fi
# payload_size_check (security audit finding, 2026-09-17): REQUEST is
# free-form text (a hand-typed request, or an earlier ORCHESTRATE
# stage's own output forwarded verbatim -- see the command-injection
# note below), unlike host800_worker.sh/jobs/*.sh's fixed, whitelisted
# remote commands, so it is the one SSH-based path where an
# attacker-influenced payload can actually grow unbounded. Every
# HTTP-based worker (ai/analysis/research_worker.sh) already runs this
# same check before sending; this SSH-based one never did until now.
if ! payload_size_check "$REQUEST" "" "" "RPI" "192.168.1.150:22"; then
  echo "[RPI DISPATCH] ERROR: payload size anomaly detected by DLP guard, emergency shutdown triggered -- request not sent"
  exit 1
fi

# Command-injection fix (Red Team finding #1, 2026-09-13): $REQUEST
# previously reached the remote shell via
# `ssh host "~/WAIO-worker/remote_worker.sh \"$REQUEST\""` -- one extra
# layer of shell parsing on the far end that a `"`, backtick, `$()`, or
# `;` in REQUEST could break out of, running arbitrary commands on the
# Pi. This was reachable indirectly, not only from a hand-typed
# request: an ORCHESTRATE pipeline forwards an earlier stage's own
# output (e.g. a RESEARCH-agent response shaped by external content it
# summarized) into a later stage's input verbatim (see
# workers/orchestrate_worker.sh's STAGE_INPUT construction) -- a
# pipeline with RPI downstream of RESEARCH/ANALYSIS/AI turned an
# indirect prompt injection into remote code execution on the Pi.
# remote_worker.sh (deployed separately on the Pi, outside this repo --
# not something this fix can change) still expects the request as a
# single $1 argument, so the fix quotes REQUEST correctly for that one
# remaining, unavoidable layer of remote shell parsing
# (security/lib.sh's shell_quote) instead of changing the calling
# convention. See tests/rpi_command_injection_test.sh for the
# attack-simulation regression tests (a faked `ssh` on PATH faithfully
# replays what a real remote shell would do with the constructed
# command line, entirely locally -- no network call).
echo "[RPI DISPATCH] sending to Raspberry Pi..."
RESPONSE="$(ssh -o BatchMode=yes masa@192.168.1.150 "~/WAIO-worker/remote_worker.sh $(shell_quote "$REQUEST")")"
RC=$?

# secret_leak_check (security audit finding, 2026-09-17): the Pi's own
# response was previously streamed straight to stdout, unscanned --
# every HTTP-based worker already scans its response before printing
# it; this SSH-based path never did until now.
if ! secret_leak_check "$RESPONSE" "" "" "RPI" "192.168.1.150:22"; then
  echo "[RPI DISPATCH] ERROR: potential credential leak detected by DLP guard in response, emergency shutdown triggered -- response withheld"
  exit 1
fi

echo "$RESPONSE"
exit "$RC"
