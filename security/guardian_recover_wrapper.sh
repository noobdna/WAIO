#!/bin/bash
set -uo pipefail

# security/guardian_recover_wrapper.sh -- the sole command a Guardian SSH
# key (see ARCHITECTURE.md Phase 34/35) is permitted to run, via an
# authorized_keys "command=" forced-command restriction on the WAIO side.
#
# sshd re-parses the authorized_keys "command=" value itself as shell
# text, so the Guardian-supplied reason (whatever the remote client
# typed, exposed here as $SSH_ORIGINAL_COMMAND) must never be interpolated
# directly into that value -- doing so would let quotes/backticks/$()/;
# in the reason text break out and run arbitrary commands. Routing
# through this script avoids that: "command=" only ever names this fixed
# path, and here "${SSH_ORIGINAL_COMMAND}" is a single quoted parameter
# expansion passed as one argument, never re-parsed as shell syntax.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "$SCRIPT_DIR/security/recover.sh" --guardian-confirm \
  "${SSH_ORIGINAL_COMMAND:-guardian recovery request, no reason text supplied}"
