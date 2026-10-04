#!/bin/bash
set -uo pipefail

# security/ssh_exposure/adapters/firewall_unknown.sh -- fallback adapter
# for any OS that is neither Darwin nor Linux (see
# ssh_exposure_monitor.sh's own `uname -s` dispatch). Deliberately
# reports everything as unknown/none rather than guessing at a tool that
# may not exist on this platform -- same "fail to unknown, never
# fabricate a positive finding" posture as every other adapter in this
# directory. Still attempts a best-effort, read-only interface-address
# listing via whichever of `ip`/`ifconfig` happens to be present, since
# that part of the contract is reasonably portable.

echo "PLATFORM=unknown"
echo "FIREWALL_TOOL=none"
echo "FIREWALL_STATE=unknown"
echo "FIREWALL_DETAIL=no adapter for this platform"

if command -v ip >/dev/null 2>&1; then
  while IFS= read -r addr; do
    [ -n "$addr" ] && echo "IFACE_ADDR=$addr"
  done < <(ip -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
elif command -v ifconfig >/dev/null 2>&1; then
  while IFS= read -r addr; do
    [ -n "$addr" ] && echo "IFACE_ADDR=$addr"
  done < <(ifconfig 2>/dev/null | awk '/inet /{print $2} /inet6 /{print $2}')
fi
