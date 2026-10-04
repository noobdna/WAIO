#!/bin/bash
set -uo pipefail

# security/ssh_exposure/adapters/firewall_macos.sh -- macOS-specific,
# READ-ONLY probe for the SSH Exposure Monitor's "firewall state" and
# "this host's own interface addresses" signals. This is the ONLY place
# in the SSH Exposure Monitor that knows macOS-specific tool names
# (socketfilterfw, ifconfig) -- ssh_exposure_monitor.sh and
# ssh_exposure_lib.py are OS-agnostic, dispatching to this script (or
# its Linux/unknown-OS siblings) by `uname -s`, per the request's own
# "OS依存部分はadapterとして分離する" requirement.
#
# Safety (same constraints as every other file in this module -- see
# ssh_exposure_monitor.sh's own header): READ-ONLY queries only. No
# `sudo`, no firewall rule change, no network connection of any kind.
# `socketfilterfw --getglobalstate` is a plain state QUERY (not a
# mutation) and runs without elevated privileges on a standard macOS
# install; if it is unavailable or fails for any reason, this script
# reports FIREWALL_STATE=unknown rather than guessing or escalating.
#
# Output contract (parsed by ssh_exposure_lib.py's own
# parse_adapter_output() -- see that function's header): fixed
# KEY=VALUE lines on stdout, one PLATFORM/FIREWALL_TOOL/FIREWALL_STATE/
# FIREWALL_DETAIL line each, plus zero or more repeated IFACE_ADDR=
# lines (one per locally observed interface address, loopback/link-local
# included -- classification happens in ssh_exposure_lib.py, not here).

echo "PLATFORM=macos"

SOCKETFILTERFW="/usr/libexec/ApplicationFirewall/socketfilterfw"
if command -v "$SOCKETFILTERFW" >/dev/null 2>&1; then
  detail="$("$SOCKETFILTERFW" --getglobalstate 2>/dev/null)"
  echo "FIREWALL_TOOL=socketfilterfw"
  case "$detail" in
    *enabled*) echo "FIREWALL_STATE=enabled" ;;
    *disabled*) echo "FIREWALL_STATE=disabled" ;;
    *) echo "FIREWALL_STATE=unknown" ;;
  esac
  echo "FIREWALL_DETAIL=${detail:-unavailable}"
else
  echo "FIREWALL_TOOL=none"
  echo "FIREWALL_STATE=unknown"
  echo "FIREWALL_DETAIL=socketfilterfw not found"
fi

if command -v ifconfig >/dev/null 2>&1; then
  while IFS= read -r addr; do
    [ -n "$addr" ] && echo "IFACE_ADDR=$addr"
  done < <(ifconfig 2>/dev/null | awk '/inet /{print $2} /inet6 /{print $2}')
fi
