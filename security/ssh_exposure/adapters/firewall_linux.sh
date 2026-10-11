#!/bin/bash
set -uo pipefail

# security/ssh_exposure/adapters/firewall_linux.sh -- Linux-specific,
# READ-ONLY probe for the SSH Exposure Monitor's "firewall state" and
# "this host's own interface addresses" signals. Sibling of
# firewall_macos.sh -- see that file's own header for the shared output
# contract and safety constraints (READ-ONLY, no sudo, no network
# connection, no rule change). This script tries each known firewall
# frontend in order and reports whichever responds first; if a tool
# exists but refuses to answer without root (common for `ufw status` /
# raw `iptables`/`nft` listing on an unprivileged account), that is
# reported as FIREWALL_STATE=unknown with an explanatory detail --
# WAIO never escalates privileges to get a better answer.

echo "PLATFORM=linux"

tool="none"
state="unknown"
detail="no supported firewall tool found"

if command -v ufw >/dev/null 2>&1; then
  tool="ufw"
  out="$(ufw status 2>&1)"
  case "$out" in
    *"Status: active"*) state="enabled" ;;
    *"Status: inactive"*) state="disabled" ;;
    *ERROR*|*root*|*permission*|*Permission*)
      state="unknown"
      out="$out (requires elevated privileges to query; WAIO does not escalate)"
      ;;
    *) state="unknown" ;;
  esac
  detail="$out"
elif command -v firewall-cmd >/dev/null 2>&1; then
  tool="firewalld"
  out="$(firewall-cmd --state 2>&1)"
  if [ "$out" = "running" ]; then
    state="enabled"
  elif [ "$out" = "not running" ]; then
    state="disabled"
  else
    state="unknown"
  fi
  detail="$out"
elif command -v nft >/dev/null 2>&1 || command -v iptables >/dev/null 2>&1; then
  tool="iptables/nft"
  state="unknown"
  detail="listing packet-filter rules requires root; WAIO does not escalate privileges"
fi

echo "FIREWALL_TOOL=$tool"
echo "FIREWALL_STATE=$state"
echo "FIREWALL_DETAIL=${detail:-unavailable}"

if command -v ip >/dev/null 2>&1; then
  while IFS= read -r addr; do
    [ -n "$addr" ] && echo "IFACE_ADDR=$addr"
  done < <(ip -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
elif command -v ifconfig >/dev/null 2>&1; then
  while IFS= read -r addr; do
    [ -n "$addr" ] && echo "IFACE_ADDR=$addr"
  done < <(ifconfig 2>/dev/null | awk '/inet /{print $2} /inet6 /{print $2}')
fi
