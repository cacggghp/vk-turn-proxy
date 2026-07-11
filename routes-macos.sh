#!/bin/zsh
set -u

default_info="$(route -n get default 2>/dev/null || true)"
default_if="$(printf '%s\n' "$default_info" | awk '/interface:/{print $2; exit}')"
gateway="$(printf '%s\n' "$default_info" | awk '/gateway:/{print $2; exit}')"

if [[ -n "${default_if:-}" && "$default_if" == utun* ]]; then
  echo "Default route is currently $default_if. Disconnect WireGuard/VPN first." >&2
  exit 1
fi

if [[ -z "${gateway:-}" ]]; then
  echo "Could not determine normal default gateway." >&2
  exit 1
fi

while IFS= read -r line; do
  line="${line//$'\r'/}"

  # Try to extract:
  # - plain IPv4
  # - IPv4/CIDR
  # - relayed-address=IPv4:port  -> use only IPv4
  remote="$(printf '%s\n' "$line" | sed -nE '
    s/.*relayed-address=(([0-9]{1,3}\.){3}[0-9]{1,3}):[0-9]+.*/\1/p
    t done
    s/^(([0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2})$/\1/p
    t done
    s/^(([0-9]{1,3}\.){3}[0-9]{1,3})$/\1/p
    :done
  ')"

  [[ -z "$remote" ]] && continue

  if [[ "$remote" == */* ]]; then
    sudo route -n delete -net "$remote" >/dev/null 2>&1 || true
    sudo route -n add -net "$remote" "$gateway" || true
  else
    sudo route -n delete -host "$remote" >/dev/null 2>&1 || true
    sudo route -n add -host "$remote" "$gateway" || true
  fi
done
