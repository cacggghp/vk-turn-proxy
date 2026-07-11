#!/bin/bash
set -euo pipefail

gateway="$(ip -o -4 route show to default | awk '/via/ {print $3}' | head -1)"
if [[ -z "${gateway}" ]]; then
  echo "Could not determine default gateway" >&2
  exit 1
fi

ip_cmd=(ip)
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  ip_cmd=(sudo ip)
fi

while IFS= read -r remote; do
  remote="${remote%$'\r'}"
  [[ -z "$remote" ]] && continue

  if [[ ! "$remote" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "Skipping unexpected input: $remote" >&2
    continue
  fi

  echo "Ensuring route to $remote via $gateway"
  "${ip_cmd[@]}" route replace "$remote" via "$gateway"
done
