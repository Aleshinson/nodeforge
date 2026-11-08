#!/bin/bash
# Сводка сервера для хаба: строки «ключ=значение». Только чтение, ничего не меняет.
# $1 — nodeforge (setup) той же версии, что и сценарий: все проверки берём у него.
set -uo pipefail
# shellcheck source=/dev/null
source "$1"

kv() { printf '%s=%s\n' "$1" "$2"; }

rel="$(uname -r)"
kv kernel "$rel"
kv cve98432 "$(_cve_kernel_state "$rel")"
if _cve_fix_pending; then kv cve98432_pending "$(_cve_newest_kernel)"; fi
if _cve_filter_up; then kv cve98432_shield on; fi
kv uptime "$(uptime -p | sed 's/^up //')"
kv disk "$(df -P / | awk 'NR == 2 { print $5 }')"
kv mem_free_mb "$(free -m | awk 'NR == 2 { print $7 }')"
if [ -f /var/run/reboot-required ]; then kv reboot needed; fi

if command -v docker >/dev/null 2>&1 && require_node >/dev/null 2>&1; then
  ref="$(_compose_service_key "${NODE_DIR}/docker-compose.yml" "$NODE_SERVICE" image)"
  ref="${ref%%@*}"
  repo="$ref"
  case "${ref##*/}" in *:*) repo="${ref%:*}" ;; esac
  kv remnanode "$(docker inspect -f '{{.State.Status}}' "$NODE_CONTAINER" 2>/dev/null || echo absent)"
  kv remnanode_version "$(_node_running_version "$(_node_hub_tags "$repo")" || true)"
fi
