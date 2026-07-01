#!/bin/sh
# clientguard-status.sh — status geral do ClientGuard (flows/clientes/sinais na janela) + top clientes por tráfego

. "$(dirname -- "$0")/lib.sh"

TOKEN=$(parse_param "token")

if ! check_session "$TOKEN"; then
  deny_unauthorized
  exit 0
fi

print_header 200
/root/clientguard/venv/bin/python3 <<'PYEOF'
import json
import sys

sys.path.insert(0, "/root/clientguard")

import yaml
import control

try:
    cfg = yaml.safe_load(open("/root/clientguard/config.yaml", encoding="utf-8"))
    sock_path = cfg["daemon"]["socket"]
    status = control.send_command(sock_path, {"cmd": "status"}, timeout=3.0)
    top = control.send_command(sock_path, {"cmd": "top", "limit": 10}, timeout=3.0)
    print(json.dumps({
        "ok": True, "status": status,
        "top": top.get("top", []) if top.get("ok") else [],
    }))
except Exception as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
PYEOF
