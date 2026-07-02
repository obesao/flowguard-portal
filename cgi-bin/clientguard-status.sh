#!/bin/sh
# clientguard-status.sh — status geral do ClientGuard (flows/clientes/sinais na janela).
# Top clientes tem endpoint próprio (clientguard-top.sh) com janela configurável.

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
    status = control.send_command(cfg["daemon"]["socket"], {"cmd": "status"}, timeout=3.0)
    print(json.dumps({"ok": True, "status": status}))
except Exception as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
PYEOF
