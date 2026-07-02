#!/bin/sh
# clientguard-top.sh — top clientes por tráfego numa janela configurável (?window_s=&limit=)

. "$(dirname -- "$0")/lib.sh"

TOKEN=$(parse_param "token")

if ! check_session "$TOKEN"; then
  deny_unauthorized
  exit 0
fi

WINDOW=$(parse_param "window_s")
LIMIT=$(parse_param "limit")

print_header 200
WINDOW="$WINDOW" LIMIT="$LIMIT" /root/clientguard/venv/bin/python3 <<'PYEOF'
import json
import os
import sys

sys.path.insert(0, "/root/clientguard")

import yaml
import control

try:
    cfg = yaml.safe_load(open("/root/clientguard/config.yaml", encoding="utf-8"))
    window_s = int(os.environ.get("WINDOW") or 3600)
    limit = int(os.environ.get("LIMIT") or 20)
    resp = control.send_command(cfg["daemon"]["socket"], {"cmd": "top", "window_s": window_s, "limit": limit},
                                 timeout=5.0)
    print(json.dumps(resp))
except Exception as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
PYEOF
