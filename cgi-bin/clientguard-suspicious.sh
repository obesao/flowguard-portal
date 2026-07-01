#!/bin/sh
# clientguard-suspicious.sh — GET lista sinais suspeitos (abertos por padrão, ?history=1
# pra resolvidos); POST resolve (id) via socket do daemon

. "$(dirname -- "$0")/lib.sh"

TOKEN=$(parse_param "token")

if ! check_session "$TOKEN"; then
  deny_unauthorized
  exit 0
fi

if [ "$REQUEST_METHOD" = "POST" ]; then
  BODY=$(read_post_body)
  print_header 200
  BODY="$BODY" /root/clientguard/venv/bin/python3 <<'PYEOF'
import json
import os
import sys

sys.path.insert(0, "/root/clientguard")

import yaml
import control

try:
    body = json.loads(os.environ.get("BODY") or "{}")
    signal_id = body.get("id")
    if not signal_id:
        print(json.dumps({"ok": False, "error": "id obrigatório"}))
    else:
        cfg = yaml.safe_load(open("/root/clientguard/config.yaml", encoding="utf-8"))
        resp = control.send_command(cfg["daemon"]["socket"], {"cmd": "resolve", "id": signal_id})
        print(json.dumps(resp))
except Exception as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
PYEOF
  exit 0
fi

HISTORY=$(parse_param "history")

print_header 200
HISTORY="$HISTORY" /root/clientguard/venv/bin/python3 <<'PYEOF'
import json
import os
import sys

sys.path.insert(0, "/root/clientguard")

import yaml
import control

try:
    cfg = yaml.safe_load(open("/root/clientguard/config.yaml", encoding="utf-8"))
    history = os.environ.get("HISTORY") == "1"
    resp = control.send_command(cfg["daemon"]["socket"], {"cmd": "suspicious", "history": history})
    print(json.dumps(resp))
except Exception as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
PYEOF
