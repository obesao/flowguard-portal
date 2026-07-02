#!/bin/sh
# flowguard-toggles.sh — GET lista o estado (habilitado/desabilitado) de cada tipo de
# ataque detectado; POST { key, value } liga/desliga um só, ou
# POST { toggles: {chave: valor, ...} } aplica vários de uma vez (1 requisição) — usado
# pelo botão "Aplicar novas configurações" do portal.

. "$(dirname -- "$0")/lib.sh"

TOKEN=$(parse_param "token")

if ! check_session "$TOKEN"; then
  deny_unauthorized
  exit 0
fi

if [ "$REQUEST_METHOD" = "POST" ]; then
  BODY=$(read_post_body)
  print_header 200
  BODY="$BODY" /root/flowguard/venv/bin/python3 <<'PYEOF'
import json
import os
import sys

sys.path.insert(0, "/root/flowguard")

import yaml
from collector import control

try:
    body = json.loads(os.environ.get("BODY") or "{}")
    cfg = yaml.safe_load(open("/root/flowguard/config.yaml", encoding="utf-8"))
    toggles = body.get("toggles")
    if isinstance(toggles, dict) and toggles:
        resp = control.send_command(cfg["daemon"]["socket"], {"cmd": "set_toggles", "toggles": toggles})
    elif body.get("key"):
        resp = control.send_command(cfg["daemon"]["socket"], {
            "cmd": "set_toggle", "key": body["key"], "value": bool(body.get("value")),
        })
    else:
        resp = {"ok": False, "error": "key ou toggles (objeto não vazio) obrigatório"}
    print(json.dumps(resp))
except Exception as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
PYEOF
  exit 0
fi

print_header 200
/root/flowguard/venv/bin/python3 <<'PYEOF'
import json
import sys

sys.path.insert(0, "/root/flowguard")

import yaml
from collector import control

try:
    cfg = yaml.safe_load(open("/root/flowguard/config.yaml", encoding="utf-8"))
    resp = control.send_command(cfg["daemon"]["socket"], {"cmd": "toggles"})
    print(json.dumps(resp))
except Exception as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
PYEOF
