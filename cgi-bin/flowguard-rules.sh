#!/bin/sh
# flowguard-rules.sh — GET lista regras FlowSpec ativas; POST remove uma regra
# (proxied para o daemon via socket — mitigação BGP real chega na Fase 3)

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
    rule_id = body.get("id")
    if not rule_id:
        print(json.dumps({"ok": False, "error": "id da regra obrigatório"}))
    else:
        cfg = yaml.safe_load(open("/root/flowguard/config.yaml", encoding="utf-8"))
        sock_path = cfg["daemon"]["socket"]
        resp = control.send_command(sock_path, {"cmd": "flowspec_del", "rule_id": rule_id})
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
from collector import storage

try:
    cfg = yaml.safe_load(open("/root/flowguard/config.yaml", encoding="utf-8"))
    conn = storage.connect(cfg["database"]["path"])
    rules = storage.list_flowspec_rules(conn, active_only=True)
    print(json.dumps({"ok": True, "rules": rules}))
except Exception as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
PYEOF
