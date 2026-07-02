#!/bin/sh
# clientguard-block.sh — GET lista IPs bloqueados (FlowSpec, via socket do ClientGuard,
# que só repassa pro FlowGuard); POST cria (ip) ou remove (id) um bloqueio.

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
    cfg = yaml.safe_load(open("/root/clientguard/config.yaml", encoding="utf-8"))
    sock_path = cfg["daemon"]["socket"]
    if body.get("id"):
        resp = control.send_command(sock_path, {"cmd": "block_del", "id": body["id"]})
    elif body.get("ip"):
        payload = {"cmd": "block_add", "ip": body["ip"]}
        if body.get("ttl_s"):
            payload["ttl_s"] = int(body["ttl_s"])
        resp = control.send_command(sock_path, payload)
    else:
        resp = {"ok": False, "error": "informe ip (bloquear) ou id (remover)"}
    print(json.dumps(resp))
except Exception as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
PYEOF
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
    resp = control.send_command(cfg["daemon"]["socket"], {"cmd": "block_list"}, timeout=3.0)
    print(json.dumps(resp))
except Exception as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
PYEOF
