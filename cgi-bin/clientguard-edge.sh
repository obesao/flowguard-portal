#!/bin/sh
# clientguard-edge.sh — mitigação direta na borda (SSH/ACL no roteador), sem depender
# do FlowGuard. GET lista mitigações (ativas + histórico); POST aplica (ip, ttl_s,
# signal_id opcional) ou reverte (id) uma mitigação. Só exige sessão normal do portal
# (sem a segunda senha do Modo Guerra) — ação cirúrgica de 1 IP por vez.

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
        resp = control.send_command(sock_path, {"cmd": "edge_revert", "id": body["id"]}, timeout=25.0)
    elif body.get("ip"):
        payload = {"cmd": "edge_apply", "ip": body["ip"]}
        if body.get("ttl_s"):
            payload["ttl_s"] = int(body["ttl_s"])
        if body.get("signal_id"):
            payload["signal_id"] = body["signal_id"]
        resp = control.send_command(sock_path, payload, timeout=25.0)
    else:
        resp = {"ok": False, "error": "informe ip (aplicar) ou id (reverter)"}
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
    resp = control.send_command(cfg["daemon"]["socket"], {"cmd": "edge_list"}, timeout=3.0)
    print(json.dumps(resp))
except Exception as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
PYEOF
