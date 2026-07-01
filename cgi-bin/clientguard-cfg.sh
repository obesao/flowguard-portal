#!/bin/sh
# clientguard-cfg.sh — GET lista redes de clientes (customers.yaml) + whitelist;
# POST aplica customers_add/customers_del/whitelist_add/whitelist_del via socket do daemon

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

ALLOWED_CMDS = {"customers_add", "customers_del", "whitelist_add", "whitelist_del"}

try:
    body = json.loads(os.environ.get("BODY") or "{}")
    cmd = body.get("cmd")
    if cmd not in ALLOWED_CMDS:
        print(json.dumps({"ok": False, "error": f"comando não permitido: {cmd}"}))
    else:
        cfg = yaml.safe_load(open("/root/clientguard/config.yaml", encoding="utf-8"))
        payload = {k: v for k, v in body.items() if k != "token"}
        resp = control.send_command(cfg["daemon"]["socket"], payload)
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

import configio

try:
    customers = configio.load_yaml_list("/root/clientguard/customers.yaml")
    whitelist = configio.load_yaml_list("/root/clientguard/whitelist.yaml")
    print(json.dumps({"ok": True, "customers": customers, "whitelist": whitelist}))
except Exception as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
PYEOF
