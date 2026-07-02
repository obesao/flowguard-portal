#!/bin/sh
# clientguard-edge-cfg.sh — GET lista a config de mitigação de borda (equipamento,
# ACL, TTL padrão e o gatilho automático por detector, nunca a credencial SSH — essa
# vive só no warmode.yaml do FlowGuard); POST { auto_mitigate: {...}, default_ttl_s? }
# aplica mudanças no gatilho automático numa escrita atômica só.

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
    auto_mitigate = body.get("auto_mitigate")
    if isinstance(auto_mitigate, dict) and auto_mitigate:
        payload = {"cmd": "edge_set_auto", "auto_mitigate": auto_mitigate}
        if body.get("default_ttl_s"):
            payload["default_ttl_s"] = int(body["default_ttl_s"])
        resp = control.send_command(cfg["daemon"]["socket"], payload)
    else:
        resp = {"ok": False, "error": "auto_mitigate (objeto não vazio) obrigatório"}
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
    resp = control.send_command(cfg["daemon"]["socket"], {"cmd": "edge_config"})
    print(json.dumps(resp))
except Exception as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
PYEOF
