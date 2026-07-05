#!/bin/sh
# flowguard-cfg.sh — GET lista prefixos monitorados + whitelist + limiares de
# detecção efetivos + templates de perfil de rede; POST aplica monitor_set/
# monitor_del/whitelist_add/whitelist_del/detection_cfg_set/
# detection_templates_set/detection_templates_del via socket do daemon

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

ALLOWED_CMDS = {
    "monitor_set", "monitor_del", "whitelist_add", "whitelist_del",
    "detection_cfg_set", "detection_templates_set", "detection_templates_del",
}

try:
    body = json.loads(os.environ.get("BODY") or "{}")
    cmd = body.get("cmd")
    if cmd not in ALLOWED_CMDS:
        print(json.dumps({"ok": False, "error": f"comando não permitido: {cmd}"}))
    else:
        cfg = yaml.safe_load(open("/root/flowguard/config.yaml", encoding="utf-8"))
        payload = {k: v for k, v in body.items() if k != "token"}
        resp = control.send_command(cfg["daemon"]["socket"], payload)
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

from collector import configio

try:
    cfg = configio.load_config("/root/flowguard/config.yaml")
    print(json.dumps({
        "ok": True,
        "protected_prefixes": cfg["protected_prefixes"],
        "whitelist": cfg["whitelist"],
        "detection": cfg["detection"],
        "detection_templates": cfg["detection_templates"],
    }))
except Exception as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
PYEOF
