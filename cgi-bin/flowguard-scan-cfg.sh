#!/bin/sh
# flowguard-scan-cfg.sh — GET lista a config de detecção de port scan (fora pra
# dentro); POST { changes: {chave: valor, ...} } aplica mudanças via socket do daemon.

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
    changes = body.get("changes")
    if not isinstance(changes, dict) or not changes:
        print(json.dumps({"ok": False, "error": "changes (objeto não vazio) obrigatório"}))
    else:
        cfg = yaml.safe_load(open("/root/flowguard/config.yaml", encoding="utf-8"))
        resp = control.send_command(cfg["daemon"]["socket"], {"cmd": "scan_detection_cfg_set", "changes": changes})
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
    resp = control.send_command(cfg["daemon"]["socket"], {"cmd": "scan_detection_cfg"})
    print(json.dumps(resp))
except Exception as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
PYEOF
