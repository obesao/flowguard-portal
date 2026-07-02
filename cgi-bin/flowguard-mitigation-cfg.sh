#!/bin/sh
# flowguard-mitigation-cfg.sh — GET lista o perfil de mitigação sugerida (kind,
# pkt_len_min, rate_limit_mbps) de cada tipo de ataque; POST { profiles: {tipo:
# {campo: valor, ...}, ...} } aplica várias mudanças de uma vez via socket do daemon.

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
    profiles = body.get("profiles")
    if not isinstance(profiles, dict) or not profiles:
        print(json.dumps({"ok": False, "error": "profiles (objeto não vazio) obrigatório"}))
    else:
        cfg = yaml.safe_load(open("/root/flowguard/config.yaml", encoding="utf-8"))
        resp = control.send_command(cfg["daemon"]["socket"], {"cmd": "set_mitigation_profiles", "profiles": profiles})
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
    resp = control.send_command(cfg["daemon"]["socket"], {"cmd": "mitigation_profiles"})
    print(json.dumps(resp))
except Exception as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
PYEOF
