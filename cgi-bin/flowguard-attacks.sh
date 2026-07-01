#!/bin/sh
# flowguard-attacks.sh — GET lista ataques (ou histórico via ?history=1);
# POST aplica mitigação (RTBH via ban/unban no daemon) sobre o alvo de um ataque

. "$(dirname -- "$0")/lib.sh"

TOKEN=$(parse_param "token")
HISTORY=$(parse_param "history")

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
from bgp import flowspec
from collector import control, storage

try:
    body = json.loads(os.environ.get("BODY") or "{}")
    action = body.get("action")
    attack_id = body.get("attack_id")
    if action not in ("mitigate", "release", "apply_suggestion") or not attack_id:
        print(json.dumps({"ok": False, "error": "action ('mitigate'|'release'|'apply_suggestion') e attack_id são obrigatórios"}))
    else:
        cfg = yaml.safe_load(open("/root/flowguard/config.yaml", encoding="utf-8"))
        conn = storage.connect(cfg["database"]["path"])
        attack = storage.get_attack(conn, int(attack_id))
        if not attack:
            print(json.dumps({"ok": False, "error": "ataque não encontrado"}))
        elif action == "release":
            resp = control.send_command(cfg["daemon"]["socket"], {"cmd": "unban", "target": attack["dst_prefix"]})
            print(json.dumps(resp))
        elif action == "mitigate":
            resp = control.send_command(cfg["daemon"]["socket"], {
                "cmd": "ban", "target": attack["dst_prefix"], "attack_id": attack["id"],
            })
            print(json.dumps(resp))
        else:  # apply_suggestion
            suggestion = flowspec.suggest_mitigation(attack["attack_type"], attack["dst_prefix"])
            if suggestion["kind"] == "rtbh":
                resp = control.send_command(cfg["daemon"]["socket"], {
                    "cmd": "ban", "target": attack["dst_prefix"], "attack_id": attack["id"],
                })
            else:
                resp = control.send_command(cfg["daemon"]["socket"], {
                    "cmd": "flowspec_add", "rule": suggestion["rule"], "attack_id": attack["id"],
                })
            print(json.dumps(resp))
except Exception as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
PYEOF
  exit 0
fi

print_header 200
HISTORY="$HISTORY" /root/flowguard/venv/bin/python3 <<'PYEOF'
import json
import os
import sys

sys.path.insert(0, "/root/flowguard")

import yaml
from bgp import flowspec
from collector import storage

try:
    cfg = yaml.safe_load(open("/root/flowguard/config.yaml", encoding="utf-8"))
    conn = storage.connect(cfg["database"]["path"])
    history = os.environ.get("HISTORY") in ("1", "true", "yes")
    attacks = storage.list_attacks(conn, active_only=not history)
    for attack in attacks:
        attack["suggested_mitigation"] = flowspec.suggest_mitigation(attack["attack_type"], attack["dst_prefix"])
    print(json.dumps({"ok": True, "attacks": attacks, "history": history}))
except Exception as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
PYEOF
