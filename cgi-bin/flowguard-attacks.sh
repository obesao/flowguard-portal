#!/bin/sh
# flowguard-attacks.sh — GET lista ataques (ou histórico via ?history=1, ou
# detalhe factual de um ataque via ?detail=<id>, sem IA — protocolo/porta e
# IPs de origem observados, derivados de flow_aggs na janela do ataque);
# POST aplica mitigação (RTBH via ban/unban no daemon) sobre o alvo de um ataque,
# ou dispensa (dismiss/dismiss_all) um ou todos os ataques ativos

. "$(dirname -- "$0")/lib.sh"

TOKEN=$(parse_param "token")
HISTORY=$(parse_param "history")
DETAIL=$(parse_param "detail")
WINDOW=$(parse_param "window")

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
from collector import configio, control, storage

try:
    body = json.loads(os.environ.get("BODY") or "{}")
    action = body.get("action")
    attack_id = body.get("attack_id")
    cfg = yaml.safe_load(open("/root/flowguard/config.yaml", encoding="utf-8"))

    if action == "dismiss_all":
        resp = control.send_command(cfg["daemon"]["socket"], {"cmd": "dismiss_all_attacks"})
        print(json.dumps(resp))
    elif action == "dismiss":
        if not attack_id:
            print(json.dumps({"ok": False, "error": "attack_id obrigatório"}))
        else:
            resp = control.send_command(cfg["daemon"]["socket"], {"cmd": "dismiss_attack", "attack_id": int(attack_id)})
            print(json.dumps(resp))
    elif action not in ("mitigate", "release", "apply_suggestion") or not attack_id:
        print(json.dumps({"ok": False, "error": "action ('mitigate'|'release'|'apply_suggestion'|'dismiss'|'dismiss_all') e attack_id são obrigatórios"}))
    else:
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
            mp_path = cfg.get("mitigation_profiles_file", configio.DEFAULT_MITIGATION_PROFILES_FILE)
            profiles = configio.load_mitigation_profiles(mp_path)
            suggestion = flowspec.suggest_mitigation(attack["attack_type"], attack["dst_prefix"], profiles)
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
HISTORY="$HISTORY" DETAIL="$DETAIL" WINDOW="$WINDOW" /root/flowguard/venv/bin/python3 <<'PYEOF'
import json
import os
import sys
import time

sys.path.insert(0, "/root/flowguard")

import yaml
from bgp import flowspec
from collector import configio, storage

try:
    cfg = yaml.safe_load(open("/root/flowguard/config.yaml", encoding="utf-8"))
    conn = storage.connect(cfg["database"]["path"])
    mp_path = cfg.get("mitigation_profiles_file", configio.DEFAULT_MITIGATION_PROFILES_FILE)
    mitigation_profiles = configio.load_mitigation_profiles(mp_path)
    detail_id = os.environ.get("DETAIL")
    if detail_id:
        attack = storage.get_attack(conn, int(detail_id))
        if not attack:
            print(json.dumps({"ok": False, "error": "ataque não encontrado"}))
        else:
            interval_s = cfg["database"]["aggregate_interval_s"]
            detail = storage.attack_detail(
                conn, attack["dst_prefix"], attack["ts_start"], attack["ts_end"], limit=20, interval_s=interval_s,
            )
            timeseries = storage.attack_timeseries(conn, attack["dst_prefix"], attack["ts_start"], attack["ts_end"])
            print(json.dumps({
                "ok": True, "attack": attack, "by_port": detail["by_port"],
                "top_sources": detail["top_sources"], "top_hosts": detail["top_hosts"],
                "summary": detail["summary"], "timeseries": timeseries,
            }))
    else:
        history = os.environ.get("HISTORY") in ("1", "true", "yes")
        window_s, _ = storage.pick_window(os.environ.get("WINDOW") or "24h")
        attacks = storage.list_attacks(conn, active_only=not history, since_s=window_s)
        now = int(time.time())
        for attack in attacks:
            attack["suggested_mitigation"] = flowspec.suggest_mitigation(
                attack["attack_type"], attack["dst_prefix"], mitigation_profiles,
            )
            # ataques encerrados já têm target_host persistido no fechamento
            # (ver storage.apply_attack_changes) — só ataques ainda ativos precisam
            # de lookup ao vivo aqui, e só sobre os últimos 5min (não a duração toda,
            # senão um ataque de horas fica caro de listar a cada poll de 5s)
            if not attack.get("ts_end"):
                lookup_start = max(attack["ts_start"], now - 300)
                attack["target_host"] = storage.attack_top_host(conn, attack["dst_prefix"], lookup_start, None)
        print(json.dumps({"ok": True, "attacks": attacks, "history": history, "window": os.environ.get("WINDOW") or "24h"}))
except Exception as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
PYEOF
