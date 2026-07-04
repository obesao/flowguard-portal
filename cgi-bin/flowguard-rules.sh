#!/bin/sh
# flowguard-rules.sh — GET lista regras FlowSpec/RTBH (?history=1 traz todo o
# histórico, incluindo expiradas/removidas — default só as ativas); POST cria
# (src_prefix/dst_prefix), remove uma regra (id), remove TODAS as ativas
# (clear_all) ou confere via SSH se uma regra está de fato no roteador
# (verify_id — usado tanto pelas regras do FlowGuard quanto pelas mitigações
# FlowSpec do ClientGuard, já que edge_mitigations.flowspec_rule_id é um id
# desta mesma tabela flowspec_rules), proxied pro daemon via socket.

. "$(dirname -- "$0")/lib.sh"

TOKEN=$(parse_param "token")

if ! check_session "$TOKEN"; then
  deny_unauthorized
  exit 0
fi

HISTORY=$(parse_param "history")

if [ "$REQUEST_METHOD" = "POST" ]; then
  BODY=$(read_post_body)
  print_header 200
  BODY="$BODY" /root/flowguard/venv/bin/python3 <<'PYEOF'
import ipaddress
import json
import os
import sys

sys.path.insert(0, "/root/flowguard")

import yaml
from collector import control

try:
    body = json.loads(os.environ.get("BODY") or "{}")
    cfg = yaml.safe_load(open("/root/flowguard/config.yaml", encoding="utf-8"))
    sock_path = cfg["daemon"]["socket"]
    rule_id = body.get("id")
    if body.get("clear_all"):
        resp = control.send_command(sock_path, {"cmd": "flowspec_del_all"}, timeout=60.0)
    elif body.get("verify_id"):
        # Netmiko pode legitimamente levar 10-20s (conecta via SSH no roteador,
        # roda um display, desconecta) — bem mais que os outros comandos deste
        # script, que só falam com o socket local do daemon.
        resp = control.send_command(sock_path, {"cmd": "rule_verify", "rule_id": body["verify_id"]}, timeout=35.0)
    elif rule_id:
        resp = control.send_command(sock_path, {"cmd": "flowspec_del", "rule_id": rule_id})
    elif body.get("src_prefix") or body.get("dst_prefix"):
        rule = {"action": body.get("action") or "discard"}
        try:
            if body.get("src_prefix"):
                rule["src_prefix"] = str(ipaddress.ip_network(body["src_prefix"], strict=False))
            if body.get("dst_prefix"):
                rule["dst_prefix"] = str(ipaddress.ip_network(body["dst_prefix"], strict=False))
        except ValueError as exc:
            raise ValueError(f"IP/CIDR inválido: {exc}")
        rule["label"] = "bloqueio manual via portal"
        ttl_s = body.get("ttl_s")
        payload = {"cmd": "flowspec_add", "rule": rule}
        if ttl_s:
            payload["ttl_s"] = int(ttl_s)
        resp = control.send_command(sock_path, payload)
    else:
        resp = {"ok": False, "error": "informe id (remover), clear_all (remover todas), "
                                       "verify_id (conferir no roteador) ou src_prefix/dst_prefix (criar)"}
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
from collector import storage

try:
    cfg = yaml.safe_load(open("/root/flowguard/config.yaml", encoding="utf-8"))
    conn = storage.connect(cfg["database"]["path"])
    history = os.environ.get("HISTORY") in ("1", "true", "True")
    rules = storage.list_flowspec_rules(conn, active_only=not history)
    print(json.dumps({"ok": True, "rules": rules}))
except Exception as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
PYEOF
