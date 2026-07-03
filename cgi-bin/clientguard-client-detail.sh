#!/bin/sh
# clientguard-client-detail.sh — série temporal de tráfego + top destinos de UM
# cliente (?src_ip=&window_s=)

. "$(dirname -- "$0")/lib.sh"

TOKEN=$(parse_param "token")

if ! check_session "$TOKEN"; then
  deny_unauthorized
  exit 0
fi

SRC_IP=$(parse_param "src_ip")
WINDOW=$(parse_param "window_s")

print_header 200
SRC_IP="$SRC_IP" WINDOW="$WINDOW" /root/clientguard/venv/bin/python3 <<'PYEOF'
import json
import os
import sys

sys.path.insert(0, "/root/clientguard")

import yaml
import control

try:
    src_ip = os.environ.get("SRC_IP") or ""
    if not src_ip:
        print(json.dumps({"ok": False, "error": "src_ip obrigatório"}))
    else:
        cfg = yaml.safe_load(open("/root/clientguard/config.yaml", encoding="utf-8"))
        window_s = int(os.environ.get("WINDOW") or 3600)
        # mesmo motivo do timeout maior em clientguard-top.sh — série temporal/top
        # destinos de um cliente também escaneiam a tabela inteira em janelas longas.
        resp = control.send_command(cfg["daemon"]["socket"],
                                     {"cmd": "client_detail", "src_ip": src_ip, "window_s": window_s},
                                     timeout=20.0)
        print(json.dumps(resp))
except Exception as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
PYEOF
