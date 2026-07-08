#!/bin/sh
# clientguard-network-series.sh — série temporal de tráfego agregada por REDE
# inteira de cliente (?customer_prefix=&window_s=), ex: a rede CGNAT.

. "$(dirname -- "$0")/lib.sh"

TOKEN=$(parse_param "token")

if ! check_session "$TOKEN"; then
  deny_unauthorized
  exit 0
fi

CUSTOMER_PREFIX=$(parse_param "customer_prefix")
WINDOW=$(parse_param "window_s")

print_header 200
CUSTOMER_PREFIX="$CUSTOMER_PREFIX" WINDOW="$WINDOW" /root/clientguard/venv/bin/python3 <<'PYEOF'
import json
import os
import sys

sys.path.insert(0, "/root/clientguard")

import yaml
import control

try:
    customer_prefix = os.environ.get("CUSTOMER_PREFIX") or ""
    if not customer_prefix:
        print(json.dumps({"ok": False, "error": "customer_prefix obrigatório"}))
    else:
        cfg = yaml.safe_load(open("/root/clientguard/config.yaml", encoding="utf-8"))
        window_s = int(os.environ.get("WINDOW") or 3600)
        # mesmo motivo do timeout maior em clientguard-top.sh/client-detail.sh —
        # agregação por rede inteira também escaneia a tabela toda em janelas longas.
        resp = control.send_command(cfg["daemon"]["socket"],
                                     {"cmd": "network_series", "customer_prefix": customer_prefix, "window_s": window_s},
                                     timeout=20.0)
        print(json.dumps(resp))
except Exception as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
PYEOF
