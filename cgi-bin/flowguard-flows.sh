#!/bin/sh
# flowguard-flows.sh — top flows por volume (janela de agregação atual)

. "$(dirname -- "$0")/lib.sh"

TOKEN=$(parse_param "token")
LIMIT=$(parse_param "limit")

if ! check_session "$TOKEN"; then
  deny_unauthorized
  exit 0
fi

print_header 200
LIMIT="$LIMIT" /root/flowguard/venv/bin/python3 <<'PYEOF'
import json
import os
import sys

sys.path.insert(0, "/root/flowguard")

import yaml
from collector import storage

try:
    cfg = yaml.safe_load(open("/root/flowguard/config.yaml", encoding="utf-8"))
    conn = storage.connect(cfg["database"]["path"])
    interval = cfg["database"]["aggregate_interval_s"]
    try:
        limit = int(os.environ.get("LIMIT") or 20)
    except ValueError:
        limit = 20
    flows = storage.top_flows(conn, window_s=interval, limit=limit)
    print(json.dumps({"ok": True, "flows": flows}))
except Exception as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
PYEOF
