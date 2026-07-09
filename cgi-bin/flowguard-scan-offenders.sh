#!/bin/sh
# flowguard-scan-offenders.sh — GET lista scanners detectados (ver
# port_scan_offenders). Somente leitura; bloqueio em si aparece na tabela de
# Regras FlowSpec Ativas já existente (flowguard-rules.sh).

. "$(dirname -- "$0")/lib.sh"

TOKEN=$(parse_param "token")

if ! check_session "$TOKEN"; then
  deny_unauthorized
  exit 0
fi

HISTORY=$(parse_param "history")

print_header 200
HISTORY="$HISTORY" /root/flowguard/venv/bin/python3 <<'PYEOF'
import json
import os
import sys

sys.path.insert(0, "/root/flowguard")

import yaml
from collector import control

try:
    cfg = yaml.safe_load(open("/root/flowguard/config.yaml", encoding="utf-8"))
    history = os.environ.get("HISTORY") in ("1", "true", "on")
    resp = control.send_command(cfg["daemon"]["socket"], {"cmd": "scan_offenders", "history": history})
    print(json.dumps(resp))
except Exception as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
PYEOF
