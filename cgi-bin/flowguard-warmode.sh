#!/bin/sh
# flowguard-warmode.sh — "botão de emergência": GET lista os equipamentos configurados
# (sem senha), POST dispara a execução real dos comandos via SSH em todos eles.

. "$(dirname -- "$0")/lib.sh"

TOKEN=$(parse_param "token")

if ! check_session "$TOKEN"; then
  deny_unauthorized
  exit 0
fi

if [ "$REQUEST_METHOD" = "POST" ]; then
  print_header 200
  /root/flowguard/venv/bin/python3 <<'PYEOF'
import json
import sys

sys.path.insert(0, "/root/flowguard")

from warmode.executor import run_war_mode

try:
    results = run_war_mode(trigger="portal")
    print(json.dumps({"ok": True, "results": results}))
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

from warmode.executor import list_devices

try:
    print(json.dumps({"ok": True, "devices": list_devices()}))
except Exception as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
PYEOF
