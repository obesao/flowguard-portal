#!/bin/sh
# flowguard-warmode.sh — "botão de emergência": GET lista os equipamentos configurados,
# POST dispara a execução real dos comandos via SSH em todos eles. As duas exigem a
# MESMA senha/sessão do Modo Guerra usada pra configuração (ver flowguard-warmode-auth.sh)
# — não basta estar logado no portal.

. "$(dirname -- "$0")/lib.sh"

TOKEN=$(parse_param "token")

if ! check_session "$TOKEN"; then
  deny_unauthorized
  exit 0
fi

if [ "$REQUEST_METHOD" = "POST" ]; then
  BODY=$(read_post_body)
  WARMODE_TOKEN=$(printf '%s' "$BODY" | "$PYTHON_BIN" -c "import json,sys; print(json.load(sys.stdin).get('warmode_token',''))" 2>/dev/null)
  if ! check_warmode_session "$WARMODE_TOKEN"; then
    print_header 401
    echo '{"ok":false,"error":"sessao do modo guerra invalida ou expirada — desbloqueie de novo"}'
    exit 0
  fi
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

WARMODE_TOKEN=$(parse_param "warmode_token")
if ! check_warmode_session "$WARMODE_TOKEN"; then
  print_header 401
  echo '{"ok":false,"error":"sessao do modo guerra invalida ou expirada — desbloqueie de novo"}'
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
