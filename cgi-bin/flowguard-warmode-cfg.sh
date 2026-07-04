#!/bin/sh
# flowguard-warmode-cfg.sh — GET/POST da lista de equipamentos do Modo Guerra
# (warmode.yaml no FlowGuard). Exige sessão normal do portal (?token=) E a
# sessão de desbloqueio própria do Modo Guerra (warmode_token) — ver
# flowguard-warmode-auth.sh. POST com {"action":"test","device":{...}} só
# autentica via SSH (sem rodar nenhum comando de produção) pra validar
# credencial/alcance; sem "action" (ou "action":"save") é o salvar de sempre.

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

  ACTION=$(printf '%s' "$BODY" | "$PYTHON_BIN" -c "import json,sys; print(json.load(sys.stdin).get('action','save'))" 2>/dev/null)

  if [ "$ACTION" = "test" ]; then
    # pode legitimamente levar alguns segundos (conexão SSH de verdade,
    # timeout de 12s dentro de test_device) — sem timeout específico aqui,
    # busybox httpd só aguarda o CGI terminar, mesmo comportamento de sempre
    print_header 200
    BODY="$BODY" /root/flowguard/venv/bin/python3 <<'PYEOF'
import json
import os
import sys

sys.path.insert(0, "/root/flowguard")

from warmode.executor import test_device

try:
    body = json.loads(os.environ.get("BODY") or "{}")
    device = body.get("device") or {}
    if not device.get("host") or not device.get("device_type"):
        raise ValueError("host e device_type sao obrigatorios pra testar")
    print(json.dumps(test_device(device)))
except Exception as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
PYEOF
    exit 0
  fi

  print_header 200
  BODY="$BODY" /root/flowguard/venv/bin/python3 <<'PYEOF'
import json
import os
import sys

sys.path.insert(0, "/root/flowguard")

from warmode.executor import save_devices

try:
    body = json.loads(os.environ.get("BODY") or "{}")
    devices = body.get("devices") or []
    for d in devices:
        if not d.get("host") or not d.get("device_type"):
            raise ValueError("cada equipamento precisa de host e device_type")
    save_devices(devices)
    print(json.dumps({"ok": True}))
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

from warmode.executor import load_devices_masked

try:
    print(json.dumps({"ok": True, "devices": load_devices_masked()}))
except Exception as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
PYEOF
