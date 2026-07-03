#!/bin/sh
# flowguard-routercfg.sh — edição de configuração do roteador de borda via
# templates validados (ver flowguard/routercfg/). Exige a MESMA senha/sessão
# do Modo Guerra usada pra configuração/execução (ver flowguard-warmode-auth.sh)
# — não basta estar logado no portal.
#
# GET  ?warmode_token=...                                  -> templates + device + histórico
# POST {"warmode_token":"...","action":"preview","template_id":"...","values":{...}}
# POST {"warmode_token":"...","action":"apply","template_id":"...","values":{...},"window":300}
# POST {"warmode_token":"...","action":"confirm","job_id":"..."}
# POST {"warmode_token":"...","action":"revert","job_id":"..."}
# POST {"warmode_token":"...","action":"discover"}                          -> lê BGP+interfaces+VLANs via SSH
# POST {"warmode_token":"...","action":"peer_routes","peer_ip":"...","direction":"advertised"|"received"}

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
  BODY="$BODY" /root/flowguard/venv/bin/python3 <<'PYEOF'
import json
import os
import sys

sys.path.insert(0, "/root/flowguard")

from routercfg.templates import ValidationError
from routercfg import apply as routercfg_apply

try:
    body = json.loads(os.environ.get("BODY") or "{}")
    action = body.get("action")

    if action == "preview":
        result = routercfg_apply.preview(body.get("template_id"), body.get("values") or {})
        print(json.dumps({"ok": True, "preview": result}))

    elif action == "apply":
        window = int(body.get("window") or routercfg_apply.DEFAULT_CONFIRM_WINDOW_S)
        window = max(30, min(window, 3600))
        job = routercfg_apply.apply_template(
            body.get("template_id"), body.get("values") or {}, trigger="portal", confirm_window_s=window
        )
        print(json.dumps({"ok": True, "job": job}))

    elif action == "confirm":
        job = routercfg_apply.confirm_job(body.get("job_id"))
        print(json.dumps({"ok": True, "job": job}))

    elif action == "revert":
        job = routercfg_apply.revert_job(body.get("job_id"), trigger="manual")
        print(json.dumps({"ok": True, "job": job}))

    elif action == "discover":
        from routercfg.discovery import discover_all
        result = discover_all()
        print(json.dumps({"ok": True, "discovery": result}))

    elif action == "peer_routes":
        from routercfg.discovery import discover_peer_routes
        result = discover_peer_routes(body.get("peer_ip"), direction=body.get("direction") or "advertised")
        print(json.dumps({"ok": True, "routes": result}))

    else:
        print(json.dumps({"ok": False, "error": "action invalida (preview|apply|confirm|revert|discover|peer_routes)"}))
except ValidationError as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
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

from routercfg.templates import list_templates_public
from routercfg import apply as routercfg_apply
from warmode.executor import load_devices_masked

try:
    templates = list_templates_public()
    devices = load_devices_masked()
    device_names = {d["name"] for d in devices if d.get("has_password") and d.get("host")}
    for t in templates:
        t["device_ready"] = t.get("device_name") in device_names
    history = routercfg_apply.list_history(limit=30)
    print(json.dumps({"ok": True, "templates": templates, "history": history}))
except Exception as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
PYEOF
