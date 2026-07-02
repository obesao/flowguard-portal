#!/bin/sh
# flowguard-whatsapp.sh — status/QR/grupos/destino dos alertas via WhatsApp
# (Evolution API self-hosted, ver /root/evolution-api). Compartilhado por
# FlowGuard e ClientGuard: só existe UMA conexão WhatsApp real.
#
# GET  ?token=...&action=status   -> estado da conexão + destino configurado
# GET  ?token=...&action=qrcode   -> QR code (base64) pra parear um número novo
# GET  ?token=...&action=groups   -> grupos do WhatsApp conectado (pro seletor)
# POST {token, action:"set_dest", dest, dest_type, dest_label}
# POST {token, action:"test"}     -> manda mensagem de teste pro destino salvo
# POST {token, action:"logout"}   -> desconecta (pra escanear outro número)

. "$(dirname -- "$0")/lib.sh"

TOKEN=$(parse_param "token")
if ! check_session "$TOKEN"; then
  deny_unauthorized
  exit 0
fi

if [ "$REQUEST_METHOD" = "POST" ]; then
  BODY=$(read_post_body)
  print_header 200
  BODY="$BODY" "$PYTHON_BIN" <<'PYEOF'
import json
import os
import sys

sys.path.insert(0, "/root/evolution-api")
import client as evo

body = json.loads(os.environ.get("BODY") or "{}")
action = body.get("action", "")

try:
    if action == "set_dest":
        dest = (body.get("dest") or "").strip()
        dest_type = body.get("dest_type") or "number"
        if not dest:
            raise ValueError("destino vazio")
        if dest_type == "number":
            digits = "".join(c for c in dest if c.isdigit())
            if not digits:
                raise ValueError("numero invalido")
            dest = f"{digits}@s.whatsapp.net"
        evo.save_dest(dest, dest_type, body.get("dest_label", ""))
        print(json.dumps({"ok": True}))
    elif action == "test":
        d = evo.load_dest()
        if not d.get("dest"):
            raise ValueError("nenhum destino configurado ainda")
        ok = evo.send_text(d["dest"], "✅ FlowGuard/ClientGuard: mensagem de teste — se você recebeu isso, os alertas via WhatsApp estão funcionando.")
        print(json.dumps({"ok": ok, "error": None if ok else "falha ao enviar (ver se o WhatsApp continua conectado)"}))
    elif action == "logout":
        evo.logout()
        print(json.dumps({"ok": True}))
    else:
        print(json.dumps({"ok": False, "error": f"acao desconhecida: {action}"}))
except Exception as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
PYEOF
  exit 0
fi

ACTION=$(parse_param "action")
print_header 200
ACTION="$ACTION" "$PYTHON_BIN" <<'PYEOF'
import json
import os
import sys

sys.path.insert(0, "/root/evolution-api")
import client as evo

action = os.environ.get("ACTION", "status")

try:
    if action == "status":
        state = evo.connection_state().get("instance", {}).get("state", "unknown")
        info = evo.instance_info() or {}
        dest = evo.load_dest()
        print(json.dumps({
            "ok": True, "state": state,
            "number": info.get("number") or (info.get("ownerJid") or "").split("@")[0] or None,
            "profile_name": info.get("profileName"),
            "dest": dest,
        }))
    elif action == "qrcode":
        qr = evo.qrcode()
        print(json.dumps({"ok": True, "base64": qr.get("base64"), "pairing_code": qr.get("pairingCode")}))
    elif action == "groups":
        groups = evo.fetch_groups()
        print(json.dumps({"ok": True, "groups": [
            {"id": g["id"], "subject": g.get("subject") or g["id"]} for g in groups
        ]}))
    else:
        print(json.dumps({"ok": False, "error": f"acao desconhecida: {action}"}))
except Exception as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
PYEOF
