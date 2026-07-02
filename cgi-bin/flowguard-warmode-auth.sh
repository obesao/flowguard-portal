#!/bin/sh
# flowguard-warmode-auth.sh — segunda camada de senha, só pra acessar a
# configuração do Modo Guerra (não a execução em si). Independente do
# login do portal: exige token de sessão normal (?token=) EM TODAS as ações
# abaixo, mais a senha própria do Modo Guerra pra unlock/change.
#
# GET                                          -> {"ok":true,"configured":bool}
# POST {"action":"setup","password":"..."}     -> só se ainda não configurado
# POST {"action":"unlock","password":"..."}    -> {"ok":true,"warmode_token":"..."}
# POST {"action":"change","warmode_token":"...","old_password":"...","new_password":"..."}

. "$(dirname -- "$0")/lib.sh"

TOKEN=$(parse_param "token")

if ! check_session "$TOKEN"; then
  deny_unauthorized
  exit 0
fi

CRED_FILE="$PORTAL_ROOT/.warmode_credentials"
WARMODE_TTL=900

if [ "$REQUEST_METHOD" != "POST" ]; then
  print_header 200
  if [ -s "$CRED_FILE" ]; then
    echo '{"ok":true,"configured":true}'
  else
    echo '{"ok":true,"configured":false}'
  fi
  exit 0
fi

BODY=$(read_post_body)
ACTION=$(printf '%s' "$BODY" | "$PYTHON_BIN" -c "import json,sys; print(json.load(sys.stdin).get('action',''))" 2>/dev/null)

case "$ACTION" in
  setup)
    if [ -s "$CRED_FILE" ]; then
      print_header 400
      echo '{"ok":false,"error":"ja existe uma senha configurada — use unlock/change"}'
      exit 0
    fi
    RESULT=$(BODY="$BODY" CRED_FILE="$CRED_FILE" "$PYTHON_BIN" <<'PYEOF'
import hashlib
import json
import os
import secrets

body = json.loads(os.environ.get("BODY") or "{}")
password = str(body.get("password") or "")
if len(password) < 6:
    print("ERRO:senha precisa de pelo menos 6 caracteres")
else:
    iterations = 200000
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), iterations)
    with open(os.environ["CRED_FILE"], "w", encoding="utf-8") as f:
        f.write(f"{salt}:{dk.hex()}:{iterations}\n")
    os.chmod(os.environ["CRED_FILE"], 0o600)
    print("OK")
PYEOF
)
    if [ "$RESULT" != "OK" ]; then
      print_header 400
      printf '{"ok":false,"error":"%s"}\n' "${RESULT#ERRO:}"
      exit 0
    fi
    WARMODE_TOKEN=$(issue_session_in "$WARMODE_SESSIONS_DIR" "$WARMODE_TTL")
    print_header 200
    printf '{"ok":true,"warmode_token":"%s","expires_in":%d}\n' "$WARMODE_TOKEN" "$WARMODE_TTL"
    ;;

  unlock)
    if [ ! -s "$CRED_FILE" ]; then
      print_header 400
      echo '{"ok":false,"error":"nenhuma senha configurada ainda — use setup"}'
      exit 0
    fi
    RESULT=$(BODY="$BODY" CRED_FILE="$CRED_FILE" "$PYTHON_BIN" <<'PYEOF'
import hashlib
import hmac
import json
import os

body = json.loads(os.environ.get("BODY") or "{}")
password = str(body.get("password") or "")
ok = False
with open(os.environ["CRED_FILE"], encoding="utf-8") as f:
    line = f.readline().strip()
if line.count(":") == 2:
    salt, hash_hex, iterations = line.split(":")
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iterations))
    ok = hmac.compare_digest(dk.hex(), hash_hex)
print("true" if ok else "false")
PYEOF
)
    if [ "$RESULT" != "true" ]; then
      print_header 401
      echo '{"ok":false,"error":"senha incorreta"}'
      exit 0
    fi
    WARMODE_TOKEN=$(issue_session_in "$WARMODE_SESSIONS_DIR" "$WARMODE_TTL")
    print_header 200
    printf '{"ok":true,"warmode_token":"%s","expires_in":%d}\n' "$WARMODE_TOKEN" "$WARMODE_TTL"
    ;;

  change)
    WARMODE_TOKEN=$(printf '%s' "$BODY" | "$PYTHON_BIN" -c "import json,sys; print(json.load(sys.stdin).get('warmode_token',''))" 2>/dev/null)
    if ! check_warmode_session "$WARMODE_TOKEN"; then
      print_header 401
      echo '{"ok":false,"error":"sessao do modo guerra invalida ou expirada — desbloqueie de novo"}'
      exit 0
    fi
    RESULT=$(BODY="$BODY" CRED_FILE="$CRED_FILE" "$PYTHON_BIN" <<'PYEOF'
import hashlib
import hmac
import json
import os
import secrets

body = json.loads(os.environ.get("BODY") or "{}")
old_password = str(body.get("old_password") or "")
new_password = str(body.get("new_password") or "")

with open(os.environ["CRED_FILE"], encoding="utf-8") as f:
    line = f.readline().strip()
salt, hash_hex, iterations = line.split(":")
dk = hashlib.pbkdf2_hmac("sha256", old_password.encode(), bytes.fromhex(salt), int(iterations))
if not hmac.compare_digest(dk.hex(), hash_hex):
    print("ERRO:senha atual incorreta")
elif len(new_password) < 6:
    print("ERRO:nova senha precisa de pelo menos 6 caracteres")
else:
    new_iterations = 200000
    new_salt = secrets.token_hex(16)
    new_dk = hashlib.pbkdf2_hmac("sha256", new_password.encode(), bytes.fromhex(new_salt), new_iterations)
    with open(os.environ["CRED_FILE"], "w", encoding="utf-8") as f:
        f.write(f"{new_salt}:{new_dk.hex()}:{new_iterations}\n")
    os.chmod(os.environ["CRED_FILE"], 0o600)
    print("OK")
PYEOF
)
    if [ "$RESULT" != "OK" ]; then
      print_header 400
      printf '{"ok":false,"error":"%s"}\n' "${RESULT#ERRO:}"
      exit 0
    fi
    print_header 200
    echo '{"ok":true}'
    ;;

  *)
    print_header 400
    echo '{"ok":false,"error":"action invalida (setup|unlock|change)"}'
    ;;
esac
