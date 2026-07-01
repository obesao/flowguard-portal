#!/bin/sh
# flowguard-login.sh — POST {"username":"...","password":"..."} -> valida contra
# cgi-bin/.credentials (usuario:salt:hash:iteracoes, PBKDF2-SHA256) e cria uma
# sessão igual à de create_dev_session.sh, retornando o token gerado.

. "$(dirname -- "$0")/lib.sh"

CRED_FILE="$PORTAL_ROOT/.credentials"
SESSION_TTL=28800

if [ "$REQUEST_METHOD" != "POST" ]; then
  print_header 400
  echo '{"ok":false,"error":"use POST com {\"username\":...,\"password\":...}"}'
  exit 0
fi

BODY=$(read_post_body)
RESULT=$(BODY="$BODY" CRED_FILE="$CRED_FILE" /root/flowguard/venv/bin/python3 <<'PYEOF'
import hashlib
import hmac
import json
import os

body = json.loads(os.environ.get("BODY") or "{}")
username = str(body.get("username") or "")
password = str(body.get("password") or "")

ok = False
if username and password:
    try:
        with open(os.environ["CRED_FILE"], encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.count(":") != 3:
                    continue
                u, salt, hash_hex, iterations = line.split(":")
                if u == username:
                    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iterations))
                    ok = hmac.compare_digest(dk.hex(), hash_hex)
                    break
    except FileNotFoundError:
        ok = False

print("true" if ok else "false")
PYEOF
)

if [ "$RESULT" != "true" ]; then
  print_header 401
  echo '{"ok":false,"error":"credenciais invalidas"}'
  exit 0
fi

TOKEN=$(head -c 32 /dev/urandom | sha256sum | cut -d' ' -f1)
HASH=$(printf '%s' "$TOKEN" | sha256sum | cut -d' ' -f1)
EXPIRY=$(($(date +%s) + SESSION_TTL))
echo "$EXPIRY" > "$SESSIONS_DIR/$HASH"
chmod 600 "$SESSIONS_DIR/$HASH"

print_header 200
printf '{"ok":true,"token":"%s","expires_in":%d}\n' "$TOKEN" "$SESSION_TTL"
