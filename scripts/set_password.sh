#!/bin/sh
# set_password.sh — utilitário de ADMIN/CLI para criar/alterar a senha de um usuário do portal.
# NÃO fica em cgi-bin: nunca deve ser exposto via HTTP.
# Uso: ./set_password.sh <usuario> [senha]
#   Se a senha não for passada como argumento, ela é lida via prompt (sem eco no terminal).

set -e
CGI_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/../cgi-bin" && pwd)"
CRED_FILE="$CGI_DIR/.credentials"

USERNAME="$1"
if [ -z "$USERNAME" ]; then
  echo "Uso: $0 <usuario> [senha]" >&2
  exit 1
fi

PASSWORD="$2"
if [ -z "$PASSWORD" ]; then
  printf 'Senha para %s: ' "$USERNAME" >&2
  stty -echo 2>/dev/null || true
  read -r PASSWORD
  stty echo 2>/dev/null || true
  echo >&2
fi

touch "$CRED_FILE"
chmod 600 "$CRED_FILE"

TMP_FILE=$(mktemp)
grep -v "^${USERNAME}:" "$CRED_FILE" > "$TMP_FILE" 2>/dev/null || true

LINE=$(PASSWORD="$PASSWORD" USERNAME="$USERNAME" /root/flowguard/venv/bin/python3 <<'PYEOF'
import hashlib
import os
import secrets

username = os.environ["USERNAME"]
password = os.environ["PASSWORD"]
iterations = 200000
salt = secrets.token_hex(16)
dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), iterations)
print(f"{username}:{salt}:{dk.hex()}:{iterations}")
PYEOF
)

echo "$LINE" >> "$TMP_FILE"
mv "$TMP_FILE" "$CRED_FILE"
chmod 600 "$CRED_FILE"
echo "Senha definida para '$USERNAME'."
