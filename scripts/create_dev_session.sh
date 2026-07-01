#!/bin/sh
# create_dev_session.sh — utilitário de ADMIN/CLI para criar uma sessão de teste.
# NÃO fica em cgi-bin: nunca deve ser exposto via HTTP.
# Uso: ./create_dev_session.sh [ttl_segundos]
# Gera um token aleatório, registra em .sessions/ e imprime o token.

set -e
SESSIONS_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/../cgi-bin" && pwd)/.sessions"
mkdir -p "$SESSIONS_DIR"
chmod 700 "$SESSIONS_DIR"

TTL="${1:-3600}"
TOKEN=$(head -c 32 /dev/urandom | sha256sum | cut -d' ' -f1)
HASH=$(printf '%s' "$TOKEN" | sha256sum | cut -d' ' -f1)
EXPIRY=$(($(date +%s) + TTL))

echo "$EXPIRY" > "$SESSIONS_DIR/$HASH"
chmod 600 "$SESSIONS_DIR/$HASH"

echo "Token: $TOKEN"
echo "Expira em: $TTL s"
