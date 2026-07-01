#!/bin/sh
# flowguard-logout.sh — GET ?token=... -> invalida a sessão (remove o arquivo em .sessions)

. "$(dirname -- "$0")/lib.sh"

TOKEN=$(parse_param "token")
if [ -n "$TOKEN" ]; then
  HASH=$(printf '%s' "$TOKEN" | sha256sum | cut -d' ' -f1)
  rm -f "$SESSIONS_DIR/$HASH"
fi

print_header 200
echo '{"ok":true}'
