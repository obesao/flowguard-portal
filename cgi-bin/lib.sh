#!/bin/sh
# lib.sh — funções compartilhadas pelos CGI scripts do portal (padrão dash/POSIX)

PORTAL_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
SESSIONS_DIR="$PORTAL_ROOT/.sessions"
mkdir -p "$SESSIONS_DIR"
chmod 700 "$SESSIONS_DIR"

# urldecode <string>
urldecode() {
  printf '%b' "$(printf '%s' "$1" | sed 's/+/ /g; s/%\([0-9A-Fa-f][0-9A-Fa-f]\)/\\x\1/g')"
}

# parse_param <name> — lê exclusivamente de $QUERY_STRING (nunca do corpo POST)
parse_param() {
  key="$1"
  val=$(printf '%s' "$QUERY_STRING" | tr '&' '\n' | sed -n "s/^${key}=//p" | head -n1)
  urldecode "$val"
}

# read_post_body — lê exatamente CONTENT_LENGTH bytes do stdin (JSON do POST)
read_post_body() {
  if [ -n "$CONTENT_LENGTH" ] && [ "$CONTENT_LENGTH" -gt 0 ] 2>/dev/null; then
    head -c "$CONTENT_LENGTH"
  fi
}

# check_session <token> — valida sessão por hash de arquivo em $SESSIONS_DIR
check_session() {
  token="$1"
  [ -n "$token" ] || return 1
  hash=$(printf '%s' "$token" | sha256sum | cut -d' ' -f1)
  session_file="$SESSIONS_DIR/$hash"
  [ -f "$session_file" ] || return 1
  expiry=$(cat "$session_file")
  now=$(date +%s)
  if [ "$now" -gt "$expiry" ]; then
    rm -f "$session_file"
    return 1
  fi
  return 0
}

# print_header <http_status> — emite cabeçalho CGI (JSON) seguido de linha em branco
print_header() {
  case "$1" in
    200) echo "Status: 200 OK" ;;
    400) echo "Status: 400 Bad Request" ;;
    401) echo "Status: 401 Unauthorized" ;;
    404) echo "Status: 404 Not Found" ;;
    500) echo "Status: 500 Internal Server Error" ;;
    *) echo "Status: $1" ;;
  esac
  echo "Content-Type: application/json"
  echo ""
}

# deny_unauthorized — atalho para resposta 401 padrão
deny_unauthorized() {
  print_header 401
  echo '{"error":"unauthorized"}'
}
