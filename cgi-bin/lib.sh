#!/bin/sh
# lib.sh — funções compartilhadas pelos CGI scripts do portal (padrão dash/POSIX)

PORTAL_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PYTHON_BIN="/root/flowguard/venv/bin/python3"
SESSIONS_DIR="$PORTAL_ROOT/.sessions"
mkdir -p "$SESSIONS_DIR"
chmod 700 "$SESSIONS_DIR"

# urldecode <string> — sob dash (o /bin/sh real usado pelo httpd), printf '%b'
# não decodifica \xHH (é extensão do bash, não POSIX) — silenciosamente devolvia
# o valor cru sempre que um parâmetro tinha "%XX" (ex: "/" em prefix=X%2F24).
# Só chama python (mais caro) quando há de fato algo a decodificar.
urldecode() {
  case "$1" in
    *%*|*+*) "$PYTHON_BIN" -c "import sys, urllib.parse as u; sys.stdout.write(u.unquote_plus(sys.argv[1]))" "$1" ;;
    *) printf '%s' "$1" ;;
  esac
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
#
# "Connection: close" é essencial aqui: sem Content-Length (não dá pra
# calcular de antemão em scripts que fazem streaming de saída) nem
# Transfer-Encoding: chunked, um cliente HTTP/1.1 assumindo keep-alive não
# tem como saber onde o corpo termina — o browser fica esperando o fechamento
# da conexão, e pra respostas maiores isso já causou hangs de dezenas de
# segundos até o timeout. Forçar o fechamento elimina a ambiguidade.
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
  echo "Connection: close"
  echo ""
}

# deny_unauthorized — atalho para resposta 401 padrão
deny_unauthorized() {
  print_header 401
  echo '{"error":"unauthorized"}'
}
