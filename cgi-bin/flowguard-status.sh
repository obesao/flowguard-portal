#!/bin/sh
# flowguard-status.sh — status geral do FlowGuard (bps/pps/flows, ataques ativos, top prefixos)

. "$(dirname -- "$0")/lib.sh"

TOKEN=$(parse_param "token")

if ! check_session "$TOKEN"; then
  deny_unauthorized
  exit 0
fi

print_header 200
/root/flowguard/venv/bin/python3 <<'PYEOF'
import json
import sys

sys.path.insert(0, "/root/flowguard")

import yaml
from collector import control, storage

try:
    cfg = yaml.safe_load(open("/root/flowguard/config.yaml", encoding="utf-8"))
    conn = storage.connect(cfg["database"]["path"])
    interval = cfg["database"]["aggregate_interval_s"]
    stats = storage.daemon_stats(conn, window_s=interval)
    top = storage.top_prefixes(conn, window_s=interval, limit=20)
    protocol_series = storage.protocol_timeseries(conn, window_s=300, bucket_s=interval)

    ping = control.send_command(cfg["daemon"]["socket"], {"cmd": "status"}, timeout=1.5)
    daemon = {"alive": bool(ping.get("ok")), "pid": ping.get("pid"), "uptime_s": ping.get("uptime_s")}

    print(json.dumps({
        "ok": True, "stats": stats, "top_prefixes": top,
        "protocol_series": protocol_series, "daemon": daemon,
    }))
except Exception as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
PYEOF
