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

    protected = yaml.safe_load(open(cfg.get("protected_prefixes_file", "/root/flowguard/protected_prefixes.yaml"), encoding="utf-8")) or []
    prefix_list = [p["prefix"] for p in protected if p.get("prefix")]
    prefix_stats = storage.stats_for_prefixes(conn, prefix_list, window_s=interval)
    top = [
        {
            "dst_prefix": p["prefix"], "customer": p.get("customer") or "",
            "bps": prefix_stats.get(p["prefix"], {}).get("bps", 0),
            "pps": prefix_stats.get(p["prefix"], {}).get("pps", 0),
        }
        for p in protected if p.get("prefix")
    ]

    protocol_series = storage.protocol_timeseries(conn, window_s=300, bucket_s=interval)

    ping = control.send_command(cfg["daemon"]["socket"], {"cmd": "status"}, timeout=1.5)
    daemon = {"alive": bool(ping.get("ok")), "pid": ping.get("pid"), "uptime_s": ping.get("uptime_s")}

    bgp_resp = control.send_command(cfg["daemon"]["socket"], {"cmd": "bgp_status"}, timeout=1.5)
    bgp = bgp_resp if bgp_resp.get("ok") else {"ok": False, "peer_state": "down", "detail": bgp_resp.get("error")}

    print(json.dumps({
        "ok": True, "stats": stats, "top_prefixes": top,
        "protocol_series": protocol_series, "daemon": daemon, "bgp": bgp,
    }))
except Exception as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
PYEOF
