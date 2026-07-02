#!/bin/sh
# flowguard-history.sh — dados históricos pro dashboard de gráficos:
#   ?metric=prefix&prefix=X&window=1h|6h|24h|7d   -> série de bps/pps do prefixo + baseline
#   ?metric=protocol&window=...                    -> série de bps por protocolo (área empilhada)
#   ?metric=attacks&window=...                      -> ataques no período (timeline/heatmap)
#   ?metric=hosts&prefix=X&window=...               -> top hosts /32 dentro do prefixo

. "$(dirname -- "$0")/lib.sh"

TOKEN=$(parse_param "token")
METRIC=$(parse_param "metric")
WINDOW=$(parse_param "window")
PREFIX=$(parse_param "prefix")

if ! check_session "$TOKEN"; then
  deny_unauthorized
  exit 0
fi

print_header 200
METRIC="$METRIC" WINDOW="$WINDOW" PREFIX="$PREFIX" /root/flowguard/venv/bin/python3 <<'PYEOF'
import json
import math
import os
import sys

sys.path.insert(0, "/root/flowguard")

import yaml
from collector import storage

try:
    metric = os.environ.get("METRIC") or "prefix"
    window = os.environ.get("WINDOW") or "1h"
    prefix = os.environ.get("PREFIX") or ""
    prefix_filter = prefix if prefix and prefix != "__all__" else None

    cfg = yaml.safe_load(open("/root/flowguard/config.yaml", encoding="utf-8"))
    conn = storage.connect(cfg["database"]["path"])
    window_s, bucket_s = storage.pick_window(window)

    protected = yaml.safe_load(open(cfg.get("protected_prefixes_file", "/root/flowguard/protected_prefixes.yaml"), encoding="utf-8")) or []
    protected_meta = {p["prefix"]: p for p in protected if p.get("prefix")}

    if metric == "prefix":
        if prefix == "__all__":
            series = storage.all_prefixes_timeseries(conn, list(protected_meta), window_s=window_s, bucket_s=bucket_s)
            prefixes_out = [
                {"prefix": p, "customer": meta.get("customer") or "", "capacity_mbps": meta.get("capacity_mbps") or 0}
                for p, meta in protected_meta.items()
            ]
            print(json.dumps({"ok": True, "mode": "all", "series": series, "prefixes": prefixes_out}))
        elif not prefix:
            print(json.dumps({"ok": False, "error": "prefix obrigatório para metric=prefix"}))
        else:
            series = storage.prefix_timeseries(conn, prefix, window_s=window_s, bucket_s=bucket_s)
            baseline = storage.get_baseline(conn, prefix)
            detection_cfg = cfg.get("detection", {})
            sigma = detection_cfg.get("baseline_sigma", 4)
            min_samples = detection_cfg.get("baseline_min_samples", 120)
            baseline_out = None
            if baseline and baseline["samples"] >= min_samples:
                bps_std = math.sqrt(max(baseline["bps_var"], 0))
                baseline_out = {
                    "bps_mean": baseline["bps_mean"],
                    "bps_upper": baseline["bps_mean"] + sigma * bps_std,
                    "samples": baseline["samples"],
                }
            capacity_mbps = (protected_meta.get(prefix) or {}).get("capacity_mbps") or 0
            print(json.dumps({"ok": True, "mode": "single", "series": series, "baseline": baseline_out, "capacity_mbps": capacity_mbps}))
    elif metric == "protocol":
        series = storage.protocol_timeseries(conn, window_s=window_s, bucket_s=bucket_s, dst_prefix=prefix_filter)
        print(json.dumps({"ok": True, "series": series}))
    elif metric == "hosts":
        if not prefix or prefix == "__all__":
            print(json.dumps({"ok": False, "error": "prefix obrigatório para metric=hosts"}))
        else:
            hosts = storage.top_hosts_for_prefix(conn, prefix, window_s=window_s, limit=15)
            print(json.dumps({"ok": True, "hosts": hosts}))
    elif metric == "attacks":
        attacks = storage.list_attacks(conn, active_only=False, since_s=window_s, dst_prefix=prefix_filter)
        print(json.dumps({"ok": True, "attacks": attacks}))
    else:
        print(json.dumps({"ok": False, "error": f"metric desconhecido: {metric}"}))
except Exception as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
PYEOF
