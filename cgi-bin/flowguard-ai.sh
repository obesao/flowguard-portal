#!/bin/sh
# flowguard-ai.sh — análise ad-hoc de um ataque via API Anthropic (Claude).
# Requer ANTHROPIC_API_KEY em /root/ai/.env (ver config.yaml: ai.env_file).

. "$(dirname -- "$0")/lib.sh"

TOKEN=$(parse_param "token")

if ! check_session "$TOKEN"; then
  deny_unauthorized
  exit 0
fi

if [ "$REQUEST_METHOD" != "POST" ]; then
  print_header 400
  echo '{"ok":false,"error":"use POST com {\"attack_id\": N}"}'
  exit 0
fi

BODY=$(read_post_body)
print_header 200
BODY="$BODY" /root/flowguard/venv/bin/python3 <<'PYEOF'
import json
import os
import sys
import time

sys.path.insert(0, "/root/flowguard")

import yaml
from collector import storage

SYSTEM = """Você é um especialista em segurança de redes para ISP.
Analise eventos de tráfego suspeito detectados por um sistema de análise de flows.
Responda em português, com: tipo de ataque, severidade, origem provável,
impacto estimado, regra FlowSpec recomendada (RFC 5575), ações adicionais."""


def read_api_key(env_file: str) -> str | None:
    try:
        with open(env_file, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("ANTHROPIC_API_KEY="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
    except FileNotFoundError:
        return None
    return None


try:
    body = json.loads(os.environ.get("BODY") or "{}")
    attack_id = body.get("attack_id")
    if not attack_id:
        print(json.dumps({"ok": False, "error": "attack_id obrigatório"}))
        raise SystemExit

    cfg = yaml.safe_load(open("/root/flowguard/config.yaml", encoding="utf-8"))
    ai_cfg = cfg.get("ai", {})
    if not ai_cfg.get("enabled", True):
        print(json.dumps({"ok": False, "error": "análise por IA está desabilitada em config.yaml (ai.enabled)"}))
        raise SystemExit

    env_file = ai_cfg.get("env_file", "/root/ai/.env")
    api_key = read_api_key(env_file)
    if not api_key:
        print(json.dumps({"ok": False, "error": f"ANTHROPIC_API_KEY não encontrada em {env_file} — crie o arquivo com ANTHROPIC_API_KEY=sk-ant-..."}))
        raise SystemExit

    conn = storage.connect(cfg["database"]["path"])
    attack = storage.get_attack(conn, int(attack_id))
    if not attack:
        print(json.dumps({"ok": False, "error": "ataque não encontrado"}))
        raise SystemExit

    protected = yaml.safe_load(open(cfg.get("protected_prefixes_file", "/root/flowguard/protected_prefixes.yaml"), encoding="utf-8")) or []
    entry = next((p for p in protected if p.get("prefix") == attack["dst_prefix"]), {})
    customer_prefixes = [p["prefix"] for p in protected if p.get("customer") == attack.get("customer")]

    now = int(time.time())
    duration_s = (attack["ts_end"] or now) - attack["ts_start"]
    top_sources = json.loads(attack["top_sources"]) if attack.get("top_sources") else []

    user_prompt = f"""
## Evento Detectado: {attack['attack_type']}
Alvo: {attack['dst_prefix']} | Cliente: {attack.get('customer') or '-'}
Início: {attack['ts_start']} | Duração: {duration_s}s

Métricas:
- Volume de pico: {(attack['bps_peak'] or 0) / 1e6:.1f} Mbps ({attack['pps_peak'] or 0:,} pps)
- Top origens: {top_sources or 'não disponível'}

Contexto:
- Prefixos do cliente: {customer_prefixes or [attack['dst_prefix']]}
- Capacidade do link: {entry.get('capacity_mbps', '?')} Mbps

Forneça:
1. Confirmação do tipo de ataque (confiança %)
2. Técnica específica
3. Regra FlowSpec recomendada
4. Ações além do FlowSpec
5. Se for falso positivo, explique
"""

    from anthropic import Anthropic

    client = Anthropic(api_key=api_key)
    model = ai_cfg.get("model_events", "claude-haiku-4-5-20251001")
    resp = client.messages.create(
        model=model,
        max_tokens=1024,
        system=SYSTEM,
        messages=[{"role": "user", "content": user_prompt}],
    )
    analysis = "".join(block.text for block in resp.content if block.type == "text")
    storage.save_ai_analysis(conn, int(attack_id), analysis)
    print(json.dumps({"ok": True, "analysis": analysis}))
except SystemExit:
    pass
except Exception as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
PYEOF
