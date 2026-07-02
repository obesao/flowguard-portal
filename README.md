# Portal POX Network

Dashboard web para operação de rede da POX Network — login único, servido via
`busybox httpd` com backend em CGI scripts (shell POSIX), sem framework.
Hoje integra dois sistemas de detecção que rodam como daemons independentes no
mesmo host, cada um com seu próprio socket Unix de controle:

- **FlowGuard** — detecção/mitigação de DDoS voltada a prefixos monitorados.
- **ClientGuard** — detecção de clientes comprometidos (scan, spam, C2, exfiltração)
  via NetFlow, agregado por cliente em vez de por prefixo de destino.

## Etapas do projeto

1. **Snapshot inicial** — dashboard com abas (Visão Geral, Ataques, Flows, Regras,
   Configuração, Gráficos), KPIs, histórico de ataques, gráficos (tráfego +
   baseline, protocolo, timeline), CRUD de config e integração com o socket de
   controle do FlowGuard.
2. **Login com usuário/senha** — substituiu o token colado manualmente; sessão
   por hash de token com expiração, validada em cada CGI script (`lib.sh`).
3. **Refinamentos na aba Ataques** — paginação, densidade de tabela, ações
   compactas via menu, correção de host `/32` atacado (não só o `/24`), painel
   de detalhe com resumo/métricas por porta/linha do tempo, análise via IA sob
   demanda.
4. **Gráficos** — linhas in/out separadas, eixo de tempo, janela selecionável no
   histórico de ataques.
5. **Aba ClientGuard** — status, top clientes por tráfego, tabela de sinais
   suspeitos (toggle Abertos/Resolvidos) com painel de detalhe mostrando
   evidência e explicação gerada por IA, e CRUD de redes de clientes/whitelist.
   Reaproveita o login/sessão existentes; CGI scripts novos
   (`clientguard-status.sh`, `clientguard-suspicious.sh`, `clientguard-cfg.sh`)
   falam com o socket de controle do ClientGuard, mesmo padrão dos scripts do
   FlowGuard.

## Estrutura

| Caminho | Papel |
|---|---|
| `index.html` | Markup das abas/painéis |
| `assets/flowguard.js` | Todo o JS do dashboard (um único módulo IIFE) |
| `cgi-bin/flowguard-*.sh` | Backend do FlowGuard (status, ataques, flows, regras, config, IA, histórico) |
| `cgi-bin/clientguard-*.sh` | Backend do ClientGuard (status, sinais suspeitos, config) |
| `cgi-bin/lib.sh` | Sessão/autenticação compartilhada por todos os CGI scripts |
| `cgi-bin/flowguard-login.sh` / `flowguard-logout.sh` | Autenticação |
| `scripts/` | Utilitários de administração (não expostos via HTTP) |

## Changelog

### 2026-07-01 — Aba ClientGuard
- Nova aba: status, top clientes, sinais suspeitos com painel de detalhe/IA,
  CRUD de redes de clientes e whitelist.
- Publicado no GitHub.

### 2026-07-01 — Refinamentos de Ataques/Gráficos
- Janela de tempo selecionável no histórico de ataques.
- Detalhe de ataque: resumo, métricas por porta, linha do tempo.
- Botão Fechar nos painéis de detalhe; correção do painel sendo apagado pelo
  polling.
- Rola a página até o painel de detalhes ao clicar.
- Reorganização das tabelas: paginação, densidade, ações compactas.
- Mostra host `/32` atacado/consumindo, não só o `/24`; correção de urldecode.
- Login com usuário/senha no lugar do token colado manualmente.

### 2026-06-30 — Snapshot inicial
- Dashboard com abas, KPIs, histórico de ataques, gráficos, CRUD de config e
  integração com o socket de controle do FlowGuard.
