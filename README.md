# Portal do Provedor

**Versão atual: v1.5.0**

Dashboard web para operação de rede do provedor — login único, servido via
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
6. **Gráficos interativos** — hover com crosshair/tooltip nos 3 gráficos de
   canvas (tráfego, protocolo, timeline de ataques), preenchimento de área,
   gap visual entre segmentos empilhados, canvas em alta resolução (HiDPI),
   clique num ataque na timeline pula direto pro histórico filtrado da aba
   Ataques, setas de tendência nos KPIs, barra de proporção na tabela de top
   hosts, e correção de um bug real (header `Connection: close` ausente nas
   respostas CGI, que deixava o gráfico de protocolo em branco).

## Estrutura

| Caminho | Papel |
|---|---|
| `index.html` | Markup das abas/painéis |
| `assets/flowguard.js` | Todo o JS do dashboard (um único módulo IIFE) |
| `cgi-bin/flowguard-*.sh` | Backend do FlowGuard (status, ataques, flows, regras, config, IA, histórico) |
| `cgi-bin/clientguard-*.sh` | Backend do ClientGuard (status, top clientes, detalhe de cliente, sinais suspeitos, config) |
| `cgi-bin/lib.sh` | Sessão/autenticação compartilhada por todos os CGI scripts |
| `cgi-bin/flowguard-login.sh` / `flowguard-logout.sh` | Autenticação |
| `scripts/` | Utilitários de administração (não expostos via HTTP) |

## Changelog

### v1.5.0 — 2026-07-01 — Top Clientes por Consumo de Dados
- Seção "Top Clientes por Tráfego" da aba ClientGuard virou "Top Clientes por
  Consumo de Dados": seletor de janela (1h/6h/24h/7d), mais colunas (pacotes,
  flows), e botão "Detalhes" por linha.
- Painel de detalhe por cliente: gráfico de tráfego ao longo do tempo
  (reaproveita `drawLineChart`, o mesmo motor de canvas dos gráficos do
  FlowGuard) e tabela de top destinos (dst_ip, protocolo, porta, ASN/país via
  GeoIP, tráfego, pacotes).
- CGI scripts novos: `clientguard-top.sh` (janela configurável) e
  `clientguard-client-detail.sh` (série temporal + top destinos de um
  cliente). `clientguard-status.sh` simplificado — não busca mais "top" junto
  do status (isso virou responsabilidade do endpoint dedicado).

### v1.4.0 — 2026-07-01 — Gráficos interativos e correção de bug
- Hover com crosshair + tooltip nos 3 gráficos de canvas (tráfego do prefixo,
  protocolo, timeline de ataques).
- Preenchimento de área sob a linha "entrada" e sob a faixa de baseline
  (contorno tracejado pra não sumir quando é bem menor que o pico real).
- Gap de 2px entre segmentos do gráfico de protocolo (área empilhada).
- Canvas em alta resolução (`devicePixelRatio`) — antes ficava borrado ao
  esticar via CSS pra largura real do card.
- Clique num ataque na timeline pula direto pro histórico filtrado da aba
  Ataques (view, janela e filtro de prefixo já preenchidos).
- Setas de tendência (▲/▼ vs. último minuto) nos KPIs de Tráfego e Pacotes/s.
- Barra de proporção na tabela de "Top hosts no prefixo".
- Sparklines da Visão Geral ganharam preenchimento de área e linha de
  referência de escala.
- Estado de "Carregando…" nos 3 gráficos, com aviso específico se a consulta
  demorar (histórico grande pode levar até ~1 min).
- **Bug corrigido**: `cgi-bin/lib.sh` não enviava `Connection: close` —
  sob HTTP/1.1 sem `Content-Length`/chunked, o browser ficava esperando o
  fechamento da conexão pra considerar o corpo completo. Não era a causa
  principal do gráfico de protocolo ficar em branco (isso era uma consulta
  SQL genuinamente lenta — ver nota no repositório `flowguard`), mas é uma
  correção de HTTP correta e válida para todos os endpoints.

### v1.3.0 — 2026-07-01 — Aba ClientGuard
- Nova aba: status, top clientes, sinais suspeitos com painel de detalhe/IA,
  CRUD de redes de clientes e whitelist.
- Publicado no GitHub.

### v1.2.0 — 2026-07-01 — Refinamentos de Ataques/Gráficos
- Janela de tempo selecionável no histórico de ataques.
- Detalhe de ataque: resumo, métricas por porta, linha do tempo.
- Botão Fechar nos painéis de detalhe; correção do painel sendo apagado pelo
  polling.
- Rola a página até o painel de detalhes ao clicar.
- Reorganização das tabelas: paginação, densidade, ações compactas.
- Mostra host `/32` atacado/consumindo, não só o `/24`; correção de urldecode.
- Login com usuário/senha no lugar do token colado manualmente.

### v1.0.0 — 2026-06-30 — Snapshot inicial
- Dashboard com abas, KPIs, histórico de ataques, gráficos, CRUD de config e
  integração com o socket de controle do FlowGuard.
