# Portal do Provedor

**Versão atual: v1.14.0**

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
7. **Configurações do ClientGuard** — seção nova na aba ClientGuard com um
   checkbox por detector/função (liga/desliga individualmente via
   `clientguard-toggles.sh`, novo) e um botão "Limpar hosts suspeitos" que
   marca todos os sinais abertos como resolvidos de uma vez (com confirmação).
8. **Configurações do FlowGuard** — mesma ideia aplicada ao FlowGuard: seção
   "Funções de Detecção" na aba Configuração (checkbox por tipo de ataque —
   volumétrico, 5 amplificações, anomalia de baseline) e botão "Limpar hosts
   suspeitos" na aba Ataques, que dispensa todos os ataques ativos de uma vez.

## Estrutura

| Caminho | Papel |
|---|---|
| `index.html` | Markup das abas/painéis |
| `assets/flowguard.js` | Todo o JS do dashboard (um único módulo IIFE) |
| `cgi-bin/flowguard-*.sh` | Backend do FlowGuard (status, ataques, flows, regras, config, toggles de funções, IA, histórico) |
| `cgi-bin/clientguard-*.sh` | Backend do ClientGuard (status, top clientes, detalhe de cliente, sinais suspeitos, config, toggles de funções) |
| `cgi-bin/lib.sh` | Sessão/autenticação compartilhada por todos os CGI scripts |
| `cgi-bin/flowguard-login.sh` / `flowguard-logout.sh` | Autenticação |
| `scripts/` | Utilitários de administração (não expostos via HTTP) |

## Changelog

### v1.14.0 — 2026-07-02 — Seção Mitigação na aba Configuração
- Uma linha por tipo de ataque: select de estratégia (RTBH / Descartar via
  FlowSpec / Limitar banda via FlowSpec), limiar de tamanho de pacote (só
  `dns_amp`/`ntp_amp`) e limite de banda em Mbps. Botão "Salvar configurações
  de mitigação" manda só os tipos realmente alterados numa única requisição
  (mesmo padrão em lote do botão de toggles de Funções de Detecção).
- `flowguard-attacks.sh` (novo import: `mitigation_profiles.yaml`) repassa o
  perfil configurado pro `suggest_mitigation()`, tanto na coluna de sugestão
  da listagem quanto no botão "Aplicar Sugestão". `flowguard-mitigation-cfg.sh`
  (novo) expõe leitura/gravação via socket do daemon.

### v1.13.0 — 2026-07-02 — Otimiza "Aplicar novas configurações": 1 requisição em lote
- Botão agora mostra quantas mudanças estão pendentes ("Aplicar 3
  alterações") e some/reaparece corretamente se o usuário desmarcar e
  remarcar de volta ao valor já salvo (a chave sai da lista de pendências —
  evita mandar uma "mudança" que não muda nada).
- Aplicar manda 1 requisição `{ toggles: {...} }` com todas as mudanças de
  uma vez, em vez de 1 requisição por checkbox em paralelo. Corrige uma race
  condition real do lado do ClientGuard (socket atende em threads de
  verdade — duas requisições concorrentes podiam intercalar leitura/escrita
  de `toggles.yaml` e perder uma mudança) e reduz custo do lado do FlowGuard.
  `clientguard-toggles.sh`/`flowguard-toggles.sh` aceitam o novo formato em
  lote além do `{ key, value }` de antes.

### v1.12.0 — 2026-07-02 — Botão "Aplicar novas configurações" nos toggles
- Checkbox de função/detector deixou de aplicar na hora — agora só marca a
  mudança como pendente (feedback visual imediato) até o usuário clicar em
  "Aplicar novas configurações", nas duas telas (ClientGuard e FlowGuard).
  Permite mexer em várias funções de uma vez e confirmar tudo junto.

### v1.11.0 — 2026-07-02 — Configurações do FlowGuard: liga/desliga tipos de ataque + limpar ativos
- Nova seção "Funções de Detecção" na aba Configuração: um checkbox por tipo
  de ataque (DDoS volumétrico, amplificação DNS/NTP/SSDP/Memcached/CLDAP,
  anomalia de baseline) — chama `flowguard-toggles.sh` (novo) na hora.
- Botão "Limpar hosts suspeitos" na aba Ataques — com confirmação, marca
  todos os ataques ativos como dispensados via `flowguard-attacks.sh`
  (`action: "dismiss_all"`, novo — reaproveita o endpoint de mitigação já
  existente em vez de criar outro).
- Validado com Playwright real contra o daemon em produção, e com um ataque
  sintético de verdade (`tools/synth_netflow.py dns_amp`) pra confirmar que
  desabilitar um tipo específico realmente impede aquele tipo de disparar
  (sem afetar os outros — o mesmo tráfego ainda abriu `ddos_volumetrico`).

### v1.10.0 — 2026-07-02 — Configurações do ClientGuard: liga/desliga funções + limpar suspeitos
- Nova seção "Configurações — Funções do ClientGuard" na aba ClientGuard: um
  checkbox por detector (scan horizontal/vertical, amplificador, spam,
  contato malicioso, destino coordenado, túnel DNS) e pela explicação por IA
  — cada mudança chama `clientguard-toggles.sh` (novo) na hora, sem precisar
  salvar/recarregar página.
- Botão "Limpar hosts suspeitos" na seção Sinais Suspeitos — com confirmação
  (ação em lote, não tem desfazer), marca todos os sinais abertos como
  resolvidos via `clientguard-suspicious.sh` (`clear_all: true`, novo).
- Validado com Playwright real contra o daemon em produção: checkboxes
  refletem o estado real na carga, alternar liga/desliga persiste no backend
  (confirmado via `clientguard-cli toggles list`), 0 erros de console.

### v1.9.1 — 2026-07-02 — Exige a senha do Modo Guerra também pra executar
- Antes só a configuração pedia a senha extra; agora executar (o botão
  "🚨 Modo Guerra") também exige — mesma sessão de 15min compartilhada entre
  as duas telas.

### v1.9.0 — 2026-07-02 — Configuração do Modo Guerra protegida por senha própria
- Botão "⚙️ Modo Guerra" abre um editor de equipamentos (host, porta, tipo,
  usuário, senha, comandos) — mas atrás de uma segunda senha, separada do
  login do portal: primeiro acesso pede pra definir; depois disso, sempre
  pede a senha antes de mostrar qualquer coisa. Sessão desse desbloqueio
  dura 15min e some se recarregar a página; dá pra trocar a senha (com a
  atual) e bloquear manualmente a qualquer momento.
- Senha nunca é reexibida — editar um equipamento sem mexer no campo senha
  mantém a já salva.

### v1.8.0 — 2026-07-02 — Botão "Modo Guerra"
- Botão vermelho fixo no topo (qualquer aba) abre um modal listando os
  equipamentos configurados no FlowGuard (`warmode.yaml`) e quantos comandos
  cada um vai rodar. Confirmar executa via SSH em paralelo em todos e mostra
  sucesso/erro + saída por equipamento.
- Pensado pra cenário de DDoS massivo: aplicar mitigação de borda em vários
  equipamentos físicos do datacenter de uma vez, sem terminal por terminal.

### v1.7.0 — 2026-07-02 — Bloqueio manual de IP (FlowGuard + ClientGuard)
- Aba Regras: formulário "Bloquear IP manualmente" cria uma regra FlowSpec
  discard por origem direto, sem precisar de um ataque associado.
- Aba ClientGuard: mesmo formulário, pra bloquear cliente abusivo — mesma
  regra/tabela de FlowSpec do FlowGuard por baixo (proxy via socket).
- Tabela de Regras FlowSpec ganhou coluna "Origem" (antes só mostrava
  Destino, escondendo bloqueios por origem).

### v1.6.0 — 2026-07-02 — Indicador de status BGP (Up/Down) na Visão Geral
- Novo KPI "BGP (ExaBGP)" ao lado do KPI "Daemon": ponto verde "Up" com o IP
  do peer, ou vermelho "Down/Idle" com o motivo — `flowguard-status.sh` passa
  a consultar o comando `bgp_status` do daemon.

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
