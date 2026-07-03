# Portal do Provedor

**Versão atual: v1.19.0**

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
9. **Configuração do roteador de borda via templates** — botão "🔧 Config.
   Roteador" (protegido pela mesma senha do Modo Guerra) permite editar a
   config do roteador de borda por templates pré-validados (sem CLI livre):
   exportação de NetFlow, rota estática, ACL simples por prefixo e
   descrição/estado de interface. Fluxo obrigatório de preview → confirmação
   → aplicação, com reversão automática se o operador não confirmar a mudança
   dentro de alguns minutos.
10. **Descoberta de BGP real** — botão "🔍 Ler configuração atual (BGP)" na
    tela de Config. Roteador lê peers e prefixos anunciados de verdade via
    SSH; dois templates novos usam essa lista pra facilitar subir/derrubar a
    sessão com uma operadora específica e anunciar/remover um prefixo da
    lista de IPs advertidos, sem precisar digitar IP na mão.

## Estrutura

| Caminho | Papel |
|---|---|
| `index.html` | Markup das abas/painéis |
| `assets/flowguard.js` | Todo o JS do dashboard (um único módulo IIFE) |
| `cgi-bin/flowguard-*.sh` | Backend do FlowGuard (status, ataques, flows, regras, config, toggles de funções, IA, histórico, config do roteador de borda) |
| `cgi-bin/clientguard-*.sh` | Backend do ClientGuard (status, top clientes, detalhe de cliente, sinais suspeitos, config, toggles de funções) |
| `cgi-bin/lib.sh` | Sessão/autenticação compartilhada por todos os CGI scripts |
| `cgi-bin/flowguard-login.sh` / `flowguard-logout.sh` | Autenticação |
| `scripts/` | Utilitários de administração (não expostos via HTTP) |

## Changelog

### v1.19.0 — 2026-07-02 — Descoberta de BGP real na tela de Config. Roteador
- Botão "🔍 Ler configuração atual (BGP)" no modal de Config. Roteador: lê
  via SSH o AS local, os peers configurados (IP, AS remoto, descrição,
  estado up/down) e os prefixos anunciados, mostrando um resumo em tabela.
- Os templates novos "Subir/derrubar sessão BGP com uma operadora" e
  "Anunciar/remover prefixo da lista de IPs advertidos" passam a usar essa
  descoberta: os campos de peer/prefixo viram um `<select>` com os valores
  reais (em vez de texto livre), e o campo de AS local é preenchido sozinho
  — reduz erro de digitação e evita apontar pra algo que não existe na
  config real. Sem descoberta ainda feita, os campos caem de volta pra texto
  livre (a tela continua utilizável).
- Validado com Playwright real (mock só da chamada SSH de descoberta —
  preview/apply continuam batendo no backend real): resumo da descoberta
  aparece corretamente, selects populados com os peers/prefixos certos,
  campo de AS local somente-leitura, preview reflete a escolha exata de
  peer+ação e prefixo+ação — ver [[feedback-verify-with-real-browser]].

### v1.18.0 — 2026-07-02 — ClientGuard: mitigação direta na borda (SSH/ACL) na aba do portal
- Nova seção "Mitigação direta na borda (SSH/ACL)" na aba ClientGuard —
  independente do bloqueio via FlowSpec (BGP) que já existia: reaproveita as
  credenciais SSH já cadastradas em "⚙️ Modo Guerra" (mesmo padrão do template
  de roteador acima, mas dirigido por sinal de detecção em vez de operador
  escolhendo um template manualmente), sem depender da sessão BGP do FlowGuard
  estar de pé.
- Botão "Aplicar na borda" por linha na tabela de Sinais Suspeitos (só na view
  "Abertos") — aplica um bloqueio de ACL pro `src_ip` daquele sinal
  especificamente. Tabela própria de mitigações ativas/histórico com botão
  "Reverter", e config de gatilho automático por detector (7 checkboxes,
  desabilitados por padrão) + TTL padrão, no mesmo padrão visual/de "aplicar
  em lote" já usado pelos toggles de detecção.
- `cgi-bin/clientguard-edge.sh` (GET lista, POST aplica/reverte) e
  `cgi-bin/clientguard-edge-cfg.sh` (GET/POST do gatilho automático) —
  seguem exatamente o padrão de `clientguard-block.sh`/`clientguard-toggles.sh`
  já existentes; só exigem a sessão normal do portal, sem a segunda senha do
  Modo Guerra (ação mais cirúrgica, 1 IP por vez).
- Achado real durante a validação: `client_flow_aggs` do ClientGuard já
  acumula ~30M linhas — sob esse volume, qualquer comando de leitura pelo
  socket (não só os novos) pode levar 10-20s pra responder quando concorre
  com o ciclo de agregação/detecção pelo mesmo lock, estourando o timeout
  padrão de 6s dos endpoints GET do portal. Pré-existente, mesma classe do
  problema já corrigido no `flow_aggs` do FlowGuard (ver CHANGELOG de lá) —
  não corrigido aqui, fora do escopo desta mudança.

### v1.17.0 — 2026-07-02 — Configuração do roteador de borda via templates
- Novo botão "🔧 Config. Roteador" no topo, protegido pela mesma senha/sessão
  do Modo Guerra (`fg-routercfg-overlay`). Edição só por templates
  pré-validados (exportação de NetFlow, rota estática, ACL simples por
  prefixo, descrição/estado de interface) — sem campo de comando livre em
  lugar nenhum da UI.
- Fluxo: escolher template → preencher campos → "Pré-visualizar comandos"
  (mostra o texto literal que será enviado, e a reversão correspondente,
  antes de qualquer mudança real) → "Aplicar no roteador" com confirmação
  explícita. Depois de aplicar, a mudança fica pendente até o operador clicar
  em "Confirmar mudança" — se não confirmar dentro da janela (padrão 5min,
  contador visível na tela), é revertida sozinha.
- `cgi-bin/flowguard-routercfg.sh` (novo): fala com o novo módulo
  `flowguard/routercfg/` via subprocess Python, mesmo padrão standalone do
  `warmode.yaml`/`warmode/executor.py` (reaproveita as mesmas credenciais SSH
  cadastradas na tela "⚙️ Modo Guerra" — não duplica um segundo arquivo de
  senha do equipamento).
- Validado com Playwright real (desbloqueio, lista de templates, preview
  válido, rejeição de valor malicioso/malformado, tentativa de aplicação
  contra equipamento ainda não configurado) — ver
  [[feedback-verify-with-real-browser]].

### v1.16.0 — 2026-07-02 — Portal persistente via systemd
- `init/flowguard-portal.service` (novo) — o `busybox httpd` que serve o portal
  na porta 18080 sempre foi iniciado manualmente (sem nohup/systemd), então
  morria em qualquer restart/instabilidade do servidor. Agora é uma unit
  systemd de verdade (`Restart=on-failure`, `enabled` — sobe sozinho no boot),
  mesmo padrão de `flowguard.service`/`clientguard.service`. `After=` inclui
  os dois daemons pra não subir o portal antes dos backends que ele consulta.
- Com isso, os três componentes do sistema (FlowGuard, ClientGuard, portal) —
  e a Evolution API via Docker (`RestartPolicy: always`) — sobrevivem a reboot
  sem intervenção manual.

### v1.15.0 — 2026-07-02 — Tela de Alertas via WhatsApp (Evolution API)
- Nova seção "📱 Alertas via WhatsApp" na aba Configuração, compartilhada por
  FlowGuard e ClientGuard (só existe UMA conexão WhatsApp real — Evolution API
  self-hosted em `/root/evolution-api/`). Mostra status da conexão (conectado/
  desconectado + número), permite escanear o QR direto no navegador (sem
  precisar de terminal), escolher o destino dos alertas (grupo do WhatsApp via
  dropdown ou número direto) e mandar mensagem de teste.
- `cgi-bin/flowguard-whatsapp.sh` (novo): GET `status`/`qrcode`/`groups`, POST
  `set_dest`/`test`/`logout` — fala com a Evolution API via
  `/root/evolution-api/client.py` (novo módulo compartilhado, fora de qualquer
  git repo — mesmo padrão do `warmode.yaml`). Exige sessão normal do portal
  (não a segunda senha do Modo Guerra — conectar/desconectar WhatsApp não tem o
  mesmo risco de executar comando em equipamento real).
- Frontend (`flowguard.js`): polling do status a cada 3s só enquanto o QR está
  sendo exibido (pra detectar a conexão automaticamente e esconder o QR),
  seletor de grupo recarrega a lista assim que conecta.
- Validado ponta a ponta com Playwright real (login, aba Configuração, clique
  em "Conectar número", QR real renderizado, mensagem de teste enviada com
  sucesso pro grupo configurado) — ver [[feedback-verify-with-real-browser]].

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
