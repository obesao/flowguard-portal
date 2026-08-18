# Portal do Provedor

**Versão atual: v1.61.0**

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
11. **Perfil de operadora + interfaces/VLANs + 5 templates novos** — botão
    "Ver rotas" em cada peer da tabela de descoberta mostra as rotas
    anunciadas/recebidas de verdade pra aquela operadora (alternável). A
    descoberta ganhou tabelas de Interfaces e VLANs; qualquer template com
    campo de interface (não só os de BGP) passa a usar essa lista real.
    Templates novos: criar/remover VLAN, VLAN numa porta trunk, IP numa
    interface, criar/remover sub-interface 802.1Q.
12. **Refinamentos visuais/UX** — paleta unificada em variáveis CSS, fonte de
    sistema, ícones SVG no lugar de emoji nos botões/títulos, transição suave
    ao trocar de aba/toast, estados de carregamento com skeleton animado,
    contorno de foco visível pra navegação por teclado, e tabelas legíveis
    (quebra de linha em vez de recorte) em telas estreitas.
13. **Aba Incidentes** — unifica Ataques (FlowGuard) e Sinais Suspeitos
    (ClientGuard) numa aba só, com toggle entre os dois lados, chips de
    severidade, agrupamento por prefixo/cliente, seleção em lote, linha do
    tempo/nota/export no detalhe, e o gráfico de tráfego ganhou faixas de
    anomalia por severidade + marcadores de evento sobrepostos.
14. **Redes do ClientGuard no gráfico de tráfego** — o seletor de barramento
    da aba Gráficos passou a listar também as redes de cliente do
    ClientGuard (ex: CGNAT), com série de tráfego agregada por rede inteira
    e top clientes daquela rede; janelas longas (24h/7d) ficam desabilitadas
    nesse modo até um índice pendente ser construído (`client_flow_aggs` tem
    280M linhas hoje).
15. **Scanners Detectados dentro de Incidentes** — a detecção de port scan
    (antes só uma tabela somente-leitura em Configuração) virou seção
    própria na aba Incidentes (lado FlowGuard), com toggle Ativos/Histórico,
    paginação, severidade estimada, badge somado e botão de bloqueio manual.

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

### v1.72.0 — 2026-08-18 — Listas de IP no detalhe do ataque preenchem o card

"Host(s) atacado(s)" e "IPs de origem observados" (detalhe do ataque, botão
"Detalhes") eram `<ul>` de 1 coluna só — com até 20 itens curtos (IP + ciclo),
a lista ficava espremida à esquerda, sobrando boa parte do card vazia à
direita (visualmente ~75%), destoando da tabela "Tráfego por protocolo/porta"
logo abaixo, que já usa a largura toda. Adicionada classe `.fg-ip-list`
(`column-width: 260px`) — o navegador decide quantas colunas cabem e
preenche a largura do card sozinho, sem JS extra pra calcular grid. Efeito
colateral bom: 20 itens que antes ocupavam 20 linhas agora cabem em ~7,
menos scroll no card.

### v1.71.0 — 2026-08-18 — KPI cards do topo reduzidos (tela pequena)

Os 7 cards de KPI no topo de cada aba (Tráfego, Pacotes/s, Ataques Ativos,
Regras FlowSpec, Mitigações de Borda, BGP, Daemon) ficavam grandes demais
num MacBook 11" (viewport ~1366px) — quebravam em 2 linhas altas.
Reduzidos: padding (`--space-4/5` → `--space-3/4`), valor
(`--text-xl` → `--text-lg`), largura mínima da grade (160px → 140px) e gap
(`--space-4` → `--space-3`). Resultado: os 7 cabem numa linha só em 1366px
de largura. `.fg-bgp-peer` (texto interno do card BGP) acompanhou a redução
proporcional (`--text-base` → `--text-sm`) pra continuar menor que o valor
padrão de KPI, mesma relação documentada no comentário original.

### v1.70.0 — 2026-08-18 — Incidentes: FlowGuard e ClientGuard viram cards separados

Reverte o layout lado a lado da v1.68.0: com ataque ativo a tabela de
ataques (10 colunas) ficava espremida em meia largura. Agora são 3 cards
full-width empilhados — FlowGuard (Ataques DDoS), ClientGuard (Sinais
Suspeitos), Outras Detecções (Scanners/Destino Coordenado) — mesmo padrão
já usado na aba Regras (`#fg-rules-nav` fora das seções, seções empilhadas
abaixo). Barra "Ir para" fica fora de qualquer card, só rola até o alvo.

Removido `.fg-incidents-columns`/`.fg-incidents-column-title` (CSS morto da
v1.68.0). Achado durante a implementação: o `<h2>` de cada card ganha um
botão de colapso injetado por `initCollapsiblePanels()` que usa
`display:flex; justify-content:space-between` — um `<span>` de subtítulo
dentro do `<h2>` virava um 3º item flex e ficava espremido entre o título e
o botão. Corrigido deixando o `<h2>` só com texto puro (`FlowGuard`/
`ClientGuard`), igual todo outro título de card do sistema.

### v1.69.0 — 2026-08-18 — Incidentes: Scanners/Destino Coordenado em card separado

Ajuste sobre a v1.68.0 (FlowGuard/ClientGuard lado a lado): "Scanners
Detectados" e "Destino Coordenado" saíram de dentro da coluna FlowGuard e
foram pra um card próprio ("Outras Detecções (FlowGuard)"), logo abaixo do
card onde Ataques DDoS/Sinais Suspeitos ficam lado a lado — são sinais menos
urgentes que ataque DDoS confirmado, então ganham menos destaque visual sem
sumir da aba. Mesmo `id` nos dois blocos (`fg-sub-scanners`,
`fg-sub-coordinated`), então a barra "Ir para" continua rolando pro lugar
certo sem mudança de JS. Ganhou colapso de painel automático de graça (mesmo
mecanismo de todo `section.fg-panel-section`).

### v1.68.0 — 2026-08-18 — Incidentes: FlowGuard/ClientGuard lado a lado + barra de intensidade em ataques

Mudança de layout pedida separadamente do redesign de 8 fases anterior
(ver v1.61.0-v1.67.0 abaixo) — aba Incidentes:

- **FlowGuard e ClientGuard lado a lado**: antes era um toggle A/B
  (`#incidents-app-toggle`, `[hidden]`) que só mostrava um lado por vez.
  Agora os dois ficam em colunas permanentemente visíveis
  (`.fg-incidents-columns`, grid 2 colunas — empilha em 1 coluna abaixo de
  700px, mesmo breakpoint do resto do sistema), cada uma com cabeçalho
  próprio (FlowGuard em azul, ClientGuard em roxo — mesma convenção de cor
  já usada no widget do cockpit). Os dois lados já eram sempre polados juntos
  (`poll()` nunca dependeu do toggle), então a mudança é só CSS/markup —
  removido `setIncidentsApp()`, o estado `incidentsApp` e o toggle A/B; a
  barra "Ir para" só rola até a subseção agora (não troca mais de lado antes).
- **Barra de intensidade nos ataques DDoS**: colunas "Pico (bps)" e "Pico
  (pps)" da tabela de ataques ganharam uma barra horizontal (mesmo
  componente `fg-hbar-wrap` já usado em Top Clientes), proporcional ao pico
  da lista filtrada inteira (não só a página atual, pra escala não pular ao
  paginar) e colorida pela severidade do ataque (`SEV_COLORS` — crítico
  salta aos olhos em vermelho), em vez de só o número cru.

### v1.67.0 — 2026-08-18 — Fase 8/8 do redesign: verificação final

Oitava e última fase — fecha o redesign visual/CSS iniciado no audit Dieter
Rams (16/30, veredito REDESIGN; ver fase 1/8 abaixo pro início da execução).

- **Drift residual da fase 2 corrigido**: a verificação (`grep -oE
  '[0-9.]+rem' index.html | sort -u`) apontou 22 valores distintos ainda
  restantes, contra o esperado ~15 tokens da escala — 9 literais no bloco
  `<style>` que a migração original não tinha coberto (`.fg-dot`,
  `.fg-skeleton-sm`, skeleton genérico, `.fg-toggle-item` checkbox,
  `#fg-toast-container`, `.fg-hbar-wrap`/`.fg-hbar-label`,
  `.fg-wm-chevron-btn`). Remapeados pro degrau mais próximo da escala
  (`--space-4/5/6/7`), fechando a consolidação. Ficaram de fora, por decisão
  deliberada (fora do escopo original de migração, que mirava o bloco
  `<style>`): 2 valores em `style=""` inline soltos no markup (`1.3rem` no
  `<h1>` do topbar, `6rem` num `<input>`).
- **Cores**: confirmado que os 14 literais hex restantes em `flowguard.js`
  são só a declaração única do objeto `FG_COLORS` (necessário porque canvas
  2D não resolve `var()` CSS) — zero uso solto fora dela.
- **Código morto**: confirmado zero ocorrência de `COCKPIT_JUMP_TARGETS`,
  `cockpitJumpToWidget`, `.fg-statusbar`, `.fg-cockpit-mini-kpis`,
  `CG_EDGE_CFG_ENDPOINT`.
- **Regressão funcional**: revalidado com Playwright — navegação entre as 7
  abas, ordenação de tabela (`aria-sort` alterna corretamente), colapso de
  painel, e o modal "Modo Guerra" completo (abre, `Escape` fecha, foco
  retorna pro botão que abriu). Zero erro de console em toda a sessão.
- **Escopo do diff**: `git diff --stat` desde antes da fase 1 mostra mudança
  concentrada em exatamente 3 arquivos — `index.html`, `assets/flowguard.js`
  e `README.md` — nenhuma lógica de negócio, endpoint ou contrato de API
  tocado em nenhuma das 8 fases.

### v1.66.0 — 2026-08-18 — Fase 7/8 do redesign: polimento de estados de erro

Sétima fase do redesign (ver fases anteriores abaixo):

- **Vazamento de erro cru (WhatsApp groups)**: `loadWaGroups` mostrava
  `data.error` verbatim dentro do `<option>` quando a chamada falhava — se o
  backend devolvesse algo tipo "HTTP Error 500", isso aparecia cru pro
  operador. Agora sempre mostra mensagem amigável fixa; o erro real vai só
  pro `console.error`, mesmo padrão já usado pelos `.catch` vizinhos do
  arquivo.
- **Label desalinhado do rótulo real**: botão "Limpar hosts suspeitos"
  renomeado pra "Marcar hosts suspeitos como resolvidos" — a ação real
  (`onCgClearSuspiciousClick`) marca sinais como resolvidos, não apaga nada
  (histórico preservado, já descrito corretamente no `confirm()` existente).
  Mesmo `id`/handler, só o texto visível muda.

### v1.65.0 — 2026-08-18 — Fase 6/8 do redesign: acessibilidade dos cockpit cards + skip link

Sexta fase do redesign (ver fases anteriores abaixo):

- **Cockpit cards clicáveis (rules, clientguard, mitigations)**: o corpo do
  card agora fica dentro de um `<button type="button" class="fg-cockpit-card-trigger">`
  nativo (reset visual completo, sem mudar aparência), em vez de depender só
  de `cursor:pointer` num `<div>`. Ganha foco/teclado de graça — Tab alcança
  o card, Enter/Espaço abre o popover — sem reescrever o listener delegado
  (que já escuta `"click"`, disparado nativamente pelo botão). Desvio do
  plano original (que previa envolver `<h3>` + corpo): o `<h3>` ficou de fora
  do botão pra não quebrar o layout flex existente de `.fg-cockpit-card-head`
  (checkbox de visibilidade + drag handle + título na mesma linha); o popover
  é anexado como irmão do botão, então não há conteúdo interativo aninhado
  dentro dele. Os 6 cards não-clicáveis continuam sem tabstop.
- **Skip link**: `<a class="fg-skip-link" href="#fg-main-content">Pular para
  o conteúdo</a>` como primeiro elemento tabável da página (invisível até
  foco). `<main>` ganhou `id="fg-main-content"` e `tabindex="-1"` — sem o
  `tabindex`, o `<a href="#...">` só rolava a página até o alvo mas não
  movia o foco de teclado pra lá (achado durante a verificação com
  Playwright); com `tabindex="-1"` o foco chega de fato no conteúdo.
- Validado com Playwright: 1º Tab da página cai no skip link, Enter move o
  foco pro `<main>`; os 3 triggers recebem foco e abrem popover com
  Enter/Espaço; card não-clicável (`traffic`) confirmado sem trigger. Zero
  erro de console, zero mudança visual fora do estado de foco.

### v1.64.0 — 2026-08-18 — Fases 4-5/8 do redesign: consentimento e jargão explicado

Quarta e quinta fases do redesign (ver fases anteriores abaixo) — camada de
apresentação, sem mudança de payload/endpoint/lógica de negócio:

- **Botão "Mitigar" (RTBH)**: ganhou `title` explicativo e `confirm()` antes
  de disparar a ação — hoje o único aviso de que "Mitigar" sempre bloqueia o
  prefixo INTEIRO via RTBH (BGP blackhole) estava num parágrafo em outra aba.
  Mesmo padrão de confirmação já usado em "Apagar todas as regras".
- **Jargão explicado no ponto de uso** (`title`/`hint`, sem mudar rótulo
  visível, exceto onde indicado): chip de severidade "watch", opção "RTBH
  (blackhole)" no filtro de regras, título do card cockpit "BGP (ExaBGP)",
  status "Down/Idle" de peer BGP, KPI "Daemon" (FlowGuard e ClientGuard),
  coluna "ASN/País" no detalhe de cliente.

### v1.63.0 — 2026-08-18 — Fase 3/8 do redesign: remoção de código morto

Terceira fase do redesign (ver fases 1/8 e 2/8 abaixo). Remove caminhos de
código confirmados sem uso via grep, sem mudança de comportamento observável:

- CSS órfão: `.fg-statusbar`, `.fg-cockpit-mini-kpis` (sem markup correspondente).
- `CG_EDGE_CFG_ENDPOINT` (`assets/flowguard.js`): constante declarada, nunca lida.
- Mecanismo `COCKPIT_JUMP_TARGETS`: mapa sempre vazio desde sua criação — a
  função `cockpitJumpToWidget` era um no-op garantido. Removidos o mapa, a
  função e o branch que a chamava no listener de clique dos cockpit cards;
  `jumpable` em `cockpitCardHtml` agora depende só de `COCKPIT_POPOVER_TARGETS`.
- Validado com Playwright: os 3 cards clicáveis (Regras, ClientGuard,
  Mitigações) continuam abrindo popover normalmente; os outros 6 cards
  seguem não-interativos, comportamento idêntico ao anterior.

### v1.62.0 — 2026-08-18 — Fase 2/8 do redesign: tokens de espaçamento e tipografia

Segunda fase do redesign visual (ver fase 1/8 na v1.61.0 abaixo — consolidação
de cores). Substitui valores `rem` literais espalhados em `index.html` por
variáveis CSS centralizadas em `:root`:

- **Escala de espaçamento**: `--space-1` a `--space-8` (0.2rem a 4rem)
  substituindo `margin`/`padding`/`gap` hardcoded em todo o CSS.
- **Escala tipográfica**: `--text-xs` a `--text-2xl` (0.72rem a 1.8rem)
  substituindo `font-size` hardcoded.
- Zero mudança visual, zero mudança de lógica/API — só consolidação de fonte
  única de valor, mesmo princípio da fase 1. Validado com screenshots
  Playwright (dashboard completo + componentes) antes/depois da mudança.

### v1.61.0 — 2026-07-17 — Segunda rodada de acessibilidade: viewport mobile, contraste, teclado, performance de poll

Auditoria técnica de acompanhamento (16 issues, P0→P3) sobre o que a rodada
`impeccable` da v1.60.0 não cobriu — todos corrigidos nesta versão:

- **P0 — viewport meta ausente**: `<meta name="viewport" content="width=
  device-width, initial-scale=1">` nunca existia no `<head>` — sem ela,
  todo o CSS responsivo/touch-target da v1.60.0 ficava inerte em celular
  real (o browser mobile renderiza a página numa viewport virtual larga e
  dá zoom-out, ignorando os breakpoints). Validado com Playwright em
  390×844: o card de login agora reduz corretamente pra ~340px de largura.
- **Contraste de badges abaixo de AA**: `.fg-badge` (contagem de alerta,
  fundo vermelho sólido) usava texto branco — media 3.35:1, abaixo do
  mínimo de 4.5:1. Trocado pra `var(--fg-bg)` (mesmo tom escuro já usado em
  `.fg-btn-danger`, que mede 5.65:1). O selo `WARMODE-ON` (texto
  `--fg-danger` sobre fundo vermelho translúcido) media 3.84–4.12:1
  dependendo se a topbar inteira também está pulsando — trocado pro tom
  mais claro `--fg-danger-hover` (#ff7b72), que garante ≥5.4:1 nos dois
  cenários mantendo a identidade "alerta vermelho".
- **Toast sem `aria-live`**: `#fg-toast-container` ganhou `role="status"
  aria-live="polite"`; `showToast()` agora alterna o próprio `aria-live`
  pra `"assertive"` quando o toast é de erro, pra leitor de tela não
  esperar uma pausa de fala antes de anunciar uma falha.
- **Ordenação de tabela só por mouse**: cabeçalhos `<th data-sort-key>` só
  respondiam a `click`. Cada label agora vive dentro de um `<button>`
  interno (foco/Enter/Espaço nativos, sem handler novo — o `click`
  sintético do teclado já é escutado pelo listener delegado existente) e
  ganhou `aria-sort="ascending"|"descending"|"none"`; todo `<th>` do
  sistema (ordenável ou não) ganhou `scope="col"`.
- **Performance/UX do poll de ~5s**: `poll()` reconstruía listas via
  `innerHTML` a cada ciclo mesmo sem dado novo, fechando qualquer menu de
  ações aberto no meio do trabalho do operador. Duas guardas: (a) hash do
  payload por endpoint (`pollPayloadUnchanged`) pula o re-render quando o
  dado é idêntico ao ciclo anterior; (b) o ciclo inteiro é adiado pro
  próximo tick se houver um menu de ações aberto (`.fg-menu-list:not(
  [hidden])`) no momento do poll.
- **Aba em segundo plano continuava fazendo poll de 5s**: `visibilitychange`
  agora reduz a frequência pra 45s quando `document.hidden`, e faz um poll
  imediato + retoma 5s assim que a aba volta a ficar visível.
- **Formulários dinâmicos sem `<label for>`**: os campos de config gerados
  por JS (equipamentos do Modo Guerra, `renderFgDetectionCfg`/
  `renderCgDetectionCfg`, `renderKvFields` usado por scan/escalation)
  tinham `<label>` visual solto, sem `for`/`id` nem input aninhado —
  ganharam `id` gerado a partir da chave do campo + `for` correspondente,
  ou passaram a envolver o input/textarea dentro do próprio `<label>`.
- **Estados sem ARIA**: `.fg-toggle-btn`/abas `.fg-tab-btn`/botões-toggle
  genéricos (`Agrupar por prefixo`, `Selecionar`) só tinham a classe
  visual `.active` — um helper único (`setActive()`) sincroniza a classe
  com `aria-pressed` (toggles) ou `aria-current="page"` (abas) em todo
  ponto do código que já alternava esse estado. Botão de colapso de
  painel ganhou `aria-expanded` sincronizado; menus dropdown
  (`data-menu-toggle`) ganharam `aria-haspopup="true"`/`aria-expanded`, e
  Escape agora fecha o menu de ações aberto (devolve o foco pro botão).
- **Canvas sem alternativa textual**: os 5 gráficos de canvas (tráfego,
  protocolo, timeline de ataques, detalhe de ataque, detalhe de cliente)
  ganharam `role="img"` + `aria-label` dinâmico resumindo os dados
  desenhados (ex.: pico em bps e horário, ou contagem de incidentes por
  severidade), recalculado a cada load/redesenho.
- **Scrollbars/controles no esquema claro do SO**: `:root { color-scheme:
  dark; }` — sem isso, scrollbar nativa e alguns controles de formulário
  renderizavam no tema claro do sistema mesmo com o portal 100% escuro.
- **Tabelas roláveis sem foco de teclado**: todas as ~30 tabelas (geradas
  via `innerHTML`, cada uma já rolando horizontalmente sozinha desde a
  v1.60.0) ganharam um wrapper com `tabindex="0"` + `role="region"` +
  `aria-label` descritivo — um único `MutationObserver` em `#fg-app`
  envolve qualquer `<table>` nova automaticamente, sem precisar editar as
  ~30 funções de render uma a uma.
- **Dois botões "Modo Guerra" com o mesmo nome acessível**: o de
  configuração (ícone de engrenagem) só se diferenciava do de execução por
  `title` e ícone decorativo — nome visível renomeado pra "Config. Modo
  Guerra".
- **Dois breakpoints mobile quase iguais**: `699px` e `760px` espalhados
  pelo CSS consolidados num único breakpoint de `700px`, documentado no
  CSS.
- **`<main>` landmark ausente**: `.fg-main` (conteúdo central, ao lado da
  sidebar de navegação) virou um `<main class="fg-main">` de verdade —
  antes era só uma `<div>`, sem landmark pra pular direto pro conteúdo via
  leitor de tela.
- **Minificação de `flowguard.js`**: avaliado e **pulado** deliberadamente —
  o projeto não tem pipeline de build (sem `package.json`/bundler/Makefile
  nesta pasta), e introduzir um só pra minificar um arquivo estático
  contradiz a filosofia "sem framework, sem build step" do projeto. Não é
  bloqueante.

Validado com Playwright real contra o portal rodando: screenshots desktop
1400×900 e mobile 390×844 da tela de login (viewport meta confirmado
funcionando — card de login reduz corretamente em mobile), sessão
autenticada via token de dev conferindo os atributos ARIA acima em runtime
(landmark, `color-scheme`, `aria-live`, `aria-current`, `aria-pressed`,
`aria-sort`, `role="img"` com `aria-label`, wrappers de tabela). 0 erros de
console novos — os 401 de "Unauthorized" que aparecem no console já
existiam de forma idêntica na v1.60.0 sem nenhuma mudança (confirmado
comparando com `git stash`), vêm do mesmo escopo de sessão do token de dev
já anotado no changelog anterior, não desta mudança.

### v1.60.0 — 2026-07-17 — Auditoria de acessibilidade/responsividade (plugin impeccable) + PRODUCT.md/DESIGN.md

Primeira rodada usando o skill `impeccable` (`/impeccable init` → `/impeccable
audit` → `/impeccable polish`) pra documentar e corrigir o sistema visual do
portal. `PRODUCT.md` e `DESIGN.md` novos na raiz do repo capturam o registro
("product"/NOC), a paleta real (derivada do GitHub Primer Dark) e as regras
implícitas do sistema (ex: Signal Blue nunca preenche botão, flat-by-doctrine
sem sombra decorativa) — servem de referência pra qualquer mudança visual
futura, própria ou via impeccable.

Auditoria (14/20, "Good") encontrou gaps reais de acessibilidade/responsivo,
todos corrigidos nesta versão:

- **Formulários sem nome acessível**: 33 inputs + 7 selects dependiam só de
  `placeholder` (que some ao digitar e nem sempre é lido por leitor de tela) —
  todos ganharam `aria-label` (WCAG 1.3.1/4.1.2).
- **Modais sem semântica**: os 3 modais (Modo Guerra execução/configuração,
  Config. Roteador) eram `<div>` simples sem `role="dialog"`/`aria-modal`,
  sem fechar no Esc e sem prender o foco — teclado vazava pro conteúdo atrás
  do modal. Adicionado `role="dialog"`/`aria-modal="true"`/`aria-labelledby`
  estático no HTML + um par `openModalA11y`/`closeModalA11y` genérico em
  `flowguard.js` (foco preso via Tab, Esc aciona o botão "Fechar" existente,
  foco volta pro elemento que abriu o modal ao fechar). Validado com
  Playwright real: 15 Tabs seguidos sem o foco escapar do modal, Esc fecha.
- **Tabelas sem scroll em mobile**: as 33+ tabelas (todas geradas via
  `innerHTML` em `flowguard.js`, nenhuma estática no HTML) usam
  `white-space: nowrap` e várias colunas — sem wrapper, estouravam a
  viewport no celular (WCAG 1.4.10). Fix de uma linha cobrindo todas de
  uma vez: `table { display: block; overflow-x: auto; }` — o browser
  mantém o modelo de tabela internamente (thead/tbody/tr/td preservam os
  `display` de tabela via UA stylesheet), só passa a rolar o excesso em vez
  de estourar a página. Validado: `document.documentElement.scrollWidth`
  igual à viewport em 375px, sem overflow de página.
- **Alvos de toque pequenos**: `.fg-btn`/`.fg-toggle-btn`/paginação ficavam
  abaixo de 44px — ajustado só dentro do breakpoint mobile (`max-width:
  699px`) pra não afetar a densidade de desktop, que é escolha deliberada
  (ver `DESIGN.md`).
- **Hex hardcoded**: 8 pontos em `index.html` duplicavam valores de token
  em vez de usar `var(--fg-*)` — trocados. Paleta categórica dos gráficos
  (`CHART_PREFIX_COLORS`, 8 cores) e o acento roxo do card ClientGuard,
  que não estavam documentados, agora estão no `DESIGN.md`.

Nada de mudança visual/estrutural fora desses pontos — sistema de cores,
densidade de tabela e layout da sidebar continuam exatamente como estavam.
Validado ponta a ponta com Playwright real contra o portal rodando (login
via token de sessão de dev, screenshots desktop 1400px + mobile 375px,
0 erros de console novos — os 401 pré-existentes vêm de escopo de sessão
do token de dev, não desta mudança).

### v1.59.0 — 2026-07-13 — Menu principal vira sidebar vertical fixa na lateral esquerda

Pedido do usuário: layout mudou de barra horizontal de abas (`#fg-tabs`
acima do conteúdo) pra menu vertical fixo na lateral esquerda, sempre
visível (sem opção de recolher). `#fg-app` passa a ser flex-row: a
sidebar (`#fg-tabs`, mesmo id, `position: sticky` + `height: 100vh`) fica
à esquerda, e todo o resto do conteúdo antigo (topbar, KPIs, abas,
modais) entrou num wrapper novo `.fg-main` à direita. Abaixo de 700px
(mesmo breakpoint já usado no grid do cockpit) a sidebar volta a virar
uma barra horizontal no topo, pra não sobrar uma faixa vertical fininha
demais em tela de celular. Só CSS + reposicionamento de HTML — nenhuma
mudança em `flowguard.js` (o `initTabs()` já lia por `id="fg-tabs"`,
não pela classe, então clique nas abas continua funcionando sem
alteração). Validado com Playwright real: sidebar renderiza à esquerda,
conteúdo não fica embaixo dela, clique em qualquer item continua trocando
de aba certinho, item ativo destacado, fallback mobile funcionando,
0 erros de console associados à mudança.

### v1.58.0 — 2026-07-13 — Card "Mitigações de Borda" também mostra a lista num popover

Terceiro card no mesmo padrão das v1.56.0/v1.57.0: "Mitigações de Borda"
entra em `COCKPIT_POPOVER_TARGETS` — clique mostra src_ip, mecanismo
(FlowSpec ou SSH legado), motivo (reaproveita `edgeMitigationReason`, já
usado na tabela da aba Regras) e expiração de cada mitigação com
`status === "active"` (mesmo filtro do número do card, qualquer
mecanismo). Fonte é `state.rulesCgEdgeData`, já polado a cada 5s.
Validado com Playwright real: popover mostra as mitigações reais em
FlowSpec com motivo e expiração corretos, fecha ao clicar fora, Visão
Geral permanece ativa, 0 erros de console associados à mudança.

### v1.57.0 — 2026-07-13 — Card "ClientGuard" também mostra a lista num popover

Mesmo tratamento da v1.56.0, agora pro segundo card: "ClientGuard" saiu
de `COCKPIT_JUMP_TARGETS` e entrou em `COCKPIT_POPOVER_TARGETS` — clique
abre popover ancorado no card com cada sinal aberto (src_ip, cliente,
tipo de sinal, confiança/severidade), fonte é o mesmo `state.cgSuspicious`
já polado a cada 5s pro badge da aba Incidentes. Filtra `!resolved`
explicitamente (não confia só na view atual estar em "Abertos", pra não
vazar sinal resolvido se o usuário tiver trocado a view antes de voltar
pra Visão Geral). `COCKPIT_JUMP_TARGETS` fica vazio por ora — nenhum
widget usa mais navegação de página, só popover; mapa continua existindo
pronto pro próximo card que precisar sair da Visão Geral de verdade.
Validado com Playwright real: popover mostra os sinais reais (scan
vertical/horizontal, confiança e severidade corretas), fecha ao clicar
fora, abrir um card fecha popover do outro (só 1 por vez, comportamento
natural do toggle), 0 erros de console associados à mudança.

### v1.56.0 — 2026-07-13 — Card "Regras Ativas" mostra a lista num popover em vez de trocar de aba

Ajuste sobre a v1.55.0: usuário testou o clique no card "Regras Ativas" e
achou melhor não sair da Visão Geral pra ver a lista — pediu um popover
ancorado no próprio card em vez do redirecionamento pra aba Regras. Novo
mapa `COCKPIT_POPOVER_TARGETS` (paralelo ao `COCKPIT_JUMP_TARGETS` da
v1.55.0): clique no card abre uma lista com IP/prefixo, tipo (RTBH/FlowSpec)
e expiração de cada regra ativa, sem navegar; clique fora do popover ou no
mesmo card de novo fecha (toggle). Conteúdo é reconstruído a cada ciclo de
poll (5s) se o popover estiver aberto, pra não ficar desatualizado em
relação ao número mostrado no card. O card "ClientGuard" não mudou —
continua levando pra aba Incidentes (sinais suspeitos), único pedido
original que fazia sentido como navegação de página mesmo. Validado com
Playwright real (sessão local): popover abre com os dados reais das
regras ativas, fecha ao clicar fora, toggle funciona, Visão Geral
permanece ativa, ClientGuard sem regressão, 0 erros de console associados
à mudança.

### v1.55.0 — 2026-07-13 — Cards "Regras Ativas" e "ClientGuard" do cockpit ficam clicáveis

Pedido do usuário: na Visão Geral, os cards "Regras Ativas (FlowSpec/RTBH)"
e "ClientGuard" só mostravam um número solto, sem jeito de ver o detalhe
por trás dele. Agora os dois ficam clicáveis (cursor muda, borda destaca
no hover) fora do modo de edição do cockpit — clicar em "Regras Ativas"
leva pra aba Regras, ativa o lado FlowGuard, expande a seção se estiver
recolhida e rola até a lista RTBH/FlowSpec; clicar em "ClientGuard" leva
pra aba Incidentes, ativa o lado ClientGuard e rola até "Sinais
Suspeitos". Mesmo padrão de navegação já usado no `jumpToAttack` e nas
barras "Ir para" de Incidentes/Regras (`COCKPIT_JUMP_TARGETS`, novo mapa
id→destino). Drag & drop e o checkbox de visibilidade continuam
funcionando normalmente durante a edição — o clique de navegação só age
fora desse modo. Validado com Playwright real (sessão local): clique nos
dois cards troca de aba, ativa o toggle certo e deixa a subseção visível
na viewport, sem erros de console associados à mudança.

### v1.54.0 — 2026-07-12 — Corrige card do cockpit oculto sem volta na Visão Geral

Achado real: na aba Visão Geral (grid de cards customizável — arrastar
pra reordenar, checkbox pra esconder), desmarcar um widget o escondia de
verdade demais — `cockpitCardHtml` usava o atributo `[hidden]` nativo na
div inteira do card, e o próprio checkbox de reativar visibilidade morava
dentro dessa mesma div, então sumia junto. Não tinha jeito de trazer o
widget de volta pela interface, só limpando `localStorage` no devtools.
Corrigido: "oculto" agora é uma classe própria (`.fg-cockpit-hidden`) —
durante o modo edição o card fica esmaecido mas continua no grid com o
checkbox acessível; some de fato só quando o usuário conclui a
personalização.

Novo botão "Restaurar layout padrão" (aparece só durante a edição) limpa
o layout salvo e remonta o grid com a ordem/tamanho/visibilidade
originais dos 9 widgets, sem precisar recarregar a página — dá uma saída
pra quem bagunçar o layout demais. Extra: botão "Personalizar" perdia o
ícone na primeira troca pra "Concluir personalização" (`textContent` no
botão inteiro apagava o SVG) — corrigido isolando o rótulo num `<span>`
próprio. Validado com Playwright real: esconder/reexibir durante edição,
concluir e confirmar que some de verdade, recarregar e confirmar que o
estado oculto persiste (esmaecido) ao reabrir a edição, restaurar layout
padrão, drag & drop continua funcionando — 0 erros de console.

### v1.53.0 — 2026-07-12 — Reorganiza aba Regras (mesmo padrão de badges/navegação de Incidentes)

Mesma melhoria da v1.52.0, aplicada na aba Regras: as 3 listas de
histórico (RTBH/FlowSpec do FlowGuard, FlowSpec via proxy do ClientGuard,
mitigação direta SSH/ACL legado do ClientGuard) ganharam badge de
contagem de itens ativos ao lado do título, e entraram na barra "Ir para"
no topo do painel (reaproveita a mesma barra/classes CSS criadas pra
Incidentes). Diferente de Incidentes, aqui o badge fica sempre neutro
(cinza) — regra ativa é estado normal de operação, não um alerta.
Contagem ignora os filtros de host/tipo/janela e o toggle Ativas/Inativas
do usuário (conta "ativas de verdade" no estado bruto, mesmo critério já
usado em Incidentes). Validado com Playwright real: badges batendo com
os endpoints CGI, navegação rolando pra lista certa e expandindo seção
recolhida quando necessário, 0 erros de console, nenhuma regressão nos
toggles/filtros/ações em massa já existentes.

### v1.52.0 — 2026-07-12 — Reorganiza aba Incidentes + KPI de Tráfego com entrada/saída

Aba Incidentes tinha 4 subseções empilhadas (Ataques DDoS, Scanners
Detectados, Destino Coordenado, Sinais Suspeitos do ClientGuard) sem
título/contagem consistentes — só o botão da aba mostrava 1 número somado.
Cada `<h3>` de subseção ganhou badge próprio com a contagem de itens
ativos daquela subseção específica (mesmos dados já buscados no polling,
sem requisição nova); nova barra "Ir para" no topo do painel pula direto
pra cada subseção (scroll suave, troca o lado FlowGuard/ClientGuard se
preciso) — painel ficou longo o suficiente pra justificar isso. As duas
subseções mais antigas (Scanners, Destino Coordenado) tinham o mesmo
inline style de moldura repetido em cada uma — extraído pra uma classe
CSS única (`.fg-incident-subsection`), reaproveitável se aparecer mais
alguma subseção no futuro. Validado com Playwright real: badges batendo
com contagem real dos endpoints CGI, navegação rolando/trocando de lado
corretamente, nenhuma regressão nos toggles/filtros/seleção em lote já
existentes, 0 erros de console.

KPI "Tráfego" do topo (todas as abas) passou a mostrar entrada e saída
separadas em vez de só entrada — motivo: usuário comparando com
ferramentas externas de monitoramento (que mostram as duas direções
separadas) estranhava o número único. Ver changelog do FlowGuard v1.36.5
pro detalhe do backend (`daemon_stats()` ganhou `bps_out`/`pps_out`).

### v1.51.1 — 2026-07-10 — Campos de filtro de bytes médios no painel de scan (evita bloquear Google/YouTube)

Dois campos novos em "Detecção de Varredura de Portas" (aba Configuração >
FlowGuard): "Horizontal — máx. bytes médios por host" e "Vertical — máx.
bytes médios por porta", ambos aceitando vazio pra desativar o filtro. Ver
changelog do FlowGuard v1.36.2 pro contexto completo (streaming/CDN sendo
confundido com scan de reconhecimento).

### v1.51.0 — 2026-07-10 — Detecção de destino coordenado (novo detector FlowGuard) no portal

Usuário pediu que os detectores não-DDoS do ClientGuard fossem portados pro
FlowGuard, "da mesma forma que eu possa habilitar quando quiser" (ver
CHANGELOG do `flowguard` v1.36.0 pro backend). Primeiro de 4:
`coordinated_destination` — N IPs externos distintos convergindo pro MESMO
host/porta protegido.

Wiring de portal: seção "Detecção de Destino Coordenado" em Configuração >
FlowGuard (toggle + limiares, mesmo padrão de "Detecção de Varredura de
Portas"), e — diferente do scan (que nasceu em Configuração e precisou de
uma leva separada pra mover) — a visualização já nasceu direto na aba
Incidentes (lado FlowGuard), sub-tabela "Destino Coordenado" abaixo de
"Scanners Detectados": toggle Ativos/Histórico, severidade estimada pela
contagem de fontes, selo "novo", paginação, contador somado ao badge único
da aba, repolado a cada ciclo. Sem botão de ação (ao contrário do scan) —
mitigação automática foi decisão explícita do usuário de deixar de fora
nesta rodada; se precisar bloquear algo manualmente, usar a aba Regras.

**Achado real de produção no mesmo dia**: as primeiras detecções foram
100% UDP/ESP (P2P/torrent/WebRTC/jogo em pools CGNAT, não ataque) — corrigido
no backend restringindo a detecção a TCP (`protocols: [6]`), documentado no
CHANGELOG do `flowguard`. Validado com Playwright real antes e depois do
fix: 0 erros de console, badge da aba caiu de 9 pra 4 incidentes depois do
fix confirmar que os falsos positivos realmente desapareceram (fecharam
sozinhos, sem intervenção manual).

### v1.50.0 — 2026-07-10 — Scanners Detectados muda de Configuração pra dentro da aba Incidentes

Usuário pediu que a detecção de port scan (adicionada em v1.49.0, até então
uma tabela somente-leitura escondida em Configuração > FlowGuard) aparecesse
de verdade na aba Incidentes, junto com Ataques e Sinais Suspeitos. Movida
(não duplicada) pra dentro do lado FlowGuard da aba Incidentes, como uma
seção própria "Scanners Detectados" abaixo da tabela de Ataques — os dados
não têm o mesmo formato de `attacks` (sem `severity`/`bps_peak`, `dst_count`
no lugar), então ficou como sub-tabela separada em vez de forçado nas
mesmas colunas.

Ganhos no processo: toggle Ativos/Histórico (o endpoint já suportava
`history=1`, só não estava exposto na UI); severidade **estimada**
client-side pela contagem de hosts/portas distintos (`scanSeverity()` —
o backend não tem coluna `severity` pra port scan, deixado explícito na UI
como "(estimada)"); selo "novo" (mesmo `isNewIncident()` já usado pelo resto
da aba); paginação client-side (histórico tem ~3.900 registros sem limite
no backend — sem paginar, a tabela inteira ia pro DOM de uma vez); contador
de scanners ativos somado ao badge único da aba Incidentes; passou a ser
repolado a cada ciclo (antes só carregava 1x ao abrir Configuração, nunca
atualizava sozinho). Botão "Bloquear" novo por linha — reaproveita o mesmo
`RULES_ENDPOINT`/mecanismo do bloqueio manual já existente na aba Regras
(TTL fixo de 1h) — **limitação honesta, não escondida na UI**: como não
existe comando de backend que ligue esse bloqueio manual ao registro do
scanner, o status "detectando" não muda sozinho depois de bloquear; a regra
criada de fato aparece normalmente na aba Regras.

Validado com Playwright real: scanner de verdade capturado na aba (ver
achado da sessão anterior sobre scan detection), toggle Ativos/Histórico
troca a lista, paginação mostra 15/página corretamente (263 páginas pros
~3.939 registros históricos atuais), badge da aba soma corretamente, seção
sumiu de Configuração > FlowGuard sem deixar duplicata, 0 erros de console.

### v1.49.0 — 2026-07-08 — Painéis de detecção de scan (FlowGuard) e bloqueio progressivo (FlowGuard + ClientGuard)

Wiring de portal pra 3 features novas do backend (ver changelog de
`flowguard` v1.35.0 e `clientguard` v1.31.0 pro contexto completo): detector
de port scan inbound e bloqueio progressivo por reincidência (estilo
fail2ban) nos dois sistemas.

Aba Configuração > FlowGuard ganhou 3 seções novas: "Detecção de Varredura
de Portas" (toggle horizontal/vertical + thresholds, estilo numeric-field
igual aos Limiares de Detecção existentes), "Bloqueio Progressivo" (janela
de reincidência/duração base/fator/teto) e "Scanners Detectados" (tabela
somente-leitura — quem está sendo detectado agora, mesmo sem bloqueio
automático ligado; o estado do bloqueio em si já aparece de graça na tabela
Regras FlowSpec Ativas existente, sem UI nova pra isso). Aba Configuração >
ClientGuard ganhou "Bloqueio Progressivo" equivalente.

Dois helpers genéricos novos em `flowguard.js` (`renderKvFields`/
`collectKvChanges`) — bool+numérico com diff-on-save numa POST só — usados
pelas 3 seções novas em vez de triplicar a lógica de
`renderCgDetectionCfg`/`renderFgMitigation`. 4 CGI scripts novos
(`flowguard-scan-cfg.sh`, `flowguard-escalation-cfg.sh`,
`flowguard-scan-offenders.sh`, `clientguard-escalation-cfg.sh`), todos
proxy fino pro socket do daemon respectivo, mesmo template de
`flowguard-mitigation-cfg.sh`/`clientguard-flowspec-cfg.sh`.

### v1.48.0 — 2026-07-08 — Redes do ClientGuard (ex: CGNAT) aparecem no gráfico de tráfego

Usuário reportou que a rede CGNAT não aparecia nos gráficos. Causa: o
seletor de barramento da aba Gráficos só listava prefixos PROTEGIDOS do
FlowGuard (`protected_prefixes.yaml`) — redes de cliente do ClientGuard
(`customers.yaml`, onde a CGNAT está cadastrada) nunca entravam ali, são
sistemas de detecção diferentes com bancos separados.

Fix: o mesmo `<select>` da aba Gráficos ganhou um `<optgroup>` "ClientGuard —
redes de clientes" (`appendCgNetworksToChartSelect()`, reaproveita a lista
já carregada por `loadClientGuardCfg()` — nenhuma consulta nova só pra
listar). Selecionar uma rede do ClientGuard (valor `cg:<prefix>`) troca o
gráfico principal pra série de tráfego agregada daquela rede inteira
(`clientguard-network-series.sh`, endpoint novo — ver CHANGELOG do
`clientguard` pro backend), e o painel "Top hosts" vira "Top clientes da
rede" (reaproveita `clientguard-top.sh`, já existente, filtrado
client-side). Protocolo e linha do tempo de ataques ficam com aviso "não
aplicável a redes do ClientGuard" nesse modo — não existe conceito de
ataque por prefixo nem quebra por protocolo do lado ClientGuard.

**Limitação temporária, documentada no CHANGELOG do `clientguard`**: janelas
24h/7d ficam desabilitadas (`updateChartWindowAvailability()`) quando uma
rede do ClientGuard está selecionada — a tabela `client_flow_aggs` tem hoje
280 milhões de linhas (achado feito durante esta mudança, não é bug —
tráfego real, ver detalhes no outro CHANGELOG) e janelas longas não
respondem em tempo hábil sem um índice que ainda não foi construído (custo
de construir ao vivo precisa de uma janela controlada, não decidido ainda).
1h/6h respondem em <5s, seguem liberadas normalmente.

Validado com Playwright real: rede `CGNAT-PPPOE (100.64.0.0/10)` aparece
corretamente agrupada no seletor, troca de contexto FlowGuard↔ClientGuard
preserva/restaura a disponibilidade de 24h/7d, gráfico renderiza a série
real da rede, 0 erros de console. `clientguard.service` reiniciado em
produção pra carregar o comando de socket novo, sem downtime perceptível.

### v1.47.0 — 2026-07-08 — Aba Incidentes unifica FlowGuard + ClientGuard, timeline com faixas de severidade

Pedido do usuário: aproximar o portal V1 dos padrões de UX do portal V2
(poxflow, em desenvolvimento paralelo) em três frentes — sem introduzir
nenhuma dependência nova, mantendo a filosofia zero build step / zero CDN.

**Aba Ataques + Sinais Suspeitos viram "Incidentes"**: nova aba `Incidentes`
substitui a antiga aba `Ataques`; um toggle `FlowGuard — vítimas` /
`ClientGuard — clientes` alterna entre a visão de ataques por prefixo e a de
sinais suspeitos por cliente, no mesmo padrão de toggle já usado nas abas
Regras/Configuração. A aba `ClientGuard` (renomeada `Clientes`) ficou só com
Status e Top Clientes por Consumo. O badge da aba passa a somar ataques
ativos + sinais abertos.

**Incidentes ganhou recursos novos**: chips de severidade com seleção
múltipla (severidade do ClientGuard agora é derivada da confiança do sinal —
high/medium/watch); agrupamento por prefixo/cliente com colapso automático de
grupos de severidade baixa; modo "Selecionar" com ação em lote (liberar/
resolver vários de uma vez, com confirmação listando os IDs); painel de
detalhe ganhou linha do tempo vertical do incidente (detecção → mitigação →
encerramento), nota do operador (persistida só no navegador via
localStorage) e exportação de dossiê em `.txt`; evidência do ClientGuard
agora é formatada campo a campo em vez de uma string crua; reincidência do
mesmo IP nos últimos 7 dias é mostrada no detalhe do sinal; selo "novo" marca
incidentes abertos desde a última visita à aba.

**Gráfico de tráfego ganhou faixas de anomalia + marcadores de evento**: o
gráfico "Tráfego — entrada x saída" (aba Gráficos) agora sobrepõe, por trás
das linhas, uma faixa translúcida colorida por severidade para cada ataque na
janela selecionada, mais uma linha tracejada + marcador circular no início de
cada ataque (hover mostra tipo/severidade/duração, clique pula pro histórico
filtrado da aba Incidentes). A consulta de ataques da janela agora é buscada
uma única vez e reaproveitada tanto pelo overlay quanto pelo Gantt de
severidade já existente (antes eram duas consultas iguais).

**Bug real encontrado e corrigido nessa revisão**: `[hidden]` não vencia
`.fg-toolbar`/`.fg-toggle-group { display:flex }` por empate de
especificidade CSS — mesma classe de bug já documentada em
`.fg-cockpit-visibility[hidden]`. Isso deixava o seletor de janela da aba
Ataques sempre visível (mesmo fora do modo Histórico) e teria deixado as
novas barras de ação em lote sempre visíveis também. Corrigido com
`.fg-toolbar[hidden], .fg-toggle-group[hidden] { display: none; }`.

Validado com Playwright real contra o portal em produção: login, troca de
toggle FlowGuard/ClientGuard, chips de severidade, agrupamento, seleção em
lote (só a UI — sem clicar nas ações reais de liberar/resolver contra dados
de produção), detalhe de ataque e de sinal reais (timeline, nota, export,
reincidência), aba Clientes enxuta, overlay de eventos no gráfico com um
prefixo com histórico real de ataques, sobrevivência a vários ciclos de
polling (5s) sem os painéis novos serem destruídos pelo refresh, 0 erros de
console.

### v1.46.0 — 2026-07-07 — Corrige painel "Limiares de Detecção" quebrado + limiar de amplificação + bug de apagar threshold ao editar prefixo
Pedido do usuário: revisar o módulo de Configuração do portal e comparar com
o que o FlowGuard atual suporta. Achados reais, dois deles críticos.

**Bug crítico #1 — "Salvar limiares" sempre falhava**: a limpeza de config
morto do `flowguard` (v1.34.0, mesma sessão) removeu do backend 5 chaves de
`detection.*` que o painel "Limiares de Detecção" ainda listava
(`dns_amp_factor`, `scan_ports_per_sec`, `scan_hosts_per_sec`,
`window_short_s`, `window_long_s`). Sem essas chaves no config, os campos
correspondentes renderizavam vazios — e a validação de salvar tratava
QUALQUER campo vazio do formulário como erro do formulário INTEIRO (não só
do campo alterado), travando "Salvar limiares" com "Valores inválidos" 100%
das vezes, mesmo pra alterar um limiar de verdade. Corrigido nas duas
pontas: campos mortos removidos de `FG_DETECTION_CFG_FIELDS`, e a validação
agora só invalida um campo vazio se ele JÁ tinha valor antes (limpar um
campo que nunca teve valor não é uma "edição").

**Bug real #2 — editar um prefixo apagava o limiar customizado dele em
silêncio**: `monitor_set` substitui a entrada inteira (não faz merge), mas
o formulário de edição nunca prefilava `ddos_bps_threshold_mbps` nem
`notify_wa` a partir do prefixo real — só parseava texto já formatado da
tabela ("35.0 Gbps", perda de precisão, e nem tentava pro threshold). Editar
qualquer outro campo (ex: só o nome do cliente) de um prefixo com limiar
customizado apagava esse limiar sem aviso nenhum. Corrigido: `renderCfg`
agora guarda o array RAW (`state.fgProtectedPrefixes`) e `edit-monitor`
prefila TUDO a partir dele (customer/capacidade/thresholds/auto_mitigate/
notify_wa/template), não mais lendo célula de tabela. Validado contra dado
real de produção: prefixo `x.x.x.0/24` (limiar 30 Gbps já configurado)
sobreviveu a uma edição completa via Playwright real.

**`amp_bps_threshold` exposto** (campo novo no backend, v1.34.0 do
`flowguard`): adicionado ao painel de ajuste fino, ao formulário/tabela de
templates de detecção, e ao formulário/tabela de prefixo — mesmo padrão dos
campos de DDoS já existentes (tipo "mbps", conversão automática).

Validado ponta a ponta com Playwright real: campos mortos sumiram, campo de
amplificação aparece e salva de verdade (`detection_overrides.yaml`
confirmado), template com `amp_bps_threshold` salva e aparece na tabela,
edição de prefixo real preserva threshold, 0 erros de console em todas as
7 abas do portal.

### v1.45.0 — 2026-07-07 — Timeout do bloqueio de cliente sobe pra 40s (PBR bypass via SSH demora)
Achado real: `clientguard-block.sh` (`block_add`/`block_del`) usava o timeout
padrão de `control.send_command` (6s), mas o socket do ClientGuard pode
disparar `push_pbr_bypass`/`remove_pbr_bypass` (SSH síncrono no equipamento
de borda, exceção de PBR pro CGNAT — ver CHANGELOG do `clientguard`), que
sozinho leva 15-30s. O CGI estourava o timeout e reportava falha ao operador
mesmo quando a regra tinha sido criada/removida com sucesso no backend.
Corrigido: `timeout=40.0` explícito nas duas chamadas.

### v1.44.0 — 2026-07-05 — Mesmo ajuste fino de detecção e templates, agora no FlowGuard
Pedido do usuário: replicar no lado FlowGuard o mesmo mecanismo de templates
+ ajuste fino que a v1.43.0 trouxe pro ClientGuard.

**Nova seção "Limiares de Detecção"** (aba Configuração > FlowGuard): 17
campos cobrindo todo `detection.*` do FlowGuard (limiar de DDoS
bps/pps, SYN flood, amplificação DNS, scan, baseline EWMA). Mesmo
salvamento **diff-only** já usado no ClientGuard — só manda ao backend as
chaves que o operador de fato mudou.

**Nova seção "Templates de Detecção"**: perfis reutilizáveis de
`ddos_bps_threshold`/`ddos_pps_threshold` (CRUD completo). A tabela de
prefixos monitorados ganhou uma coluna "Template", e o formulário de
prefixo um `<select>` pra atribuir/limpar o template de um prefixo.

Backend: `flowguard-cfg.sh` (GET) passa a devolver `detection` e
`detection_templates` (lidos direto do loader do FlowGuard, sem round-trip
por socket — diferente do ClientGuard, cujo reload não relê o config
principal); POST ganha `detection_cfg_set`/`detection_templates_set`/
`detection_templates_del` na lista de comandos permitidos.

**Bug real encontrado e corrigido na validação com Playwright contra o
daemon ao vivo**: o salvamento diff-only arredondava (`Math.round`) todo
campo numérico antes de comparar com o valor original — limiares
fracionários (ex: `syn_ratio_threshold: 0.9`) sempre batiam como "alterado"
mesmo sem edição nenhuma, gravando um override espúrio (`0.9` → `1`) a cada
clique em "Salvar limiares". Pego durante a própria validação (o teste
automatizado corrompeu o valor ao vivo), corrigido antes de dar por
encerrado, e o override espúrio revertido manualmente via socket.

Validado com Playwright real contra o daemon: as 3 seções carregam com
valores reais, criar/editar/remover template funciona, atribuir e limpar
template de um prefixo funciona (preservando os demais campos do prefixo),
e "Salvar limiares" sem alteração nenhuma não dispara requisição nenhuma.
Sem erros no console em nenhum passo.

### v1.43.0 — 2026-07-05 — Ajuste fino dos limiares de detecção e templates (cgnat/cdn) no portal
Pedido do usuário: expor no portal tudo que foi recalibrado no ClientGuard
(limiares de scan/amplificação/spam/coordenação + templates de perfil de
rede cgnat/cdn), com ajuste fino direto na tela em vez de editar YAML na
borda.

**Nova seção "Limiares de Detecção"** (aba Configuração > ClientGuard): um
campo por limiar (`scan_horizontal_hosts`, `scan_vertical_ports`,
`scan_max_avg_bytes`, `amplifier_min_bps`, `spam_min_distinct_dest`,
`coordinated_min_clients`, `dns_tunneling_min_queries`) e um campo de texto
por lista de porta (`amplifier_ports`, `spam_ports`, `common_service_ports`,
vírgula-separado). "Salvar limiares" manda só os campos que **realmente
mudaram** em relação ao valor carregado — mandar o formulário inteiro a
cada save materializaria todo `detection.*` no override do ClientGuard, e
uma mudança futura direto no `config.yaml` de lá nunca mais teria efeito
(achado e corrigido ainda durante a validação desta feature). Aplica sem
reiniciar o daemon do ClientGuard.

**Nova seção "Templates de Detecção"**: tabela com os templates cadastrados
(nome, limiares, descrição) + formulário de criar/editar (salvar com nome
já existente substitui o template inteiro) + remover.

**"Redes de Clientes" ganha 2 colunas novas**: `Template` (`<select>` com
os templates cadastrados) e `Multiplicador`, editáveis direto na linha
("Salvar" por linha, sem precisar excluir e recadastrar a rede) — mais os
mesmos 2 campos no formulário de adicionar rede nova.

Backend: `clientguard-cfg.sh` (GET) passa a devolver `detection` (limiar
efetivo, via socket) e `detection_templates`; POST ganha
`detection_cfg_set`/`detection_templates_set`/`detection_templates_del`/
`customers_edit` na lista de comandos permitidos.

**Bug real encontrado e corrigido na validação**: o atributo `pattern` do
campo de nome do template (`[a-z0-9_-]+`) quebrava em navegador com engine
de regex mais nova (`-` dentro de `[...]` interpretado como sintaxe de
subtração de conjunto) — corrigido escapando (`[a-z0-9_\-]+`).

Validado com Playwright real contra o daemon: limiares carregam com os
valores reais, salvar só o campo alterado persiste só ele (conferido lendo
o arquivo de override direto), criar/editar/remover template funciona e
reflete na hora no `<select>` das redes, editar template de uma rede
existente persiste após reload da página, 0 erros de console.

### v1.42.0 — 2026-07-05 — "sem proteção" não aparece mais pra host que já parou de ser atacado
Pedido do usuário: mesmo com o indicador de atividade da v1.41.0, o selo de
mitigação continuava mostrando "⚠ sem proteção" pra ataques/sinais que já
não tinham atividade real há um tempo (🟡 sem atividade) — na prática já
encerrados, só aguardando o fechamento automático por inatividade.

Nova função `isGenuinelyActive(closed, tsLastSeen)`: "⚠ sem proteção" agora
só aparece quando o mesmo critério do 🟢 (reconfirmação há menos de 90s)
bate — senão o selo volta a "encerrada" (neutro), tanto na aba Ataques
quanto em Sinais Suspeitos (tabela e painel de detalhe). Contraparte no CLI
dos dois backends em commits próprios.

**Auditoria à parte, sobre por que ainda aparecem hosts "sem mitigação"**:
investigação nos dois sistemas encontrou causas legítimas, não bug — ver
changelogs do FlowGuard (v1.29.0: tipo de ataque novo sem perfil de
mitigação ainda + ataques antigos anteriores a uma mudança de config) e do
ClientGuard (v1.26.0: orçamento de regras FlowSpec genuinamente saturado
por volume real de scans concorrentes, confirmado no log de produção).

Validado com Playwright real: 0 linhas "sem atividade" mostrando "sem
proteção" nas duas telas, 0 erros de console.

### v1.41.0 — 2026-07-04 — Indicador "atividade recente" nas abas Ataques e Sinais Suspeitos
Pedido do usuário: "ativo"/"aberto" sozinho não diz se está REALMENTE
acontecendo agora — validado ao vivo que, na prática, a maioria dos
registros "ativos" já estava sem tráfego/evidência real há minutos ou
horas, só ainda não tinham fechado sozinhos (rede de segurança de 6h,
ver changelogs do FlowGuard/ClientGuard).

Nova sub-linha embaixo de "Duração" (aba Ataques) e "Última vez" (aba Sinais
Suspeitos), calculada a partir de `ts_last_seen` (já existente nos dois
backends): 🟢 "em andamento" quando a última reconfirmação foi há menos de
90s (~3 ciclos de agregação de 30s, com folga pra jitter), senão 🟡 "sem
atividade há Xm/Xh". Só aparece pra registros ainda ativos/abertos — histórico
não mostra (já tem `ts_end`/`resolved`, a informação já é factual ali).

Mesmo padrão visual das sub-linhas já usadas na aba Regras (`.fg-kpi-sub`
embaixo da célula principal), sem coluna nova. Contraparte no CLI dos dois
projetos em commits próprios. Validado com Playwright real: badge 🟢
aparece em ataques com tráfego confirmado há poucos segundos, 🟡 em sinais
sem reconfirmação há 15-50min (a maioria dos sinais abertos no momento do
teste, confirmando exatamente o padrão relatado), 0 erros de console.

### v1.40.0 — 2026-07-04 — Toggle e mitigação do novo tipo "SYN flood"
Espelha o FlowGuard v1.27.0 (pesquisa do FastNetMon + gap analysis). Nova
entrada `syn_flood` em `FG_TOGGLE_META` — mesma lista já usada tanto pela
seção "Funções de Detecção" quanto pela tabela "Mitigação" na aba
Configuração, então uma linha só no frontend cobre as duas telas. Sem
mudança de endpoint/CGI — os dados já vêm do backend, que só ganhou a
chave nova.

Validado com Playwright real contra um ataque `syn_flood` sintético de
verdade em produção (ver changelog do `flowguard`): toggle "SYN flood"
aparece com a descrição certa, linha na tabela de Mitigação mostra
"Descartar (FlowSpec)" + automático "Desligado" (diferente de todo o
resto, que já está em "Automático" em produção — decisão deliberada do
lado do FlowGuard, não bug), ataque sintético visível na aba Ataques
(view Ativos enquanto durou, Histórico depois que fechou sozinho), 0
erros de console.

### v1.39.0 — 2026-07-04 — Selo "sem proteção" quando ataque/sinal segue ativo com mitigação encerrada
Pedido do usuário: um ataque (FlowGuard) ou sinal suspeito (ClientGuard)
continuava marcado como ativo/aberto mesmo muito depois do TTL da mitigação
já ter vencido, sem nenhuma pista visual de que a proteção tinha caído.

O selo de mitigação (já existente nas abas Ataques e Sinais Suspeitos) agora
recebe o estado do próprio ataque/sinal: quando ele segue ativo/aberto mas a
última mitigação não está mais em vigor, o selo muda de "encerrada" (neutro,
cinza) pra "⚠ sem proteção" (vermelho, mesma classe visual de "falhou").
Continua "encerrada" normal quando o ataque/sinal já fechou de verdade — só
o caso "ainda te atacando e sem bloqueio" fica em destaque.

Trabalho pareado com a correção equivalente no backend do FlowGuard e do
ClientGuard (fechamento automático por inatividade, rede de segurança —
ver changelogs dos dois projetos), que reduz a frequência desse estado mas
não o elimina (é esperado: enquanto o atacante mandar tráfego, o ataque
segue "ativo" de verdade, mesmo sem mitigação).

Validado ao vivo contra os daemons reais após reinício de ambos: o selo "⚠
sem proteção" apareceu corretamente nos sinais cuja mitigação a reconciliação
automática do ClientGuard tinha acabado de reverter, tanto na tabela quanto
no painel de detalhe, sem erro de console.

### v1.38.0 — 2026-07-04 — Filtros na aba Regras e em todas as telas com muitos hosts
Pedido do usuário: filtros por tipo, por hora e por host/status na aba
Regras, generalizado pra "todo lugar que tenha muitos hosts".

**Aba Regras (Histórico de Interações com a Borda)** — nova barra de
filtros abaixo dos toggles existentes, 100% client-side (mesma filosofia
das outras abas — a lista de regras não chega perto do volume que
justificaria filtro no backend):
- **Host/IP**: busca substring em `src_prefix`/`dst_prefix` (regras
  FlowSpec/RTBH) ou `src_ip` (mitigação de borda SSH legado).
- **Tipo**: RTBH / FlowSpec descarte / rate-limit / redirect — não se
  aplica à tabela de mitigação SSH (mecanismo é sempre SSH lá).
- **Janela de tempo**: qualquer período / 1h / 6h / 24h / 7d, sobre
  `created_at` (regras) ou `ts_applied` (mitigação de borda).
- **Status**: o toggle "Ativas / Histórico completo" virou tri-state
  **Ativas / Inativas / Todas** — antes não existia jeito de ver só o que
  já saiu do ar sem misturar com o que ainda está ativo.

Todos os filtros combinam entre si (AND) e se aplicam às 3 tabelas da
aba (`rules-fg-list`, `rules-cg-flowspec-list`, `rules-cg-edge-list`),
reaproveitando os helpers genéricos já existentes (`filterRows`).

**ClientGuard — Sinais Suspeitos e Top Clientes**: as duas telas restantes
com potencial de crescer bastante em número de hosts e que ainda não
tinham nenhum filtro (achado ao mapear a base antes de implementar)
ganharam busca por IP/cliente (Sinais Suspeitos também busca por tipo de
sinal). A contagem do badge de sinais abertos continua sobre o total real
(não filtrado) — a busca é só uma lente sobre a mesma lista.

Validado com Playwright real contra os daemons ao vivo: filtro de host
reduz corretamente a tabela (testado com IP real da base, todas as linhas
restantes contêm o termo buscado), tri-state Ativas/Inativas/Todas retorna
contagens diferentes e corretas, filtro de tipo/janela sem falso positivo,
busca com termo inexistente zera a tabela com mensagem apropriada nas 4
telas, 0 erros de console.

### v1.37.0 — 2026-07-04 — Cockpit customizável na aba Visão Geral
Pedido do usuário: dashboard completo, dinâmico e colorido tipo "cockpit" na
Visão Geral, customizável. As 2 seções antigas (Tráfego em Tempo Real, Meus
Prefixos) viraram uma grade de 9 widgets coloridos (`.fg-cockpit-grid`):
Tráfego (reaproveita as sparklines existentes), Ataques Ativos (com
detalhamento por severidade), BGP, Mitigações de Borda, Modo Guerra,
ClientGuard, Meus Prefixos (reaproveita a tabela/busca existentes), Regras
Ativas e Daemon. Cada widget tem uma cor de acento própria (borda superior) —
não a paleta de severidade, que continua intocada.

**Regra de ouro seguida à risca: nenhum widget dispara fetch próprio** — só
lê `state.status`/`state.attacks`/`state.rulesFgData`/`state.rulesCgEdgeData`/
`state.cgStatus`/`warmodeActive`, todos já populados pelo poll de 5s
existente. Duas pré-condições precisaram ser corrigidas pra isso ser
verdade: `loadStatus()` não guardava a resposta pra reaproveitar (só
renderizava na hora) — passou a gravar em `state.status`; e o status do
ClientGuard só era consultado quando a própria aba ClientGuard era aberta —
`loadClientGuardStatus()` entrou no `poll()` principal.

**Customização**: botão "Personalizar" liga um modo de edição — checkbox
de visibilidade + alça de arrastar (`⠿`) aparecem em cada card; reordenar
usa Drag and Drop nativo do HTML5 (sem lib nenhuma). Layout (ordem,
visibilidade, tamanho) persiste em `localStorage`
(`fg-cockpit-layout`) por navegador; se o catálogo de widgets mudar no
código no futuro (novo widget, ou um removido), a reconciliação na carga
não trava com id órfão nem esconde o widget novo por engano.

**3 bugs reais encontrados e corrigidos durante a validação com Playwright:**
1. Card de tamanho `md` usava `grid-column: span 2` incondicional — numa
   tela que só cabe 1 coluna (mobile), isso força uma coluna implícita
   extra e estoura a largura da página. Corrigido restringindo o `span 2` a
   `@media (min-width: 700px)`.
2. Os checkboxes de visibilidade apareciam mesmo fora do modo de edição —
   `.fg-cockpit-visibility { display: flex }` tinha a mesma especificidade
   do `[hidden]` do navegador, e regra de autor sempre vence a do user-agent
   independente de especificidade. Corrigido com `.fg-cockpit-visibility[hidden] { display: none }` explícito.
3. De passagem, achado um overflow horizontal pré-existente no topbar em
   mobile (390px) — o grupo de botões à direita (selo Modo Guerra, timer,
   3 botões, Sair) não tinha `flex-wrap`, sem relação com o cockpit mas
   quebrava o mesmo critério de "sem scroll horizontal" que este trabalho
   já vinha seguindo — corrigido de graça.

Validado com Playwright real: 9 cards renderizando com dado real do poll;
busca em "Meus Prefixos" continua funcionando dentro do card; 0 requisições
de rede novas em 6s de observação (só o poll de sempre); esconder 1 widget +
reordenar + reload → layout customizado sobrevive; mobile (390px) com
`scrollWidth === clientWidth`; 0 erros de console.

### v1.36.0 — 2026-07-04 — Remove duplicação entre as 2 tabelas do ClientGuard na aba Regras
Pedido do usuário: "Bloqueio via FlowSpec" e "Mitigação automática/manual na
borda" mostravam a MESMA mitigação duas vezes — toda vez que uma mitigação
automática do ClientGuard usava FlowSpec (a maioria, hoje), ela aparecia como
regra em `flowspec_rules` (tabela de cima) **e** como mitigação em
`edge_mitigations` (tabela de baixo, que reúne SSH E FlowSpec). A tabela de
cima já tinha ficado autossuficiente com a v1.35.0 (equipamento/gatilho
próprios, não precisa mais olhar pra `edge_mitigations`), então:

- Tabela de baixo (`rules-cg-edge-list`) agora filtra `mechanism !== "flowspec"`
  — só mostra o que não tem equivalente em cima: mitigação direta via
  SSH/ACL legado. Renomeada pra "Mitigação direta na borda (SSH/ACL legado)".
- Tabela de cima ganhou rótulo amigável ("scan horizontal"/"scan vertical" em
  vez de `"ClientGuard auto: port_scan_horizontal"` cru) — mesmo texto já
  usado na aba Sinais Suspeitos, aplicado ao campo `label` que já vinha do
  backend (nenhum dado novo, só reaproveita `CG_SIGNAL_LABELS`).
- Botão "Reverter todas as mitigações do ClientGuard" ganhou um tooltip
  deixando claro que afeta as duas tabelas (FlowSpec e SSH/ACL), já que
  visualmente ele fica ao lado de só uma agora.

Validado com Playwright real: tabela de baixo mostrando "Nenhuma mitigação
de borda registrada" (nenhum SSH/ACL ativo hoje, só FlowSpec — confirma que
não haveria mais linhas duplicadas), tabela de cima com rótulos amigáveis e
sem nenhuma regressão na tabela equivalente do FlowGuard (que reaproveita a
mesma função de renderização), 0 erros de console.

### v1.35.0 — 2026-07-04 — Etiquetas de mecanismo/equipamento/gatilho/status na aba Regras
Pedido do usuário: nas 3 tabelas da aba Regras (RTBH/FlowSpec do FlowGuard,
FlowSpec do ClientGuard via proxy, e mitigação direta SSH/ACL+FlowSpec do
ClientGuard), mostrar como cada regra foi feita — mesmo padrão já usado na
aba Sinais Suspeitos (v1.31.0/v1.22.0 do ClientGuard).

- **Novas colunas "Equipamento" e "Gatilho"** nas tabelas de FlowSpec/RTBH
  (`renderFlowspecRulesTable`, usada tanto por `rules-fg-list` quanto por
  `rules-cg-flowspec-list`) — dados vêm de `flowspec_rules.device_name`/
  `trigger_type`, novos no backend (ver FlowGuard v1.25.0).
- **Coluna "Equipamento"** na tabela de mitigação direta do ClientGuard
  (`renderRulesCgEdgeTable`) — já tinha Mecanismo/Gatilho/Status, só faltava
  o equipamento (ver ClientGuard v1.23.0).
- **"Status" virou selo colorido** (`.fg-mitigation-badge`, mesma paleta
  verde/âmbar já usada nas outras abas) em vez de texto plano — "ativa"
  (verde), "expirada"/"removida" (âmbar). Mesmas 2 colunas novas + status
  também adicionadas ao painel de detalhe de cada regra.

Validado com Playwright real contra o daemon: regras automáticas recém-criadas
(FlowGuard e ClientGuard) mostrando o nome do equipamento de borda
correspondente (roteador principal e peer PPPoE/CGNAT) e gatilho
("automático") corretos nas 3 tabelas, 0 erros de console.

### v1.34.0 — 2026-07-04 — "Mitigações ativas/histórico" do ClientGuard: deduplicada e com motivo
Pedido do usuário: a lista "Mitigações ativas / histórico (FlowSpec e SSH
legado)" na Configuração > ClientGuard mostrava muitos hosts sem dar pra
saber o que tinha acontecido ou se estava ativa. Achado real ao investigar:
essa lista já era um **duplicado sem paginação nem filtro** de uma tabela
melhor que já existia na aba Regras → ClientGuard (`renderRulesCgEdgeTable`)
— a mesma classe de duplicação já corrigida no "Bloquear IP manualmente"
(v1.32.0). Em vez de melhorar duas listas, removida a pior (a da
Configuração) e melhorada a que sobrou.

- **Deduplicação**: `cg-edge-list`, seu botão "Reverter todas" e todo o JS
  só usado por ela (`renderCgEdgeList`, `loadCgEdgeList`, `onCgEdgeListClick`,
  `onCgEdgeRevertAllClick`) foram removidos. Nada se perde — os mesmos dados
  já carregavam independentemente via `loadRulesUnified()` (poll de 5s), e o
  botão "Reverter todas" sobrevive na aba Regras.
- **Nova coluna "Motivo"**: extrai o label do detector (`match_json.label`,
  ex: "ClientGuard auto: port_scan_vertical") e mostra o nome amigável já
  usado na lista de detectores ("scan vertical") — antes essa informação só
  aparecia enterrada dentro do "Match" do painel de Detalhes, e a chave
  `label` era explicitamente filtrada de lá.
- **Status virou selo colorido** (`.fg-mitigation-badge`, já usado em
  Ataques/Sinais Suspeitos) em vez de texto puro — ativa (verde), revertida
  (âmbar), falhou (vermelho, com o erro no tooltip).
- **Paginação** (reaproveita `paginate()`/`paginationHtml()` já usados em
  Ataques/Flows/Top Prefixos) — 121 linhas acumuladas viram 15 por página em
  vez de um despejo só.
- Colunas menos essenciais pro dia a dia (ID, nº do sinal associado, erro
  bruto) saíram da tabela principal — continuam no painel de Detalhes.

Sobre "será que faz sentido guardar isso": guardar o histórico continua
fazendo sentido e é consistente com o resto do portal (Ataques e Regras
também nunca apagam, só ficam "encerrados") — o problema real era mostrar
tudo de uma vez sem filtro, não o volume de dados em si (121 linhas em ~4
dias não é preocupante).

Validado com Playwright real: lista antiga (`cg-edge-list`) e botão antigo
confirmados ausentes da Configuração, tabela nova na aba Regras com coluna
Motivo/selos/paginação nas duas visões (Ativas: 20 itens/2 páginas; Histórico:
100+ itens paginados), painel de Detalhes mostrando "Motivo" no topo — 0
erros de console.

### v1.33.0 — 2026-07-04 — Selo de mitigação na aba Ataques (FlowGuard)
Espelha o FlowGuard v1.24.0 e o mesmo padrão já usado na aba Sinais Suspeitos
do ClientGuard (v1.31.0). Coluna "Mitigação" (antes "Mitigado" sim/não) mostra
🛡 verde "ativa (RTBH/discard/limitado a X Mbps)" quando o ataque tem regra
em vigor agora, âmbar "encerrada" quando já teve mitigação mas ela saiu do
ar (TTL, remoção manual, ou o `flowguard.service` reiniciar — ver auditoria
do ClientGuard v1.21.0), ou cinza "sem mitigação". Mesmo selo no painel de
detalhe do ataque. `.cg-mitigation-badge` (só ClientGuard) virou
`.fg-mitigation-badge` (compartilhado pelas duas abas agora) — zero mudança
visual, só renomeado pra refletir que deixou de ser exclusivo de uma aba.

Validado com Playwright real e CLI: histórico de ataques mostrando "encerrada
(RTBH)" pra um ataque cuja regra foi retirada, 0 erros de console.

### v1.32.0 — 2026-07-04 — Reorganização de abas/painéis + "Recolher/Expandir tudo"
Pedido do usuário: reduzir a aba ClientGuard (8 seções empilhadas, a mais
lotada do portal) e reorganizar sem prejudicar a visualização. Mudanças:

- **ClientGuard enxugada pra 3 seções** (Status, Top Clientes, Sinais
  Suspeitos) — só o que é monitoramento ao vivo. As outras 4 seções
  (Configurações — Funções, Mitigação automática por detector, Redes de
  Clientes, Whitelist) migraram pra aba **Configuração**, atrás de um novo
  toggle FlowGuard/ClientGuard (`#cfg-app-toggle`) — mesmo padrão que a aba
  Regras já usava pra unificar os dois sistemas. Nenhum endpoint novo: os
  dados desses 4 painéis já carregavam de forma independente da aba estar
  visível (`loadClientGuardCfg`/`loadCgEdgeAuto`/`loadCgEdgeList` já rodavam
  no login; só faltou somar `loadCgToggles` na mesma leva).
- **"Bloquear IP manualmente" deixou de existir duplicado.** Existia uma
  cópia quase idêntica na aba Regras (FlowGuard) e outra na ClientGuard,
  ambas manipulando a MESMA sessão BGP FlowSpec real. Virou um formulário só
  (na aba Regras) com um seletor "origem: FlowGuard/ClientGuard" que só
  decide qual endpoint recebe o POST — a lista/remoção já era unificada
  desde a v1.22.0 (histórico de interações com a borda), então nada se
  perdeu ao apagar a tabela duplicada (`cg-blocks`) da ClientGuard.
- **Aba Gráficos**: as 5 visualizações (tráfego, resumo por barramento, top
  hosts, protocolo, timeline) viraram 5 seções colapsáveis próprias, em vez
  de uma seção única com tudo dentro — o filtro de prefixo/janela ficou fora,
  sempre visível, no topo da aba.
- **Botão "Recolher tudo" / "Expandir tudo"** em qualquer aba com 2+ painéis
  — complementa os painéis colapsáveis da v1.30.0.
- **Badge de contagem na aba Regras** (nº de regras FlowSpec/RTBH ativas),
  no mesmo padrão visual das badges de Ataques/ClientGuard, só que neutro
  (cinza) em vez de vermelho — é uma contagem informativa, não um alerta.
- **Divisor visual entre as abas do FlowGuard e a aba ClientGuard** na barra
  de navegação — são dois sistemas distintos compartilhando a mesma barra;
  de quebra, "Gráficos" (que é só do FlowGuard) passou a ficar agrupado
  antes do divisor, não mais como última aba isolada.

Bug real encontrado e corrigido no processo (mesma classe do bug do título
do Modo Guerra, v1.26.0): os títulos dinâmicos dos gráficos "Tráfego" e "Top
hosts" (`#fg-chart-traffic-title`/`#fg-chart-hosts-title`) são reescritos via
`textContent` toda vez que o prefixo/janela muda — como isso mira o `<h2>`
inteiro, apagava o botão de colapsar recém-adicionado a cada troca de
filtro. Corrigido isolando o texto dinâmico num `<span>` próprio dentro do
`<h2>`, que o JS já teria como alvo mesmo sem essa mudança (`getElementById`
não se importa com profundidade).

Validado com Playwright real: ClientGuard com 3 seções, Configuração com o
toggle funcionando (4 seções do ClientGuard aparecem/somem corretamente),
formulário de bloqueio único com os dois destinos, badge "N" na aba Regras
batendo com `active_rules`, 5 seções colapsáveis em Gráficos sobrevivendo a
uma troca de janela (que antes apagava 2 dos 5 botões), botão Recolher/
Expandir tudo alternando corretamente em 2 cliques — 0 erros de console.

### v1.31.0 — 2026-07-04 — Selo de mitigação na aba Sinais Suspeitos (ClientGuard)
Espelha o ClientGuard v1.22.0. Aba ClientGuard > Sinais Suspeitos ganha uma
coluna "Mitigação" — selo verde "🛡 ativa (FlowSpec/SSH-ACL)" quando o
`src_ip` está mesmo bloqueado agora, âmbar "encerrada" quando já teve
mitigação mas não está mais em vigor (TTL vencido, revert manual, ou a
reconciliação automática com o FlowGuard corrigindo um registro que tinha
ficado desatualizado — ver v1.21.0 do ClientGuard), vermelho "✖ falhou"
quando a última tentativa não deu certo, e cinza neutro "sem mitigação"
quando nunca houve nenhuma. Mesmo selo replicado no painel de detalhe do
sinal. Zero endpoint novo — o campo já vem populado em `clientguard-suspicious.sh`
(mesma chamada de sempre pro socket).

Validado com Playwright real: coluna renderizando "🛡 ativa" corretamente
pra clientes com mitigação FlowSpec ativa (conferido contra o daemon real),
e as 4 variações visuais (ativa/encerrada/falhou/sem mitigação) com cores
distintas e legíveis no tema escuro — 0 erros de console.

### v1.30.0 — 2026-07-04 — Painéis colapsáveis (todas as abas)
Pedido do usuário: opção de colapsar painéis pra otimizar a visualização do
portal. Implementado de forma genérica (`initCollapsiblePanels()`) em vez de
editar as 19 seções (`.fg-panel-section`) uma por uma: no carregamento, cada
`<h2>` de seção ganha um botão ▾/▸, e tudo que vem depois do `<h2>` vira um
"corpo" que esconde/mostra — populações futuras via `innerHTML` em elementos
por id continuam funcionando normal, só ficaram um nível mais fundo no DOM.
Clicar em qualquer lugar do título (não só no botão) já colapsa/expande.
Estado persistido em `localStorage` por chave `aba + texto do título` —
sobrevive a reload e não interfere com o polling de 5s que já existia.

Detalhe importante: `jumpToAttack()` (clique num ataque na timeline dos
Gráficos, pula pro histórico filtrado da aba Ataques) agora força a expansão
de qualquer painel colapsado daquela aba antes de aplicar o filtro — sem
isso, se o operador tivesse colapsado "Ataques" antes, o salto cairia numa
lista invisível.

Validado com Playwright real: 19 seções, 19 botões de colapsar aplicados,
colapsar "Meus Prefixos" esconde o corpo e persiste depois de um reload
completo da página, KPIs/polling continuam atualizando normalmente com os
painéis movidos pra dentro do wrapper, 0 erros de console.

### v1.29.0 — 2026-07-04 — Configuração do Modo Guerra: cards colapsáveis, ativar/desativar, testar conexão, histórico
Pedido do usuário: melhorias na tela "Configuração do Modo Guerra" — cada
equipamento virou um card colapsável (resumo: nome, host, tipo, contagem de
comandos, badge de última execução, checkbox "participa do lote") que expande
só quando clicado, em vez de formulários sempre abertos empilhados. Reflete
`enabled` do FlowGuard v1.23.0 — desmarcar tira o equipamento do próximo lote
sem apagar credenciais/comandos; o modal de execução ("Confirmar e executar
agora") mostra o equipamento desativado esmaecido com "não vai rodar" em vez
de simplesmente omitir (evita "cadê meu equipamento" em cima da hora).

Três ações novas por card: **Testar conexão** (autentica via SSH sem enviar
nenhum comando de produção — novo endpoint `flowguard-warmode-cfg.sh` com
`{"action":"test"}`, usa a senha já salva se o campo ficar em branco);
**Duplicar** (clona um equipamento como base pra outro parecido, nunca
duplica a senha); **Remover** ganhou confirmação (`confirm()`) — antes tirava
o card na hora sem perguntar. Badge de última execução (`última: ok há 2h` /
`falhou há 3h` / `nunca executado`) vem do audit log via
`last_runs_by_device()` do FlowGuard. Bug real corrigido: alternar o
checkbox "participa do lote" só mudava o valor — o esmaecimento visual do
card ficava "preso" no estado de quando a lista carregou; agora reage na
hora via um listener de `change` dedicado.

De passagem: o texto do campo "Comandos de reversão" ainda dizia 'rodados
pelo botão "Sair do Modo Guerra"', botão que não existe mais desde a v1.26.0
(botão único) — atualizado pra "no 2º clique do botão único do Modo Guerra".

Validado com Playwright real sem tocar na senha real do Modo Guerra nem em
equipamento de produção: sessão de desbloqueio criada diretamente no arquivo
de sessões do servidor (mesmo mecanismo de `scripts/create_dev_session.sh`,
só que pro `warmode_token`) e interceptação só do POST de unlock — todo o
resto (listar/testar equipamentos) falou com o backend de verdade, incluindo
os 3 equipamentos reais configurados. "Testar conexão" testado contra um
host inexistente (timeout de 12s confirmado, sem alcançar nenhum equipamento
real). Nenhum clique em "Salvar" durante o teste — `warmode.yaml` de
produção conferido (mtime) como intocado depois. 0 erros de console.

### v1.28.0 — 2026-07-04 — Selo WARMODE-OFF/WARMODE-ON + topo vermelho quando ativo
Pedido do usuário: uma sinalização clara de que o Modo Guerra está desativado
Pedido do usuário: uma sinalização clara de que o Modo Guerra está desativado
("tipo link saudável") e, quando ativado, mudar a cor do topo da página pra
vermelho, indicando problema/ataque em andamento. Novo selo `#fg-warmode-badge`
no topbar, sempre visível (ao contrário do timer, que só aparece ativo):
"WARMODE-OFF" (verde, parado) ou "WARMODE-ON" (vermelho, pulsante) — mesmo
padrão visual de "saudável vs alerta" já usado nos indicadores de sessão BGP
(`fg-dot-up`/`fg-dot-down`). O `.fg-topbar` inteiro ganha um brilho vermelho
pulsante (`is-warmode-active`, reaproveitando a mesma paleta/opacidade do botão
já existente) quando o Modo Guerra está ativo — fica óbvio em qualquer aba, não
só olhando o botão. Estado vem do mesmo polling que já alimentava
botão/timer (`loadWarmodeStatus`, a cada 5s), sem endpoint novo.

Validado com Playwright real: estado OFF (selo verde, sem glow no topo),
estado ON simulado diretamente em `warmode/state.json` (sem tocar em nenhum
equipamento real — mesmo método já usado pra validar o timer na v1.26.0),
confirmando selo vermelho pulsante + brilho no topbar + timer visível
simultaneamente, e retorno a OFF depois — 0 erros de console nos dois
estados.

### v1.27.0 — 2026-07-04 — Duração personalizável do bloqueio RTBH
Espelha o FlowGuard v1.22.0. Aba Configuração > Mitigação ganha um campo
"Duração padrão do bloqueio RTBH" (minutos) abaixo da tabela por tipo de
ataque — reaproveita o mesmo mecanismo de pendência/salvar em lote das
outras colunas. Aba Ataques: o menu "Ações" de cada ataque ganha um campo de
minutos ao lado do botão "Mitigar", pra sobrescrever a duração só daquela
vez sem mexer no padrão configurado (em branco = usa o padrão). Bug real
evitado nesse processo: o listener global que fecha o menu "Ações" ao
clicar fora dele (`initActionMenus`) fecharia o menu assim que o operador
clicasse no campo de minutos pra digitar — corrigido ignorando cliques
dentro de `input`/`select` do menu.

Validado com Playwright real: campo na aba Configuração > Mitigação
salvando/resetando corretamente (valor persistido após reload), campo de
minutos na aba Ataques mantendo o menu aberto ao clicar e digitar, 0 erros
de console.

### v1.26.0 — 2026-07-04 — Modo Guerra: botão único com timer digital
Pedido do usuário: em vez de dois botões ("🚨 Modo Guerra" pra ligar e "🔙
Sair do Modo Guerra" pra desligar), agora é um botão único que alterna —
clique liga (abre o modal de confirmação de sempre: senha + lista de
equipamentos + "Confirmar e executar agora"), clique de novo abre o mesmo
modal só que em modo reversão. A etapa de confirmação por senha continua
obrigatória nos dois sentidos — não foi removida. Enquanto ativo, o botão
ganha um visual "pressionado" (brilho vermelho pulsante, `is-warmode-active`)
e aparece um timer digital no topo da página (`#fg-warmode-timer`, fonte
monoespaçada vermelha, `HH:MM:SS`) contando o tempo decorrido desde que foi
ligado — atualiza a cada segundo no navegador e resincroniza a cada poll
(5s) com o estado real do servidor (`flowguard-warmode.sh?status=1`, novo,
não exige a senha do Modo Guerra — só sessão normal do portal, pra qualquer
operador ver que está em Modo Guerra sem precisar da senha de equipamentos).
Estado (`{"active", "started_at"}`) persistido pelo `flowguard` (v1.21.0,
`warmode/state.json`) toda vez que o botão é confirmado — sobrevive a reload
da página. Bug real corrigido de passagem: o título do modal (`#fg-warmode-title`)
era reescrito via `textContent`, o que apagava o ícone SVG (adicionado na
v1.24.0) toda vez que o modal abria — só o texto agora fica num `<span>`
próprio, o ícone nunca é tocado.

Segunda parte do pedido (aviso periódico no WhatsApp com resumo por IA
enquanto ativo) é 100% no lado do `flowguard` — ver changelog dele (v1.21.0)
pro timer systemd/`warmode/report.py`, este repo só consome o estado via o
endpoint de status acima.

Validado com Playwright real: estado ativo simulado diretamente no arquivo
(sem rodar nenhum comando SSH real), timer incrementando corretamente
(00:01:34 → 00:01:36 em 2s reais), classe `is-warmode-active` aplicada,
clique no botão único abrindo o modal em modo reversão com ícone intacto —
0 erros de console.

### v1.25.0 — 2026-07-04 — Mitigação automática + "Verificar no roteador" na aba Regras
- **Mitigação automática** (FlowGuard v1.20.0): aba Configuração > Mitigação
  ganhou uma coluna "Automático" (select desligado/perfil/RTBH direto) por
  tipo de ataque, ao lado das já existentes (estratégia, limiar de pacote,
  limite de banda) — mesmo padrão de pendência/salvar em lote das colunas
  vizinhas. Só tem efeito nos prefixos com "auto-mitigar" marcado na aba
  Monitor (texto explicativo atualizado na seção).
- **"Verificar no roteador" na aba Regras**: cada regra FlowSpec/RTBH (do
  FlowGuard, e as mitigações do ClientGuard que reaproveitam a mesma tabela)
  ganhou um botão que conecta via SSH no equipamento real (mesmas credenciais
  do Modo Guerra) e confere se a regra está de fato anunciada — não confia só
  no que está gravado no banco local. Mostra resultado (confirmado/com
  diferenças/não encontrado/inconclusivo), estado da sessão BGP correspondente
  e, quando disponível, o comando e a saída bruta do roteador. Pode levar
  10-30s (é uma conexão SSH de verdade), timeout do CGI (`flowguard-rules.sh`)
  subido pra 35s só nesse caso.
- FlowGuard agora fala com 2 sessões BGP simultâneas (roteador de borda
  principal e o peer PPPoE/CGNAT) — reflexo disso no portal via o mecanismo de verificação
  acima, que mostra qual peer/equipamento foi consultado.

### v1.24.0 — 2026-07-04 — Refinamentos visuais/UX
Passe de polimento visual pedido pelo usuário ("melhorias gráficas"),
implementado só em `index.html` (zero mudança em `assets/flowguard.js` —
havia trabalho em progresso não commitado nesse arquivo, isolado desta
mudança de propósito). Escopo: (1) paleta hardcoded (dezenas de `#0d1117`,
`#30363d` etc. repetidos) virou variáveis `:root { --fg-bg, --fg-border, ... }`
— zero mudança visual, facilita qualquer ajuste de tema futuro; (2)
`font-family: sans-serif` trocado por uma stack de fontes de sistema; (3)
emoji nos botões/títulos do topo (🚨/🔙/⚙️/🔧/🔍/📱) substituídos por ícones
SVG inline (`currentColor`, sem dependência externa) — renderização
consistente entre SOs/navegadores; (4) transição suave (CSS `@keyframes`,
sem JS) ao trocar de aba e ao aparecer um toast; (5) placeholders estáticos
"Carregando..." (23 ocorrências) viraram skeleton animado (shimmer) —
`.fg-skeleton-lines`/`.fg-skeleton-card`; (6) contorno de foco visível
(`:focus-visible`) em links/botões/inputs, pra navegação por teclado; (7)
`@media (max-width: 760px)`: tabelas passam a quebrar linha em vez de
recortar texto, topbar/tabs ganham `flex-wrap`. Acento sutil (borda superior)
nos cards de KPI, cedendo pra vermelho quando `.fg-card-danger` está ativo
(mitigação/regra ativa) — checada a especificidade CSS pra garantir que o
estado de alerta sempre vence o acento neutro. Paleta de severidade
(crítico/alto/médio) não foi alterada, por decisão de sessão anterior (ver
changelog de Gráficos interativos). Validado com Playwright real: desktop
(1440px, 7 abas) e mobile (390px, sem overflow horizontal em nenhuma aba,
`scrollWidth === clientWidth`), 0 erros de console em ambos, card de KPI em
estado de alerta confirmado mantendo borda vermelha.

### v1.23.0 — 2026-07-03 — Botão "Sair do Modo Guerra" (reversão dos comandos)
Usuário pediu um botão ao lado do "🚨 Modo Guerra" pra reverter os comandos
aplicados: "digito os comandos novamente e salvo" descrevia o ciclo desejado
(rodar mitigação → sair revertendo → reconfigurar pro próximo incidente).
Cada equipamento ganhou um campo `revert_commands` (novo textarea "Comandos
de reversão" no editor de equipamentos, mesmas regras de `commands` —
`system-view` como primeiro item entra em modo de configuração
automaticamente). Novo botão "🔙 Sair do Modo Guerra" reaproveita o MESMO
modal de execução do "🚨 Modo Guerra" (só troca título/descrição/rótulo do
botão e manda `action: "revert"` no POST) — evita duplicar toda a lógica de
sessão/desbloqueio/renderização. Equipamento sem `revert_commands`
configurado simplesmente não roda nada nesse botão (erro tratado por
equipamento, não trava os outros). Validado com Playwright real contra o
backend de produção (contagem de comandos batendo com `warmode.yaml` real,
0 erros de console) — ver nota de reversão de sessão de teste no repo
`flowguard`.

### v1.22.0 — 2026-07-02 — Aba Regras vira histórico unificado (FlowGuard + ClientGuard)
Usuário pediu que a aba Regras mostre TUDO que já foi gerado/enviado pra
borda, de qualquer sistema, separado por aplicação, com o máximo de detalhe
possível. Antes: só regras FlowSpec **ativas** do FlowGuard, 5 colunas,
zero noção de histórico ou de ClientGuard.

- Novo toggle "FlowGuard" / "ClientGuard" (`#rules-app-toggle`) + "Ativas" /
  "Histórico completo" (`#rules-view-toggle`), mesmo padrão já usado em
  Ataques/Sinais Suspeitos (`.fg-toggle-group`, não abas aninhadas).
- **FlowGuard**: uma tabela só (RTBH e FlowSpec convivem na mesma
  `flowspec_rules`) com ID, Criada em, Tipo (RTBH/FlowSpec descarte/
  rate-limit/redirect, derivado de `action`), Origem, Destino, Protocolo,
  Portas, Rótulo, Ataque associado (`attack_id`), Status (ativa/expirada/
  removida, derivado de `active`+`expires_at`) e Expira em.
- **ClientGuard**: duas tabelas — a mesma `flowspec_rules` filtrada por
  `origin === "clientguard"` (bloqueio manual via proxy BGP) e a mitigação
  direta na borda via SSH/ACL (`edge_mitigations`, reaproveitando o mesmo
  endpoint já usado na aba ClientGuard) com ID, src_ip, Status, Gatilho
  (manual/automático), Sinal associado, Aplicada em, Revertida em, Expira e
  Erro (se falhou).
- `flowguard-rules.sh` ganha `?history=1` (repassa pro socket, mesmo padrão
  de `flowguard-attacks.sh`) — sem isso o backend só devolvia ativas.
- Filtro de app/status é 100% client-side (`applyRulesFilter`) — busca sempre
  o histórico completo uma vez e reparte na hora; volume de regras nunca
  chega perto do de flow_aggs/client_flow_aggs, não precisou de parâmetro
  novo por combinação.
- Validado com Playwright real: criar regra manual → aparece com todos os
  detalhes (tipo, status "ativa", botão Remover) → remover → some da view
  "Ativas". Alternar entre os 4 toggles sem erro de console. Contagem de
  linhas no histórico bateu exatamente com `flowguard-cli rules --history`.

### v1.21.0 — 2026-07-02 — Desempenho: timeouts maiores nos endpoints pesados do ClientGuard
Usuário reportou timeout constante no portal. Causa raiz real era no daemon
(contenção de lock + `COUNT(*)` recalculado a toda hora — ver CHANGELOG do
`clientguard`, corrigido lá). Do lado do portal, dois endpoints de leitura
(`clientguard-top.sh`, `clientguard-client-detail.sh`) faziam `GROUP BY`+
`ORDER BY` sobre a tabela inteira em janelas longas (7 dias) — mesmo com o
lock resolvido, essa consulta específica ainda leva ~10-16s sob o volume
atual de dados, acima do timeout de 5s configurado aqui. Subido pra 20s nos
dois — validado com Playwright real: painel "Top Clientes" com janela de 7d
renderizou em ~9s sem erro (antes: timeout sempre). Os demais endpoints do
ClientGuard (status, sinais suspeitos, mitigações de borda) já ficaram
rápidos o bastante (sub-10ms) com o fix no daemon, timeout deles não precisou
mudar.

### v1.20.0 — 2026-07-02 — Perfil de operadora, interfaces/VLANs e 5 templates novos
- Botão "Ver rotas" em cada linha da tabela de peers (descoberta BGP): mostra
  as rotas anunciadas/recebidas de verdade pra aquele peer específico, com
  alternância entre as duas direções — é a resposta direta a "quero ver
  redes/hosts advertidos por operadora".
- A tela de descoberta ganhou tabelas de "Interfaces" e "VLANs" (nome/IP/
  estado; VID/nome/status/portas).
- Generalização: qualquer campo de interface em qualquer template (não só
  os de BGP) agora vira uma lista de interfaces reais depois da descoberta
  — inclui o template de descrição/estado de interface que já existia.
- 5 templates novos na tela de Config. Roteador: criar/remover VLAN,
  adicionar/remover VLAN de uma porta trunk, adicionar/remover IP de uma
  interface, criar/remover sub-interface 802.1Q (11 templates no total).
- Validado com Playwright real (mock só nas chamadas de descoberta/rotas —
  preview/apply seguem batendo no backend real): tabelas de interfaces/VLANs
  aparecem corretamente, "Ver rotas" alterna anunciadas/recebidas, campos de
  interface viram select nos templates de VLAN — ver
  [[feedback-verify-with-real-browser]].

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
