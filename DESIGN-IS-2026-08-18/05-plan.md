# Plano de Implementação — Redesign flowguard-portal (visual/CSS only)

Origem: audit Dieter Rams (16/30, veredito REDESIGN) — ver `03-verdict.md` e `04-handoff-prompt.md` nesta pasta.

**Restrição dura, vale para TODAS as fases:** só CSS/markup/estilo inline. Nenhuma mudança em lógica de negócio, endpoints, polling, contratos de API. Backup existe: branch `backup/pre-redesign-20260818`, tag `backup-pre-redesign-20260818`, tar em `/root/backups/flowguard-portal-pre-redesign-20260818-093012.tar.gz`.

Cada fase é autocontida (arquivo, linhas, snippet a copiar, checklist de verificação) — pode ser executada em sessão nova sem depender do contexto desta conversa.

---

## Fase 0 — Descoberta (já feita, resumo)

**Token block atual** — `index.html:8-23`:
```css
:root {
  color-scheme: dark;
  --fg-bg: #0d1117;
  --fg-bg-panel: #161b22;
  --fg-bg-elevated: #21262d;
  --fg-border: #30363d;
  --fg-text: #c9d1d9;
  --fg-text-muted: #8b949e;
  --fg-accent: #58a6ff;
  --fg-danger: #f85149;
  --fg-danger-hover: #ff7b72;
  --fg-success: #3fb950;
  --fg-orange: #ffa657;
  --fg-warning: #d29922;
  --fg-font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
```
12 cores + 1 font-stack. Este bloco é a base — as fases abaixo referenciam essas variáveis por nome (`var(--fg-accent)` etc.), nunca reescrevem o bloco do zero.

Padrão de botão nativo já usado no código (copiar sempre que precisar de foco/teclado "de graça"), `flowguard.js:367-376` (`sortableTh`):
```js
return '<th data-sort-key="' + key + '" scope="col" class="' + cls + '" aria-sort="' + ariaSort + '">' +
  '<button type="button" class="fg-th-sort-btn">' + escapeHtml(label) + "</button></th>";
```

Padrão de `confirm()` já usado (copiar para a Fase 4), `flowguard.js:2342-2361`:
```js
if (!window.confirm(
  "Apagar TODAS as " + activeCount + " regra(s) FlowSpec/RTBH ativas (FlowGuard + ClientGuard)? " +
  "Isso retira o bloqueio/limite de banda de todo mundo imediatamente e não pode ser desfeito.",
)) {
  return;
}
```

Padrão de `title=` explicativo já usado (copiar para a Fase 5), `index.html:908`:
```html
title="Reverte TODAS as mitigações do ClientGuard, tanto FlowSpec (tabela de cima) quanto SSH/ACL (tabela de baixo)"
```

---

## Fase 1 — Consolidar cores hardcoded em tokens

**O que fazer:** substituir todo literal hex/rgba que duplica um token existente por `var(--fg-*)`; promover as 4 cores novas do gráfico de prefixos a tokens nomeados (ex: `--fg-chart-purple`, `--fg-chart-pink`, `--fg-chart-cyan`, `--fg-chart-blue2`).

**Migração exata (flowguard.js), agrupado por valor:**
- `#58a6ff` → `var(--fg-accent)` — 9 ocorrências: linhas 1350, 1670, 4151, 5157, 5897, 5898, 6030, 6034, 6074
- `#8b949e` → `var(--fg-text-muted)` — 15 ocorrências: linhas 1353, 5147, 5158, 5243, 5270, 5304, 5327, 5401, 5477, 5506, 5595, 5619, 5657, 6039, 6040, 6074
- `#f85149` → `var(--fg-danger)` — 4 ocorrências: linhas 2585, 5147, 6046, 6047
- `#d29922` → `var(--fg-warning)` — 3 ocorrências: linhas 1352, 5147, 6074
- `#ffa657` → `var(--fg-orange)` — 3 ocorrências: linhas 5147, 6031, 6035
- `#3fb950` → `var(--fg-success)` — 2 ocorrências: linhas 1351, 6074
- `#21262d` → `var(--fg-bg-elevated)` — 3 ocorrências: linhas 5303, 5505, 5600
- `#0d1117` → `var(--fg-bg)` — 1 ocorrência: linha 5149 (`var CHART_BG`)
- `#c9d1d9` → `var(--fg-text)` — 1 ocorrência: linha 5623
- `#30363d` → `var(--fg-border)` — 1 ocorrência: linha 1379 (dentro de SVG inline via concatenação de string — usar `getComputedStyle` ou interpolar a variável no template, não um `var()` CSS puro, já que é atributo SVG `stroke=`)
- `rgba(88,166,255,X)` (X = 0.18, 0.55, 0.25) → manter como tint do accent, mas via helper único (ex: `function accentAlpha(a){ return "rgba(88,166,255,"+a+")"; }`) em vez de 3 literais soltos — linhas 5336, 5346, 6042
- `rgba(201,209,217,0.4)` → mesma ideia, helper de tint do `--fg-text` — linhas 5420, 5552

**Novas variáveis a adicionar no `:root` (index.html:22, antes do fechamento em linha 23):**
```css
--fg-chart-purple: #a371f7;
--fg-chart-pink: #db61a2;
--fg-chart-cyan: #39c5cf;
--fg-chart-blue2: #79c0ff;
```
Usar essas variáveis em `CHART_PREFIX_COLORS` (flowguard.js:5157) e no `accent` do widget `clientguard` (flowguard.js:804, hoje `#a371f7` hardcoded).

**Migração exata (index.html `<style>`, linhas 8-558):** 18 literais `rgba()` em 15 linhas, todos ligados a estados de Modo Guerra ou sombras — linhas 65, 66, 70, 71, 91, 274, 305 (2 literais), 309 (2), 310 (2), 321, 335, 440, 459, 521, 525. Cada um já usa a paleta danger/black — trocar por `rgba(var(--fg-danger-rgb), X)` requer expor `--fg-danger-rgb: 248,81,73;` como token auxiliar (CSS não permite extrair componentes de um hex var diretamente). Adicionar tokens RGB auxiliares:
```css
--fg-danger-rgb: 248,81,73;
--fg-black-rgb: 0,0,0;
```
Fora do escopo do `<style>`: `index.html:947` (`background:#fff` inline num `<img>`) — trocar por `background:#fff` mantido (é fundo de QR code, precisa ficar branco de propósito — **não migrar**, documentar como exceção intencional).

**Verificação:**
- `grep -c '#[0-9a-fA-F]\{3,6\}' assets/flowguard.js` deve cair de ~57 para próximo de 0 (exceto os novos tokens declarados uma vez)
- Rodar visualmente: gráficos de tráfego, badges de severidade, cockpit devem renderizar exatamente as mesmas cores de antes (é substituição 1:1, zero mudança visual esperada)
- `git diff` não deve tocar nenhuma linha fora de `style=`, `<style>`, ou literais de cor em `flowguard.js`

**Guard-rails:** não mudar nenhum valor de cor, só a referência (literal → var). Não tocar em `SEV_COLORS`/`CHART_PREFIX_COLORS` além de trocar os valores por vars.

---

## Fase 2 — Escala real de spacing e tipografia

**O que fazer:** hoje `index.html` usa 21 valores rem distintos de spacing e 14 de font-size, sem escala visível (ex: 0.32rem, 0.35rem, 0.45rem, 0.55rem convivendo sem lógica). Definir uma escala de ~8 degraus e remapear cada valor existente para o degrau mais próximo.

**Escala proposta (adicionar ao `:root`):**
```css
--space-1: 0.2rem;
--space-2: 0.4rem;
--space-3: 0.6rem;
--space-4: 0.8rem;
--space-5: 1rem;
--space-6: 1.5rem;
--space-7: 2rem;
--space-8: 4rem;

--text-xs: 0.72rem;
--text-sm: 0.8rem;
--text-base: 0.85rem;
--text-md: 0.95rem;
--text-lg: 1.1rem;
--text-xl: 1.5rem;
--text-2xl: 1.8rem;
```

**Tabela de remapeamento de spacing** (valor atual → degrau, contagem de ocorrências no arquivo):
0.05rem, 0.1rem, 0.15rem, 0.2rem → `--space-1` (0.2rem) | 0.25rem, 0.3rem, 0.32rem, 0.35rem, 0.4rem, 0.45rem → `--space-2` (0.4rem) | 0.5rem, 0.55rem, 0.6rem, 0.7rem → `--space-3` (0.6rem) | 0.8rem, 0.9rem → `--space-4` | 1rem → `--space-5` | 1.2rem, 1.5rem → `--space-6` | 2rem → `--space-7` | 4rem → `--space-8`

**Tabela de remapeamento de font-size:**
0.7rem, 0.72rem, 0.75rem → `--text-xs` | 0.78rem, 0.8rem, 0.82rem → `--text-sm` | 0.85rem, 0.92rem → `--text-base` | 0.95rem → `--text-md` | 1rem, 1.05rem, 1.1rem → `--text-lg` | 1.5rem → `--text-xl` | 1.8rem → `--text-2xl`

**Como executar sem quebrar layout:** ir seletor por seletor (não find-replace global — muitos valores como `0.5rem` aparecem em `padding: 0.5rem 1rem` misturado com outros), começando pelos componentes mais isolados (`.fg-badge`, `.fg-toggle-btn`, `.fg-kpi-*`) antes dos layouts estruturais (`.fg-sidebar`, `.fg-main`, `.fg-modal`).

**Verificação:**
- Screenshot antes/depois de cada aba via Playwright (`agent-browser` skill) comparando pixel a pixel — diferença deve ser imperceptível (é normalização, não redesign visual)
- `grep -oE '[0-9.]+rem' index.html | sort -u | wc -l` deve cair de ~21+14 valores distintos para os ~15 tokens da escala

**Guard-rails:** essa fase é só sobre consistência de escala, não sobre mudar tamanhos/densidade do layout. Se um valor não bater exatamente num degrau, escolher o mais próximo, não inventar um nono degrau.

---

## Fase 3 — Remover código morto

**Itens confirmados (zero outras referências via grep):**
1. `.fg-statusbar` — `index.html:236-237` — deletar as 2 linhas de CSS
2. `.fg-cockpit-mini-kpis` — `index.html:529` — deletar a linha
3. `CG_EDGE_CFG_ENDPOINT` — `flowguard.js:31` — deletar a declaração
4. Mecanismo `COCKPIT_JUMP_TARGETS` — sempre vazio (`{}`, `flowguard.js:815`), usado em 2 lugares:
   - `flowguard.js:911` dentro de `cockpitJumpToWidget` (linhas 910-926) — função inteira é hoje um no-op garantido (`if (!jump) return;` sempre dispara)
   - `flowguard.js:983` dentro de `cockpitCardHtml`: `var jumpable = !!COCKPIT_JUMP_TARGETS[w.id] || !!COCKPIT_POPOVER_TARGETS[w.id];` — simplificar para `var jumpable = !!COCKPIT_POPOVER_TARGETS[w.id];`
   - Chamada em `flowguard.js:1090-1101` (grid click listener): remover o branch `cockpitJumpToWidget(id)` e a função inteira `cockpitJumpToWidget` (910-926), já que nunca executa nada
   - Atualizar comentário em `index.html:509-511` que referencia `COCKPIT_JUMP_TARGETS` (hoje diz "ver COCKPIT_JUMP_TARGETS em flowguard.js") para refletir que só `COCKPIT_POPOVER_TARGETS` está ativo

**Por que é seguro (não é mudança funcional):** `COCKPIT_JUMP_TARGETS` está vazio desde sempre pelo próprio comentário do código-fonte (`flowguard.js:810-814`: "Hoje nenhum card usa mais esse caminho"). Remover um caminho de código que nunca executa não muda comportamento observável.

**Verificação:**
- `grep -n "COCKPIT_JUMP_TARGETS\|cockpitJumpToWidget\|fg-statusbar\|fg-cockpit-mini-kpis\|CG_EDGE_CFG_ENDPOINT" index.html assets/flowguard.js` deve retornar vazio após a fase
- Testar manualmente: clicar nos 3 cards clicáveis (rules, clientguard, mitigations) ainda deve abrir o popover normalmente; os outros 6 cards continuam não-clicáveis (comportamento inalterado)

**Guard-rails:** não mexer em `COCKPIT_POPOVER_TARGETS` nem nas 3 funções de popover (`cockpitRulesPopoverHtml` etc.) — só remover o caminho morto do jump.

---

## Fase 4 — Corrigir disclosure/confirm do botão "Mitigar"

**Problema:** `flowguard.js:1459` renderiza `<button data-action="mitigate">Mitigar</button>` sem `title` e sem `confirm()`. O handler (`onAttacksClick`, corpo relevante em `flowguard.js:1748-1798`) vai direto pro `postJson(ATTACKS_ENDPOINT, {action:"mitigate",...})`. O único lugar que explica que "Mitigar" = RTBH (bloqueio total do prefixo via BGP) é um parágrafo em `index.html:991`, noutra aba.

**O que fazer (2 mudanças, ambas puramente de apresentação):**

1. Adicionar `title` explicativo no botão, `flowguard.js:1459`:
```js
'<button data-action="mitigate" title="Bloqueia o prefixo inteiro via RTBH (BGP blackhole) — ação manual de emergência, sempre RTBH independente de outras estratégias configuradas.">Mitigar</button>'
```

2. Adicionar `confirm()` no handler, copiando o padrão exato de `flowguard.js:2342-2361`, inserido em `onAttacksClick` antes do bloco `if (action === "mitigate") {...}` (linha ~1780, antes do `postJson`):
```js
if (action === "mitigate" && !window.confirm(
  "Mitigar " + prefix + " agora vai bloquear o prefixo INTEIRO via RTBH (BGP blackhole), imediatamente. Essa é sempre a ação do botão \"Mitigar\" — para bloqueio parcial (FlowSpec), use a Configuração de Mitigação. Confirma?"
)) {
  return;
}
```

**Verificação:**
- Clicar em "Mitigar" numa linha de ataque deve mostrar o `confirm()` com o texto acima antes de disparar `postJson`
- Cancelar o confirm não deve disparar nenhuma request (mesmo padrão das 3 ações existentes)
- `postJson(ATTACKS_ENDPOINT, ...)` deve continuar recebendo exatamente o mesmo payload de antes (`{action, attack_id, ttl_s?}`) — só a camada de confirmação muda

**Guard-rails:** não mudar o payload enviado ao backend, não mudar `successLabel`/toast, não adicionar confirm nas outras ações (`release`, `apply_suggestion`) que não foram sinalizadas no audit.

---

## Fase 5 — Explicar jargão no ponto de uso

**Padrão a copiar** (já existe no código): `title="..."` explicativo, como em `index.html:908` e `flowguard.js:1458`.

**Itens a corrigir:**
- `index.html:836` — chip de severidade "watch" → adicionar `title="Observação — sinal de baixa severidade, não é crítico nem urgente"` (ou considerar renomear a label visível para "observação", mantendo o valor interno)
- `index.html:914` — opção "RTBH (blackhole)" no filtro de tipo de regra → `title="Bloqueio total do prefixo via anúncio BGP (Remote-Triggered Black Hole)"`
- `flowguard.js:801` — título do widget cockpit "BGP (ExaBGP)" → adicionar/ajustar `hint` do objeto `COCKPIT_WIDGETS` (linha 796-808, já suporta campo `hint` renderizado como `title` no `<h3>`, ver `cockpitCardHtml` linha 986) para "ExaBGP é o serviço que mantém nossa sessão BGP com a operadora"
- `flowguard.js:1257-1258, 2017` — status "Up"/"Idle" de peer BGP → adicionar `title="Idle = sessão BGP não estabelecida"` ao lado do texto ou trocar por rótulo traduzido com o termo técnico entre parênteses
- `flowguard.js:1291, 1337` — KPI "Daemon" → `title="Serviço de detecção em segundo plano (daemon)"`
- `flowguard.js:4146` — coluna "ASN/País" → `title="ASN = Número do Sistema Autônomo"`
- `flowguard.js:3606-3608` — campos EWMA/sigma → confirmar que o texto explicativo já presente ("número MAIOR = menos sensível") também expande a sigla na primeira aparição

**Verificação:** cada elemento acima deve ter um `title` não-vazio ao passar o mouse (ou já ter texto visível equivalente); nenhum texto de rótulo principal muda de significado, só ganha explicação auxiliar.

**Guard-rails:** só adicionar `title`/`hint`, não reescrever rótulos existentes exceto "watch" (caso se opte por renomear, manter o `data-`/valor interno igual, só a label visível muda).

---

## Fase 6 — Acessibilidade dos cockpit cards + skip link

**Cockpit cards clicáveis (hoje mouse-only):**
`flowguard.js:979-995` (`cockpitCardHtml`) renderiza `<div class="fg-cockpit-card ... fg-cockpit-clickable" data-widget-id="...">` sem `tabindex`, sem `role`, sem handler de teclado. O clique é capturado por delegação em `flowguard.js:1090-1101`.

**Padrão a copiar:** `sortableTh` (`flowguard.js:367-376`) — envolve o elemento clicável num `<button type="button">` real em vez de um `<div>` com `cursor:pointer`, porque um botão nativo recebe foco e dispara `click` com Enter/Espaço de graça, sem precisar reescrever o listener delegado (que já escuta `"click"`).

**O que fazer:** só para os 3 cards com `jumpable` true (rules, clientguard, mitigations — os únicos com `fg-cockpit-clickable`), envolver o `<h3>` + corpo clicável dentro de um `<button type="button" class="fg-cockpit-card-trigger">` interno, mantendo `data-widget-id` no `<div>` pai para o listener delegado continuar funcionando sem mudança de lógica.

**Skip link:**
1. Adicionar `id="fg-main-content"` na tag `<main class="fg-main">` — hoje sem id, `index.html:584`
2. Adicionar logo no início do `<body>` (antes de `#fg-app`, ou como primeiro filho de `#fg-app`):
```html
<a class="fg-skip-link" href="#fg-main-content">Pular para o conteúdo</a>
```
3. CSS novo (visualmente oculto até foco, padrão comum de skip-link):
```css
.fg-skip-link {
  position: absolute; left: -9999px; top: 0;
  background: var(--fg-bg-elevated); color: var(--fg-text);
  padding: var(--space-3) var(--space-4); z-index: 1000;
  border: 1px solid var(--fg-accent); border-radius: 6px;
}
.fg-skip-link:focus { left: var(--space-3); top: var(--space-3); }
```

**Verificação:**
- Tab a partir do topo da página: primeiro stop deve ser o skip-link (invisível até foco), Enter deve mover o foco para `#fg-main-content`
- Tab pelos 3 cockpit cards clicáveis: devem receber foco visível e abrir popover com Enter/Espaço
- Os 6 cards não-clicáveis continuam sem tabstop (comportamento correto, não são interativos)

**Guard-rails:** não mudar `COCKPIT_POPOVER_TARGETS` nem a lógica de abrir/fechar popover — só a camada de foco/marcação em volta do card.

---

## Fase 7 — Polimento de estados de erro

**Vazamento de erro cru (WhatsApp groups):** `flowguard.js:6314-6327` (`loadWaGroups`) exibe `data.error` verbatim dentro de um `<option>` quando a chamada falha — se o backend (CGI, fora do escopo desta revisão de front-end) devolver texto tipo "HTTP Error 500: Internal Server Error", isso aparece cru pro operador.

**O que fazer:** trocar o fallback de `data.error || "erro ao listar grupos"` para sempre mostrar uma mensagem amigável fixa, e mandar o `data.error` cru só pro console (mesmo padrão já usado pelos `.catch` vizinhos do arquivo, ex. linha 6326):
```js
if (!data.ok) {
  console.error("flowguard.js: loadWaGroups falhou:", data.error);
  sel.innerHTML = '<option value="">erro ao carregar grupos — tente novamente</option>';
  return;
}
```

**Label "Limpar hosts suspeitos" (mismatch menor, honestidade):** `index.html:841` — a ação real (`onCgClearSuspiciousClick`, `flowguard.js:5124-5134`) marca todos os sinais como resolvidos, não apaga nada (histórico preservado). Trocar o rótulo visível para `Marcar hosts suspeitos como resolvidos` (o `confirm()` já existente já descreve isso corretamente — só o rótulo do botão está desalinhado).

**Verificação:** simular falha na chamada de grupos do WhatsApp (ou revisar visualmente o dropdown) — deve mostrar a mensagem amigável, nunca o texto cru do backend. Botão renomeado deve manter mesmo `id`/handler, só o texto visível muda.

**Guard-rails:** não tocar em `WHATSAPP_ENDPOINT` nem no CGI backend — é puramente sobre o que a UI mostra quando `data.ok` é falso.

---

## Fase 8 — Verificação final

1. Re-rodar os scores das evidências que dependem de código (`grep` das listas acima) para confirmar migração de cor/spacing completa
2. Rodar Playwright contra `http://127.0.0.1:18080/` (mesma sessão de dev usada no audit) e re-testar a checklist de "Preserve" do `03-verdict.md`:
   - Contraste AA em todos os pares de texto/fundo/status/botão (não deve regredir)
   - Navegação completa por teclado: tabs, os 3 modais (focus trap + Escape + retorno de foco), ordenação de tabela, colapso de painel, checkboxes de seleção em massa
   - Todas as ações destrutivas em massa continuam com `confirm()` e texto de consequência
   - Zero copy com inflação/dark pattern
   - Os 6 estados (empty/loading/error/success/focus/disabled) continuam presentes
3. `git diff --stat` deve mostrar mudanças concentradas em `index.html` (CSS/markup) e `assets/flowguard.js` (apenas templates de string/estilo, nenhuma função de lógica de negócio/API alterada em assinatura ou comportamento)
4. Atualizar `README.md`/`CHANGELOG` do repo (`obesao/flowguard-portal`) com a versão nova, seguindo a convenção já usada (ex: v1.62.0) — lembrando de sanitizar qualquer IP/modelo de equipamento real antes do commit, por regra já vigente neste projeto
5. Commit local (não push sem autorização explícita)
