---
name: Portal do Provedor (FlowGuard/ClientGuard)
description: Console de operação de rede — DDoS e abuso de cliente, denso e sem decoração
colors:
  void-ink: "#0d1117"
  panel-charcoal: "#161b22"
  elevated-slate: "#21262d"
  steel-border: "#30363d"
  fog-white: "#c9d1d9"
  muted-steel: "#8b949e"
  signal-blue: "#58a6ff"
  alert-red: "#f85149"
  alert-red-hover: "#ff7b72"
  status-green: "#3fb950"
  amber-flag: "#ffa657"
  warning-ochre: "#d29922"
typography:
  headline:
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif"
    fontSize: "1.5rem"
    fontWeight: 600
    lineHeight: 1.3
  title:
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif"
    fontSize: "1rem"
    fontWeight: 600
    lineHeight: 1.4
  body:
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif"
    fontSize: "0.85rem"
    fontWeight: 400
    lineHeight: 1.5
  label:
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif"
    fontSize: "0.75rem"
    fontWeight: 400
    lineHeight: 1.3
    letterSpacing: "0.03em"
  mono:
    fontFamily: "'Courier New', ui-monospace, monospace"
    fontSize: "0.82rem"
    fontWeight: 400
rounded:
  sm: "4px"
  md: "6px"
  lg: "8px"
  pill: "999px"
spacing:
  xs: "0.2rem"
  sm: "0.4rem"
  md: "0.6rem"
  lg: "0.8rem"
  xl: "1.2rem"
components:
  button-neutral:
    backgroundColor: "{colors.elevated-slate}"
    textColor: "{colors.fog-white}"
    rounded: "{rounded.md}"
    padding: "0.2rem 0.6rem"
  button-neutral-hover:
    backgroundColor: "{colors.steel-border}"
  button-danger:
    backgroundColor: "{colors.alert-red}"
    textColor: "{colors.void-ink}"
    rounded: "{rounded.md}"
    padding: "0.2rem 0.6rem"
  button-danger-hover:
    backgroundColor: "{colors.alert-red-hover}"
  badge-pill:
    backgroundColor: "{colors.elevated-slate}"
    textColor: "{colors.muted-steel}"
    rounded: "{rounded.pill}"
    padding: "0.15rem 0.5rem"
  kpi-card:
    backgroundColor: "{colors.panel-charcoal}"
    textColor: "{colors.fog-white}"
    rounded: "{rounded.lg}"
    padding: "0.9rem 1rem"
---

# Design System: Portal do Provedor

## 1. Overview

**Creative North Star: "The Ops Console"**

Este portal é a sala de controle de um NOC, não um produto que precisa convencer alguém a assinar um plano. Toda decisão visual serve a uma pergunta única, feita sob pressão: "o que está acontecendo agora, e o que eu faço a respeito?". O sistema é escuro por padrão, denso, e recusa qualquer elemento cuja única função seja decorativa — nenhuma sombra difusa, nenhum gradiente, nenhum card fofo. A cor tem função de sinal (severidade, estado, ação disponível), não de humor de marca.

O portal rejeita explicitamente a estética de marketing SaaS: sem hero, sem CTA persuasivo, sem tom de "produto vendendo plano". Também rejeita a extremidade oposta — planilha crua sem hierarquia — através de badges, cores de severidade e agrupamento visual consistentes.

**Key Characteristics:**
- Escuro, denso, sem sombra decorativa (flat-by-doctrine)
- Azul como único acento "de marca" — reservado a foco, estado ativo e sinal neutro, nunca decoração
- Vermelho/verde/âmbar carregam significado operacional real (severidade, sucesso, atenção), nunca são escolha estética
- Tabelas e cards compactos: cabe mais dado por tela do que respiro visual

## 2. Colors

Paleta escura de alto contraste derivada da família GitHub Primer Dark — cada cor tem um papel operacional fixo, nunca decorativo.

### Primary
- **Signal Blue** (#58a6ff): único acento "de identidade" do sistema. Usado em foco de teclado, borda esquerda de aba ativa, topo de KPI card, links e cabeçalho de tabela ordenável em hover. Nunca aparece como cor de fundo de botão — não existe "botão primário azul" neste sistema; ver **The One Accent Rule** abaixo.

### Secondary (papéis de severidade — funcionalmente paralelos, não hierárquicos entre si)
- **Alert Red** (#f85149) / hover **#ff7b72**: severidade crítica, erro, ação destrutiva (`.fg-btn-danger`), Modo Guerra ativo.
- **Status Green** (#3fb950): sucesso, mitigação ativa, sessão BGP saudável.
- **Amber Flag** (#ffa657): severidade alta (abaixo de crítico).
- **Warning Ochre** (#d29922): atenção/estado intermediário (mitigação expirada mas ainda relevante, countdown de auto-revert).

### Neutral
- **Void Ink** (#0d1117): fundo base da página — a camada mais profunda.
- **Panel Charcoal** (#161b22): fundo de `section`/`.fg-card` — a camada de conteúdo.
- **Elevated Slate** (#21262d): terceira camada — hover de botão neutro, badge neutro, linha de tabela agrupada.
- **Steel Border** (#30363d): toda borda 1px do sistema; também o estado "pressed"/hover mais escuro de elementos interativos.
- **Fog White** (#c9d1d9): texto primário.
- **Muted Steel** (#8b949e): texto secundário, labels, timestamps, contagens.

### Data Visualization (categorical, extensão)
Os gráficos de canvas (protocolo, prefixo, ClientGuard) usam uma paleta categórica de 8 cores, distinta da paleta de severidade acima — série de dado, não estado: `#58a6ff, #ffa657, #a371f7, #3fb950, #db61a2, #39c5cf, #d29922, #79c0ff` (`CHART_PREFIX_COLORS` em `assets/flowguard.js`). O card cockpit do ClientGuard também usa um roxo próprio (`#a371f7`) como acento — diferencia visualmente "outro sistema" sem reusar Signal Blue. Ambos já foram checados com o validador de paleta do skill `dataviz` contra o fundo `#0d1117`: separação de CVD (daltonismo) e contraste passam.

### Named Rules
**The One Accent Rule.** Signal Blue é o único acento de identidade e aparece em ≤10% de qualquer tela. Ele nunca preenche a área de um botão — não existe botão "primário" azul neste sistema, só neutro (`.fg-btn`) e destrutivo (`.fg-btn-danger`). Isso é deliberado: um NOC não precisa ser guiado a uma "ação recomendada" via cor de marca, precisa ver estado.

**The Severity-Never-Alone Rule.** Vermelho/verde/âmbar nunca são o único sinal de estado. Todo estado de severidade tem um segundo canal — texto (`"Down"`, `"Ativo"`), posição (badge vs. célula normal) ou ícone — para sobreviver a print/WhatsApp e a daltonismo. Isto está diretamente ligado ao requisito de acessibilidade WCAG AA do PRODUCT.md.

## 3. Typography

**Body/UI Font:** -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif (pilha de sistema — sem webfont carregado, consistente com "sem dependência de CDN")
**Mono Font:** "Courier New", ui-monospace, monospace (usado só no display do countdown do Modo Guerra e em blocos `<pre>` de resultado técnico)

**Character:** Uma única família sans do sistema faz todo o trabalho de hierarquia — peso e tamanho substituem a variedade de fontes. É a escolha certa para um console operacional: zero latência de carregamento, aparência neutra e "nativa do SO" em vez de estilizada.

### Hierarquia
- **Headline** (600, 1.5rem, 1.3): título de seção (`h2`), inclusive o cabeçalho colapsável de painel.
- **Title** (600, 1rem, 1.4): subtítulo de bloco (`h4`), nome de item em listas de toggle/config.
- **Body** (400, 0.85rem, 1.5): conteúdo de tabela — a unidade de informação mais repetida na tela; tamanho reduzido deliberadamente para caber mais linhas.
- **Label** (400, 0.75rem, letter-spacing 0.03em, uppercase quando é label de KPI): rótulo de KPI, label de navegação "Ir para", contagem secundária.
- **Mono**: countdown do Modo Guerra e saída técnica bruta (comandos SSH, resultado de execução).

### Named Rules
**The No-Display-Type Rule.** Este sistema não tem tipografia de destaque/hero — o maior texto na tela é 1.5rem (headline de seção). Um console operacional nunca precisa "gritar" com tipografia; a urgência é comunicada por cor de severidade e animação de estado (pulse), não por tamanho de fonte.

## 4. Elevation

Sistema flat por doutrina — decisão explícita, não lacuna. Profundidade vem inteiramente de três camadas de fundo (Void Ink → Panel Charcoal → Elevated Slate) mais bordas de 1px, nunca de `box-shadow` difuso decorativo. As únicas exceções reais são utilitárias: o menu-dropdown (`.fg-menu-list`) e o toast usam uma sombra curta e escura (`0 4px 12px rgba(0,0,0,0.5)` / `0 2px 8px rgba(0,0,0,0.4)`) para se destacar do conteúdo por baixo quando sobrepõem a página — não para simular profundidade física.

### Shadow Vocabulary
- **overlay-pop** (`box-shadow: 0 4px 12px rgba(0,0,0,0.5)`): dropdown de menu de ações, precisa se destacar do conteúdo atrás.
- **toast-pop** (`box-shadow: 0 2px 8px rgba(0,0,0,0.4)`): notificação flutuante no canto da tela.
- **alert-glow** (`box-shadow: 0 0 16px 1px rgba(248,81,73,0.35)`, pulsante): reservado exclusivamente ao estado "Modo Guerra ativo" — a única situação no sistema em que um brilho é intencional, porque o objetivo ali é literalmente ser impossível de ignorar.

### Named Rules
**The Flat-By-Doctrine Rule.** Superfícies em repouso nunca têm sombra. Sombra só aparece como resposta funcional (dropdown sobreposto, toast temporário) ou como alarme deliberado de um único estado (Modo Guerra). Nunca decorativa, nunca "pra dar profundidade" a um card comum.

## 5. Components

### Buttons
- **Shape:** cantos levemente arredondados (6px, `{rounded.md}`).
- **Neutral (padrão):** fundo Elevated Slate, texto Fog White, borda Steel Border — é o botão-padrão para toda ação não-destrutiva, incluindo o que em outros sistemas seria "primário". Sem preenchimento azul.
- **Hover:** fundo escurece para Steel Border (transição de 0.15s).
- **Danger:** fundo Alert Red, texto Void Ink (alto contraste sobre vermelho), peso bold. Hover clareia para #ff7b72. Reservado a ações destrutivas reais (mitigar, banir, executar Modo Guerra).
- **Disabled:** opacidade 0.4–0.5, cursor default.

### Badges (pill)
- **Shape:** totalmente arredondado (999px, `{rounded.pill}`).
- **Neutral/contagem:** fundo Elevated Slate, texto Muted Steel, borda Steel Border — contagem informativa (ex: regras ativas), não um alerta.
- **Alerta:** fundo Alert Red sólido, texto branco — usado só para contagens que exigem atenção (ex: sinais abertos).
- **Estado de mitigação:** variante outline (sem preenchimento, só borda + texto colorido) para `active`/`inactive`/`failed`/`none` — a cor de borda é o sinal primário, reforçada por texto.

### Cards / KPI Cards
- **Corner Style:** 8px (`{rounded.lg}`).
- **Background:** Panel Charcoal.
- **Border:** 1px Steel Border, mais um topo de 2px em Signal Blue (`.fg-card`) — a única aplicação "decorativa" do acento azul, e mesmo assim funcional (identifica visualmente "isto é um KPI").
- **Shadow Strategy:** nenhuma (ver Elevation). Estado de alerta (`fg-card-danger`) troca a borda para Alert Red em vez de adicionar sombra.
- **Internal Padding:** 0.9rem 1rem.

### Tables
- **Style:** sem zebra-striping; separação só por `border-bottom` 1px Steel Border por linha. Fonte reduzida (0.85rem) e padding compacto (0.32rem 0.55rem) — density-first.
- **Header ordenável:** cursor pointer, hover muda cor para Signal Blue, seta ▾/▴ indica direção ativa.
- **Linha de grupo:** fundo Elevated Slate, texto bold — diferencia cabeçalho de agrupamento de dado real.

### Navigation (sidebar)
- **Style:** sidebar vertical fixa à esquerda (200px), item de aba com borda-esquerda de 3px transparente que vira Signal Blue quando ativo, fundo Panel Charcoal só na aba ativa. Abaixo de 700px vira barra horizontal no topo — mobile nunca perde a navegação, só muda orientação.
- **Hover:** texto clareia para Fog White sem mudar borda.
- **Divisor:** linha 1px Steel Border separa os itens de menu do FlowGuard dos do ClientGuard — são dois sistemas de detecção compartilhando um menu.

### Modo Guerra (componente de assinatura)
Botão vermelho fixo de emergência com estado "armado" visualmente distinto: brilho pulsante (`alert-glow`) tanto no botão quanto no topbar inteiro da página quando ativo, e um display tipo LCD (fonte mono, `text-shadow` vermelho) para o countdown. É a única concessão do sistema a um efeito "chamativo" — deliberado, porque corresponde ao único cenário em que a interface *deve* competir por atenção acima de tudo o resto.

## 6. Do's and Don'ts

### Do:
- **Do** usar Signal Blue (#58a6ff) só como sinal — foco, aba ativa, topo de KPI card, link. Nunca como preenchimento de botão.
- **Do** dar a todo estado de severidade um segundo canal além da cor (texto, ícone, posição), conforme WCAG AA do PRODUCT.md.
- **Do** manter tabelas densas: fonte 0.85rem, padding compacto, sem respiro extra "pra elegância".
- **Do** reservar sombra/glow só para overlays funcionais (dropdown, toast) ou para o alarme deliberado do Modo Guerra.

### Don't:
- **Don't** introduzir gradiente, glassmorphism ou qualquer decoração — anti-referência explícita do PRODUCT.md é "SaaS marketing genérico".
- **Don't** criar um botão "primário" azul preenchido. Este sistema não tem CTA de conversão; todo botão não-destrutivo é neutro.
- **Don't** adicionar `box-shadow` decorativo a cards ou seções em repouso — viola a Flat-By-Doctrine Rule.
- **Don't** aumentar padding/fonte de tabela "pra respirar" — density-first é a escolha confirmada, não uma lacuna a corrigir.
- **Don't** usar `border-left`/`border-right` colorido maior que 1px como faixa decorativa em card ou item de lista (anti-padrão geral do skill, reforçado aqui: as únicas bordas de destaque no sistema são o topo de 2px do KPI card e a borda-esquerda de 3px da aba ativa — ambas com função de estado, não decoração solta).
