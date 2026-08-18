# Evidence — Design Is Audit — flowguard-portal (/root/site)

Consolidated from 5 parallel subagent reports (structural, visual, copy/honesty, weight/friction, accessibility). All facts, no scoring. Citations are file:line unless marked INFERRED/ESTIMATED.

## Structural

- 154 static interactive controls in index.html (111 `<button>`, 33 `<input>`, 7 `<select>`, 3 interactive `<canvas>`), plus dynamic templates in flowguard.js: 49 `<button` literals, 35 `<input`, 14 `<select`, 131 `addEventListener` sites.
- Max DOM nesting depth: 14 levels (two chains — Modo Guerra device-editor form, and table-row action buttons).
- Repeated patterns: 15× `.fg-toggle-group` filter clusters, 5× near-identical 2-3-state view toggles, 4× time-window chip groups (1h/6h/24h/7d), 2× severity chip groups, 5× "filtrar por..." free-text inputs, 3× modal+close pattern (shared `openModalA11y`/`closeModalA11y` helpers, flowguard.js:464), 37× skeleton-loading placeholder blocks, 8× sortable-column-header call sites, 3-of-9 cockpit cards using an anchored-popover pattern.
- Dead code: 2 unused CSS classes (`.fg-statusbar` index.html:236-237, `.fg-cockpit-mini-kpis` index.html:529), 1 unused JS var (`CG_EDGE_CFG_ENDPOINT` flowguard.js:31), and an abandoned feature path — `COCKPIT_JUMP_TARGETS = {}` (flowguard.js:815) leaves the `.fg-cockpit-card.fg-cockpit-clickable` CSS state (index.html:511-513) and its jump-handling branch (flowguard.js:911) currently unreachable.

## Visual

- Spacing: 30 distinct computed px values live (source: ~39 distinct rem/em literals) — no visible 4px/8px-style scale, ad hoc.
- Type scale: 15 distinct computed font-sizes.
- Color: 12 values via CSS custom properties (index.html:8-22). 18 hardcoded hex/rgba literals directly in flowguard.js (10 duplicate existing tokens, 4 are novel hues not in the token set: `#39c5cf`, `#79c0ff`, `#a371f7`, `#db61a2`). The inline `<style>` block itself also hardcodes 26 literal colors instead of `var()` (mostly alpha steps for Modo Guerra glow states).
- Lowest contrast on primary text: placeholder text `rgb(117,117,117)` (browser default, no `::placeholder` rule defined anywhere) on `--fg-bg` #0d1117 = **4.11:1, fails WCAG AA** (affects every filter/search/login field). On panel bg: 3.75:1.
- States checklist: empty (present), loading (present, shimmer skeleton), error (present, but one path surfaces a raw **"HTTP Error 500: Internal Server Error"** backend string verbatim into a `<select>` dropdown — flowguard.js:6316-6318), success (present), focus (present, visible 2px accent-blue ring), disabled (present, opacity 0.4-0.5).

## Copy & Honesty

- Zero marketing-inflation strings found (no "poderoso", "avançado", "state-of-the-art", etc.) across both files.
- Zero dark patterns found. Destructive bulk actions ("Apagar todas as regras", "Reverter todas as mitigações", "Dispensar todos os ataques") all gate behind `confirm()` with explicit "não pode ser desfeito" text. Modo Guerra's real/immediate SSH execution is explicitly disclosed (index.html:615), not hidden. Router-config auto-revert countdown is a disclosed safety net, not fake urgency.
- Jargon without in-context explanation: "watch" severity (untranslated, index.html:836), "RTBH (blackhole)" unexpanded at the rule-filter dropdown (index.html:914), "ExaBGP" (flowguard.js:801), BGP "Up"/"Idle" raw protocol terms (flowguard.js:1257-1258), "Daemon" (flowguard.js:1291), "ASN" unexpanded column header (flowguard.js:4146), "EWMA"/"sigma" (flowguard.js:3606-3608).
- Two label→behavior mismatches: **"Limpar hosts suspeitos"** (index.html:841) reads as delete/wipe but actually marks all open signals resolved (moves to history, nothing removed — flowguard.js:5125). **"Mitigar"** row action (index.html via flowguard.js:1459) is a generic verb with zero in-context disclosure that it always executes a full-prefix RTBH (BGP blackhole) as documented only in a separate Configuração-tab paragraph (index.html:991) — and unlike other destructive actions, has **no `confirm()` guard**.
- Side finding (data hygiene, not part of the design score): real-looking IP block `177.86.16.0/24`/`177.86.30.0/24` and hardware model strings ("NE8000BGP", "NE8000-PPPOE") are hardcoded as example/placeholder text in index.html and flowguard.js — flag for sanitization if this code is ever pushed to a public surface (README/CHANGELOG rule already in place; source code itself wasn't previously in scope of that rule).

## Weight & Friction

- Initial JS: flowguard.js = 345,800 bytes on disk, confirmed via live `Content-Length`. Server does **not** support gzip (busybox httpd, verified via curl) — 345,800 bytes is the real wire figure, not an estimate. index.html = 87,809 bytes. Total initial payload ≈ 433.6KB.
- Network requests, unauthenticated/idle first 5s: 7 (document, script, 5 CGI config fetches fired unconditionally from `init()` regardless of auth state, flowguard.js:7138-7151). INFERRED (not measured live): authenticated steady-state poll cycle fires 9 fetches every 5000ms (`REFRESH_MS`), backing off to 45000ms when tab hidden.
- TTI (Playwright, loopback, no throttling — not representative of real-world network): domInteractive 26.8ms, domComplete 45.8ms.
- Idle-screen continuous animation count: **0** on a true baseline idle screen. The only 3 `infinite` CSS animations (Modo Guerra pulse ×2, topbar pulse ×1) are all gated behind `.is-warmode-active`/`.on` classes — they don't run unless Modo Guerra is engaged. Skeleton shimmer only runs during active data fetch. `prefers-reduced-motion` is respected (index.html:203) and disables all of the above.
- No modal/toast/banner auto-opens on load — all three modals start `hidden`, wired only to explicit button clicks; toast container starts empty. 16 static `.fg-badge` elements in initial markup (14 render literal "0", 2 start `display:none` pending data).

## Accessibility

- Contrast: all main text/background/status/button pairs using CSS custom properties **pass WCAG AA** (ratios 4.95:1 to 12.26:1). Two failures found: warmode badge ON state at full "both pulses active" composite = 4.13:1 (FAIL) — but the code comment (index.html:86-90) shows this was already deliberately mitigated by choosing `--fg-danger-hover` instead of `--fg-danger` for the actually-used color (5.48:1, PASS) — the 4.13:1 figure is a hypothetical/base-color check, not the shipped state. Disabled `.fg-toggle-item.disabled` at 55% opacity: 2.63:1–4.27:1 (FAIL), but WCAG has no contrast requirement for disabled-component text, so this is a factual note, not a violation.
- Focus order: 17 tab stops mapped through sidebar nav → topbar buttons → cockpit "Personalizar" → first main-content control, all in logical DOM/visual order, no mismatch. **Gap**: none of the 9 cockpit KPI cards receive a tab stop (`tabIndex=-1`, no `tabindex`/`role`/`onclick` on the elements) — they're visually between the topbar and "Personalizar" but entirely invisible to keyboard navigation, not just out of order.
- Keyboard reachability: every tested primary action (tab switching, opening/closing all 3 modals with focus-trap + Escape + focus-return, toggling detection functions, sorting tables, collapsing panel sections, bulk-select checkboxes) is fully keyboard-operable via native `<button>`/`<input>`/`<label for>` elements. **Two confirmed gaps**: (1) cockpit KPI cards are mouse-only (no tabindex/keyboard handler); (2) cockpit card drag-to-reorder has no keyboard alternative (INFERRED from source, not live-tested).
- ARIA landmarks: 1 `<nav>`, 1 `<main>` (present, not missing), 3 `role="dialog"` (all with `aria-modal` + `aria-labelledby`), 9 `role="region"` (one per table, dynamic `aria-label`), 3 `role="img"` (the 3 canvas charts), 1 `role="status"` (toast container). No `<header>`/`<aside>`/`<footer>`, no `aria-label` on the single `<nav>` (not currently ambiguous since there's only one).
- Skip link: **absent**. A keyboard user must Tab through 11 nav/topbar stops before reaching first main content, on every page load, with no bypass mechanism.

## Known gaps across all subagents

- No authenticated poll-cycle traffic was measured live (avoided touching real credentials/production mitigation actions).
- Mobile/narrow-viewport (≤700px) breakpoint not live-tested — CSS-only inference.
- Modo Guerra ON state, router-apply flow, and other production-mutating actions were deliberately not exercised live.
- Contrast figures for alpha-composited/opacity-based elements are computed via manual blend math, not pixel-sampled.
