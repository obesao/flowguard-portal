/make-plan Redesign the flowguard-portal NOC dashboard (/root/site — obesao/flowguard-portal). Current design failed audit at 16/30 with critical gaps in principles #3 (aesthetic), #4 (understandable), and #10 (as little design as possible).

Verdict paragraph (quoted from 03-verdict.md):
> REDESIGN. Total score 16/30 — below the REFINE threshold (≥20) — driven by a token system that exists but is eroded by systemic hardcoding (aesthetic: 1/3), understandability gaps stacking jargon with an undisclosed high-stakes label mismatch (understandable: 1/3), and dead/abandoned code paths past the minor-cleanup threshold (as-little-as-possible: 1/3). No principle scored 0 — the bones are functional, not broken. This is a visual/system redesign, not a functional rewrite: nothing here requires touching detection logic, mitigation actions, or the API contracts.

Why redesign and not refine: total is 16/30, below the 20/30 REFINE threshold, driven by systemic (not isolated) token-system erosion and a stacked pile of jargon/mismatches rather than one or two fixable spots.

**Hard constraint for this redesign: visual/CSS/markup only. Do not change any JS logic, API calls, polling behavior, backend contracts, or function signatures in flowguard.js beyond what's needed to reference CSS tokens instead of hardcoded colors and to add missing tabindex/ARIA/confirm-dialog wiring called out below.** A full backup exists (git branch `backup/pre-redesign-20260818`, tag `backup-pre-redesign-20260818`, tar.gz at `/root/backups/flowguard-portal-pre-redesign-20260818-093012.tar.gz`) — safe to iterate boldly on the visual layer.

Preserve from current design (already strong — do not touch structurally):
- WCAG AA contrast already passing on all main text/status/button token pairs (4.95:1–12.26:1) — index.html:8-22 CSS custom properties.
- Full keyboard operability of tabs, all 3 modals (focus trap + Escape + focus-return via `openModalA11y`/`closeModalA11y`, flowguard.js:438-471), table sorting, panel collapse, bulk-select checkboxes.
- Confirm-gated destructive bulk actions with explicit consequence text (all except "Mitigar" — see fixes below).
- Zero marketing inflation, zero dark patterns in existing copy — keep this bar.
- Complete state coverage (empty/loading/error/success/focus/disabled) — needs polish, not rebuilding.

Discard (name the structural patterns causing the failures):
- Hardcoded color literals bypassing the token system: 18 in flowguard.js (10 duplicate existing tokens, 4 are novel untokenized hues: `#39c5cf`, `#79c0ff`, `#a371f7`, `#db61a2`) and 26 in index.html's inline `<style>` block. Caused failure on principle #3 (aesthetic).
- Ad hoc spacing scale: ~39 distinct rem/em literals with no visible 4/8px rhythm across index.html's `<style>` block. Caused failure on principle #3.
- Dead code: `.fg-statusbar` and `.fg-cockpit-mini-kpis` (unused CSS classes, index.html:236-237, 529), `CG_EDGE_CFG_ENDPOINT` (unused JS var, flowguard.js:31), and `COCKPIT_JUMP_TARGETS = {}` (flowguard.js:815) which leaves the `.fg-cockpit-card.fg-cockpit-clickable` CSS state (index.html:511-513) and its jump-handling branch (flowguard.js:911) unreachable. Caused failure on principle #10.

Top 5 moves from the audit (verbatim):
1. #3 aesthetic: Collapse all hardcoded JS/inline-style colors into the existing 12-token CSS variable system; either promote the 4 novel hues to named tokens or remove them. Evidence: 01-evidence.md Visual section.
2. #4 understandable: Fix "Mitigar" so label/disclosure match behavior (always full-prefix RTBH/BGP blackhole) — rename, add inline disclosure, or add the same confirm() pattern used for every other destructive bulk action. Evidence: index.html:991, flowguard.js:1459.
3. #3/#10: Establish one real spacing scale and delete the 4 dead-code items listed above (or wire up `COCKPIT_JUMP_TARGETS` if it's meant to ship). Evidence: 01-evidence.md Structural/Visual.
4. #4 understandable: Expand or tooltip recurring jargon (watch, RTBH, ExaBGP, BGP Up/Idle, Daemon, ASN, EWMA/sigma) at first point of use. Evidence: 01-evidence.md Copy & Honesty.
5. #2 useful / accessibility: Make cockpit KPI shortcut cards keyboard-reachable (currently tabIndex=-1) and add a visible skip-link before the current 11-stop nav/topbar sequence. Evidence: 01-evidence.md Accessibility.

Redesign principles in priority order:
1. #3 Aesthetic — one enforced token system (color + spacing + type scale) with zero literal-value escape hatches in JS or inline styles.
2. #4 Understandable — every label matches its behavior exactly; jargon explained at point of use, not buried in a different tab.
3. #10 As little design as possible — no dead classes, no dead vars, no half-wired abandoned features; every element in the shipped surface does something.

Deliverables for the plan:
- New/consolidated design tokens file or `:root` block covering color, spacing, and type scale, with a migration list of every hardcoded literal to replace (cite file:line from 01-evidence.md)
- Side-by-side plan for the cockpit card interaction model (current: mouse-only anchored popovers on 3-of-9 cards, abandoned jump-mechanism) vs proposed
- Copy pass: jargon glossary/tooltip plan + the "Mitigar" and "Limpar hosts suspeitos" label fixes
- States checklist carried forward unchanged (empty/loading/error/success/focus/disabled) plus a fix for the raw "HTTP Error 500" leak (flowguard.js:6316-6318)
- Migration path: since this is CSS/markup-layer only, plan for incremental rollout (e.g. tab-by-tab or component-by-component) with the existing backup as rollback point, not a big-bang rewrite
- Cutover criteria: visual regression check against the "Preserve" list above (contrast ratios, keyboard operability, confirm-gating) before considering any tab "done"

Anti-patterns to guard against (specific to REDESIGN):
- Touching flowguard.js business logic, polling intervals, or API call shapes — this is strictly forbidden, backup or not
- Porting the same ad hoc spacing/color literals under new class names
- Redesigning to chase a visual trend rather than fixing the token-system erosion and understandability gaps identified
- Treating the Preserve list as optional — WCAG AA contrast and full keyboard operability must not regress
