# Verdict — flowguard-portal

**REDESIGN.** Total score 16/30 — below the REFINE threshold (≥20) — driven by a token system that exists but is eroded by systemic hardcoding (aesthetic: 1/3), understandability gaps stacking jargon with an undisclosed high-stakes label mismatch (understandable: 1/3), and dead/abandoned code paths past the minor-cleanup threshold (as-little-as-possible: 1/3).

No principle scored 0 — the bones are functional, not broken. This is a **visual/system redesign**, not a functional rewrite: nothing here requires touching detection logic, mitigation actions, or the API contracts. It requires a real design pass (a spacing/type/color token system actually enforced everywhere, not partially), not a handful of CSS tweaks.

## Top 5 highest-leverage moves

1. **#3 aesthetic** — Collapse the 18 hardcoded JS colors + 26 hardcoded inline-style colors into the existing 12-token CSS variable system (add the 4 novel hues — `#39c5cf`, `#79c0ff`, `#a371f7`, `#db61a2` — as named tokens if they're intentional, or remove them). Evidence: 01-evidence.md Visual section; flowguard.js hardcoded hex/rgba literals; index.html inline `<style>` block.

2. **#4 understandable** — Fix "Mitigar" so its label and disclosure match its actual behavior (always full-prefix RTBH/BGP blackhole): either rename the button to state the action, add inline disclosure at the point of use, or add a confirm dialog matching the pattern already used for every other destructive bulk action. Evidence: index.html:991 (disclosure buried in a different tab), flowguard.js:1459 (no confirm guard), copy/honesty section of 01-evidence.md.

3. **#3/#10 aesthetic + as-little-as-possible** — Establish one real spacing scale (currently ~39 ad hoc rem values with no visible 4/8px rhythm) and remove the 4 dead-code items: `.fg-statusbar`, `.fg-cockpit-mini-kpis` (unused CSS), `CG_EDGE_CFG_ENDPOINT` (unused JS var), and the abandoned `COCKPIT_JUMP_TARGETS = {}` path (either wire it up or delete the disabled `.fg-cockpit-clickable` CSS state it leaves dangling). Evidence: 01-evidence.md Structural/Visual sections.

4. **#4 understandable** — Expand or tooltip the recurring jargon cluster (watch, RTBH, ExaBGP, BGP Up/Idle, Daemon, ASN, EWMA/sigma) at first point of use rather than only in a separate config-tab paragraph. Evidence: 01-evidence.md Copy & Honesty section.

5. **#2/accessibility useful** — Make the cockpit KPI shortcut cards keyboard-reachable (currently `tabIndex=-1`, mouse-only) and add a visible skip-link before the 11-stop nav/topbar sequence. Evidence: 01-evidence.md Accessibility section (focus order, skip-link absence).

**Preserve (already strong, do not disturb in this pass):**
- Contrast on all main text/status/button pairs already passes WCAG AA (4.95:1–12.26:1) — a prior accessibility audit already did this work correctly.
- Every destructive bulk action except "Mitigar" already discloses consequence and confirm-gates.
- Full keyboard operability of tabs, modals (with focus trap + Escape + focus-return), table sorting, panel collapse, bulk-select.
- Zero marketing inflation, zero dark patterns in copy.
- State coverage (empty/loading/error/success/focus/disabled) is complete — needs polish (the raw HTTP 500 leak), not rebuilding.
