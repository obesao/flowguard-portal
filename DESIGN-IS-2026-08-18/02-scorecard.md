# Scorecard — Design Is Audit — flowguard-portal

1. Good design is innovative — Score: 1/3
   Evidence: standard admin-dashboard pattern (sidebar + KPI cards + tables + modals), GitHub-dark-style palette, no novel interaction model (01-evidence.md, Structural/Visual).
   Justification: refreshes nothing new — imitates the conventional NOC/ops-dashboard genre with minor variation, no more.

2. Good design makes a product useful — Score: 2/3
   Evidence: primary task (monitor + act on incidents) fully completable via keyboard and mouse in the Incidentes tab (Structural, Accessibility). Cockpit KPI shortcut cards are mouse-only (tabIndex=-1) and 5 CGI config fetches fire unconditionally on load regardless of auth.
   Justification: the primary task path works end-to-end; the adjacent cockpit-shortcut layer adds friction without blocking the core flow.

3. Good design is aesthetic — Score: 1/3
   Evidence: 12 CSS custom-property colors exist as a token system, but 18 hardcoded colors in JS (4 novel hues outside the palette) plus 26 hardcoded colors in the inline `<style>` block bypass it; spacing is ~39 ad hoc rem literals with no visible 4/8px scale (Visual).
   Justification: a token system exists but is eroded by systemic hardcoding in more than a handful of places — beyond "2 minor inconsistencies," not yet "no visible system."

4. Good design makes a product understandable — Score: 1/3
   Evidence: 7+ unexplained jargon terms (watch, RTBH, ExaBGP, BGP Up/Idle, Daemon, ASN, EWMA/sigma) and 2 label→behavior mismatches, the more serious being "Mitigar" — a generic label for an always-full-prefix RTBH blackhole with zero in-context disclosure and no confirm dialog (Copy & Honesty).
   Justification: well past "1 tooltip needed" — multiple unclear terms plus a high-stakes label mismatch on a network-wide destructive action.

5. Good design is unobtrusive — Score: 2/3
   Evidence: dark, dense, data-forward layout; chrome (sidebar/topbar/modals) is functional rather than decorative (Structural, Visual).
   Justification: chrome is visible but quiet — standard dashboard chrome, not competing with content, but present in volume (11 tab stops before content, 15 toggle-group instances).

6. Good design is honest — Score: 2/3
   Evidence: zero inflations, zero dark patterns; destructive bulk actions are explicitly disclosed and confirm-gated (Copy & Honesty). Two label mismatches found ("Limpar hosts suspeitos", "Mitigar") — the latter uniquely lacking any confirm or disclosure.
   Justification: overall disclosure-first design with one meaningful mismatch that matters (Mitigar's undisclosed blackhole scope), not a pattern of dishonesty.

7. Good design is long-lasting — Score: 2/3
   Evidence: dark GitHub-style palette, flat cards, no skeuomorphism or fad gradients (Visual).
   Justification: safe, conventional dev-tool aesthetic that won't read as dated, but also isn't distinctive enough to call timeless-by-design — one dated marker: the token system's erosion (hardcoded colors) will age worse than the palette itself.

8. Good design is thorough down to the last detail — Score: 2/3
   Evidence: all six states (empty/loading/error/success/focus/disabled) present and considered (Visual) — but one error path leaks a raw "HTTP Error 500: Internal Server Error" backend string directly into a user-facing dropdown.
   Justification: full state coverage with one rough edge — exactly the "1 state rough" bucket.

9. Good design is environmentally friendly — Score: 2/3
   Evidence: 433.6KB total initial payload (uncompressed, server has no gzip), zero continuous idle-screen animation on the true baseline (Modo Guerra pulses are gated), `prefers-reduced-motion` respected (Weight & Friction).
   Justification: under 500KB with motion properly gated — solid but not the sub-100KB/zero-animation ideal of a 3.

10. Good design is as little design as possible — Score: 1/3
    Evidence: 2 dead CSS classes, 1 dead JS variable, and 1 abandoned feature path (`COCKPIT_JUMP_TARGETS = {}` leaving a whole clickable-card CSS state unreachable) (Structural).
    Justification: 4 concretely removable/dead elements — past the "≤2 minor" bucket, into "3-5 removable."

**Total: 16/30**
