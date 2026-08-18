# Scope Lock — Design Is Audit

**Date:** 2026-08-18
**Audited surface:** `/root/site` (repo `obesao/flowguard-portal`), served live at `http://127.0.0.1:18080/`
**Files in scope:** `index.html` (1205 lines), `assets/flowguard.js` (7266 lines), inline/embedded CSS
**Excluded:** `cgi-bin/` backend logic, `graphify-out/`, git history

**Primary user:** NOC operator monitoring an ISP-scale DDoS detection/mitigation system (FlowGuard) and a client-abuse detector (ClientGuard) from a single portal.

**Primary task:** At-a-glance situational awareness (active attacks, mitigation status, system health) plus drill-down into detection/mitigation config and client-abuse signals.

**Constraints:**
- Static HTML/CSS/JS, no framework, served by busybox httpd + cgi-bin
- Backend/API contracts, polling logic, socket comms MUST NOT change — visual/design only
- Prior accessibility audit already applied (v1.61.0, commit d30c34b) — do not regress those fixes
- Backup exists (branch `backup/pre-redesign-20260818`, tag, tar.gz) — safe to iterate

**Reference designs / competitors:** none supplied by user.

**Known prior findings (from project memory, unverified — to re-check, not to inherit as truth):**
- Hardcoded hex colors in JS alongside CSS variables (incomplete token migration)
- 111 `innerHTML` calls
- Canvas charts lack `aria-label`
- Mixed color approach (hex vs CSS vars) duplicated inline styles in JS renders
