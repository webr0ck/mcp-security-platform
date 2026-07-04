# PRD-0004 — Portal UI/UX Redesign

- **Status:** DRAFT v1 (supersedes a prior draft under this same filename that
  proposed a React-only cutover + HTMX portal retirement — that draft did not
  reflect an actual decision by the platform owner and has been discarded, not
  merged. D-1 from PRD-0003 stands: the HTMX portal is canonical, the React app
  stays frozen.)
- **Date:** 2026-07-04
- **Author:** senior dev / UI-UX / lead architect review
- **Scope:** Visual design, information architecture, and front-end code structure
  of the HTMX portal (`proxy/app/routers/portal.py`). No new backend functionality.
- **Depends on:** PRD-0003 (portal finalization) — this redesign assumes PRD-0003's
  functional gaps are closed; it does not re-litigate D-1 (HTMX portal is canonical,
  React app frozen). If any PRD-0003 P0 item is still open when this starts, land it
  first — redesigning a screen whose data model is still changing is wasted work.
- **Non-goals:** reviving/rebuilding the React app, adding new admin capabilities,
  changing any API contract or database schema.

## 0. Why now

PRD-0003 closed the functional gaps (wizard clipping, dead fields, missing Access/
Profile/Detections-drilldown pages, SBOM, auto-provisioning) by adding onto the
existing HTMX portal fragment-by-fragment. That was the right call for PRD-0003's
goal (make things work), but it means every fix added more inline styles and more
sidebar nav items to a file that had no design system to begin with. The result:
functionally complete, visually and structurally undisciplined. This PRD is the
cleanup pass — same portal, same stack, deliberately designed instead of
accreted.

## 1. Current-state findings

Verified against `proxy/app/routers/portal.py` (5,472 lines as of this PRD).

### F-1 No design system — inline styles are the primary styling mechanism
395 inline `style="..."` attributes across the file, on top of a 788-line shared
`_CSS` block. Every fragment function hand-rolls colors, spacing, and typography
as literal values (`#0f172a`, `#1e293b`, `0.75rem`, `13px`...) rather than reusing
tokens. The `_CSS` block does define some custom properties (`--blue`, `--cyan`,
`--muted`, `--adm-*`) but most fragments bypass them. Every new feature this
session (Access tab, Profile page, MCP-profiles manager, detections drawer) added
its own one-off inline-styled markup rather than extending a shared component
vocabulary — not a criticism of that work (correct call under PRD-0003's time
pressure), but it compounds the debt this PRD exists to pay down.

### F-2 Information architecture: flat, ungrouped, order-of-addition nav
The admin sidebar has 10 items in 2 groups (`SECURITY`: Dashboard/Detections/SBOM;
`ADMIN`: Identity/MCP Servers/Access/Submissions/Credentials/Request Limits/
Profile — `portal.py:1037-1049`). "Access" sits between "MCP Servers" and
"Submissions" only because that's the order it was built in, not because that's
where a security reviewer would look for it. No IA pass has happened since the
first two items were added; every subsequent feature was appended to a list, not
placed in a hierarchy.

### F-3 No responsive design
Only 2 `@media` queries in the entire file. All admin layouts are fixed-width
flex/grid (`.adm-layout { display: flex; ... }`, `.srv-tbl-row { display: grid;
grid-template-columns: 2.1fr 2.3fr 1.15fr ... }`). QA already found one concrete
symptom of this during PRD-0003 (server-table column misalignment from an
unbreakable long injection-mode label — `.mode-chip` has no `min-width:0` /
`text-overflow:ellipsis`, so one long value distorts the whole row's grid
tracks). There is no tablet or mobile layout at all; the portal is unusable below
~1024px.

### F-4 No accessibility pass
Detections tables are not keyboard-navigable (flagged already in PRD-0003 F-10,
never scheduled). No skip-to-content link, no visible focus states beyond
browser defaults, icons conveyed via emoji/HTML entities with no `aria-label`,
color is sometimes the only signal (status pills rely on hue alone — `pill-
approved`/`pill-pending`/`pill-quarantined` — no icon or text-weight
differentiation for colorblind users beyond the text label itself, which is
present but small and low-contrast in places, e.g. `color:var(--muted)` at
11-12px is used for a lot of load-bearing status text).

### F-5 Inconsistent empty/loading/error states
Each fragment implements its own version of "no data" / "loading" / "error"
markup (`_error_fragment`, ad-hoc `<div class="empty-state">...</div>` strings,
inline `<div class="loading-state"><span class="spinner"></span> Loading…</div>`
literals repeated ~8 times verbatim). No visual regression risk today, but any
future visual change requires editing the same markup in 8+ places.

### F-6 The submit wizard and the admin shell are visually two different products
The wizard (`portal.py:~4200-4900`) uses `--ff-mono`/`--ff-sans` font vars, a
step-indicator pattern, and card styling distinct from the admin shell's sidebar/
topbar chrome. Reasonable given they're different tasks (onboarding vs.
administering), but they don't currently share a button, input, or badge
component — a submit-wizard button and an admin-shell button look different for
no functional reason.

### F-7 Detections/SBOM/Submissions tables duplicate table chrome
`.tbl-wrap` + `<table>` markup with near-identical `<thead>`/badge patterns is
copy-pasted across `fragment_admin_detections`, `fragment_admin_sbom_detail`,
`fragment_admin_submissions`, `fragment_admin_servers`, `fragment_admin_access`,
each with slightly different inline column widths and badge color literals.

### F-8 No brand mark (resolved during this PRD — see R-8)
No logo file, no favicon; the sidebar/topbar used a generic CSS-drawn diamond
glyph (`_aegis_logo_mark()`, `portal.py:991`) with no identity behind it.
**Resolved 2026-07-04**: owl icon (`docs/assets/owl-icon.png`, sourced from
`https://purplehootie.com/images/owl-icon.png`, 295×426 PNG) adopted as the
brand mark — served at `/static/owl-icon.png`, wired as the favicon and the
sidebar/topbar logo across all three portal shells (admin, agent, submit
wizard). See R-8.

## 2. Design principles for this pass

- **Server-rendered HTML stays server-rendered.** No client framework, no build
  step change. Redesign means better CSS/HTML authoring discipline within the
  existing HTMX-fragment architecture, not a rewrite.
- **Tokens over literals.** Every color, spacing value, and font size used more
  than twice becomes a CSS custom property. No new inline hex codes.
- **Group by mental model, not by build order.** IA reorganized around what an
  admin/security-reviewer is trying to do (see R-2).
- **Fewest files possible.** This can (and should) mostly stay in `portal.py`
  unless a specific extraction earns its complexity (see R-7's size cap).

## 3. Requirements

Sizes: S ≤ ½ day, M ≤ 2 days, L ≤ 1 week.

### R-1 Design tokens (F-1) — P0, M
Extend the existing `_CSS` custom-property block into a complete token set:
color (surface/border/text/accent, each with a semantic name — `--surface-1`,
`--surface-2`, `--border-default`, `--text-primary`, `--text-muted`, plus the
existing severity colors), spacing scale (4/8/12/16/24/32px named `--space-*`),
type scale (`--text-xs` through `--text-xl`), radius (`--radius-sm/md/lg`).
- FM: a token rename breaks a fragment that still hardcodes the old hex value —
  mitigate by grepping for every literal this PRD's tokens replace before
  removing the old value, not just adding new tokens alongside.
- AC: `grep -c 'style="[^"]*#[0-9a-fA-F]\{3,6\}'` (inline hex literals) drops by
  ≥ 80% from the F-1 baseline; visual diff of 5 representative screens
  (Dashboard, Detections, SBOM, Servers, Profile) shows no unintended color
  shift.

### R-2 Admin IA reorganization (F-2) — P0, M
Regroup the sidebar into 4 named sections reflecting task, not history:
- **Overview** — Dashboard
- **Security** — Detections, SBOM
- **Access & Servers** — MCP Servers, Access, Identity (OIDC)
- **Operations** — Submissions, Credentials, Request Limits
- Profile stays out of the sidebar list entirely (already reachable via the
  user-panel/avatar click built in PRD-0003 — this PRD just confirms that stays
  the pattern, not a 5th sidebar section).
- FM: a bookmarked/shared deep link to a tab by name must keep working — this is
  a visual regroup of the SAME tab identifiers (`_VALID_TABS` unchanged), not a
  route change.
- AC: `/portal/admin/{tab}` deep links for all existing tabs still resolve
  correctly; a user asked "where would you look for X" test (informal, ask 2-3
  people unfamiliar with the build order) picks the correct section ≥ 80% of
  the time for Access, SBOM, and Credentials specifically (the three most
  ambiguous placements today).

### R-3 Responsive layout (F-3) — P1, L
Add real breakpoints: desktop (>1200px, current layout), tablet (768-1200px,
collapsible sidebar → icon rail or hamburger), mobile (<768px, single-column
stacked cards, sidebar becomes a bottom sheet or top drawer). Fix the specific
QA-found `.mode-chip`/`.srv-tbl-row` column-collision bug as part of this (it's
the same root cause — fixed-width grid tracks with no `min-width:0` handling —
as the broader responsive gap).
- FM: a fragment loaded via htmx partial swap must render correctly at whatever
  viewport it lands in — test partial-swap navigation at each breakpoint, not
  just full-page loads.
- AC: Playwright viewport tests at 375×667 (mobile), 768×1024 (tablet), and
  1366×768 (desktop, existing baseline) for the 5 representative screens in
  R-1's AC — no horizontal scroll, no clipped/overlapping content, no
  `grid-template-columns` distortion from long cell content.

### R-4 Accessibility pass (F-4) — P1, M
Keyboard navigation for every interactive table row (detections, submissions,
servers — currently mouse-only `onclick`); visible focus rings (don't rely on
browser default, but don't remove it either — add a consistent `:focus-visible`
style using the new token set); `aria-label` on icon-only/emoji-only buttons;
minimum 4.5:1 contrast for all status/badge text (audit `--muted` usage at small
sizes specifically, per F-4).
- FM: a screen-reader pass is out of scope for this PRD (would need a dedicated
  audit) — this requirement covers keyboard operability and contrast only; say
  so explicitly rather than implying full WCAG compliance.
- AC: every row that currently has an `onclick` handler (detection rows, access
  principal rows, server rows) is reachable and activatable via Tab + Enter;
  automated contrast check (e.g. axe-core via Playwright) on the 5 representative
  screens reports zero "serious"/"critical" contrast violations.

### R-5 Shared component patterns (F-5, F-7) — P1, M
Factor the repeated empty-state/loading-state/table-chrome markup into small
Python helper functions (`_empty_state(message)`, `_loading_state()`,
`_table(headers, rows)`) already-partially-present as `_error_fragment`/`_badge`
— extend that same pattern, don't introduce a templating engine. This is a
refactor of existing copy-pasted strings into functions that already have a
precedent in the file, not a new abstraction layer.
- FM: none meaningful — pure extraction of identical markup, verified by diffing
  rendered HTML before/after for a sample of fragments.
- AC: `grep -c 'class="empty-state"'` and `grep -c 'class="loading-state"'`
  literal-markup occurrences drop to ≤ 2 (the helper definition + at most one
  legitimate special case); rendered HTML for 3 sampled fragments is
  byte-identical before/after the refactor.

### R-6 Wizard/admin-shell visual unification (F-6) — P2, M
Bring the submit wizard's buttons/inputs/badges onto the same token set and
component patterns as the admin shell (R-1/R-5), without merging their distinct
layouts (wizard keeps its step-card structure, admin shell keeps its
sidebar/topbar — only the atomic pieces converge).
- FM: the wizard is a different trust context (self-service, less chrome) —
  don't accidentally give it admin-shell navigation affordances it shouldn't have.
- AC: a button/input/badge in the wizard and the equivalent in the admin shell
  render from the same CSS classes (visual diff shows only necessary contextual
  differences — step-card padding etc., not divergent button styles).

### R-7 File organization guardrail — P2, S
`portal.py` is 5,472 lines and grew ~1,000 lines during PRD-0003. This PRD does
not mandate splitting it (premature — see PRD-0003's own risk section, which
already flagged this and deferred a `portal/` package split as future work), but
sets a hard rule for this pass: **no fragment function may exceed 150 lines
after this redesign** (several currently do, e.g. `fragment_admin_access` at
~180 lines). If token/component extraction (R-1/R-5) doesn't get a function
under that cap on its own, that specific function is a candidate for the actual
package split — flag it, don't silently let it grow further.
- FM: none (this is a code-hygiene tripwire, not a behavior change).
- AC: `awk` line-count check per `async def fragment_*` function reports zero
  functions over 150 lines, OR each violator has a one-line comment explaining
  why it's deferred to the future package split.

### R-8 Brand mark (F-8) — **done**
Owl icon adopted as the platform's brand mark (`docs/assets/owl-icon.png`,
sourced from `https://purplehootie.com/images/owl-icon.png`). Implemented:
copied to `proxy/app/static/owl-icon.png` (served at `/static/owl-icon.png` via
the existing static mount); `_aegis_logo_mark()` (`portal.py:991`) now renders
this image instead of the CSS-drawn diamond glyph, used unchanged at all 3
existing call sites (admin shell sidebar, agent shell topbar); a new
`_FAVICON_LINK` constant adds `<link rel="icon">` to all three portal
`<head>` blocks (admin shell, agent shell, submit wizard).
- FM: none — pure asset swap, verified live (favicon HTTP 200, sidebar `<img>`
  present, acceptance suite unaffected).
- AC: met — `curl` confirms `/static/owl-icon.png` returns 200; Playwright
  confirms `link[rel="icon"]` and the sidebar `<img>` both resolve to
  `/static/owl-icon.png` post-login; 36/36 acceptance tests still pass.
- Follow-up (not done): the now-unused `.adm-logo-mark` gradient-background CSS
  rule (`portal.py:518-527`) is dead code left over from the old glyph — clean
  up as part of R-1's token pass, not urgent enough to block this PRD.

## 4. Phasing

- **P0 (do first):** R-1 (tokens), R-2 (IA regroup) — highest visual/usability
  impact, lowest risk (no new interaction patterns, just reorganizing what
  exists).
- **P1:** R-3 (responsive), R-4 (accessibility), R-5 (shared components) — each
  independent, can run in parallel once R-1's tokens exist to build on.
- **P2 (stretch):** R-6 (wizard unification), R-7 (file-size guardrail).

**Estimate honesty:** P0 ≈ 1.5 engineer-weeks. Full P0+P1 ≈ 4 engineer-weeks. R-3
(responsive) is the biggest unknown — the AC's viewport matrix may reveal more
broken layouts than the ones already known; budget contingency there specifically
if the estimate is tight.

## 5. Verification

- Every AC above becomes a Playwright check (viewport tests, deep-link checks,
  axe-core contrast scan) extending `ui/e2e/portal-acceptance.spec.ts`.
- `make test-lab-functional` and the full acceptance suite stay green throughout
  — this PRD changes presentation, not behavior; any test failure means a
  behavior accidentally changed and must be treated as a regression, not
  "expected from the redesign."
- No new inline hex/spacing literals introduced during implementation — enforce
  informally via review (grep count from R-1's AC should only go down over the
  course of implementation, never back up).

## 6. Risks

- **Redesigning while PRD-0003 follow-ups are still landing** (e.g. the
  auto-provisioning fix, admin UI for maintainers) risks merge conflicts in the
  same fragments. Sequence this PRD's work to start on tabs that are stable
  (Dashboard, Profile) and defer tabs still under active change (Servers,
  Submissions) until their functional work settles.
- **No dedicated design resource** — this PRD is written from a developer's
  visual-audit pass, not a designer's. R-1's token values and R-2's grouping are
  reasonable defaults, not the product of user research; treat them as a
  starting point open to revision, not a spec to defend.
- **Accessibility scope creep risk** — R-4 is deliberately scoped to keyboard +
  contrast, not full WCAG AA/AAA. Resist expanding it mid-implementation without
  updating the estimate.
