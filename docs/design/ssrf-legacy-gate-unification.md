# Design: Unify the legacy SSRF gate with allowlist-aware validation

Status: proposed · Author: system-architect (design task) · Date: 2026-07-17

## Problem

Two independent SSRF stacks exist. The legacy blind gate (`ssrf.py::validate_server_url`)
runs **before** the allowlist-aware gate at two live call sites and unconditionally
400s any private/reserved IP — including `100.64.0.0/10` (Tailscale/CGNAT) — even
when that exact server was legitimately allowlisted at onboarding and its
`server_registry.upstream_allowlist_entry` is set. Net effect: any allowlisted
private-IP server can never complete discovery or invocation.

Confirmed call sites of the legacy gate:
| Call site | Has server context? | Registered allowlist entry available? |
|---|---|---|
| `tools.py:1989` `discover_tools` Step 2a | yes (`server_row`) | yes — `server_row.upstream_allowlist_entry` |
| `invocation.py:680` `Step 3b` | yes (`tool_record`) | yes, but fetched **later** at Step 3c (line 790) — ordering bug, see below |
| `oauth_provider_profile.py:128` | no | n/a — correctly stays strict |

Also confirmed: `server_registry.py::approve_server` (D1 approval flow) does **not**
call the legacy gate — it already calls the allowlist-aware
`server_onboarding.py::validate_upstream_url_ssrf(url, private_cidr_allowlist=..., allow_http_dev=...)`,
which matches against the **global** `UPSTREAM_PRIVATE_CIDR_ALLOWLIST` and persists
the matched entry. So approval is not broken; only discovery and invocation are.

## Is Step 2a/3b pure redundancy with Step 2b/3c?

No — checked `revalidate_upstream_ip_at_invoke` (`server_onboarding.py:545`) line by
line. It does DNS resolution + registered-CIDR/public-IP validation + returns pinned
IPs, but it performs **no scheme check** and **no credentials-in-URL check**. Those
two checks exist only in the legacy `validate_server_url`. So dropping the legacy
call entirely (the alternative floated) would silently remove scheme enforcement
(`https`-only, dev-mode `http`+localhost carve-out) and the `user:pass@` embedded-
credential block from the hot path. Rejected.

## Decision

Extend `validate_server_url` with an `allowed_cidr` parameter, scoped narrowly to
the **single registered CIDR** for that server (never the whole global allowlist —
that distinction already belongs to `validate_upstream_url_ssrf`, used only at
onboarding/approval where "which allowlist entry matches" must be discovered).
Discovery and invocation already know which CIDR was registered; they don't need to
re-search the global list, and re-running the heavier global-match/DNS logic a
second time in the hot path is wasted work `revalidate_upstream_ip_at_invoke`
already does authoritatively right after.

### Function signature

```python
def validate_server_url(
    url: str,
    allow_http_localhost: bool = False,
    allowed_cidr: str | None = None,
) -> None:
    """
    Raise SSRFError if the URL is unsafe.

    allowed_cidr: a single CIDR string (server_registry.upstream_allowlist_entry)
    that exempts a private/reserved IP host from the blanket private-IP block.
    Pass None (default) to preserve today's blind behaviour — every existing
    caller that doesn't opt in is unaffected.

    Exemption applies ONLY to the private/reserved-range checks (_BLOCKED_V4 /
    _BLOCKED_V6 / CGNAT / non-global IPv6). It never overrides:
      - scheme enforcement (https, or dev-mode http+localhost)
      - the no-credentials-in-URL check
      - the ALWAYS-BLOCKED cloud-metadata floor (see below)
    """
```

### Always-blocked floor (metadata endpoints)

Today `169.254.0.0/16` is blocked as one range, which conflates ordinary link-local
with the cloud metadata address. If `allowed_cidr` is ever a sloppy admin entry like
`169.254.0.0/16` or `169.254.169.0/24`, a naive exemption would open the metadata
endpoint. Fix: split the check into two tiers.

```python
_ALWAYS_BLOCKED_V4 = [ipaddress.ip_network("169.254.169.254/32")]   # AWS/GCP/Azure/OCI/Alibaba all use this address
_ALWAYS_BLOCKED_V6 = [ipaddress.ip_network("fd00:ec2::254/128")]    # AWS IPv6 metadata
```

`_is_blocked_ip` checks the always-blocked floor **first**, including against any
embedded IPv4 extracted from IPv6 transition forms (reuse existing
`_embedded_v4s`) — this closes the same smuggling vector already handled for the
regular blocklist. The floor is checked unconditionally, before `allowed_cidr` is
even consulted, and has no exemption path at all — not even for a matching
`allowed_cidr`. Everything else in `_BLOCKED_V4`/`_BLOCKED_V6` (10/8, 172.16/12,
192.168/16, 127/8, 100.64/10, the rest of 169.254/16, ULA, link-local, etc.) is
exemptable when the resolved IP falls inside `allowed_cidr`.

```python
def _is_blocked_ip(addr: str, allowed_cidr: ipaddress._BaseNetwork | None = None) -> bool:
    ip = ipaddress.ip_address(addr)
    if _is_always_blocked(ip):          # metadata floor — never exemptable
        return True
    blocked = _v4_blocked(ip4) / existing v6 logic  # unchanged
    if blocked and allowed_cidr is not None and ip in allowed_cidr:
        return False
    return blocked
```

`allowed_cidr` is parsed once via `ipaddress.ip_network(allowed_cidr, strict=False)`
inside `validate_server_url` (wrap in try/except → `SSRFError` on a malformed stored
value, fail closed) and threaded into every `_is_blocked_ip` call in the function
(the raw-IP check and the DNS-resolution loop).

### Call sites — what each passes

1. **`tools.py:1989` (`discover_tools` Step 2a)** — change to:
   ```python
   validate_server_url(
       upstream_url,
       allow_http_localhost=(_settings.ENVIRONMENT == "development"),
       allowed_cidr=server_row.upstream_allowlist_entry,
   )
   ```
   `server_row` is already loaded before this line — no new query.

2. **`invocation.py:680` (Step 3b)** — same fix, but the registered entry is
   currently fetched **after** this call, at Step 3c (line 790, via
   `tool_record.get("upstream_allowlist_entry")` with a fallback `SELECT` at
   line 800). **Reorder**: hoist that fetch (lines ~782–810) to run immediately
   before Step 3b instead of before Step 3c, so both steps share one fetch and
   one variable:
   ```python
   _registered_allowlist_entry: str | None = tool_record.get("upstream_allowlist_entry")
   if _registered_allowlist_entry is None:
       # existing fallback SELECT, moved up unchanged
       ...
   validate_server_url(
       upstream_url,
       allow_http_localhost=(settings.ENVIRONMENT == "development"),
       allowed_cidr=_registered_allowlist_entry,
   )
   ...
   _pinned_ips = await revalidate_upstream_ip_at_invoke(
       upstream_url=upstream_url,
       registered_allowlist_entry=_registered_allowlist_entry,
   )
   ```
   This removes a duplicate lookup rather than adding one.

3. **`oauth_provider_profile.py:128`** — unchanged. No server row, no allowlist
   context; `allowed_cidr` stays `None` (default), preserving today's strict
   behaviour. Call it out explicitly in the diff so a future reviewer doesn't
   "fix" it into passing a global allowlist by mistake — this path validates an
   OIDC provider's base URL, not an onboarded MCP server, and has no
   provenance record to scope an exemption to.

4. **`server_registry.py::approve_server`** — no change. Already uses the
   correct allowlist-aware `validate_upstream_url_ssrf` + `revalidate_upstream_ip_at_invoke`
   pair. Do not migrate it onto the newly-extended `validate_server_url` — keep
   one code path per lifecycle stage (global-match-and-discover at onboarding,
   registered-single-CIDR-check at discovery/invocation) rather than
   collapsing them; the two have different inputs (list vs. single entry) and
   conflating them risks a future edit silently widening one call site's scope
   to the whole global allowlist.

### Dev-mode (`allow_http_localhost`) interplay

No interaction changes. `allow_http_localhost` governs scheme (http permitted only
for localhost / private container hostnames that resolve to a private IP); `allowed_cidr`
governs which private IPs are permitted at all. They compose independently:
a dev-mode HTTP request to a Tailscale-allowlisted host still goes through the
existing dev-mode DNS-resolution-must-be-private branch, then the (now-exempted)
private-IP check. No new branch is needed — the exemption lives inside
`_is_blocked_ip`, which both the raw-IP check and every DNS-resolution loop in the
function already call.

### Back-compat / migration

- `allowed_cidr` defaults to `None` — every caller not touched by this change
  (any test harness, any future caller) keeps today's blind-block behaviour
  byte-for-byte.
- No schema change — `upstream_allowlist_entry` already exists and is already
  populated by the onboarding flow (Task 3.1).
- No config change — reuses the existing `UPSTREAM_PRIVATE_CIDR_ALLOWLIST` /
  per-row `upstream_allowlist_entry` provenance; no new env var.
- Deploying this fix requires no data migration or backfill: rows onboarded
  under the allowlist already have `upstream_allowlist_entry` set and start
  working the moment this ships; rows without it (public upstreams) are
  unaffected since `allowed_cidr=None` degrades to current behaviour.

## Test matrix

| # | Scenario | `allowed_cidr` | Host / IP | Expected |
|---|---|---|---|---|
| 1 | No allowlist entry, public IP | `None` | public | pass (unchanged) |
| 2 | No allowlist entry, private IP | `None` | `10.0.0.5` | `SSRFError` (unchanged baseline) |
| 3 | Allowlisted private IP inside entry | `100.64.0.0/10` | `100.64.3.9` | pass |
| 4 | Private IP outside the registered entry | `100.64.0.0/10` | `10.0.0.5` | `SSRFError` |
| 5 | Metadata IP, no allowlist | `None` | `169.254.169.254` | `SSRFError` |
| 6 | Metadata IP, allowlist covers it (sloppy admin: `169.254.0.0/16`) | `169.254.0.0/16` | `169.254.169.254` | `SSRFError` — floor wins |
| 7 | Metadata IP smuggled via IPv6-mapped form, allowlist set | any | `::ffff:169.254.169.254` | `SSRFError` — floor wins on embedded v4 |
| 8 | AWS IPv6 metadata, allowlist set | any | `fd00:ec2::254` | `SSRFError` — floor wins |
| 9 | Credentials in URL, allowlisted host | set | `user:pass@100.64.3.9` | `SSRFError` — unaffected by exemption |
| 10 | HTTP scheme, non-dev, allowlisted host | set | `http://100.64.3.9` | `SSRFError` — unaffected by exemption |
| 11 | Malformed stored `allowed_cidr` (data corruption) | `"not-a-cidr"` | any | `SSRFError`, fail closed |
| 12 | Mixed DNS resolution: one IP in entry, one outside | `100.64.0.0/10` | resolves to `[100.64.3.9, 10.0.0.5]` | `SSRFError` (existing DNS-loop logic already rejects per-IP; confirm it still does with exemption applied per-IP, not globally) |
| 13 | `discover_tools` end-to-end | server row has entry | Tailscale IP | 200, tools returned (currently 400) |
| 14 | `invoke` end-to-end | tool_record has entry | Tailscale IP | 200 (currently 400) |
| 15 | `oauth_provider_profile` unaffected | n/a (no param passed) | private IP | still `SSRFError` |
| 16 | `approve_server` unaffected | n/a (different function) | allowlisted private IP | still passes via `validate_upstream_url_ssrf` |
| 17 | invocation.py fetch reorder: `upstream_allowlist_entry` not in `tool_record`, fallback SELECT needed | fetched via fallback query | Tailscale IP | 200, single query, no duplicate fetch |

## Summary for implementers

- `backend_dev` / whoever picks this up: touch only `ssrf.py` (new param + floor
  split), `tools.py:1989`, and `invocation.py` (pass `allowed_cidr` at 3b, hoist
  the allowlist-entry fetch above 3b, remove the now-duplicate fetch before 3c).
  `oauth_provider_profile.py` and `server_registry.py::approve_server` are
  explicitly out of scope — do not touch.
- `appsec`: review the always-blocked metadata floor and the embedded-v4
  smuggling check (test cases 5–8) before sign-off; this is the one place a
  wrong implementation reopens SSRF-to-cloud-metadata even with the fix
  otherwise "working."
- `qa`: the 17-case matrix above is the acceptance bar; cases 13/14 are the
  regression that motivated this change and must be exercised against a real
  Tailscale-range (or equivalent CGNAT-range) allowlisted lab server, not just
  unit-level `_is_blocked_ip` calls.

## Deferred follow-ups (filed 2026-07-17, appsec-review risk acceptances)

Implemented change was appsec-APPROVED with these HIGH/MEDIUM items explicitly
deferred; compensating controls are the unconditional metadata floor (in every
layer) plus the new WARNING audit logs on allowlisted-private-CIDR
discovery/invocation.

1. **Platform-infra denylist** (appsec #5, HIGH): allowlisting a whole Podman
   subnet makes the platform's own DB/Vault/Keycloak/OPA reachable as
   "upstreams". Podman IPs are dynamic, so this needs a name/alias-based
   denylist design, not a hardcoded IP list. Detective control until then: the
   allowlisted-private WARNING logs.
2. **`provide_running_url` second-reviewer gate + audit gap** (appsec #3, HIGH):
   the submitter picks the final IP inside any admin-allowlisted CIDR with no
   second human touch, and the new allowlisted-private WARNING logging covers
   discover/invoke only — it does NOT cover `provide_running_url` completions.
   Add at minimum a WARNING/audit event there; consider a reviewer re-touch for
   the private-CIDR case.
3. **`oauth_provider_profile.py:128` pinning** (appsec #4, MEDIUM, pre-existing):
   `discover_metadata` validates then connects with a fresh resolver lookup —
   live TOCTOU/rebind gap independent of this change. Needs the same
   revalidate + `PinnedIPTransport` treatment. Never thread `allowed_cidr` here.
4. **Broad-CIDR hard limit** (appsec #5a): currently WARN-only for IPv4 entries
   broader than /24 because the lab legitimately runs 10.89.0.0/16 and
   100.64.0.0/10. Revisit if/when per-server CIDRs replace the global env var.
