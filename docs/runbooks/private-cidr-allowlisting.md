# Runbook: Allowlisting a Private CIDR for Self-Hosted MCP Servers

## Symptom

- Onboarding/registering a self-hosted MCP server whose upstream URL resolves
  to a private/RFC1918 address fails validation with an error like:
  `Hostname '<host>' resolves to private/reserved IP '<ip>' which is not
  covered by UPSTREAM_PRIVATE_CIDR_ALLOWLIST.`
- A previously-working self-hosted server starts failing at invoke-time
  revalidation after a network/DNS change (see
  `revalidate_upstream_ip_at_invoke` — the check re-runs on every invoke, not
  just at registration).

## Security model — why this exists

The proxy's onboarding/SSRF path (`proxy/app/services/server_onboarding.py`,
`validate_upstream_url_ssrf`) blocks upstream URLs that resolve to private,
loopback, link-local, or reserved IPs **by default** — this is what stops a
malicious or compromised submitter from pointing the proxy at
`169.254.169.254` (cloud metadata), `127.0.0.1` (something else on the same
host), or an arbitrary internal service the proxy has network reach to (SSRF
into your own infra). `UPSTREAM_PRIVATE_CIDR_ALLOWLIST` is the **explicit,
narrow exception list** — an admin opts specific private ranges back in for
legitimate self-hosted-in-your-own-network MCP servers, instead of disabling
the SSRF check wholesale.

Key invariants enforced by `_validate_resolved_ips_against_allowlist` (Task
3.1 / ISO-F2.6):
- **All** resolved IPs for the hostname must be private-and-allowlisted, or
  **all** must be public — a hostname resolving to a **mix** of public and
  allowlisted-private IPs is denied outright (closes partial-DNS-rebind
  attacks).
- A hostname whose IPs land in **two different** allowlisted CIDR entries is
  also denied (prevents a host straddling two trust zones).
- Always-blocked ranges (loopback, link-local, unspecified, cloud metadata)
  are **never** allowlistable — `UPSTREAM_PRIVATE_CIDR_ALLOWLIST` only
  widens the RFC1918/CGNAT private-range check, not the always-block list.

## Diagnosis

```bash
# Current allowlist value (proxy env)
podman exec mcp-proxy printenv UPSTREAM_PRIVATE_CIDR_ALLOWLIST

# Or check .env.lab directly
grep '^UPSTREAM_PRIVATE_CIDR_ALLOWLIST=' .env.lab

# Confirm what IP(s) the failing hostname actually resolves to
podman exec mcp-proxy python3 -c "import socket; print(socket.getaddrinfo('<host>', None))"

# Reproduce the exact validation the proxy runs
podman exec mcp-proxy python3 -c "
from app.services.server_onboarding import _parse_cidr_allowlist, _ip_in_allowlist
import ipaddress
nets = _parse_cidr_allowlist(['10.20.0.0/24'])
print(_ip_in_allowlist('10.20.0.5', nets))
"
```

## Resolution

1. Add the **narrowest CIDR that actually covers the upstream's resolved
   IP(s)** — not a broad `10.0.0.0/8` unless you genuinely need all of it.
   The format is a comma-separated list of CIDR strings:
   ```bash
   # .env.lab or the proxy's real env
   UPSTREAM_PRIVATE_CIDR_ALLOWLIST=10.20.0.0/24,192.168.50.0/28
   ```
2. Restart the proxy so it re-reads the env (per the "Proxy Reload Does Not
   Work" gotcha — bind-mounted app code needs a restart; env changes always
   need a restart regardless):
   ```bash
   podman restart mcp-proxy
   ```
3. Re-attempt the server registration/onboarding call.

Note: an **HTTP (not HTTPS)** upstream additionally requires its host to be
covered by the allowlist — plain-HTTP to a public host is rejected outright
("Use HTTPS for public upstreams"), so adding a private CIDR is also the
mechanism that allows a self-hosted server to skip TLS for same-network
traffic. Don't allowlist a range just to dodge the HTTPS requirement for a
publicly-reachable host — that defeats the point.

## Verification

```bash
# Registration/onboarding call should now succeed
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  http://localhost:8000/api/v1/servers -d '{"upstream_url": "http://<host>:<port>", ...}'

# Confirm the allowlist entry actually matched (proxy log should show the
# matched CIDR being recorded, not a fresh rejection)
podman logs mcp-proxy --tail 50 | grep -i cidr

# Confirm invoke-time revalidation also passes (not just registration-time) —
# revalidate_upstream_ip_at_invoke re-checks on every call
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/tools/<tool_id>/invoke -d '{...}'
```

## Prevention / Related

- Treat every `UPSTREAM_PRIVATE_CIDR_ALLOWLIST` change as a security-relevant
  config change worth a second reviewer — it's the same class of decision as
  `git_providers.allow_private` in
  `docs/runbooks/git-provider-setup.md`.
- `docs/runbooks/quarantine-release.md` — a self-hosted tool released from
  quarantine still runs the same live invocation probe through this SSRF
  path; a bad allowlist entry can silently make that probe pass against the
  wrong host.
- See `proxy/tests/unit/test_upstream_validator.py` for the exact behavior
  this runbook describes, if you need to confirm an edge case before
  changing the allowlist in a shared environment.
