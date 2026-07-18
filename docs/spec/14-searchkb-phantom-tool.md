# 14 — `search-kb` "Unknown tool" root cause + fix

Status: **Fixed (2026-07-18)**
Source: Fix 3 of `docs/spec/11-server-lifecycle-and-hardening-batch.md`
(external acceptance run `ExternalTestResults/2026-07-18_21_40_results.md`).

## Symptom

`search-kb` was listed in the catalog as `active` with
`enabled_for_your_profile: true`, but every invocation — both the
`invoke_tool` meta-tool and a direct top-level `tools/call` — returned:

```
Unknown tool: search-kb
```

## Verdict: misrouted, not phantom

`search-kb` is a **real, correctly-onboarded backend**, not a stale/phantom
seed row:

- `tool_registry` row: `name='search-kb'`, `upstream_url='http://lab-mcp-search:8000/mcp'`,
  `status='active'` (`lab/seeder/sql/tools.sql`).
- `server_registry` row `lab-search` links to the same upstream URL, is
  `approved`, and carries the `10.89.0.0/16` allowlist entry the invoke-time
  SSRF/TOCTOU guard requires (`lab/seeder/sql/servers.sql`). `tool_registry.server_id`
  is backfilled from this link.
- `alice@corp` (human + agent/mTLS principals) and the shared
  `svc-mcp-agent` service account all hold entitlements on `lab-search`.
- The container `lab-mcp-search` is built and wired in `podman-compose.lab.yml`
  (`mcp-search-net`, pairwise net with the proxy).

So catalog visibility, entitlement, network isolation, and upstream
reachability were all correctly wired. The break was purely in **name
resolution at dispatch time**.

## Root cause

`lab/mcp-servers/search/server.py` registers its tool with FastMCP as:

```python
@mcp.tool()
async def search(query: str, limit: int = 5, category: Optional[str] = None) -> dict:
    ...
```

With no explicit `name=` kwarg, FastMCP names the tool after the function:
**`search`**. But `tool_registry.name` for this server is **`search-kb`**
(the catalog-facing name). When a caller issues `tools/call {"name":
"search-kb", ...}`, the proxy forwards `params.name="search-kb"` upstream
verbatim — and the upstream server, which only knows about a tool called
`search`, bounces it with `Unknown tool: search-kb`.

This is the exact same class of bug as the R-2 fix already shipped for
single-tool-per-server wrappers (e.g. `gitea-repos` → upstream `list_repos`):
the registry's catalog name and the upstream server's real primary tool name
diverge, and something has to bridge the two at dispatch time.

**The bridge existed for one of the two invocation paths but not the other:**

- `_route_to_registry()` (`proxy/app/routers/mcp_server.py`) — the direct
  top-level `tools/call` path — already had the R-2 retry: on an "unknown
  tool" bounce, it calls `_resolve_upstream_subtool_name()` (issues a
  `tools/list` against the upstream through the same security pipeline,
  takes the first/only tool's real name) and retries once with the resolved
  name. This path already worked correctly for `search-kb`.
- `_handle_invoke_tool_real()` — the `invoke_tool` meta-tool handler used by
  MCP clients that call the platform's self-describing `invoke_tool` tool —
  had **no such retry**. It built `json_rpc_request.params` directly from the
  caller-supplied `arguments` (which embeds `{"name": "search-kb", ...}`),
  forwarded it upstream unchanged, and on an error response just
  `json.dumps()`'d the raw JSON-RPC error (`Unknown tool: search-kb`) back to
  the caller as tool output text. This is the path the acceptance run's
  `invoke_tool` case actually exercised and observed failing.

## Fix

`proxy/app/routers/mcp_server.py` — `_handle_invoke_tool_real()`: after the
initial `inv_svc.invoke_tool()` call, when `method == "tools/call"` and the
result is a JSON-RPC error whose message contains `"unknown tool"`, resolve
the upstream's real primary tool name via the existing
`_resolve_upstream_subtool_name()` helper (unchanged — already shared with
`_route_to_registry`) and retry once with the resolved name, forwarding the
same `arguments.arguments` payload. On success the retried result replaces
the original error before being JSON-dumped back to the caller. This mirrors
`_route_to_registry`'s retry byte-for-byte (same helper, same one-retry
policy, same TTL'd cache in `_wrapper_subtool_cache`) so the two dispatch
paths can no longer drift on this behavior.

No data/seed change was needed — `search-kb` is not phantom, so no migration
(`V080` or otherwise) was added.

## What was NOT touched

- `lab/seeder/sql/*` — no phantom row to remove; `search-kb`'s seed data is
  correct as-is.
- `proxy/app/routers/catalog.py` — catalog listing logic was not the bug;
  `search-kb` correctly shows `active` + `enabled_for_your_profile: true`
  because it *is* a valid, entitled, active tool. The bug was purely in
  dispatch-time name resolution.
- `authz.rego` / OPA — no policy change; this was never a policy denial.

## Regression coverage

`proxy/tests/unit/test_search_kb_wrapper_retry.py` — two unit tests, mocking
`app.services.invocation.invoke_tool` to reproduce the real upstream
sequence (`tools/call('search-kb')` → `Unknown tool: search-kb`,
`tools/list` → `[{"name": "search"}]`, `tools/call('search')` → success):

1. `test_route_to_registry_resolves_search_kb_wrapper_mismatch` — pins that
   the direct top-level path already resolves and succeeds (regression
   guard on existing R-2 behavior).
2. `test_invoke_tool_meta_tool_resolves_search_kb_wrapper_mismatch` — pins
   the new retry in `_handle_invoke_tool_real`; fails without the fix
   (asserts `"Unknown tool"` does not appear in the returned text and the
   JSON-decoded payload has no `error` key).

Both pass locally (`.venv/bin/python -m pytest
tests/unit/test_search_kb_wrapper_retry.py -v` from `proxy/`). Ruff diff
against `main` on `app/routers/mcp_server.py` is neutral (69 pre-existing
findings before and after this change; none introduced by the new code).
Not verified against a live lab boot (out of scope for this fix — QA should
confirm both `invoke_tool` and direct `tools/call` against `search-kb`
succeed end-to-end on next lab boot).
