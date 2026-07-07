# Self-service MCP server onboarding — walkthrough

**Audience:** anyone (no platform expertise required) submitting a new MCP server for review and
release. This walks a real submission end-to-end against the lab environment; every command below
is copy/pasteable.

Before you start: [auth-mode-decision-guide.md](auth-mode-decision-guide.md) helps you answer "how
does the platform authenticate to my backend?" — you'll need that answer for step 3.

## Prerequisites

- The lab is up (`podman ps` shows `mcp-proxy`, `lab-keycloak`, etc.).
- You have a lab user account and its real password from `.env.lab`
  (`DEX_ALICE_PASSWORD`/`DEX_BOB_PASSWORD`/`DEX_CAROL_PASSWORD`) — this walkthrough uses `carol`.
- **Run every command below INSIDE the `mcp-proxy` container**, not from your host shell. The proxy
  has an ingress guard (SEC-05) that rejects any direct inbound peer that isn't the gateway or
  loopback — a real client always goes through the gateway/mTLS, but for this walkthrough the
  simplest verbatim-reproducible path is the same one `make test-lab-functional` uses:
  ```bash
  podman exec -it mcp-proxy sh
  ```
  Every command in the rest of this doc is meant to be pasted into that shell.

## Step 0 — Get a token

```bash
TOKEN=$(curl -sf -X POST http://lab-keycloak:8080/realms/mcp/protocol/openid-connect/token \
  -d grant_type=password -d client_id=lab-test -d client_secret=lab-test-secret \
  -d username=carol -d "password=$DEX_CAROL_PASSWORD" -d scope="openid profile email" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
echo "${TOKEN:0:20}..."   # expect a non-empty JWT prefix
```

(`$DEX_CAROL_PASSWORD` must be exported into the shell first — e.g. paste it from `.env.lab`, or
if you're outside the container run `podman exec -e DEX_CAROL_PASSWORD=... mcp-proxy sh` instead of
the plain `podman exec -it mcp-proxy sh` above.)

**Expected output:** a non-empty string starting with `eyJ` (a JWT header). If this fails with
`invalid_grant`, double check the password came from `.env.lab` verbatim — this is not a platform
bug, `labpassword` is only a test-suite *default* for `carol`/`bob`, not what this lab is actually
seeded with.

## Step 1 — Create a draft submission

```bash
curl -sf -X POST http://localhost:8000/api/v1/submissions \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "my-first-server", "description": "walkthrough test server"}'
```

**Expected output:**
```json
{"server_id": "<uuid>", "submission_status": "draft"}
```
Save `server_id` — every following command needs it:
```bash
export SID=<the server_id from above>
```

## Step 2 — Fill in the rest (wizard steps 2–3)

For a real server you'd set `github_repo_url` (so the platform can scan and, optionally, build it
for you) and your chosen auth mode from step 3. For this walkthrough, a no-credential upstream:

```bash
curl -sf -X PATCH http://localhost:8000/api/v1/submissions/$SID \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"injection_mode": "none"}'
```

**Expected output:** `{"server_id": "<uuid>", "updated": true}` (HTTP 200).
`PATCH` only works while the submission is in `draft` or `changes_requested` — see
[submission-lifecycle.md](submission-lifecycle.md).

## Step 3 — Submit for review

```bash
curl -sf -X POST http://localhost:8000/api/v1/submissions/$SID/submit \
  -H "Authorization: Bearer $TOKEN"
```

**Expected output:** submission_status moves to `scan_pending` (a `github_repo_url` submission)
or straight to `awaiting_review` (a no-code submission, nothing to scan).

## Step 4 — Check status

```bash
curl -sf http://localhost:8000/api/v1/submissions/$SID -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

**Expected output:** a JSON object including `"submission_status"`. Poll this until it reads
`"awaiting_review"` (a scan, if any, has finished) — see
[submission-lifecycle.md](submission-lifecycle.md) for what every value means and what to do next.

## Step 5 — Wait for reviewer approval

An admin/reviewer now needs to approve your submission (see
[../admin/reviewer-approval-guide.md](../admin/reviewer-approval-guide.md) — that's their side of
this walkthrough). This must be a **different** identity than the one that submitted — the
platform blocks self-review even for an admin (`carol` cannot approve her own submission; get a
token for `alice`/`bob` instead, the same way as step 0, and re-run the approve call from
[reviewer-approval-guide.md](../admin/reviewer-approval-guide.md) with that token). Once approved,
`submission_status` becomes `approved_pending_url` (if you gave a repo URL) or `scaffold_ready`
(no-code).

## Step 6a — Self-hosted path: provide your running URL

If you're running the server yourself somewhere reachable from the platform:

```bash
curl -sf -X POST http://localhost:8000/api/v1/submissions/$SID/provide-url \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"upstream_url": "http://lab-mcp-echo:8000/mcp"}'
```

**Expected output:**
```json
{"server_id": "<uuid>", "submission_status": "active", "tools_provisioned": <N>,
 "tools_skipped": [], "quarantined": true, "next": "<N> tool(s) discovered..."}
```

## Step 6b — Platform-managed path: let the platform build/deploy it

Only valid if you gave a `github_repo_url` and a scan has completed:

```bash
curl -sf -X POST http://localhost:8000/api/v1/submissions/$SID/apply -H "Authorization: Bearer $TOKEN"
# then poll:
curl -sf http://localhost:8000/api/v1/submissions/$SID/verification-report -H "Authorization: Bearer $TOKEN"
```

See [../admin/deploy-verify-operations.md](../admin/deploy-verify-operations.md) for what each
`deployment_status` value means while you're polling.

## Step 7 — Your tools are quarantined — ask for release

Whichever path you took, your tools now exist but **cannot be invoked yet** — they're
`quarantined` by design (deployment success ≠ tool trust). An admin releases each one:
`POST /api/v1/admin/tools/{tool_id}/release`. Once released:

```bash
curl -sf -X POST http://localhost:8000/mcp -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"walkthrough","version":"1.0"}}}'
```

See [invoking-tools.md](invoking-tools.md) for the full invoke sequence and expected responses.

## Troubleshooting

If any step above didn't match its expected output, check
[../troubleshooting/common-errors.md](../troubleshooting/common-errors.md) before assuming it's a
bug — most non-200 responses at this stage are a state-machine mismatch (e.g. calling `apply`
before a scan finishes) or an auth-mode config gap, both documented there with the exact fix.
