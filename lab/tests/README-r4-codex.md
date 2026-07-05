# R-4 — Codex-driven MCP submission QA (runbook)

PRD-0005 R-4. Two halves:

1. **Scriptable lifecycle** — `lab/tests/submission_lifecycle_e2e.sh` (runs now, no
   human): submit → automated scan (mcp_checker + declared-dep SBOM + syft CycloneDX)
   → segregation-of-duties (submitter cannot self-approve) → reviewer approves →
   SBOM download. 12 assertions.

2. **Codex-driven generation** (this runbook) — a human drives Codex to *author* an
   MCP server from the wizard answers and push it, because it needs an interactive
   browser login that cannot be automated in CI.

## Prerequisites

- Lab up (`make -f Makefile.lab lab-up`), gateway reachable at `https://<host>:8443`.
- Codex CLI configured with the gateway MCP server (`~/.codex/config.toml`):
  ```toml
  [mcp_servers.mcp-gateway]
  url = "https://<host>:8443/mcp"
  ```
- Test workspace: `~/Code/test-api-server` (a benign read-only policy MCP server).

## Step 1 — Authenticate Codex to the gateway (MANUAL, interactive)

```sh
codex mcp login mcp-gateway
```

This opens a browser for the OAuth 2.1 PKCE flow (Keycloak). Copy the login URL if
it doesn't auto-open, authenticate as a **submitter** (e.g. `alice` / `bob`), and
paste the callback string back into Codex when prompted.

> Why manual: the PKCE browser round-trip (and the `codex mcp login` copy/paste)
> is interactive by design — there is no headless credential path, and adding one
> would be a static-secret bypass of the very auth model this platform enforces.

## Step 2 — Codex generates the server from the wizard answers

Prompt Codex (in `~/Code/test-api-server`) to:

1. `GET /api/v1/design-assist` (decision tree) then
   `GET /api/v1/design-assist?mode=<chosen>` for the mode-specific design prompts —
   these are the **admin-editable wizard prompts** (PRD-0005 R-0). Answer them.
2. Generate a minimal, **benign** MCP server implementing the described tools.
3. Push it to a repo the configured git provider's service account can read
   (GitHub, or corporate Bitbucket — PRD-0005 R-2).
4. Create + submit: `POST /api/v1/submissions` then `.../{id}/submit`.

## Step 3 — Automated gate + security-agent approval

- The submission scanner runs automatically (mcp_checker MCP-specific SAST +
  trufflehog + pip-audit + custom rules), collects both SBOMs, and moves a clean
  submission to `awaiting_review`.
- A **separate** reviewer identity (a `security_reviewer` such as `carol`, or an
  automated security agent) approves via
  `POST /api/v1/admin/submissions/{id}/approve`. Segregation-of-duties forbids the
  submitter from approving their own.

## Assertions (what a passing run proves)

Same as the scripted test, plus that a Codex-authored server survives the real
gate. To prove the gate has teeth, also submit a **deliberately vulnerable**
variant (e.g. `github.com/kenhuangus/mcp-vulnerable-server-demo`) and confirm
mcp_checker surfaces findings on the review card (SQL-injection param, env
exposure, STDIO transport).

Run the scripted half any time:

```sh
bash lab/tests/submission_lifecycle_e2e.sh
```
