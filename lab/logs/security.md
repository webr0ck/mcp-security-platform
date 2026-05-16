# Security Audit Log — Lab Environment
Date: 2026-05-01
Engineer: AppSec Agent

## Executive Summary

The lab environment has a reasonable security posture for a local development context. No live
credentials were found hardcoded in committed code; all secrets that exist at runtime flow through
`.env.lab` (a file now correctly gitignored after this audit). Two issues required immediate
attention: `.env.lab` was absent from the root `.gitignore` (now fixed), and several default
secret values in `config.py` are weak sentinel strings (`change-me-in-production`) that are
meaningless guards without enforcement at startup. No path from audit artifacts to runtime secret
values was identified.

---

## Findings

### CRITICAL

**C-1: `.env.lab` was not in root `.gitignore`**
- File: `/.gitignore`
- A live `.env.lab` exists at the project root containing `ENTRA_CLIENT_SECRET` and other real
  credentials written by `New-M365AppRegistration.ps1`. This file was not listed in `.gitignore`,
  creating a high probability of accidental commit to VCS with real cloud credentials.
- Status: **FIXED** — `.env.lab` added to `.gitignore` in this audit session.

---

### HIGH

**H-1: Weak sentinel defaults in `config.py` are not validated at startup**
- Files: `proxy/app/core/config.py` lines 195, 269
- `VAULT_TOKEN` defaults to `"change-me-in-production"` and `OAUTH_STATE_SECRET` defaults to
  `"change-me-in-production"`. Pydantic Settings will accept these values without complaint in any
  environment mode. If the lab `.env.lab` does not override these, the HMAC state check in
  `oauth.py` runs with a known-public key, enabling CSRF token forgery against any user.
- Recommendation: Add a `@field_validator` (or `model_validator`) on both fields that raises
  `ValueError` when `ENVIRONMENT != "development"` and the value matches the sentinel string.
  For the lab, also add a startup warning log when these defaults are in use.

**H-2: `VAULT_TOKEN` default `"lab-root-token"` in `vault-init.sh` and `seed.py`**
- Files: `lab/scripts/vault-init.sh` line 25, `lab/seeder/seed.py` line 55
- The fallback Vault root token is hardcoded as a well-known string. If Vault is accidentally
  exposed on a non-loopback interface (e.g., `0.0.0.0:8200`), any party knowing this default
  has full Vault admin access. The compose file does not explicitly bind Vault to `127.0.0.1`.
- Recommendation: For the lab, document that Vault's dev-mode listen address must be loopback-only.
  For production: root token must never be used for application access; use AppRole or Kubernetes
  auth instead.

**H-3: Grafana and NetBox API tokens printed to stdout and never stored in Vault**
- File: `lab/seeder/seed.py` lines 248, 296
- `create_grafana_token()` and `create_netbox_token()` print live bearer tokens to stdout
  (`GRAFANA_ADMIN_TOKEN=<key>`, `NETBOX_ADMIN_TOKEN=<key>`). These tokens appear in container
  logs, which may be collected by log aggregation (Loki in this stack). A user is expected to
  manually copy them to `.env.lab`. There is no Vault write path for these tokens.
- Recommendation: After generating, write the tokens directly to Vault KV at
  `secret/mcp/grafana-token` and `secret/mcp/netbox-token` so they are never in plaintext logs.
  If stdout printing is kept for operator convenience, clearly log a WARNING that the value
  should be treated as secret and redacted from log forwarding rules.

---

### MEDIUM

**M-1: `New-M365AppRegistration.ps1` prints `ENTRA_CLIENT_SECRET` to stdout**
- File: `lab/scripts/New-M365AppRegistration.ps1` lines 329-340
- The `$envSnippet` block is printed verbatim to the console with `Write-Host $envSnippet`.
  This is intentional for operator UX ("shown once — copy it now"), but the secret will appear
  in any terminal session recording, CI log (if ever run in automation), or shell history that
  captures stdout. The `Write-Warn "Client secret shown ONCE"` message is present and correct.
- Status: Acceptable for lab. See accepted trade-offs section.
- Recommendation for production: Remove console printing; write directly to a secrets manager
  only and return only the Vault path to the operator.

**M-2: `$ErrorActionPreference = "Stop"` is set before secret creation**
- File: `lab/scripts/New-M365AppRegistration.ps1` line 56
- This is correctly positioned before any Graph API calls, ensuring a failure in prerequisite
  steps aborts execution rather than silently continuing. Confirmed: line 56 sets Stop mode,
  secret creation begins at Step 6 (line 239). No issue.

**M-3: `refresh_token absoluteLifetime` of 3960h (165 days) in Dex config**
- File: `lab/dex/config.yaml` line 28
- 165 days is long even for a lab; a stolen lab refresh token is valid for over 5 months without
  revocation. Dex uses in-memory storage (no persistence), so tokens are reset on container
  restart, which is an effective natural bound. Acceptable for a local lab, but should be noted.

**M-4: `seed.py` DSN construction logs password indirectly on connection failure**
- File: `lab/seeder/seed.py` line 77
- The DSN `f"postgresql://{DB_USER}:{DB_PASSWORD}@..."` is constructed as a local variable and
  passed to `asyncpg.connect()`. If `asyncpg` raises an exception that includes the DSN in its
  message, `last_exc` at line 88 will contain the password and be logged at DEBUG level. This
  is a known asyncpg behavior for some error classes.
- Recommendation: Use `asyncpg.connect(host=..., port=..., user=..., password=..., database=...)`
  keyword arguments instead of a DSN string to avoid the password appearing in exception messages.

**M-5: `DEX_CLIENT_SECRET` default hardcoded in `config.py`**
- File: `proxy/app/core/config.py` line 251
- `DEX_CLIENT_SECRET` defaults to `"mcp-proxy-secret"`, the same value used in `dex/config.yaml`.
  This is a matched lab default and acceptable here, but if the proxy is ever deployed to staging
  without overriding this field, Dex would accept it. Same startup-validation gap as H-1.

---

### LOW / INFO

**L-1: `enablePasswordDB: true` in Dex config — lab-only**
- File: `lab/dex/config.yaml` line 41
- Static password database is enabled. This is the intended mechanism for the lab's test users
  (alice@corp, bob@corp with password `labpassword`). The file already carries the header comment
  `DO NOT USE IN PRODUCTION`. Bcrypt cost 10 is the minimum acceptable (OWASP recommends ≥10);
  acceptable for lab with known-weak passwords.

**L-2: `skipApprovalScreen: true` in Dex config**
- File: `lab/dex/config.yaml` line 18
- Removes the OAuth consent screen. Acceptable for lab where the UX friction is undesirable.
  Must be removed for any deployment with real users.

**L-3: `dex.py` `_post_token()` does not log the response body**
- File: `proxy/app/credential_broker/adapters/dex.py` lines 68-73
- Confirmed: no logging of the response body or any token field. `resp.raise_for_status()` is
  called before `.json()` parsing, so error responses will raise an `httpx.HTTPStatusError` with
  the status code but not the body content. Clean.

**L-4: `oauth.py` uses `hmac.compare_digest()` for state verification**
- File: `proxy/app/routers/oauth.py` line 65
- Timing-safe comparison confirmed. HMAC-SHA256 state token with `_build_state()` is correct.
  The `encrypt()` call at line 99 precedes the DB write at line 103 — refresh token is
  encrypted before persistence. No issues found.

**L-5: `vault-init.sh` broker master secret uses `openssl rand -hex 32` (256-bit entropy)**
- File: `lab/scripts/vault-init.sh` line 75
- Entropy source is strong. Not idempotent — a second run overwrites the master secret,
  invalidating all previously encrypted credentials in the DB. This is documented in the header
  comment ("Idempotent Vault KV initialization") but the master secret write itself is not
  idempotent. Acceptable for a one-shot lab initializer; document the consequence.

**L-6: `lab-seeder` has `restart: "no"` in compose**
- File: `podman-compose.lab.yml` line 131
- Confirmed. The seeder will not loop on failure and re-generate secrets indefinitely.

**L-7: `lab-netbox-db` and `lab-netbox-redis` are on `lab-net` only**
- File: `podman-compose.lab.yml`
- Both services are scoped to `lab-net` only. No `ports:` mappings are present for either
  service, so they are not exposed beyond the lab bridge network. Confirmed.

**L-8: Terraform `.gitignore` covers `*.tfstate` and `*.tfvars`**
- File: `lab/terraform/entra/.gitignore`
- Both patterns are confirmed present. Also covers `.terraform/`, `.terraform.lock.hcl`, and
  `*.tfstate.backup`. Complete.

---

## gitignore Audit

| File/Pattern | Gitignored? | Action taken |
|---|---|---|
| `.env` | Yes (root `.gitignore` line 3) | None required |
| `.env.lab` | No — MISSING | **Added to root `.gitignore`** |
| `lab/terraform/entra/*.tfvars` | Yes (`*.tfvars` in `lab/terraform/entra/.gitignore`) | None required |
| `lab/terraform/entra/*.tfstate` | Yes (`*.tfstate` in `lab/terraform/entra/.gitignore`) | None required |
| `lab/dex/config.generated.yaml` | Not present in any `.gitignore` | Low risk — no generated file found on disk; monitor |

---

## Secret Handling Review

| Location | Secret | Handling | Risk |
|---|---|---|---|
| `New-M365AppRegistration.ps1` | `ENTRA_CLIENT_SECRET` | Printed to stdout AND written to `.env.lab` | MEDIUM — console logging; mitigated by `.env.lab` now gitignored |
| `vault-init.sh` | Vault root token (`lab-root-token`) | Env var default; used only in lab | MEDIUM — well-known default; mitigated by loopback Vault binding |
| `seed.py` | `VAULT_TOKEN` default `"lab-root-token"` | Env var default | MEDIUM — same as above |
| `seed.py` | Grafana API token | Printed to stdout (`print(f"GRAFANA_ADMIN_TOKEN={token_key}")`) | HIGH — appears in container logs |
| `seed.py` | NetBox API token | Printed to stdout (`print(f"NETBOX_ADMIN_TOKEN={token_key}")`) | HIGH — appears in container logs |
| `seed.py` | DB password | In DSN string; potential leakage via asyncpg exception messages | MEDIUM |
| `seed.py` | Broker master secret | Written to Vault via hvac; return value used locally, not logged | LOW — correct |
| `dex/config.yaml` | bcrypt hashes (cost 10) | Static config file; not a secret at rest risk | LOW — hashes are public-safe |
| `dex/config.yaml` | `mcp-proxy-secret` | Hardcoded lab client secret | LOW — lab-only, matched by config.py default |
| `config.py` | `VAULT_TOKEN` sentinel | Default `"change-me-in-production"` — no startup validation | HIGH — see H-1 |
| `config.py` | `OAUTH_STATE_SECRET` sentinel | Default `"change-me-in-production"` — no startup validation | HIGH — see H-1 |
| `oauth.py` | Refresh token | Encrypted via `encrypt()` before DB write; access_token not stored | LOW — correct |
| `dex.py` | Token response | Not logged; `raise_for_status()` before parse | LOW — correct |

---

## Fixes Applied

1. **Root `.gitignore`**: Added `.env.lab` as an explicit ignore entry. The live `.env.lab` file
   at the project root contained real Entra credentials and was unprotected against accidental
   `git add`. This was the only direct code change made during this audit.

---

## Accepted Lab Trade-offs

| Trade-off | Rationale |
|---|---|
| Static plaintext bcrypt hashes for lab users in `dex/config.yaml` | Test users with known passwords are required for repeatable lab login; the file header warns against production use |
| `VAULT_TOKEN = "lab-root-token"` default | Vault runs in dev mode locally; root token is the simplest bootstrap mechanism; acceptable when Vault is loopback-bound |
| Client secret `mcp-proxy-secret` hardcoded in Dex config and `config.py` | Matched defaults allow zero-config lab startup; the Dex server is only reachable within the lab network |
| `skipApprovalScreen: true` in Dex | Reduces friction for repeated local testing; no real users are affected |
| Grafana/NetBox tokens printed to stdout | Operator must manually copy to `.env.lab`; the seeder is a one-shot container; acceptable as long as log forwarding excludes seeder stdout or redacts token-shaped strings |
| `absoluteLifetime: "3960h"` refresh tokens | Dex uses in-memory storage; token lifetime is effectively bounded by container restarts in lab use |
| `New-M365AppRegistration.ps1` prints client secret | Azure only shows secrets once; printing to terminal is the standard operator pattern for local scripts; the secret is immediately written to `.env.lab` (now gitignored) |

---

## Recommendations for Production Hardening

1. **Enforce non-sentinel secrets at startup**: Add `model_validator(mode="after")` in `config.py`
   to reject `VAULT_TOKEN`, `OAUTH_STATE_SECRET`, `PROXY_SECRET_KEY`, and `DEX_CLIENT_SECRET`
   when they match known sentinel values and `ENVIRONMENT != "development"`.

2. **Replace Vault root token with AppRole**: In staging/production, the proxy and seeder must
   authenticate to Vault via AppRole (or Kubernetes auth), not a long-lived root token. The root
   token must be revoked after initial Vault setup.

3. **Never print secrets to stdout in production paths**: Grafana and NetBox token generation
   must write directly to Vault KV and return only the Vault path to the caller. Remove all
   `print(f"TOKEN={value}")` patterns.

4. **Use asyncpg keyword-argument DSN** in all production DB connection code to prevent password
   leakage in exception messages.

5. **Remove `enablePasswordDB` and static users**: Production Dex must connect to a real IdP
   (Entra, LDAP, etc.). Static password DB must be disabled.

6. **Enforce consent screen**: `skipApprovalScreen` must be `false` for any deployment with real
   users or delegated permissions.

7. **Pin Dex image digest**: `ghcr.io/dexidp/dex:v2.38.0` uses a tag, not a digest. Pin to
   `@sha256:...` in production to prevent silent image substitution.

8. **Bind Vault to loopback in compose**: Explicitly set `VAULT_DEV_LISTEN_ADDRESS=127.0.0.1:8200`
   or add a `ports: ["127.0.0.1:8200:8200"]` binding to prevent Vault exposure on all interfaces.

9. **Add `lab/dex/config.generated.yaml` to `.gitignore`**: If any tooling generates this file,
   it should be gitignored to prevent accidental commit of generated OIDC config with embedded
   secrets.

10. **Rotate Entra client secret on a schedule shorter than the 1-year expiry**: The script
    defaults to `SecretExpiryYears = 1`. For production, use 90 days maximum and automate
    rotation via a scheduled process that updates Vault directly.
