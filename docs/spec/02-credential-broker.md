# Credential Broker Specification

**Status: matches code at HEAD (`4dfa7b5`).**

The credential broker is the platform component that lets a client invoke a tool that needs an upstream credential **without the client or the backend MCP server ever seeing the stored raw secret**. On each tool call the broker resolves the identity's credential, decrypts it just-in-time, injects it as an HTTP header into the single upstream request, and drops the plaintext. This document is language-agnostic and normative: **MUST/SHOULD/MAY** are RFC 2119 keywords, `(roadmap)` marks an item present in code but not yet enforced/wired per the [README Enforced-vs-Roadmap table](../../README.md#enforced-today-vs-roadmap), and *Reference implementation:* points at the Python that realizes each requirement.

---

## 1. Purpose & invariants

1. The client MUST NOT receive, and the backend MCP server MUST NOT be handed, any credential the platform stores. The resolved token is injected server-side into the upstream request only. *Reference: `credential_broker/dispatcher.py` returns a headers dict merged into the upstream call inside `services/invocation.py`.*
2. Credential resolution MUST be just-in-time (per call), not cached in plaintext on the client path.
3. Every derived key-encryption key (KEK) and the master secret MUST be held in a mutable buffer and zeroed after use. *Reference: `broker.py::CredentialBroker._zero`, `approaches/approach_a.py::encrypt/decrypt` `finally` blocks.*
4. Every stored credential MUST be AES-256-GCM envelope-encrypted under a per-identity HKDF-SHA256 KEK keyed on the **authenticated** identity, with a synchronous lifecycle audit (INV-013). *Reference: `credential_broker/{kms,approaches/approach_a}.py`.*
5. Any failure on a mode that requires a credential MUST fail closed (abort the upstream call), never forward an unauthenticated request. *Reference: `dispatcher.py` — every error path raises `CredentialInjectionError`; no path returns `{}` except `injection_mode='none'` and intercepted passthrough.*

---

## 2. Crypto chain (normative)

The chain is **master secret → per-identity KEK → AES-256-GCM with row-binding AAD**. Each link exists for a stated reason; a re-implementation MUST preserve all three plus their failure semantics.

### 2.1 Master secret (from Vault KMS)

- The master secret MUST be fetched from Vault (KV v2) at a configured path (`BROKER_MASTER_SECRET_PATH`, default `secret/data/mcp/broker-master`). *Reference: `kms.py::VaultKMSClient.get_master_secret`.*
- The secret MUST be seeded idempotently at Vault startup: the lab Vault entrypoint (`lab/vault/auto-unseal.sh`) writes a fresh random 32-byte value on first boot **only if the path is absent**, and MUST NEVER rotate an existing value (rotation orphans every encrypted `credential_store` row). `lab/scripts/vault-init.sh` performs the same absent-only seeding for manual runs. If the path 404s at runtime, every OIDC callback fails with HTTP 500 ("Failed to encrypt KC tokens"), so seeding cannot be left to a manually-invoked script alone.
- Transport MUST be HTTPS outside development. `VAULT_ADDR` beginning `http://` MUST be rejected at config load in staging/production. *Reference: `core/config.py` `_reject_http_vault_addr` (env-gated on `ENVIRONMENT`); `kms.py` sets `verify=ca_bundle or True` and NEVER disables TLS verification (CB-009).*
- If `VAULT_TOKEN` is empty the broker MUST NOT be constructed; the broker is disabled and every credentialed tool MUST fail closed at call time. *Reference: `factory.py::build_broker` returns `None` when `VAULT_TOKEN` is empty; `dispatcher.py` raises when `broker_instance is None` for any mode `!= none`.*
- The decoded master secret MUST have ≥256-bit (32-byte) entropy; a shorter/weaker value MUST fail closed **before** any KEK is derived. This is required because HKDF silently stretches any-length input, so a misconfigured value (e.g. `"0"`) would otherwise yield a deterministic key with no error. *Reference: `kms.py::_decode_master_secret` raises `KMSError` when `len(raw) < 32`.*
- Encoding: the stored value MUST be decoded as hex when unambiguously hex (even length, all hex digits), else base64. *Reference: `kms.py::_decode_master_secret`. Note: the `get_master_secret` docstring still says "base64-decoded" — stale; the code is hex-first.*
- The master secret SHOULD be cached in a zeroable `bytearray` and re-fetched after a TTL (`BROKER_MASTER_SECRET_TTL_SECONDS`, default 300s) so Vault rotation is honoured and the heap-exposure window is bounded. On refresh the previous copy MUST be zeroed. *Reference: `broker.py::_get_master_secret` (CB-008).*

### 2.2 Per-identity KEK (HKDF-SHA256)

- The KEK MUST be derived `HKDF-SHA256(IKM=master_secret, salt=<per-blob random 32B>, info="mcp-credential-broker-kek-v2:" || user_sub)`, length 32 bytes. *Reference: `approaches/approach_a.py::_derive_kek`.*
- **Why identity in `info`:** binding `user_sub` into the HKDF `info` domain-separates keys per identity — a different identity derives a different KEK, so no cross-user key reuse is possible.
- **Why per-blob salt:** the salt MUST be freshly generated per `encrypt()` call and prepended to the stored blob; `decrypt()` MUST read it back from the first 32 bytes. Stored blob layout MUST be `salt(32) || nonce(12) || ciphertext+tag`. *Reference: `approach_a.py::encrypt/decrypt`, constants `_SALT_SIZE/_NONCE_SIZE`.*
- The derived KEK MUST be a mutable buffer zeroed in a `finally` block after encrypt/decrypt (CB-F004).
- v1 blobs (pre-salt format) are intentionally unreadable and MUST NOT be migrated; the lab seeder re-encrypts on startup. A truncated blob (`< 45` bytes) MUST raise, prompting re-enrolment.

### 2.3 AES-256-GCM with row-binding AAD

- Payloads MUST be sealed with AES-256-GCM using a fresh 96-bit nonce per row. *Reference: `approach_a.py`.*
- The GCM **AAD MUST bind the ciphertext to its `credential_store` row context**: `"mcp-cred-v2" | user_sub | service | tool_id | owner_type`. Decryption MUST succeed only when all four context fields match the values used at encryption time. *Reference: `approach_a.py::_make_aad`.*
- **Why:** row-binding AAD defeats credential-swap / blob-confusion attacks — an attacker who moves an encrypted blob to a different `(user_sub, service, tool_id, owner_type)` row cannot decrypt it, because the AAD no longer matches (FIND-010, INV-013).

> **Exactly ONE ciphertext codec exists**: `approaches/approach_a.py` (`encrypt`/`decrypt`), the salt+AAD row-bound format (`salt(32) || nonce(12) || ct+tag`). Every writer (admin upload, enrollment, oauth/oidc, portal) and every reader (`service`/`user`/`service_account` modes via `decrypt_credential`, `entra_client_credentials` via `services/credential_storage.py::retrieve_credential`) MUST use it. `credential_storage.py` additionally enforces row-context equality in application code before decrypting (fail-closed pre-check on top of the AAD). The former second format (`kms.py::envelope_encrypt/decrypt`, `nonce || ciphertext`, no salt/AAD) was deleted: it was write/read-incompatible with approach_a, so credentials stored by the admin path raised `InvalidTag` when the dispatcher retrieved them — every stored-credential injection failed closed. Do NOT reintroduce a second codec.
>
> **Write/read context tuple MUST match.** `admin_credentials.upload_credential` encrypts service-owned credentials with `(user_sub="__service__", service=tool.service_name or tool.name, tool_id=str(tool.tool_id), owner_type="service")` and links `tool_registry.credential_id` to the upserted row. The `entra_client_credentials` dispatcher path retrieves with the same tuple (`service_name` falling back to `name`, never a hardcoded literal).

---

## 3. Injection modes (dispatcher)

`dispatch_credential_injection(tool_record, client_id, user_kc_token)` resolves the effective mode and returns a headers dict (or `{}` for `none`). Mode resolution order MUST be: (1) tool-level `injection_mode`, (2) `server_default_injection_mode`, (3) `none`. An **empty string `""` MUST NOT collapse to `none`** — it MUST fail the enum parse and fail closed. An **unknown mode MUST fail closed**. *Reference: `dispatcher.py::dispatch_credential_injection`.*

| Mode | Status | Behaviour | Fail-closed trigger |
|---|---|---|---|
| `none` | active | no-op; upstream called with no injected credential | n/a |
| `service` | active | decrypt shared service credential (`user_sub="__service__"`, `owner_type="service"`) from `credential_store`, inject as `{prefix} {token}` | no row → `ServiceCredentialMissingError` |
| `user` | active | decrypt per-user credential keyed by caller `client_id` | no row → `CredentialEnrollmentRequiredError` (carries enroll URL) |
| `service_account` | active | Keycloak `client_credentials` token for the tool's `kc_client_id`; client secret read from `credential_store` (`user_sub="__kc_sa__"`) | missing `kc_client_id`/secret/token → raise |
| `kc_token_exchange` (canonical) / `oauth_user_token` (alias) | active, **direct-OIDC callers only** | RFC 8693 subject-token exchange **within the Keycloak realm**: exchange caller's KC access token for an upstream-audience token; then S-5 verify | no caller KC token (e.g. browser-session/portal callers) → raise; missing/non-allowlisted audience → raise |
| `entra_client_credentials` | active | app-only Microsoft Graph token via Azure `client_credentials`; Entra secret read from Vault-backed `credential_store` via `credential_id`; token cached in Redis | missing `credential_id`/fields/token → raise |
| `passthrough` | code-present, **not settable via admin API (roadmap)** | forward the client-supplied `X-Downstream-Authorization` header verbatim; intercepted at `invocation.py`, not here | reaching dispatcher returns `{}` (invocation layer forwards inbound header) |
| `entra_user_token` | code-present, **not settable via admin API (roadmap)** | per-user delegated Graph token via broker Approach-A resolve (decrypt refresh → `M365Adapter.refresh` → re-store) | no `client_id` → raise (S-1); not enrolled → `CredentialEnrollmentRequiredError` |
| `basic_auth` | active (CR-05) | RFC 7617 HTTP Basic. Stored secret MUST be structured JSON `{"username","secret"}` (NEVER a prebuilt header), written with the same unified Approach-A codec; per-user row (`owner_type='user'`, keyed by caller sub) wins over the shared `owner_type='service'` row; header value `Basic base64(username:secret)` is built at injection time; `inject_header` override respected, the `Basic` scheme is NOT overridable | no `service_name` → raise (CRITICAL-1 parity); no row → `ServiceCredentialMissingError`; malformed payload or colon-in-username → raise with NO payload excerpt (redaction invariant: neither `username:secret` nor its base64 may appear in logs/audit/errors) |

The alias `oauth_user_token` MUST be normalized to `kc_token_exchange` at dispatch entry before enum parsing. *Reference: `dispatcher.py` lines ~166.*

### 3.1 kc_token_exchange verification (S-5)

For `kc_token_exchange`, before injecting the exchanged token the broker MUST verify it, even on Redis cache hits (the cache stores no pre-computed claims):
1. Signature MUST verify against the KC JWKS key matching the token `kid` (RS256).
2. `aud` MUST equal the expected audience.
3. `sub` MUST equal the caller's sub.
4. `azp` MUST equal `mcp-proxy` (KC 24 delegation evidence).

*Reference: `token_assert.py::assert_exchanged_token`, `keycloak_client.py::get_public_key_for_token`.* The proxy MUST also enforce a **hardcoded audience allowlist** so a malicious/buggy DB row cannot widen the mint: `_ALLOWED_EXCHANGE_AUDIENCES = {"lab-tickets"}`. *Reference: `dispatcher.py` (S-6(b)). This allowlist is lab-specific; a re-implementer MUST maintain an equivalent proxy-side allowlist.*

### 3.2 The three canonical downstream flows

1. **Token-exchange / federation** (`kc_token_exchange`, `entra_user_token` (roadmap), `entra_client_credentials`): the platform mints or exchanges a fresh upstream token per call. Cross-IdP delegation (KC → Entra) is the `entra_user_token` shape (roadmap); same-realm delegation is `kc_token_exchange` (active, direct-OIDC only).
2. **Passthrough, same trust domain** (`passthrough`, roadmap-gated at the admin API): the client presents its own upstream token in `X-Downstream-Authorization`; the proxy forwards it. This is *not* "forward the caller's gateway token" — a normal client that never sets that header gets **no** Authorization forwarded.
3. **Static injection** (`service`, `user`, `service_account`): a stored secret/token (or a KC service-account token) is decrypted/minted and injected. `service`/`user` inject the decrypted `credential_store` blob directly.

### 2.6 ms365-class servers (device-code / self-managed token cache) — architectural gap (validation HIGH-1)

The broker's model is **stateless per-call injection**: it resolves one credential and injects it into one upstream request. A real-world server like [`softeria/ms-365-mcp-server`](https://github.com/softeria/ms-365-mcp-server) is a **different shape** — it runs an OAuth **device-code** flow and **owns and refreshes its own MSAL token cache across its process lifetime**. The broker has no concept of a long-lived, server-managed token store, and every scaffold template + the SDK context assume the stateless-per-call shape.

- **"Dozens of tools" is NOT the blocker** — Pattern B (`mcp-server-onboarding.md`) already proxies `tools/list` for an arbitrarily large upstream.
- The needed delegated mode `entra_user_token` is **(roadmap)** (see the table above); `entra_client_credentials` is single-tenant (no multi-tenant Azure AD).
- **Current supported path:** run such a server with `injection_mode=none` and let the server **self-manage its OAuth** (device-code + its own token cache) *outside* the broker. This is the pattern to use today; the broker simply injects nothing and the server authenticates upstream itself.
- **Roadmap:** a broker-native device-code / persistent-token-store flow so the platform can own the MSAL cache and keep per-user attribution. Until then, `injection_mode=none` self-managed is the documented, supported answer for ms365-class servers — with the trade-off that the broker gives no per-call credential isolation for that server (the server holds its own tokens).

---

## 4. Enrollment flow (zero raw credentials to the client)

Per `docs/ARCHITECTURE.md` §5.2, credential enrollment MUST bind the stored credential to the **authenticated** identity, never a client-controlled header. *Reference: `routers/oauth.py`.*

1. `GET /auth/enroll/{service}` MUST require an authenticated identity (`request.state.client_id`) and render a **server-side consent page** with the exact requesting client, redirect URI, and requested scopes (new scopes highlighted vs stored). It MUST write only a pending-consent record to Redis (`enroll_consent:{csrf}`, TTL 300s) — **no PKCE state yet**. Per-client enrollment consent is a gate: PKCE state is minted only after consent. *Reference: `oauth.py::enroll`.*
2. `POST /auth/enroll/{service}/consent` MUST consume the CSRF-keyed consent record via **atomic get-and-delete** (single-use), MUST re-confirm the POSTing session identity equals the record's `client_id`, and MUST emit a synchronous `CREDENTIAL_CONSENT_DENIED` audit before any 4xx. Only then does it mint a **single-use nonce** (the OAuth `state`) plus a PKCE S256 verifier/challenge, store `oauth_flow:{nonce}` in Redis (TTL 300s, bound to the authenticated identity), emit a synchronous consent-grant audit, and 302 to the IdP. *Reference: `oauth.py::enroll_consent`.*
3. `GET /auth/callback/{service}` MUST recover the flow by consuming `oauth_flow:{state}` atomically (get+delete pipeline) so a captured callback cannot be replayed; **identity is recovered from the nonce record, not any header**. It MUST exchange the code (PKCE `code_verifier`), envelope-encrypt the **refresh token** under the authenticated `client_id`'s KEK, upsert into `credential_store`, and emit a synchronous `CREDENTIAL_ENROLLED` audit (failure = hard error, INV-001). *Reference: `oauth.py::callback`, `_emit_credential_audit`.*

Nonce properties (MUST): server-side only, single-use, short TTL (300s), identity-bound, `state`/`service` mismatch rejected. Consent-time scopes MUST be stored with the flow and used at callback (no TOCTOU re-read of `tool_registry`).

---

## 5. Adapter plugin model

Credentialed backends are onboarded as **self-registering adapters**, so adding one requires no edit to the factory or enrollment router. *Reference: `credential_broker/adapters/registry.py`.*

- An adapter module MUST declare itself via `@register_adapter(name, approach, requires=(...))`, exposing a pure `build(settings)` constructor. `approach` MUST be `"A"` or `"B"`. `requires` names settings that MUST all be truthy for the adapter to be included (declarative gating; empty = always). *Reference: `registry.py::register_adapter/AdapterSpec.is_configured`.*
- Discovery MUST import every adapter module (`discover_adapters`), skip non-adapter infra modules (`__init__`, `base`, `registry`, `healthcheck`), and tolerate a single adapter's import failure without breaking the rest. A duplicate `(approach, name)` registration MUST be last-import-wins **and** logged loudly (supply-chain tamper signal). *Reference: `registry.py::discover_adapters`, `_NON_ADAPTER_MODULES`.*
- `build_adapters(settings)` MUST return `(approach_a, approach_b)` dicts keyed by service name, including only configured adapters. *Reference: `factory.py::build_broker` → `adapters/registry.py::build_adapters`.*

**Approach A** (per-user OAuth authorization-code + refresh): `build_auth_url` / `exchange_code` / `refresh`. Adapters: `m365` (Entra, PKCE S256), `bitbucket`, `dex`. Token-endpoint errors MUST raise `TokenExchangeError` carrying **only the HTTP status** — never the IdP response body, which can echo secrets (CB-010, INV-002). *Reference: `adapters/{m365,bitbucket,dex}.py`, `adapters/base.py::TokenExchangeError`.*

**Approach B** (gateway-provisioned token, `provision`/`revoke`): `grafana` (per-user SA token), `netbox` (per-user token), `gitea` (static shared token). *Reference: `adapters/{grafana,netbox,gitea}.py`.*

### 5.1 Orphaned / unwired adapters (honest status)

- The dispatcher's live injection modes **never call `broker.resolve(approach="B")`** — no `injection_mode` routes to `_resolve_b`. Therefore the **Approach-B adapters (`grafana`, `netbox`, `gitea`) are orphaned** on the live path; `service`/`user` modes read static blobs from `credential_store` via Approach-A crypto instead. *(roadmap to wire, matches README "Approach-B service adapters … are orphaned".)*
- The Approach-A refresh path (`_resolve_a`) is reached **only** via `entra_user_token`, which is still not settable via the admin API **(roadmap)** — but the lab now exercises it end-to-end: the seeded `m365-graph-delegated` tool row (seeder SQL, injection_mode=`entra_user_token`, service_name=`m365`) drives `_resolve_a` → `M365Adapter.refresh()` per call. In the lab the adapter's endpoints are pointed at `lab-mock-idp` via the `ENTRA_TOKEN_URL`/`ENTRA_AUTH_URL` setting overrides (empty default = derive real `login.microsoftonline.com` URLs from `ENTRA_TENANT_ID`), and enrollment is seeded directly into `credential_store` (`seed.py::seed_m365_delegated_credentials`, deterministic `mock-refresh-<sub>` refresh tokens the mock IdP accepts statelessly).
- `adapters/healthcheck.py` is a separate interface (server-approval reachability probe: `gitea`, `m365`), not a credential adapter.

---

## 6. Admin credential management API

*Reference: `routers/admin_credentials.py`, prefix `/admin/credentials`, all endpoints admin-gated.*

- `GET /api` — list tools with `injection_mode` + `has_service_credential`.
- `PUT /{tool_id}` — upload/rotate: encrypt secret with Approach-A `encrypt()` under the resolved identity, upsert into `credential_store` (`ON CONFLICT (tool_id, service) WHERE owner_type='service'`), emit `CREDENTIAL_UPLOADED` audit. For `credential_type='basic_auth'` the body MUST also carry `username` (400 without it; 400 on RFC 7617-forbidden `:` in username) and the stored plaintext is the structured JSON `{"username","secret"}` the dispatcher expects — the audit detail carries neither `username` nor `secret`.
- `DELETE /{tool_id}` — hard-delete credential row, emit `CREDENTIAL_REVOKED`.
- `PUT /{tool_id}/injection-mode` — set mode. **Valid modes are sourced from the canonical `AuthMode` status matrix (`services/auth_modes.py`, every `status="supported"` mode — including `basic_auth` since CR-05 — plus the `oauth_user_token` alias)**, so the endpoint cannot drift behind dispatcher support. `passthrough` remains admin-store-only, not settable here.

Every mutation MUST emit a durable credential-lifecycle audit; audit failure MUST log at CRITICAL (does not raise, but is monitorable). *Reference: `_emit_credential_audit`.*

---

## 7. Operational

### 7.1 Master-secret drift

**Symptom:** a service/user tool fails with "not provisioned" / `ServiceCredentialMissingError` even though a `credential_store` row exists. **Root cause:** the stored blob was encrypted under a master the broker no longer loads (or tampering) — the broker correctly fail-closes on an undecryptable blob; this is NOT a broker bug. *Reference: `approach_a.py::decrypt_credential` logs "row FOUND … but decryption FAILED … likely broker master-secret drift" and returns `None` (which the dispatcher surfaces as "not provisioned").*

**Re-provisioning (lab):** `lab/seeder/reprovision_service_creds.py` mints fresh downstream tokens (grafana/gitea) on the lab network and prints `TOKEN:<service>:<value>`; the proxy then re-encrypts+upserts them under **its own** master secret (two-step because the minter and the authoritative master live in different containers). *Reference: `lab/seeder/reprovision_service_creds.py`, `seed.py`.*

### 7.2 Rotation (honest status)

- **Master secret:** re-fetched from Vault every `BROKER_MASTER_SECRET_TTL_SECONDS` (default 300s), so rotating the Vault value is picked up without restart — but there is **no re-encryption of existing blobs on rotation**; rotating the master invalidates all stored blobs until re-provisioned (this is the drift symptom above). Automated master rotation with blob re-wrap is **(roadmap)**.
- **Per-credential rotation:** admin `PUT /{tool_id}` re-encrypts and stamps `rotated_at`. Enrollment refresh rotates the stored refresh token per call on the Approach-A path (`broker.py::_resolve_a` re-encrypts `new_refresh`).
- **Entra app-only tokens:** cached in Redis with `expires_in - 60s` TTL; refreshed on expiry.

---

## 8. Discrepancies found (docs ↔ code)

1. `kms.py::get_master_secret` docstring says "base64-decoded from Vault value"; code is hex-first (`_decode_master_secret`).
2. `entra_client_credentials` is documented "active/settable" but is **not** in the admin injection-mode endpoint's `valid_modes`; it is set via `server_registry`/seeder.
3. ~~Two envelope formats coexist~~ **Resolved:** `kms.py` envelope helpers deleted; `credential_storage.py` now uses `approach_a` (one codec platform-wide, see §2.3).
4. Approach-B adapters (grafana/netbox/gitea) and `broker.resolve("B")` are unreachable from any live injection mode (orphaned) — matches README but not obvious from `factory.py`.
5. `dispatcher.py::InjectionMode.OAUTH_USER_TOKEN` match-arm is unreachable (alias normalized before enum parse); kept as a belt-and-suspenders guard.
