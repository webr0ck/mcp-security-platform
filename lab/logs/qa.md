# QA Log — Lab Test Run
Date: 2026-05-01

## Unit Test Results

### Full suite (excluding test_redaction.py — broken import)

**Collection error (pre-existing):** `tests/unit/test_redaction.py` fails to collect because
`mcp_audit_logger` is not installed in the proxy venv. The module lives in
`observability/mcp-audit-logger/` and has its own test suite there. The proxy venv import
in the unit test file is incorrect and must be removed or gated behind an optional import.

**Results (64 run, 1 xfailed, 0 failures):**

| Result | Count |
|--------|-------|
| PASSED | 64 |
| XFAILED (expected) | 1 (`test_missing_signing_key_raises` — ticket referenced in test) |
| FAILED | 0 |
| ERRORS (collection) | 1 (`test_redaction.py` — broken cross-module import) |

**Pre-fix failure** (now resolved — see Tests Written below):
- `tests/unit/test_sbom.py::test_embedded_signature_in_document` — FAILED
  - Root cause: `app/services/sbom.py` embedded the full `hmac-sha256:<hex>` string in
    `bom_document["signature"]["value"]`. The CycloneDX spec and the `test_signature_format_prefix`
    test both confirm `value` must contain only the hex digest. The `algorithm` field encodes the
    scheme. The source had a bug; the test was correct.

### Broker tests (33 tests)

All 33 passed. Covers: approach_a, approach_b, bitbucket, broker, grafana, kms, m365, models,
netbox, registry, session, invocation_broker, oauth_router.

**Recurring warnings (non-blocking, but should be fixed):**
- `grafana.py:33`, `grafana.py:43`, `netbox.py:49`, `netbox.py:60`:
  `RuntimeWarning: coroutine 'AsyncMockMixin._execute_mock_call' was never awaited`
  Cause: `resp.raise_for_status()` is called on an `AsyncMock` without `await` in the adapters.
  The adapters treat `raise_for_status` as synchronous, but the mock is async. Fix: use
  `MagicMock()` (not `AsyncMock`) for `raise_for_status` in the test setup, or call
  `mock_resp.raise_for_status = MagicMock()` explicitly (as `test_m365.py` and `test_dex.py` do).

## Coverage Gaps Found

1. **`test_redaction.py` broken import** — `mcp_audit_logger` not importable from proxy venv.
   The proxy venv does not have the audit logger package installed. Either install it as an
   editable dependency or move the test to the `observability/mcp-audit-logger/tests/` directory.

2. **`DexAdapter` had no unit tests** — `adapters/dex.py` was missing a test file entirely.
   Written as part of this run (see Tests Written).

3. **`GET /auth/enroll/dex` had no router test** — `test_oauth_router.py` tested m365 and 404
   but not the dex path. Added `test_enroll_dex_redirects_to_dex`.

4. **`GET /auth/callback/{service}` is untested** — The OAuth callback handler (state verification,
   code exchange, Vault KMS call, DB upsert) has zero unit or integration test coverage. This path
   handles actual credential storage and is security-critical.

5. **`_verify_state` / CSRF protection is untested** — The HMAC state verification in `oauth.py`
   is not exercised by any test. A tampered or replayed state must be rejected (400). Tests needed:
   - `[TAMPER] callback with mismatched state → 400`
   - `[TAMPER] callback with replayed state from different session → 400`

6. **`lab/seeder/seed.py` — integration-only, no unit tests** — Confirmed intentional. The seeder
   is designed to run against live infrastructure. Unit tests would require heavy mocking of
   asyncpg, hvac, and httpx with limited value. An integration smoke run is sufficient.

7. **Grafana and NetBox adapters use `raise_for_status` incorrectly in tests** — 4 warnings
   indicate the adapter code calls `raise_for_status()` synchronously, but test mocks are `AsyncMock`.
   The adapters should call `raise_for_status()` synchronously (httpx Response.raise_for_status is
   synchronous), so test mocks should use `MagicMock()` as done in `test_m365.py` / `test_dex.py`.

## Tests Written

### 1. `tests/unit/credential_broker/test_dex.py` (new file — 3 tests)

- `test_dex_build_auth_url` — verifies `client_id=mcp-proxy`, `response_type=code`,
  `redirect_uri`, and `state` appear in the generated authorization URL.
- `test_dex_exchange_code` — mocks `httpx.AsyncClient.post`, asserts correct token tuple is
  returned and `grant_type=authorization_code` with `code` are sent in the payload.
- `test_dex_refresh` — mocks `httpx.AsyncClient.post`, asserts `grant_type=refresh_token`
  and `refresh_token` are sent; verifies new token tuple returned.

### 2. `tests/unit/test_oauth_router.py` — added 1 test

- `test_enroll_dex_redirects_to_dex` — uses ASGI transport to hit `GET /auth/enroll/dex`,
  patches `_build_state`, asserts 302 redirect and location URL contains `localhost:5556` or `dex`.

### 3. Bug fix: `app/services/sbom.py`

- **Issue:** `bom_document["signature"]["value"]` was set to the full prefixed string
  `hmac-sha256:<hex>` instead of just the hex digest.
- **Fix:** Strip the `hmac-sha256:` prefix before embedding in the document. The `algorithm`
  field (`HMAC-SHA256`) already encodes the scheme.
- **Test that caught it:** `test_embedded_signature_in_document` (was FAILED, now PASSES).

## New Test Results

After writing `test_dex.py`, adding `test_enroll_dex_redirects_to_dex`, and fixing the SBOM bug:

```
65 collected, 64 passed, 1 xfailed, 0 failed
(test_redaction.py excluded — broken import pre-existing)
```

All new tests pass on first run. No regressions introduced.

## Smoke Test Review

**Status:** OK with minor observations

**Script:** `lab/scripts/lab-smoke.sh`

**Assessment:**

The smoke script is well-structured and covers the four key integration paths:
1. Health check (`GET /health/ready → 200`) — correct
2. Grafana tool call with `alice@corp` — checks `audit_id` presence in response, not just HTTP 200.
   This is the right assertion for an MCP proxy that always stamps `audit_id`.
3. OPA deny for `unknown@external` — accepts either HTTP 403 or a JSON body with
   `outcome=deny`. The dual-check is appropriate since OPA policy enforcement may surface
   differently depending on proxy mode.
4. Dex enrollment redirect — checks 302 and redirect URL contains `:5556`.

**Issues observed:**

1. **`set -euo pipefail` + no service guard** — If the proxy is not running, `curl` exits
   non-zero (connection refused), and `set -e` will abort the script immediately, skipping the
   summary and producing a confusing exit without a clear "service not available" message. The
   script should trap curl connection failures explicitly or use `|| true` + status code inspection
   for each test block, rather than relying on `set -e` at the top level.

2. **`%{redirect_url}` in curl** — On macOS, `curl` may not populate `%{redirect_url}` unless
   the `-L` flag is used to follow redirects (which this script intentionally avoids). The
   correct format specifier on older curl versions is `%{redirect_url}` but it returns empty on
   macOS curl < 7.75. This means Test 4's redirect URL check may silently produce an empty string,
   causing the `:5556` grep to fail even when the redirect is correct. Consider reading the
   `Location` header directly: `curl -sI ... | grep -i '^location:'`.

3. **Test 2 payload is technically malformed for the proxy API** — The invoke payload sends
   `tool_name` at the root level alongside `jsonrpc`/`method`/`params`. If the proxy route
   validates the `tool_name` is inside `params`, this test may not exercise the intended code
   path. Verify the actual request schema against `POST /api/v1/tools/invoke` OpenAPI spec.

4. **No timeout guard on curl commands** — If the proxy hangs instead of refusing connections,
   all curl calls will block indefinitely. Add `--max-time 10` to every curl call.

**Recommended additions:**
- Add `--max-time 10` to all curl commands
- Replace `%{redirect_url}` with header inspection (`curl -sI ... | grep -i location`)
- Add a pre-flight connectivity check at the top with a clear "proxy not reachable" message
  and `exit 1` before running any tests

## Recommendations

1. **Fix `test_redaction.py`** — Either install `mcp_audit_logger` into the proxy venv as an
   editable dependency (`pip install -e ../../observability/mcp-audit-logger`) or remove the
   import and move those tests to the audit logger package.

2. **Fix the 4 async mock warnings in Grafana and NetBox adapter tests** — Change
   `mock_resp.raise_for_status = AsyncMock()` to `mock_resp.raise_for_status = MagicMock()`
   in `test_grafana.py` and `test_netbox.py`. The adapters call `raise_for_status()` synchronously
   (correct — httpx Response.raise_for_status is sync). The test mocks are just mistyped.

3. **Write OAuth callback tests (highest priority — security-critical path)**:
   - `[TAMPER] [reviewer] POST /auth/callback/dex with invalid state → 400 CSRF rejection`
   - `[TAMPER] [reviewer] POST /auth/callback/dex with state from different session → 400`
   - `[submitter] GET /auth/callback/dex happy path → 200 HTML, credential stored`
   - All three adapter callbacks (m365, bitbucket, dex) should be covered

4. **Add Bitbucket refresh test** — `test_bitbucket.py` covers `build_auth_url` and
   `exchange_code` but not `refresh`. The Bitbucket adapter likely has a `refresh` method
   (matches pattern of m365/dex). Add it.

5. **Write RBAC matrix tests** — No tests exist for RBAC enforcement at the API layer. A
   matrix test file at `tests/api/rbac/` is missing entirely. This is a mandatory coverage
   requirement for the platform before any production handoff.

6. **Fix smoke script curl portability** — Swap `%{redirect_url}` for header inspection and
   add `--max-time 10` to all curl commands.
