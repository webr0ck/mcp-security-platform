# Runbook: OPA Policy Bundle Signing

## Symptom

- You edited `policies/rego/authz.rego` (or any file under `policies/rego/`)
  and the new rule has **no effect** at runtime — OPA keeps evaluating the
  old logic.
- `mcp-opa` container is crash-looping with a log line like `bundle
  signature verification failed` or `scope mismatch`.
- `make policy-reload` shows "OPA not reachable" or lists policies that don't
  match what's in `policies/rego/` on disk.

## Diagnosis

```bash
# What does OPA think is currently loaded?
curl -sf http://localhost:8181/v1/policies | python3 -m json.tool

# Is bundle.tar.gz even newer than your edited .rego file?
ls -la policies/bundle.tar.gz policies/rego/authz.rego

# OPA container logs — look for "bundle loaded" vs signature/scope errors
podman logs mcp-opa --tail 100

# Confirm POLICY_SIGNING_KEY is set and not a placeholder
grep -c "^POLICY_SIGNING_KEY=" .env 2>/dev/null
```

**Root cause, every time this bites someone**: `policies/bundle.tar.gz` is a
**built artifact**, checked in as the thing OPA actually loads
(`--bundle /policies/bundle.tar.gz`, read-only bind mount in
`docker-compose.yml`). Editing `.rego` source under `policies/rego/` does
**nothing** to the running OPA until you rebuild and re-sign that bundle —
`git` is the source of truth for Rego, `bundle.tar.gz` is the signed
derived artifact.

## Resolution

```bash
# 1. Rebuild + sign the bundle from policies/rego/ (requires the `opa` CLI on PATH,
#    and POLICY_SIGNING_KEY set in .env — sign_policy_bundle.sh refuses empty/placeholder keys)
make sign-policy-bundle
# equivalent to:
#   set -a; . ./.env; set +a; scripts/sign_policy_bundle.sh

# 2. Restart OPA so it picks up the new bundle.tar.gz (it's a read-only bind
#    mount, not hot-reloaded in the signed/production posture)
podman restart mcp-opa
# or, if using compose directly:
docker compose restart opa
```

What `make sign-policy-bundle` actually produces: `scripts/sign_policy_bundle.sh`
runs `opa build -b policies/rego --signing-alg HS256 --signing-key <tmpfile> -o
policies/bundle.tar.gz`, then immediately round-trip-verifies it with
`opa build --bundle ... --verification-key ... -o /dev/null` before declaring
success. It uses OPA 1.17-era flags (no `--signing-key-id`, no `--scope` — both
were removed/never worked with this repo's tooling per the script's own
comments). The bundle's `.manifest` (auto-included by `opa build -b`) declares
`"roots": ["mcp"]`, deliberately leaving `mcp_grants` unowned so the proxy can
still push OPA data via `PUT /v1/data/mcp_grants` without a bundle conflict.

**Note on environments**: `docker-compose.dev.yml` overrides OPA to run in
`--watch` mode against a read-only rego mount with no signature required
(development only, per INV-012). Only the signed-bundle posture
(`docker-compose.yml` base, i.e. staging/production-style) requires
`make sign-policy-bundle` before OPA will start at all — OPA's
`--verification-key`/`--verification-key-id`/`--signing-alg=HS256` flags mean
it refuses to boot on an unsigned or wrong-key bundle.

## Verification

```bash
# Round-trip proof that signing/verification actually works (no running stack needed)
make test-signed-bundle
# PASS: unsigned bundle rejected, wrong-key bundle rejected, correct-key bundle accepted

# Confirm the running OPA loaded the NEW bundle and the specific rule is live
curl -sf http://localhost:8181/v1/policies | python3 -c \
  "import json,sys; print([p['id'] for p in json.load(sys.stdin)['result']])"

curl -sf -X POST http://localhost:8181/v1/data/mcp/<your_new_rule_path> \
  -d '{"input": {...}}' | python3 -m json.tool
```

## Prevention / Related

- Any `authz.rego` change is a no-op in the signed posture until
  `make sign-policy-bundle` + `podman restart mcp-opa` — make this the last
  two steps of every policy-change PR, not an afterthought.
- `docs/runbooks/incident-triage.md` — OPA health is one of the subsystems
  checked first during triage; a crash-looping OPA blocks every tool
  invocation (fail-closed).
- Keep `docs/SECURITY_NONNEGATABLES.md` (INV-012) in sync if the signing
  scheme itself ever changes (e.g. moving off HS256).
