# Apply / deploy / verify pipeline — admin operations

**Audience:** `admin` operators supporting submitters who use the platform-managed build path
(`/apply`) instead of self-hosting.

## The pipeline at a glance

```
build_requested → building → built → deploy_requested → deploying → deployed
                                                                          │
                                                                          ▼
                                              verify_requested → verifying → verified
```

Any stage fails closed to `failed` — no automatic retry-forward. A submitter (or you, on their
behalf) re-triggers with a fresh `POST /api/v1/submissions/{id}/apply` call, which re-pins the
build to the submission's already-scanned+approved commit digest
(`server_registry.scan_commit`) — the platform refuses to build past a stale/unscanned commit,
never a warning-only TOCTOU gap.

- **Build** (`build_worker/build_engine.py`) clones the approved commit, builds a container image
  with rootless buildah/kaniko (unprivileged — no daemon socket access).
- **Deploy** (`services/deploy_launcher.py`) runs the built image in an isolated lab launcher.
- **Verify** (`services/deploy_verifier.py::run_verification_probes`) is the **exact same**
  verification code path the self-hosted `provide-url` flow uses — healthcheck, tool discovery
  (into quarantine — see [reviewer-approval-guide.md](reviewer-approval-guide.md)), then an
  invocation probe. This is deliberate: there is exactly one verification implementation, not two
  that could silently diverge.

## Checking progress

```bash
curl -sf http://localhost:8000/api/v1/submissions/$SID/verification-report -H "Authorization: Bearer $TOKEN"
```

- `404` before the verify phase has ever run (still building/deploying, or nothing applied yet).
- Once present, `verification_report` includes `healthcheck` (bool), `tools_discovered` (int),
  `tools_skipped` (list, with reasons), `invocation_probe_ok` (bool), `contract_version`.

## When a stage fails

`deployment_status = 'failed'` — check `verification_report`/scan-worker logs (see WP-D1's
runbooks for infra-level triage: build worker dead-letter, deploy launcher errors). Common,
non-bug reasons a build/deploy fails:

- The scanned commit no longer exists on the remote (force-pushed/rebased since scan) — the
  submitter needs to re-scan.
- The repo doesn't produce a runnable container per the platform's build contract (see
  `docs/reference/mcp-server-compatibility-contract.md`) — this is a submitter-side fix, not a
  platform bug.
- Deploy launcher resource limits — an admin/infra concern, see WP-D1 runbooks.

## Same-IdP verification (kc_token_exchange servers)

If the submission's auth mode is `kc_token_exchange` ("Same platform IdP" —
see [../user/auth-mode-decision-guide.md](../user/auth-mode-decision-guide.md)),
`services/same_idp_verify.py::run_same_idp_verify_probe` is available as a standalone check that
confirms the deployed server actually rejects a missing token, a wrong-audience token, and an
expired token — i.e. that the submitter's own JWT-validation code is real, not just present. This
is not yet wired into the automatic verify phase above (a documented follow-up — see
`docs/spec/01-authentication.md` §4.7) — run it manually against a deployed same-IdP server if you
want that extra assurance before releasing its tools.

## Releasing tools after verification

`verified`/`active` does **not** make tools invocable — see
[reviewer-approval-guide.md](reviewer-approval-guide.md#after-approval--releasing-tools).
