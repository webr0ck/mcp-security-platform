"""AT3 — self-service onboarding lifecycle, driven entirely through the real
submissions API (POST /api/v1/submissions -> submit -> scan -> admin review
-> provide-url -> discover-tools -> activate -> entitle -> invoke).

Prerequisite: lab/tests/acceptance/fixtures/setup_gitea_fixtures.sh must have
run (the runner script does this automatically). It stands up a small nginx
TLS sidecar (lab-gitea-tls) in front of the lab's plain-HTTP Gitea so the
submission scanner's git_providers host-matching regex (which requires a
literal "https://<host>/" with no port suffix) has something real to clone
from, pushes the malicious-mcp/clean-mcp fixtures into it, and registers the
git_providers row. See that script's header comment for the full rationale,
including the "gitea itself refuses to bind :443" dead end that was tried and
reverted.

Two more real, working platform mechanisms this file leans on directly rather
than working around:
  * mcp_checker's own block_checks in proxy/scan-config.yaml (live-mounted at
    /app/scan-config.yaml via docker-compose.dev.yml's `./proxy:/app` bind —
    the repo-root scan-config.yaml is a DECOY, not read by the running
    container) already blocks on malicious_doc_ast/crypto_stealer/etc; this
    suite adds one more deterministic custom_rules entry
    (acceptance_test_planted_marker) so the malicious-mcp fixture trips the
    gate on a fixed, harmless string rather than needing a live-verified
    secret (trufflehog's block_on=verified requires an ACTUAL live credential)
    or a real CVE'd dependency (pip-audit's severity heuristic in
    submission_scanner.py never actually reaches "critical" — see REPORT.md).
  * The B-coarse taint floor (see conftest.py docstring): a freshly onboarded
    server defaults to trust_tier=0, which taints the invoking principal and
    then denies the very next tool call. The clean-mcp full-chain test sets
    trust_tier=2 after approval (mirroring how the lab's own pre-seeded
    servers — lab-echo, lab-grafana-mcp, etc. — are seeded) and clears any
    stale taint before invoking, so the "server actually works end-to-end"
    assertion isn't masked by an unrelated, already-passing security control.
"""
from __future__ import annotations

import json
import time
import uuid

import httpx
import pytest

from conftest import (
    BASE_URL,
    _auth_headers,
    db_query,
    mcp_session_headers,
    podman_exec,
)

MALICIOUS_URL = "https://lab-gitea-tls/gitadmin/malicious-mcp.git"
CLEAN_URL = "https://lab-gitea-tls/gitadmin/clean-mcp.git"

_CLEAN_FIXTURE_CONTAINER = "at3-clean-mcp-fixture"
_CLEAN_FIXTURE_UPSTREAM = f"http://{_CLEAN_FIXTURE_CONTAINER}:8000/mcp"


@pytest.fixture(scope="module")
def clean_mcp_upstream():
    """Actually RUN the clean-mcp fixture (reusing the already-built
    mcphub-sdk:base image every other lab-mcp-* server uses, so no new
    Dockerfile/build is needed) as its own container on lab-net, so
    provide-url/discover-tools has a genuinely fresh upstream to register —
    every already-running lab MCP server's tools are already claimed in
    tool_registry (name+version is globally unique), so pointing this test at
    e.g. the pre-existing lab-mcp-echo just collides with its own registration."""
    import subprocess
    server_py = str((__import__("pathlib").Path(__file__).resolve().parent
                     / "fixtures" / "clean-mcp" / "server.py"))
    # Idempotency: tool_registry_name_version_unique is a PLAIN UNIQUE(name,
    # version) constraint with no `WHERE deleted_at IS NULL` (unlike e.g.
    # entitlement's partial indexes) — see REPORT.md. A soft-deleted 'echo'
    # row therefore still permanently occupies the name, so reruns of this
    # test need to free it. A hard DELETE doesn't work either: audit_events.tool_id
    # has ON DELETE SET NULL, but audit_events is trigger-guarded append-only
    # (fn_audit_events_immutability_guard rejects the UPDATE the cascade tries
    # to run) — also a real finding, see REPORT.md. Renaming the stale row out
    # of the way (no DELETE, so no cascade) is what's left.
    db_query("UPDATE tool_registry SET name = 'echo-superseded-' || tool_id::text "
             "WHERE name='echo' AND deleted_at IS NULL")
    subprocess.run(["podman", "rm", "-f", _CLEAN_FIXTURE_CONTAINER], capture_output=True)
    subprocess.run([
        "podman", "run", "-d", "--name", _CLEAN_FIXTURE_CONTAINER,
        "--network", "mcp-security-platform_lab-net",
        "-e", "HOST=0.0.0.0", "-e", "PORT=8000",
        "-v", f"{server_py}:/app/server.py:ro",
        "localhost/mcphub-sdk:base", "python", "server.py",
    ], check=True, capture_output=True, text=True)
    for _ in range(15):
        r = podman_exec("mcp-proxy", ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                        f"http://{_CLEAN_FIXTURE_CONTAINER}:8000/health"])
        if r.stdout.strip() == "200":
            break
        time.sleep(2)
    yield _CLEAN_FIXTURE_UPSTREAM
    subprocess.run(["podman", "rm", "-f", _CLEAN_FIXTURE_CONTAINER], capture_output=True)


def _create_draft(token: str, name: str, repo_url: str) -> str:
    r = httpx.post(f"{BASE_URL}/api/v1/submissions", headers=_auth_headers(token),
                   json={"name": name, "github_repo_url": repo_url,
                         "description": f"{name} acceptance test fixture"},
                   verify=False, timeout=60)
    assert r.status_code == 201, f"draft create failed: {r.status_code} {r.text}"
    return r.json()["server_id"]


def _submit(token: str, server_id: str, requested_upstream_url: str = "http://at3-placeholder:8000/mcp") -> None:
    # description + requested_upstream_url are required before submit (V075) —
    # description is set at draft-create time above, requested_upstream_url
    # needs its own PATCH since POST /api/v1/submissions doesn't accept it.
    patch = httpx.patch(f"{BASE_URL}/api/v1/submissions/{server_id}",
                         headers=_auth_headers(token),
                         json={"requested_upstream_url": requested_upstream_url},
                         verify=False, timeout=60)
    assert patch.status_code == 200, f"patch requested_upstream_url failed: {patch.status_code} {patch.text}"
    r = httpx.post(f"{BASE_URL}/api/v1/submissions/{server_id}/submit",
                   headers=_auth_headers(token), json={}, verify=False, timeout=60)
    assert r.status_code == 200, f"submit failed: {r.status_code} {r.text}"


def _poll_scan(server_id: str, timeout_s: int = 240) -> tuple[str, str]:
    """Returns (scan_status, submission_status) once scanning has left pending/running."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        scan_status = db_query(f"SELECT scan_status FROM server_registry WHERE server_id='{server_id}'")
        if scan_status not in ("pending", "running", ""):
            break
        time.sleep(3)
    submission_status = db_query(f"SELECT submission_status FROM server_registry WHERE server_id='{server_id}'")
    return scan_status, submission_status


def _clear_taint(client_id: str) -> None:
    """Reset the B-coarse taint floor (proxy/app/services/taint_store.py) for
    one principal. See module docstring — a freshly onboarded (trust_tier=0)
    server taints whoever invokes it, denying their next high-integrity call
    for up to an hour; isolate this test from that residue."""
    import hashlib
    from pathlib import Path
    key = "mcp_taint:" + hashlib.sha256(client_id.encode()).hexdigest()[:16]
    env_lab = Path(__file__).resolve().parents[3] / ".env.lab"
    pw = ""
    for line in env_lab.read_text().splitlines():
        if line.startswith("REDIS_PASSWORD="):
            pw = line.split("=", 1)[1]
    podman_exec("mcp-redis", ["redis-cli", "-a", pw, "DEL", key])


# ═════════════════════════════════════════════════════════════════════════════
# malicious-mcp: submit -> scan BLOCKED -> reviewer approve refused
# ═════════════════════════════════════════════════════════════════════════════

def test_malicious_submission_blocked_and_unapprovable(alice_token, carol_token):
    name = f"at3-malicious-{uuid.uuid4().hex[:8]}"
    server_id = _create_draft(alice_token, name, MALICIOUS_URL)
    _submit(alice_token, server_id)

    scan_status, submission_status = _poll_scan(server_id)
    assert scan_status == "blocked", f"expected scan_status=blocked, got {scan_status!r}"
    assert submission_status == "scan_blocked", f"expected submission_status=scan_blocked, got {submission_status!r}"

    report = db_query(f"SELECT scan_report::text FROM server_registry WHERE server_id='{server_id}'")
    assert "acceptance_test_planted_marker" in report, f"planted marker finding missing from scan_report: {report[:500]}"

    # Reviewer (carol) attempts to approve a scan-blocked submission -> refused.
    r = httpx.post(f"{BASE_URL}/api/v1/admin/submissions/{server_id}/approve",
                   headers=_auth_headers(carol_token), json={}, verify=False, timeout=60)
    assert r.status_code in (400, 409), f"expected 400/409 refusing approval of a blocked scan, got {r.status_code}: {r.text}"

    # No tool from this submission can ever become invocable — it has no
    # server_id-linked tool_registry rows at all (discovery never ran).
    tool_count = db_query(f"SELECT count(*) FROM tool_registry WHERE server_id='{server_id}'")
    assert tool_count == "0", f"a blocked submission must have zero discovered tools, found {tool_count}"


# ═════════════════════════════════════════════════════════════════════════════
# clean-mcp: submit -> scan PASSED -> approve -> provide-url -> discover ->
#            activate -> entitle -> invoke (real echo response)
# ═════════════════════════════════════════════════════════════════════════════

def test_clean_submission_full_chain_to_invoke(alice_token, carol_token, clean_mcp_upstream):
    name = f"at3-clean-{uuid.uuid4().hex[:8]}"
    server_id = _create_draft(alice_token, name, CLEAN_URL)
    _submit(alice_token, server_id, requested_upstream_url=clean_mcp_upstream)

    scan_status, submission_status = _poll_scan(server_id)
    assert scan_status == "passed", f"expected scan_status=passed, got {scan_status!r}"
    assert submission_status == "awaiting_review", f"expected submission_status=awaiting_review, got {submission_status!r}"

    # Reviewer approves (carol != alice -> segregation of duties satisfied).
    r = httpx.post(f"{BASE_URL}/api/v1/admin/submissions/{server_id}/approve",
                   headers=_auth_headers(carol_token), json={"notes": "AT3 approve"}, verify=False, timeout=60)
    assert r.status_code == 200, f"approve failed: {r.status_code} {r.text}"
    assert r.json()["submission_status"] == "approved_pending_url"

    # Alice (owner) supplies the running upstream — her own freshly-started
    # clean_mcp_upstream fixture container (running the exact server.py that
    # was just scanned), not a pre-existing lab server whose tool names
    # (name+version is globally unique in tool_registry) would just collide.
    r = httpx.post(f"{BASE_URL}/api/v1/submissions/{server_id}/provide-url",
                   headers=_auth_headers(alice_token),
                   json={"upstream_url": clean_mcp_upstream},
                   verify=False, timeout=30)
    assert r.status_code == 200, f"provide-url failed: {r.status_code} {r.text}"
    provide_body = r.json()
    # R-10: provide-url auto-runs tool discovery synchronously (see
    # submission.py's provide_running_url) — a second explicit
    # POST .../discover-tools would just see "already registered" (0 new).
    assert provide_body["tools_provisioned"] >= 1, f"expected >=1 auto-discovered tool: {provide_body}"

    tool_id, tool_name, tool_status = db_query(
        f"SELECT tool_id || ',' || name || ',' || status FROM tool_registry "
        f"WHERE server_id='{server_id}' AND deleted_at IS NULL LIMIT 1"
    ).split(",")
    assert tool_status == "quarantined", f"INV-005: discovered tool must start quarantined, got {tool_status!r}"
    assert tool_name == "echo", f"expected the clean-mcp fixture's 'echo' tool, got {tool_name!r}"
    tool = {"tool_id": tool_id, "name": tool_name}

    # Activation is on /api/v1/tools/{id}, which is mTLS-only at the gateway
    # (PRD-0006 R-2, nginx `location /api/v1/tools/`) — call it via the
    # proxy's own loopback instead (SEC-05's ingress guard always allows
    # loopback, and nginx's mTLS rule never applies since it's bypassed
    # entirely), exactly as conftest.py's proxy_exec_json helper does for
    # GETs; PATCH needs its own inline curl since that helper is GET-shaped.
    import subprocess
    r2 = subprocess.run(
        ["podman", "exec", "mcp-proxy", "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
         "-X", "PATCH", f"http://localhost:8000/api/v1/tools/{tool['tool_id']}",
         "-H", f"Authorization: Bearer {alice_token}", "-H", "Content-Type: application/json",
         "-d", json.dumps({"status": "active"})],
        capture_output=True, text=True, timeout=60,
    )
    assert r2.stdout.strip() == "200", f"tool activation failed: {r2.stdout} {r2.stderr}"

    # Realistic reviewer step: assign an operational trust tier (mirrors how
    # every pre-seeded lab server — lab-echo, lab-grafana-mcp, etc. — is
    # seeded at tier 2; a freshly onboarded server defaults to 0/untrusted,
    # which is correct-by-default but not yet what an approved, hand-reviewed
    # server should carry going forward).
    db_query(f"UPDATE server_registry SET trust_tier=2 WHERE server_id='{server_id}'")

    client_id = "alice@corp"
    _clear_taint(client_id)  # isolate this test from whatever earlier AT1/AT2 calls tainted

    r = httpx.post(f"{BASE_URL}/api/v1/servers/{server_id}/entitlements",
                   headers=_auth_headers(alice_token),
                   json={"principal_id": f"human:keycloak:{client_id}", "principal_type": "human"},
                   verify=False, timeout=60)
    assert r.status_code in (200, 201), f"entitlement grant failed: {r.status_code} {r.text}"

    headers = mcp_session_headers(alice_token)
    invoke = httpx.post(f"{BASE_URL}/mcp", headers=headers, verify=False, timeout=30,
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/call",
              "params": {"name": "invoke_tool",
                         "arguments": {"tool_name": tool["name"], "method": "tools/call",
                                      "arguments": {"name": tool["name"], "arguments": {}}}}})
    assert invoke.status_code == 200, f"invoke failed: {invoke.status_code} {invoke.text}"
    body = invoke.json()
    assert "error" not in body, f"JSON-RPC error on invoke: {body}"
    blob = json.dumps(body).lower()
    for bad in ("not entitled", "access denied", "quarantin", "unknown tool"):
        assert bad not in blob, f"gate-chain failure leaked through: {blob[:400]}"
    assert "clean-mcp" in blob, f"expected the real clean-mcp upstream response, got: {blob[:400]}"
