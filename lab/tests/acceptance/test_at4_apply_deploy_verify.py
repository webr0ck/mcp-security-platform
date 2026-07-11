"""AT4 — CR-01/CR-06/CR-07 (WP-B3) apply/deploy/verify loop, end to end
through the REAL submissions API and the REAL background evaluator/launcher/
verifier code running inside mcp-proxy.

This exercises the full state machine draft -> submit -> scan passed ->
approve -> apply -> build_requested -> (simulated build-worker result) ->
built -> deploy attempt -> verify probes -- and is deliberately HONEST about
the one thing this dev sandbox cannot do for real: there is no buildah
binary and no container registry here (see build_worker/build_engine.py's
_run_buildah_build STUB and deploy_launcher.py's module docstring), so a
platform-managed deploy of a stub-digest "image" cannot actually launch a
real container. Rather than fake that success, this test:

  1. Drives apply -> build_requested -> built through the REAL API +
     REAL build_evaluator background loop (already running inside
     mcp-proxy's lifespan) -- only the build-WORKER's output is simulated
     (a single INSERT into build_results, standing in for the container
     that would normally write it), matching exactly the row shape
     build_engine.run_build produces (see infra/db/migrations/
     V072__build_worker_queue.sql).
  2. Calls the REAL deploy_launcher.deploy_server() directly (there is no
     automatic trigger/orchestrator loop for deploy/verify yet -- see
     Codex_review/Claude_status.md CR-01 row -- so this test IS the
     trigger, exactly like a future orchestrator would be) and asserts it
     fails CLOSED (deployment_status stays 'failed', never 'deployed')
     because no real image exists to run -- proving the fail-closed gate
     works, not faking a pass.
  3. Proves the shared verify code path
     (deploy_verifier.run_verification_probes) -- the same function a
     REAL deploy success would hand off to -- genuinely works end-to-end
     (healthcheck, quarantined discovery, invocation probe, CR-06
     contract check) by calling it directly against a real running
     upstream (the clean-mcp fixture container), then carries that
     result all the way through the existing evidence-gated release
     endpoint (CR-07) to a real invocable tool call.

Every code path this test exercises is real, unit-tested-in-isolation
production code (build_evaluator, deploy_launcher, deploy_verifier,
contract_check) driven live against the actual lab DB/containers -- only
the buildah/podman-run STUB's *output* is simulated, and that simulation is
called out explicitly at every step, per this program's honesty convention.
"""
from __future__ import annotations

import json
import subprocess
import time
import uuid

import httpx
import pytest

from conftest import BASE_URL, _auth_headers, db_query, mcp_session_headers, podman_exec

CLEAN_URL = "https://lab-gitea-tls/gitadmin/clean-mcp.git"
_FIXTURE_CONTAINER = "at4-clean-mcp-fixture"
_FIXTURE_UPSTREAM = f"http://{_FIXTURE_CONTAINER}:8000/mcp"


@pytest.fixture(scope="module")
def clean_mcp_upstream_b3():
    """Same clean-mcp fixture server test_at3_onboarding.py uses, run under a
    DISTINCT container name so this module's tool registrations (name='echo')
    don't collide with AT3's own fixture/teardown."""
    server_py = str((__import__("pathlib").Path(__file__).resolve().parent
                     / "fixtures" / "clean-mcp" / "server.py"))
    db_query("UPDATE tool_registry SET name = 'echo-superseded-' || tool_id::text "
             "WHERE name='echo' AND deleted_at IS NULL")
    subprocess.run(["podman", "rm", "-f", _FIXTURE_CONTAINER], capture_output=True)
    subprocess.run([
        "podman", "run", "-d", "--name", _FIXTURE_CONTAINER,
        "--network", "mcp-security-platform_lab-net",
        "-e", "HOST=0.0.0.0", "-e", "PORT=8000",
        "-v", f"{server_py}:/app/server.py:ro",
        "localhost/mcphub-sdk:base", "python", "server.py",
    ], check=True, capture_output=True, text=True)
    for _ in range(15):
        r = podman_exec("mcp-proxy", ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                        f"http://{_FIXTURE_CONTAINER}:8000/health"])
        if r.stdout.strip() == "200":
            break
        time.sleep(2)
    yield _FIXTURE_UPSTREAM
    subprocess.run(["podman", "rm", "-f", _FIXTURE_CONTAINER], capture_output=True)


def _create_draft(token: str, name: str, repo_url: str) -> str:
    r = httpx.post(f"{BASE_URL}/api/v1/submissions", headers=_auth_headers(token),
                   json={"name": name, "github_repo_url": repo_url,
                         "description": f"{name} acceptance test fixture"},
                   verify=False, timeout=60)
    assert r.status_code == 201, f"draft create failed: {r.status_code} {r.text}"
    return r.json()["server_id"]


def _submit(token: str, server_id: str, requested_upstream_url: str = "http://at4-placeholder:8000/mcp") -> None:
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


def _poll(sql: str, predicate, timeout_s: int = 180, interval_s: int = 3) -> str:
    deadline = time.monotonic() + timeout_s
    val = ""
    while time.monotonic() < deadline:
        val = db_query(sql)
        if predicate(val):
            return val
        time.sleep(interval_s)
    return val


def _clear_taint(client_id: str) -> None:
    """Reset the B-coarse taint floor (proxy/app/services/taint_store.py) for
    one principal. Copied from test_at3_onboarding.py's identical helper — a
    freshly onboarded (trust_tier=0) server taints whoever invokes it,
    denying their next high-integrity call for up to an hour. Found live:
    omitting this call let alice@corp's taint from this test leak into
    unrelated `make test-lab-functional` runs afterward ("access denied:
    session restricted by trust policy" on otherwise-unrelated tools)."""
    import hashlib
    from pathlib import Path
    key = "mcp_taint:" + hashlib.sha256(client_id.encode()).hexdigest()[:16]
    env_lab = Path(__file__).resolve().parents[3] / ".env.lab"
    pw = ""
    for line in env_lab.read_text().splitlines():
        if line.startswith("REDIS_PASSWORD="):
            pw = line.split("=", 1)[1]
    podman_exec("mcp-redis", ["redis-cli", "-a", pw, "DEL", key])


def _proxy_exec_python(code: str, timeout: int = 60) -> subprocess.CompletedProcess:
    """Run a Python snippet inside the REAL mcp-proxy container, against the
    REAL app package (/app/app) and REAL DB connection -- used to invoke
    deploy_launcher/deploy_verifier directly since no HTTP trigger endpoint
    exists for deploy/verify yet (see this file's module docstring)."""
    return subprocess.run(
        ["podman", "exec", "mcp-proxy", "python3", "-c", code],
        capture_output=True, text=True, timeout=timeout,
    )


def test_apply_deploy_verify_full_loop(alice_token, carol_token, clean_mcp_upstream_b3):
    name = f"at4-clean-{uuid.uuid4().hex[:8]}"
    server_id = _create_draft(alice_token, name, CLEAN_URL)
    _submit(alice_token, server_id, requested_upstream_url=clean_mcp_upstream_b3)

    scan_status = _poll(
        f"SELECT scan_status FROM server_registry WHERE server_id='{server_id}'",
        lambda v: v not in ("pending", "running", ""),
        timeout_s=240,
    )
    assert scan_status == "passed", f"expected scan_status=passed, got {scan_status!r}"

    r = httpx.post(f"{BASE_URL}/api/v1/admin/submissions/{server_id}/approve",
                   headers=_auth_headers(carol_token), json={"notes": "AT4 approve"},
                   verify=False, timeout=60)
    assert r.status_code == 200, f"approve failed: {r.status_code} {r.text}"
    assert r.json()["submission_status"] == "approved_pending_url"

    # ── /apply: the platform-managed pipeline entry point (CR-01, Task 6) ──
    r = httpx.post(f"{BASE_URL}/api/v1/submissions/{server_id}/apply",
                   headers=_auth_headers(alice_token), json={}, verify=False, timeout=60)
    assert r.status_code == 200, f"apply failed: {r.status_code} {r.text}"
    apply_body = r.json()
    assert apply_body["deployment_status"] == "build_requested"
    job_id = apply_body["job_id"]

    expected_digest, job_type = db_query(
        f"SELECT expected_digest || ',' || job_type FROM scan_jobs WHERE job_id='{job_id}'"
    ).split(",")
    assert job_type == "build_requested"
    assert expected_digest, "expected_digest (the TOCTOU pin) must be set on the enqueued job"

    scan_commit = db_query(f"SELECT scan_commit FROM server_registry WHERE server_id='{server_id}'")
    assert expected_digest == scan_commit, "apply must pin expected_digest to the approved scan_commit"

    # ── Simulate the build-worker's output (no buildah binary in this
    # sandbox -- see build_engine.py's _run_buildah_build STUB). This is the
    # ONE simulated step in this test; everything downstream of it
    # (build_evaluator, deploy_launcher, deploy_verifier, contract_check) is
    # real code exercised for real. The row shape matches exactly what
    # build_engine.run_build's happy path produces (see
    # build_worker/tests/test_build_engine.py).
    fake_digest = f"sha256:stub-{expected_digest[:12]}"
    fake_image_ref = f"mcp-server-{server_id[:12]}:{expected_digest[:12]}"
    provenance = json.dumps({"commit": expected_digest, "builder": "AT4-simulated-build-worker",
                             "built_at_job_id": job_id, "image_ref": fake_image_ref})
    db_query(
        f"INSERT INTO build_results (job_id, server_id, job_type, build_artifact_digest, "
        f"image_ref, provenance) VALUES ('{job_id}', '{server_id}', 'build_requested', "
        f"'{fake_digest}', '{fake_image_ref}', '{provenance}'::jsonb)"
    )
    db_query(f"UPDATE scan_jobs SET status='completed' WHERE job_id='{job_id}'")

    # ── build_evaluator: REAL background loop already running inside
    # mcp-proxy's lifespan (main.py) -- poll for it to pick up the row we
    # just wrote and flip deployment_status to 'built'.
    deployment_status = _poll(
        f"SELECT deployment_status FROM server_registry WHERE server_id='{server_id}'",
        lambda v: v not in ("build_requested",),
        timeout_s=30,
    )
    assert deployment_status == "built", (
        f"build_evaluator did not mark deployment_status='built' from a digest-bearing "
        f"build_results row (got {deployment_status!r}) -- either the evaluator isn't running "
        f"(check mcp-proxy was restarted after this session's code changes) or its policy "
        f"changed"
    )
    build_provenance = db_query(f"SELECT build_provenance::text FROM server_registry WHERE server_id='{server_id}'")
    assert fake_image_ref in build_provenance, "build_evaluator must fold image_ref into build_provenance"

    # ── deploy_launcher: REAL code, called directly (no orchestrator loop
    # exists yet to trigger it automatically -- this call IS that trigger).
    # No real OCI image was ever pushed (the buildah step above was
    # simulated, not real), so `podman run` against fake_image_ref MUST
    # fail -- proving the fail-closed gate for real, not faking a deploy.
    deploy_code = (
        "import asyncio\n"
        "from app.services import deploy_launcher\n"
        f"print(asyncio.run(deploy_launcher.deploy_server('{server_id}')))\n"
    )
    deploy_result = _proxy_exec_python(deploy_code, timeout=90)
    assert deploy_result.returncode == 0, f"deploy_launcher crashed: {deploy_result.stderr}"
    assert "'deployment_status': 'failed'" in deploy_result.stdout, (
        f"expected deploy_server to fail closed against a non-existent image, got: "
        f"{deploy_result.stdout} {deploy_result.stderr}"
    )
    post_deploy_status = db_query(f"SELECT deployment_status FROM server_registry WHERE server_id='{server_id}'")
    assert post_deploy_status == "failed", (
        f"deployment_status must be 'failed' after a podman-run failure, never 'deployed' "
        f"(got {post_deploy_status!r}) -- fail-closed violation"
    )

    # ── deploy_verifier's SHARED verify path: prove it genuinely works,
    # end to end, against a real running upstream (this test's clean-mcp
    # fixture) -- this is the SAME function a real deploy success would
    # hand off to (run_verification_probes), just invoked directly here
    # since deploy_server correctly refused to promote a non-existent
    # container to runtime_url above.
    #
    # This test calls run_verification_probes DIRECTLY (bypassing
    # verify_server, which structurally cannot run here since
    # deployment_status is 'failed', not 'deployed'). verify_server()
    # itself sets status='approved' AND upstream_url=runtime_url BEFORE
    # calling run_verification_probes (found live in this session:
    # _run_tool_discovery, reused inside the probes, requires
    # status='approved' as a precondition AND reads upstream_url directly
    # from server_registry, not from a parameter) -- replicate both here
    # since we're bypassing verify_server.
    # upstream_allowlist_entry is the CIDR revalidate_upstream_ip_at_invoke
    # checks the fixture container's resolved IP against (see
    # app.services.ssrf/server_onboarding docstrings) -- provide-url computes
    # this via validate_upstream_url_ssrf; replicate it here by reading the
    # same UPSTREAM_PRIVATE_CIDR_ALLOWLIST env var the running proxy uses.
    _cidr = ""
    for _line in (__import__("pathlib").Path(__file__).resolve().parents[3] / ".env.lab").read_text().splitlines():
        if _line.startswith("UPSTREAM_PRIVATE_CIDR_ALLOWLIST="):
            _cidr = _line.split("=", 1)[1]
    assert _cidr, "UPSTREAM_PRIVATE_CIDR_ALLOWLIST not found in .env.lab"
    db_query(f"UPDATE server_registry SET status='approved', "
             f"upstream_url='{clean_mcp_upstream_b3}', upstream_allowlist_entry='{_cidr}' "
             f"WHERE server_id='{server_id}'")

    verify_code = (
        "import asyncio, json\n"
        "from app.services import deploy_verifier\n"
        f"r = asyncio.run(deploy_verifier.run_verification_probes("
        f"'{server_id}', '{clean_mcp_upstream_b3}', actor_client_id='at4-test'))\n"
        "print(json.dumps(r))\n"
    )
    verify_result = _proxy_exec_python(verify_code, timeout=60)
    assert verify_result.returncode == 0, f"run_verification_probes crashed: {verify_result.stderr}"
    report = json.loads(verify_result.stdout.strip().splitlines()[-1])
    assert report["healthcheck"] is True, report
    assert report["invocation_probe_ok"] is True, report
    assert report["tools_discovered"] >= 1, report
    assert report["contract_check"]["initialize_ok"] is True, report
    assert report["contract_check"]["tools_list_ok"] is True, report
    assert report["contract_check"]["health_ok"] is True, report
    assert report["contract_check"]["violations"] == [], report

    # ── Tool registered quarantined (INV-005, unchanged) by the discovery
    # this verify pass just ran -- carry it through the REAL evidence-gated
    # release endpoint (CR-07) to a REAL invocable call, same as AT3's tail.
    tool_id, tool_name, tool_status = db_query(
        f"SELECT tool_id || ',' || name || ',' || status FROM tool_registry "
        f"WHERE server_id='{server_id}' AND deleted_at IS NULL LIMIT 1"
    ).split(",")
    assert tool_status == "quarantined", f"INV-005: discovered tool must start quarantined, got {tool_status!r}"
    assert tool_name == "echo"

    # release_tool's evidence gate requires server_registry.status='approved'
    # (already set above) and scan_status IN ('passed','not_applicable')
    # (already 'passed' from the scan step).
    #
    # /api/v1/tools/{id}/... is mTLS-only at the gateway (PRD-0006 R-2,
    # nginx `location /api/v1/tools/`) -- call it via the proxy's own
    # loopback instead, exactly like AT3's tool-activation step does (SEC-05's
    # ingress guard always allows loopback, and nginx's mTLS rule never
    # applies since it's bypassed entirely).
    release_r = subprocess.run(
        ["podman", "exec", "mcp-proxy", "curl", "-s", "-o", "/tmp/_at4_release_resp",
         "-w", "%{http_code}",
         "-X", "POST", f"http://localhost:8000/api/v1/tools/{tool_id}/release",
         "-H", f"Authorization: Bearer {carol_token}", "-H", "Content-Type: application/json",
         "-d", json.dumps({"notes": "AT4 release"})],
        capture_output=True, text=True, timeout=60,
    )
    release_body = podman_exec("mcp-proxy", ["cat", "/tmp/_at4_release_resp"]).stdout
    assert release_r.stdout.strip() == "200", f"release failed: {release_r.stdout} {release_body} {release_r.stderr}"

    # Same operational trust-tier step AT3 takes for every freshly onboarded
    # server (mirrors lab-echo/lab-grafana-mcp's seeded tier 2) -- a fresh
    # server defaults to trust_tier=0, which taints the invoking principal
    # and denies their NEXT high-integrity call for up to an hour (B-coarse
    # taint floor). Clearing taint AFTERWARD (not just before) is essential
    # here too -- found live: omitting this leaked alice@corp's taint into
    # unrelated `make test-lab-functional` runs afterward.
    db_query(f"UPDATE server_registry SET trust_tier=2 WHERE server_id='{server_id}'")

    client_id = "alice@corp"
    _clear_taint(client_id)
    r = httpx.post(f"{BASE_URL}/api/v1/servers/{server_id}/entitlements",
                   headers=_auth_headers(alice_token),
                   json={"principal_id": f"human:keycloak:{client_id}", "principal_type": "human"},
                   verify=False, timeout=60)
    assert r.status_code in (200, 201), f"entitlement grant failed: {r.status_code} {r.text}"

    headers = mcp_session_headers(alice_token)
    invoke = httpx.post(f"{BASE_URL}/mcp", headers=headers, verify=False, timeout=30,
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/call",
              "params": {"name": "invoke_tool",
                         "arguments": {"tool_name": tool_name, "method": "tools/call",
                                      "arguments": {"name": tool_name, "arguments": {}}}}})
    assert invoke.status_code == 200, f"invoke failed: {invoke.status_code} {invoke.text}"
    body = invoke.json()
    assert "error" not in body, f"JSON-RPC error on invoke: {body}"
    blob = json.dumps(body).lower()
    for bad in ("not entitled", "access denied", "quarantin", "unknown tool"):
        assert bad not in blob, f"gate-chain failure leaked through: {blob[:400]}"
    assert "clean-mcp" in blob, f"expected the real clean-mcp upstream response, got: {blob[:400]}"
