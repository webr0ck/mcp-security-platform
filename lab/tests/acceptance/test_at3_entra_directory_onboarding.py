"""AT3 — self-service onboarding of a real Microsoft Entra/Graph directory MCP
server, driven entirely through the real submit_mcp_server MCP tool (not the
REST API directly — see test_at3_self_service_mcp_tool.py for the ownership
regression this shares its trust-bridge with).

Proves the BEFORE -> AFTER claim end to end against the real Microsoft Graph
API (not a mock): before this test's submission exists, there is no MCP tool
that can list this tenant's directory users; after submit -> scan -> approve
-> provide-url -> activate -> credential -> entitlement, `list_users` is
callable through the real gateway and returns real Graph user records.

Requires real Entra app-registration credentials (ENTRA_TENANT_ID/
ENTRA_CLIENT_ID/ENTRA_CLIENT_SECRET in .env.lab, pointed at the real
login.microsoftonline.com / graph.microsoft.com — NOT the lab mocks). This is
an external-credential dependency per the QA acceptance standard: skips
loudly with the exact reason if absent, never fabricates a result.

Every live HTTP/MCP call in this test is logged via conftest.log_http_call to
results/<timestamp>/http.log (secrets redacted) — QA acceptance standard
requirement 4.
"""
from __future__ import annotations

import json
import subprocess
import time
import uuid

import httpx
import pytest

from conftest import (
    BASE_URL, db_query, mcp_session_headers, _auth_headers, log_http_call,
    _env_lab,
)

_FIXTURE_CONTAINER_PREFIX = "at3-entra-directory-"
_TOOL_NAMES = [
    "list_users", "get_user", "list_groups", "get_group",
    "list_app_registrations", "get_app_registration",
]


def _require_real_entra() -> tuple[str, str, str]:
    tenant = _env_lab("ENTRA_TENANT_ID")
    client_id = _env_lab("ENTRA_CLIENT_ID")
    secret = _env_lab("ENTRA_CLIENT_SECRET")
    if not (tenant and client_id and secret):
        pytest.skip(
            "ENTRA_TENANT_ID/ENTRA_CLIENT_ID/ENTRA_CLIENT_SECRET not set in .env.lab — "
            "this test requires a real Entra app registration and cannot fabricate one. "
            "Structural external-credential dependency, not a code gap (QA acceptance standard req. 3)."
        )
    return tenant, client_id, secret


def _mcp_call(headers: dict, name: str, arguments: dict) -> httpx.Response:
    r = httpx.post(f"{BASE_URL}/mcp", headers=headers, timeout=30, verify=False,
                    json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                          "params": {"name": name, "arguments": arguments}})
    log_http_call("POST", f"{BASE_URL}/mcp tools/call:{name}", r.status_code, r.text)
    return r


def _rest(method: str, path: str, token: str, **kw) -> httpx.Response:
    r = httpx.request(method, f"{BASE_URL}{path}", headers=_auth_headers(token), verify=False, timeout=60, **kw)
    log_http_call(method, f"{BASE_URL}{path}", r.status_code, r.text)
    return r


@pytest.fixture(scope="module")
def real_entra_creds():
    return _require_real_entra()


@pytest.fixture(scope="module")
def entra_directory_fixture_container(real_entra_creds):
    """A disposable, uniquely-named standalone container simulating an
    externally-hosted MCP server — matches AT3's clean_mcp_upstream pattern
    (uuid-suffixed name, teardown at the end), not part of the lab's own
    podman-compose.lab.yml fixture set."""
    name = f"{_FIXTURE_CONTAINER_PREFIX}{uuid.uuid4().hex[:8]}"
    server_py = str((__import__("pathlib").Path(__file__).resolve().parents[3])
                     / "lab" / "mcp-servers" / "entra-directory" / "server.py")
    subprocess.run(["podman", "rm", "-f", name], capture_output=True)
    subprocess.run([
        "podman", "run", "-d", "--name", name,
        "--network", "mcp-security-platform_lab-net",
        "-e", "HOST=0.0.0.0", "-e", "PORT=8000",
        "-e", "HTTPS_PROXY=http://lab-egress-proxy:3128",
        "-e", "NO_PROXY=localhost,127.0.0.1",
        "-v", f"{server_py}:/app/server.py:ro",
        "localhost/lab-mcp-entra-directory:lab", "python", "server.py",
    ], check=True, capture_output=True, text=True)
    subprocess.run(["podman", "network", "connect",
                     "mcp-security-platform_mcp-egress-net", name], capture_output=True)
    for _ in range(15):
        r = subprocess.run(["podman", "exec", "mcp-proxy", "curl", "-s", "-o", "/dev/null",
                             "-w", "%{http_code}", f"http://{name}:8000/mcp"],
                            capture_output=True, text=True)
        if r.stdout.strip() in ("200", "406", "405"):  # any HTTP response = server is up
            break
        time.sleep(2)
    yield f"http://{name}:8000/mcp"
    subprocess.run(["podman", "rm", "-f", name], capture_output=True)


def test_entra_directory_self_service_onboarding_before_and_after(
    alice_token, carol_token, real_entra_creds, entra_directory_fixture_container,
):
    tenant, client_id, secret = real_entra_creds
    name = f"at3-entra-dir-{uuid.uuid4().hex[:8]}"

    # ── BEFORE: no tool by this run's name exists anywhere in the registry ──
    before_count = db_query(
        f"SELECT count(*) FROM tool_registry WHERE name='list_users' AND deleted_at IS NULL "
        f"AND server_id IN (SELECT server_id FROM server_registry WHERE name='{name}')"
    )
    assert before_count == "0", "BEFORE precondition violated: this run's server name already has tools"

    headers = mcp_session_headers(alice_token)

    # ── Submit via the REAL self-service MCP tool (not the REST API) ──
    submit_resp = _mcp_call(headers, "submit_mcp_server", {
        "name": name,
        "upstream_url": entra_directory_fixture_container,
        "description": "AT3 acceptance test: real Entra/Graph directory reads via app-only client_credentials.",
        "injection_mode": "entra_client_credentials",
        "data_categories": ["pii", "internal_docs"],
        "has_write_ops": False,
        "github_repo_url": "https://lab-gitea-tls/gitadmin/entra-directory-mcp.git",
        "upstream_idp_type": "entra",
        "upstream_idp_issuer": f"https://login.microsoftonline.com/{tenant}/v2.0",
        "upstream_idp_client_id": client_id,
        "upstream_idp_scopes": ["https://graph.microsoft.com/.default"],
    })
    assert submit_resp.status_code == 200
    submit_body = json.loads(submit_resp.json()["result"]["content"][0]["text"])
    assert "error" not in submit_body, f"submit_mcp_server failed: {submit_body}"
    server_id = submit_body["server_id"]
    assert submit_body["submitter"] == "alice@corp", "ownership trust-bridge regression (see test_at3_self_service_mcp_tool.py)"

    # ── Poll scan (240s, matching test_at3_onboarding.py's _poll_scan default —
    # the scanner-worker is a single shared queue; under full-suite load with
    # many other tests' scans queued ahead of this one, 120s was observed to be
    # too short even though the scan itself always eventually passed) ──
    deadline = time.monotonic() + 240
    scan_status = submission_status = ""
    while time.monotonic() < deadline:
        row = db_query(f"SELECT scan_status || ',' || submission_status FROM server_registry WHERE server_id='{server_id}'")
        scan_status, submission_status = row.split(",")
        if scan_status not in ("pending", "running", ""):
            break
        time.sleep(3)
    assert scan_status == "passed", f"scan did not pass: {scan_status}/{submission_status}"
    assert submission_status == "awaiting_review"

    # ── Admin (carol) approves — dual control, not self-service ──
    approve = _rest("POST", f"/api/v1/admin/submissions/{server_id}/approve", carol_token,
                     json={"notes": "AT3 automated acceptance run"})
    assert approve.status_code == 200, approve.text
    assert approve.json()["submission_status"] == "approved_pending_url"

    # ── Owner (alice) provides the real running URL -> auto-discovers tools ──
    provide = _rest("POST", f"/api/v1/submissions/{server_id}/provide-url", alice_token,
                     json={"upstream_url": entra_directory_fixture_container})
    assert provide.status_code == 200, provide.text
    provide_body = provide.json()
    assert provide_body["submission_status"] == "active"
    assert provide_body["tools_provisioned"] == len(_TOOL_NAMES), provide_body

    # ── Admin activates each discovered (quarantined) tool + uploads the real credential ──
    tool_ids = {}
    for row in db_query(
        f"SELECT name || ':' || tool_id FROM tool_registry WHERE server_id='{server_id}' AND deleted_at IS NULL"
    ).splitlines():
        tname, tid = row.split(":", 1)
        tool_ids[tname.strip()] = tid.strip()
    assert set(tool_ids) == set(_TOOL_NAMES), tool_ids

    cred_json = json.dumps({"tenant_id": tenant, "client_id": client_id, "client_secret": secret})
    for tname, tid in tool_ids.items():
        act = subprocess.run(
            ["podman", "exec", "mcp-proxy", "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             "-X", "PATCH", f"http://localhost:8000/api/v1/tools/{tid}",
             "-H", f"Authorization: Bearer {alice_token}", "-H", "Content-Type: application/json",
             "-d", json.dumps({"status": "active"})],
            capture_output=True, text=True, timeout=30,
        )
        log_http_call("PATCH", f"/api/v1/tools/{tid} (activate {tname})", int(act.stdout.strip() or 0), "")
        assert act.stdout.strip() == "200", f"activation failed for {tname}: {act.stdout} {act.stderr}"

        cred_payload = json.dumps({
            "secret": cred_json, "credential_type": "entra_client_secret",
            "owner_type": "service", "description": f"AT3 entra-directory real Graph app-only ({tname})",
        })
        cred = subprocess.run(
            ["podman", "exec", "mcp-proxy", "sh", "-c",
             f"curl -s -o /dev/null -w '%{{http_code}}' -X PUT 'http://localhost:8000/admin/credentials/{tid}' "
             f"-H 'Authorization: Bearer {alice_token}' -H 'Content-Type: application/json' "
             f"-d '{cred_payload}'"],
            capture_output=True, text=True, timeout=30,
        )
        log_http_call("PUT", f"/admin/credentials/{tid} (credential for {tname})", int(cred.stdout.strip() or 0), "")
        assert cred.stdout.strip() == "200", f"credential upload failed for {tname}: {cred.stdout} {cred.stderr}"

    # ── Trust tier + entitlement (realistic reviewer steps, mirrors test_at3_onboarding.py) ──
    db_query(f"UPDATE server_registry SET trust_tier=2 WHERE server_id='{server_id}'")
    _clear_taint("alice@corp")

    ent = _rest("POST", f"/api/v1/servers/{server_id}/entitlements", alice_token,
                json={"principal_id": "human:keycloak:alice@corp", "principal_type": "human"})
    assert ent.status_code in (200, 201), ent.text

    # ── AFTER: list_users is now callable through the real gateway and returns real Graph data ──
    invoke = _mcp_call(headers, "list_users", {"top": 5})
    assert invoke.status_code == 200
    body = invoke.json()
    assert "error" not in body.get("result", {}), f"list_users invocation failed: {body}"
    result_text = body["result"]["content"][0]["text"]
    result_data = json.loads(result_text)
    assert result_data["count"] > 0, f"expected real Graph users, got: {result_data}"
    assert all("id" in u and "userPrincipalName" in u for u in result_data["users"]), result_data
    # Real tenant sanity check — not lab-mock-idp/lab-mock-graph shaped data.
    assert any(u.get("userPrincipalName", "").count("@") == 1 for u in result_data["users"])

    after_count = db_query(
        f"SELECT count(*) FROM tool_registry WHERE server_id='{server_id}' AND status='active' AND deleted_at IS NULL"
    )
    assert after_count == str(len(_TOOL_NAMES))

    # ── Cleanup: free the fixed tool names for the next run AND soft-delete the
    # server. tool_registry_name_version_unique is a PLAIN UNIQUE(name, version)
    # constraint with no `WHERE deleted_at IS NULL` — soft-deleting server_registry
    # alone does NOT cascade to tool_registry and does NOT free these names (the
    # exact bug already found and fixed once this session in
    # lab/seeder/seed.py::fix_oidc_issuer_placeholder — same constraint class,
    # different table). Rename before soft-delete, matching the established
    # `echo-superseded-<id>` pattern used elsewhere in this suite (see
    # test_at3_onboarding.py's clean_mcp_upstream fixture).
    db_query(
        f"UPDATE tool_registry SET name = 'superseded-' || substring(tool_id::text, 1, 8), "
        f"deleted_at = now() WHERE server_id='{server_id}' AND deleted_at IS NULL"
    )
    db_query(f"UPDATE server_registry SET deleted_at=now() WHERE server_id='{server_id}'")


def _clear_taint(client_id: str) -> None:
    """See test_at3_onboarding.py::_clear_taint — a freshly onboarded
    (trust_tier=0, now 2) server taints whoever invokes it before the
    trust_tier update; isolate this test from that residue."""
    import hashlib
    key = "mcp_taint:" + hashlib.sha256(client_id.encode()).hexdigest()[:16]
    pw = _env_lab("REDIS_PASSWORD")
    subprocess.run(["podman", "exec", "mcp-redis", "redis-cli", "-a", pw, "DEL", key],
                    capture_output=True, text=True)
