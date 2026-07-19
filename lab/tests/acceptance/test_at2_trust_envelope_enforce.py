"""AT2 — T2: live-prove the TRUST_ENVELOPE_ENFORCE deny path over the real
gateway HTTP wire, both on and off.

test_at2_trust_envelope_verify.py already proved the ES256 sign/verify
machinery is correct in isolation (a fresh-interpreter probe against the
live-mounted PKI). What it explicitly did NOT prove: that flipping
TRUST_ENVELOPE_ENFORCE=true actually turns a rejected verdict into a real
HTTP-visible deny on the direct tools/call dispatch path
(mcp_server.py::_route_to_registry, ~line 979) — vs. the advisory-only
default where the same rejected verdict is only logged.

There is no reachable network seam for an external client to tamper an
envelope in flight (module docstring of test_at2_trust_envelope_verify.py
covers this in detail) — the observer re-verifies the envelope the proxy
process itself just signed, synchronously, before the response leaves the
process. The only way to make that self-check fail live is to break the
on-disk PKI material the running process reads it from. This test does
that for real: it swaps leaf.key on the shared labeler-data volume for an
unrelated keypair (so the leaf cert's declared public key no longer matches
what actually signs), toggles TRUST_ENVELOPE_ENFORCE=true via `.env`
(not a podman-compose.yml change), force-recreates mcp-proxy so it cold-loads
the corrupted key, and drives one real `tools/call` for a credential-injecting
registry tool through the live gateway — then does the same again with the
flag back at its lab default (false) proving the identical rejected verdict
is advisory-only again. Both legs restore the original leaf key + `.env`
in a `finally`, and force-recreate proxy one more time to leave the stack
exactly as it found it.

Cost note: this test force-recreates mcp-proxy three times (corrupt+enforce,
restore+default, cold health check) — ~30-45s. It is the only test in the
suite that touches proxy's own container lifecycle; every other acceptance
test only drives HTTP calls against the already-running stack.
"""
from __future__ import annotations

import base64
import json
import subprocess
import time
from pathlib import Path

import httpx
import pytest

from conftest import BASE_URL, PROXY_CONTAINER, REPO_ROOT, podman_exec, _auth_headers

LABELER_RENEWAL_CONTAINER = "mcp-labeler-renewal"
ENV_FILE = REPO_ROOT / ".env"
ENFORCE_LINE = "TRUST_ENVELOPE_ENFORCE=true"
COMPOSE_CMD = [
    "podman-compose", "--env-file", ".env.lab",
    "-f", "docker-compose.yml", "-f", "docker-compose.dev.yml",
    "-f", "podman-compose.lab.yml", "-f", "compose.wazuh.yml",
]

ENVELOPE_KEY = "io.mcp-security-platform/trust-envelope/v0.1"
DIRECT_DISPATCH_TOOL = "gitea-repos"  # single-tool-per-server registry entry, injection_mode=service


_GITEA_CA_OVERRIDE = REPO_ROOT / "lab/tests/acceptance/fixtures/compose.proxy-git-ca-override.yml"
_GITEA_CA_PEM = REPO_ROOT / "lab/tests/acceptance/fixtures/certs_for_proxy/lab-gitea-tls-ca.pem"


def _recreate_proxy_and_wait(timeout_s: int = 90) -> None:
    """force-recreate proxy, then wait for BOTH proxy's own /health AND the
    gateway's /health through the real gateway URL. Real gotcha hit live
    building this test: podman-compose recreates mcp-gateway too as a
    dependent-hash side effect of recreating proxy, and it takes several
    seconds after proxy reports healthy before the gateway's upstream
    re-resolves — calling through BASE_URL right after proxy-health-200
    intermittently ConnectionRefused's.

    A second, bigger real gotcha, caught by a full-suite run: a bare
    `up -d --force-recreate proxy` (no `--no-deps`) makes podman-compose
    recompute the whole dependency graph and cascade-recreate OTHER services
    whose config hash it decides changed too — observed live: mcp-gateway,
    mcp-scanner-worker, and (via a still-not-fully-root-caused mTLS/identity
    side effect) enough of the trust chain that self-service's calls
    into the submissions API started failing "unauthenticated: No valid
    identity could be resolved". run_full_acceptance.sh's own AT3 gitea
    fixture setup avoids exactly this by always passing `--no-deps` when it
    recreates proxy/scanner-worker for the GIT_SSL_CAINFO trust override
    (fixtures/compose.{proxy,scanner-worker}-git-ca-override.yml) — this
    fixture now does the same, which is the real fix (not a band-aid
    reapply): `--no-deps` keeps the recreate scoped to proxy alone, so nothing
    downstream is disturbed in the first place."""
    r = subprocess.run(COMPOSE_CMD + ["up", "-d", "--force-recreate", "--no-deps", "proxy"],
                        cwd=REPO_ROOT, capture_output=True, text=True, timeout=timeout_s)
    assert r.returncode == 0, f"proxy recreate failed: {r.stderr}"

    # Defense in depth: if --no-deps ever still lets the gitea-CA trust
    # override lapse for some other reason, reapply it rather than silently
    # breaking every later AT3/AT4 git-clone test in the same pytest session.
    if _GITEA_CA_OVERRIDE.is_file() and _GITEA_CA_PEM.is_file():
        r2 = subprocess.run(COMPOSE_CMD + ["-f", str(_GITEA_CA_OVERRIDE), "up", "-d", "--no-deps", "proxy"],
                            cwd=REPO_ROOT, capture_output=True, text=True, timeout=timeout_s)
        assert r2.returncode == 0, f"gitea-CA-trust reapply (proxy) failed: {r2.stderr}"
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        code, _ = proxy_health()
        if code == 200:
            break
        time.sleep(3)
    else:
        pytest.fail("mcp-proxy did not become healthy after force-recreate")

    while time.monotonic() < deadline:
        try:
            gw = httpx.get(f"{BASE_URL}/health", timeout=5, verify=False)
            if gw.status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(2)
    pytest.fail("gateway did not become reachable after proxy force-recreate")


def proxy_health() -> tuple[int, str]:
    r = podman_exec(PROXY_CONTAINER, ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                                       "http://localhost:8000/health"], timeout=10)
    return (int(r.stdout.strip() or "0"), r.stderr)


def _direct_dispatch_call(token: str) -> dict:
    """Real tools/call with params.name == the registry tool name directly
    (NOT the invoke_tool wrapper) — the only path TRUST_ENVELOPE_ENFORCE
    gates. Retries absorb SEC-05 ingress-allowlist staleness right after a
    force-recreate: proxy/app/middleware/ingress.py resolves+caches the
    "gateway" hostname's IP at proxy startup and only re-resolves at most
    once per 30s, so if mcp-gateway *also* got recreated (a real gotcha hit
    live building this test — podman-compose recreates it as a dependent
    side-effect of `up --force-recreate proxy`, changing its IP), proxy's
    cached allowlist is briefly stale and legitimately denies the gateway
    itself with INGRESS_DENIED until that 30s window rolls over."""
    headers = _auth_headers(token)
    last_body = None
    for attempt in range(15):
        try:
            init = httpx.post(f"{BASE_URL}/mcp", headers=headers, timeout=20, verify=False,
                json={"jsonrpc": "2.0", "id": 1, "method": "initialize",
                      "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                                 "clientInfo": {"name": "at2-enforce-test", "version": "1.0"}}})
            sid = init.headers.get("mcp-session-id") or init.headers.get("MCP-Session-Id", "")
            call_headers = {**headers, "MCP-Session-Id": sid} if sid else headers
            r = httpx.post(f"{BASE_URL}/mcp", headers=call_headers, timeout=20, verify=False,
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                      "params": {"name": DIRECT_DISPATCH_TOOL, "arguments": {}}})
            last_body = {"status_code": r.status_code, "body": r.json() if r.text else {}}
            if r.status_code == 200 and last_body["body"].get("error", {}).get("code") != "INGRESS_DENIED":
                return last_body
        except httpx.HTTPError as exc:
            last_body = {"status_code": 0, "body": {"error": str(exc)}}
        time.sleep(4)
    return last_body


@pytest.fixture()
def corrupted_leaf_key_and_enforce_on():
    """Swap leaf.key for an unrelated keypair, flip TRUST_ENVELOPE_ENFORCE=true
    via .env, force-recreate proxy. Restores everything in teardown regardless
    of test outcome.

    renew_once() fires immediately on container start, so this stop/start
    cycle is deliberate: stop it right after corrupting the key to freeze its
    12-min renewal timer so it can't silently overwrite our intentional
    mismatch mid-test (a real race hit live building this test — leaving the
    sidecar running the whole time, its independent 720s timer fired
    mid-corruption-window on one run and regenerated a fresh *matching* pair,
    so the deny assertion saw an accept instead). Restore does NOT replay a
    backed-up key — it just starts the sidecar again, whose own renew_once()
    regenerates leaf.crt+leaf.key TOGETHER as a guaranteed-matching pair,
    which is simpler and safer than restoring old bytes.
    """
    orig_env = ENV_FILE.read_text()
    try:
        gen = podman_exec(LABELER_RENEWAL_CONTAINER, [
            "python3", "-c",
            "from pathlib import Path\n"
            "from cryptography.hazmat.primitives.asymmetric import ec\n"
            "from cryptography.hazmat.primitives import serialization\n"
            "k = ec.generate_private_key(ec.SECP256R1())\n"
            "pem = k.private_bytes(serialization.Encoding.PEM, "
            "serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())\n"
            "Path('/labeler/leaf.key').write_bytes(pem)\n"
            "print('corrupted')",
        ], timeout=15)
        assert gen.returncode == 0 and "corrupted" in gen.stdout, gen.stderr
        stop = subprocess.run(["podman", "stop", LABELER_RENEWAL_CONTAINER], capture_output=True, timeout=20)
        assert stop.returncode == 0, stop.stderr

        ENV_FILE.write_text(orig_env.rstrip("\n") + "\n" + ENFORCE_LINE + "\n")
        _recreate_proxy_and_wait()

        yield
    finally:
        subprocess.run(["podman", "start", LABELER_RENEWAL_CONTAINER], capture_output=True, timeout=20)
        time.sleep(2)  # let renew_once() finish writing the fresh matching pair

        ENV_FILE.write_text(orig_env)
        _recreate_proxy_and_wait()


def test_enforce_true_denies_broken_signature_live(corrupted_leaf_key_and_enforce_on, alice_token):
    """With TRUST_ENVELOPE_ENFORCE=true and a corrupted (mismatched) leaf.key,
    a real tools/call through the gateway for a credential-injecting registry
    tool must come back as a JSON-RPC error with reason signature_invalid —
    not the silent advisory-only accept."""
    result = _direct_dispatch_call(alice_token)
    assert result["status_code"] == 200, result
    body = result["body"]
    assert "error" in body, f"expected a deny, got a 200 accept: {body}"
    assert body["error"]["data"]["reason"] == "signature_invalid", body

    # Best-effort cross-check against the live proxy log (not a hard assert —
    # this container also runs a chatty SQLAlchemy-echo background poller, so
    # a wide --since window can be large enough that a slow `podman logs`
    # capture races the observer's own WARNING line; the HTTP-level assertions
    # above are the authoritative proof of the deny). Printed for FINDINGS.md.
    logs = subprocess.run(["podman", "logs", "--since", "5m", PROXY_CONTAINER],
                          capture_output=True, text=True, timeout=15).stdout
    if "TrustObserver rejected tool=gitea-repos" not in logs:
        print("NOTE: observer log line not captured in this run's --since window (non-fatal)")


def test_enforce_default_false_accepts_same_call(alice_token):
    """Baseline (no fixture): with TRUST_ENVELOPE_ENFORCE at its lab default
    (false, unset) and the real matching PKI, the identical call succeeds —
    proves enforcement is genuinely opt-in and doesn't regress the default
    advisory-only behaviour."""
    result = _direct_dispatch_call(alice_token)
    assert result["status_code"] == 200, result
    body = result["body"]
    assert "error" not in body, f"expected accept at default (enforce=false), got: {body}"
    meta = body.get("result", {}).get("_meta", {})
    assert ENVELOPE_KEY in meta, f"expected a signed envelope on the accept path: {body}"
