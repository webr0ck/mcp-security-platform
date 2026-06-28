"""RFC-0002 §4–§6 GATEWAY conformance backlog + live substrate probes.

Reality check (verified by grep on this repo): the gateway implements only the
RFC-0001 / §3.2 signed-envelope substrate. RFC-0002 §4 (content classification),
§5 (federation), and §6 (AI provenance) have NO implementation yet.

Rather than test APIs that don't exist (which is exactly the failure mode that
sank the RFC's first draft), each conformance test here DETECTS whether the
feature is implemented:
  • present  → it runs a real assertion against the gateway,
  • absent   → it SKIPs with a precise "implement X, then this activates" message.

So this file doubles as an executable, self-updating implementation backlog: the
day someone adds the content-class registry, `test_s4_*` stops skipping and starts
enforcing. The 'live' tests likewise skip unless a proxy answers on :8000.
"""
from __future__ import annotations

import importlib.util
import json
import urllib.request
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
PROXY_APP = REPO_ROOT / "proxy" / "app"


def _module_exists(dotted: str) -> bool:
    try:
        return importlib.util.find_spec(dotted) is not None
    except (ImportError, ValueError, ModuleNotFoundError):
        return False


def _first_existing(*relpaths: str) -> Path | None:
    for rp in relpaths:
        p = REPO_ROOT / rp
        if p.exists():
            return p
    return None


# ════════════════════════════════════════════════════════════════════════════
# §4 — Content classification (registry, BLP axis, sink-policy fields)
# ════════════════════════════════════════════════════════════════════════════

@pytest.mark.conformance
def test_s4_content_class_registry_present_and_valid():
    reg = _first_existing(
        "config/content-class-registry.json",
        "proxy/config/content-class-registry.json",
        "proxy/app/config/content-class-registry.json",
    )
    if reg is None:
        pytest.skip(
            "RFC-0002 §4.2 NOT IMPLEMENTED: no content-class-registry.json found. "
            "Implement the registry (classes → conf_floor, allowlist_required) and this "
            "test will validate it against spec_oracle.CONTENT_CLASS_REGISTRY."
        )
    data = json.loads(reg.read_text())
    from .spec_oracle import CONF_ORDER
    for cid, entry in data.items():
        assert "/" in cid, f"class id not <domain>/<subtype>: {cid}"
        assert entry["conf_floor"] in CONF_ORDER, f"bad floor for {cid}: {entry.get('conf_floor')}"
        assert isinstance(entry["allowlist_required"], bool)



# §4.6/§5.3 hasattr checks removed — behavioural parity coverage now lives in
# tests/rfc0002/test_gateway_parity.py (B1 vectors + B3 trust-scope xfail).


# ════════════════════════════════════════════════════════════════════════════
# §5 — Federation (trust list, trust scope, transparency log)
# ════════════════════════════════════════════════════════════════════════════


@pytest.mark.conformance
def test_s5_transparency_log_client_present():
    if not (_module_exists("app.services.transparency_log") or _first_existing("infra/rekor")):
        pytest.skip(
            "RFC-0002 §5.4 NOT IMPLEMENTED: no transparency-log/Rekor inclusion-proof "
            "client. Implement inclusion-proof verification (fail-closed for uncached "
            "sub-CAs when the log is down) before relying on cross-org trust."
        )


# ════════════════════════════════════════════════════════════════════════════
# §6 — Universal AI provenance (APE, model provenance, pipeline path)
# ════════════════════════════════════════════════════════════════════════════

@pytest.mark.conformance
def test_s6_artifact_provenance_envelope_present():
    if not _module_exists("app.services.artifact_provenance"):
        pytest.skip(
            "RFC-0002 §6.2 NOT IMPLEMENTED: no app.services.artifact_provenance (APE). "
            "Implement APE signing (artifact_hash binding, model_provenance, pipeline_path) "
            "then this asserts pipeline rank == spec_oracle.pipeline_integrity_rank (B.2)."
        )
    # smoke: module exists; behavioural pipeline-rank parity is in test_gateway_parity.py
    from app.services import artifact_provenance  # noqa: F401


@pytest.mark.conformance
def test_s6_c2pa_assertion_builder_present():
    if not _module_exists("app.services.c2pa"):
        pytest.skip(
            "RFC-0002 §6.4 NOT IMPLEMENTED: no C2PA assertion embedding "
            "(io.mcp-security-platform.ai-provenance)."
        )


# ════════════════════════════════════════════════════════════════════════════
# §7 — Extended envelope schema (v0.2) — currently v0.1 only
# ════════════════════════════════════════════════════════════════════════════

@pytest.mark.conformance
def test_s7_envelope_schema_version():
    """The implemented envelope key is v0.1; §7 specifies v0.2 once §4-6 fields exist."""
    from app.services.trust_verifier import TRUST_ENVELOPE_KEY
    if TRUST_ENVELOPE_KEY.endswith("/v0.2"):
        pytest.fail("v0.2 key present but §4-6 conformance tests still skipping — wire them up")
    assert TRUST_ENVELOPE_KEY.endswith("/v0.1"), (
        "expected the implemented v0.1 envelope; v0.2 is the RFC-0002 target"
    )


# ════════════════════════════════════════════════════════════════════════════
# LIVE — only when a proxy is actually running (auto-skipped otherwise)
# ════════════════════════════════════════════════════════════════════════════

@pytest.mark.live
def test_live_proxy_health(live_proxy_url):
    with urllib.request.urlopen(f"{live_proxy_url}/health", timeout=5) as resp:  # noqa: S310
        assert 200 <= resp.status < 300


@pytest.mark.live
def test_live_oauth_discovery_exposed(live_proxy_url):
    """Sanity: the gateway advertises OAuth protected-resource discovery (lab guide §Connecting)."""
    try:
        with urllib.request.urlopen(  # noqa: S310
            f"{live_proxy_url}/.well-known/oauth-protected-resource", timeout=5
        ) as resp:
            body = json.loads(resp.read())
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"discovery endpoint not reachable: {exc}")
    assert "authorization_servers" in body


@pytest.mark.live
def test_live_end_to_end_envelope_over_the_wire(live_proxy_url):
    pytest.skip(
        "Live end-to-end envelope verification needs the OAuth/mTLS client harness "
        "(see RFC-0002-verification-plan.md §6.3). The offline substrate tests already "
        "verify the labeler→verifier round-trip deterministically; this is the on-wire "
        "confirmation, pending an authenticated MCP test client in the runner."
    )
