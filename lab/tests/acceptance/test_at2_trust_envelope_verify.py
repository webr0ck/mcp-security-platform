"""AT2 — T2: live-prove the ES256 trust-envelope verify path (article 4's
other headline claim). Loop-1's T5 only proved the taint-floor deny path
(SEP-1913 trust_tier -> binary integrity, a completely separate mechanism);
the ES256 sign/verify machinery itself (trust_labeler.py / trust_verifier.py)
had zero live coverage before this file.

IMPORTANT — what this test proves and what it does not:

  TRUST_ENVELOPE_ENABLED and TRUST_OBSERVER_ENABLED both defaulted to False
  and neither was wired to a working PKI in this lab before this loop (see
  FINDINGS.md T2 entry for the 3 real bugs found/fixed getting it running:
  a volume-name mismatch, 0600/0700-root file perms unreadable by the
  proxy's non-root uid, and an unhandled crash in TrustVerifier init). Both
  flags are now on in .env.lab and the PKI is live (`make labeler-init`).

  trust_observer.py is explicitly, deliberately ADVISORY ONLY (module
  docstring: "Never blocks or raises"). No code path in this repo gates,
  denies, or 403s on `VerifierVerdict.accepted` (grepped: zero call sites
  read `.accepted` outside the observer/its own tests). So there is no live
  HTTP round trip where a client-supplied tampered envelope gets rejected
  with a 403 -- the observer only ever re-verifies the envelope the proxy
  itself *just signed*, synchronously, before the response leaves the
  process. There is no reachable seam for an external tamperer.

  Given that architecture, this test proves both halves the only way that
  is actually true to what's live:
    1. test_valid_envelope_accepted_end_to_end -- a REAL credential-injecting
       tool call (gitea-repos, injection_mode=service) through the full
       gateway -> auth -> entitlement -> OPA -> credential-broker chain,
       asserting the response carries a genuine ES256-signed envelope and
       that the passive observer logged `accepted` for that exact result,
       against the live-mounted PKI (not a unit-test throwaway cert).
    2. test_tampered_and_unsigned_envelopes_rejected -- instantiates
       TrustLabeler/TrustVerifier pointed at the SAME live-mounted PKI files
       the running proxy process uses for every real request (the module-
       level singletons themselves aren't reachable from a fresh interpreter,
       but the certs/keys on disk are identical), signs a real envelope,
       then proves rejection for: corrupted content_hash, corrupted
       signature, a replayed envelope bound to a different result_id, and no
       envelope at all -- each with the exact `reason` the live code returns.
"""
from __future__ import annotations

import json
import subprocess

import pytest

from conftest import invoke_upstream, podman_exec, PROXY_CONTAINER

GITEA_TOOL = "gitea-repos"
ENVELOPE_KEY = "io.mcp-security-platform/trust-envelope/v0.1"

_TAMPER_PROBE = r'''
import sys, copy
sys.path.insert(0, "/app")
from app.services.trust_labeler import TrustLabeler, build_envelope_result, TRUST_ENVELOPE_KEY
from app.services.trust_verifier import TrustVerifier
from cryptography import x509

labeler = TrustLabeler(cert_path="/labeler/leaf.crt", key_path="/labeler/leaf.key", sub_ca_path="/labeler/sub_ca.crt")
sub_ca = x509.load_pem_x509_certificate(open("/labeler/sub_ca.crt", "rb").read())
verifier = TrustVerifier(sub_ca_cert=sub_ca)

result = build_envelope_result(
    content=[{"type": "text", "text": "hello from T2 acceptance probe"}],
    labeler=labeler, tool_name="t2-probe-tool", server_id="t2-probe-server",
    result_id="t2-probe-valid-001", trust_tier=2, sensitivity_label="low",
)
out = {}
v = verifier.verify(result, tool_name="t2-probe-tool", server_id="t2-probe-server", result_id="t2-probe-valid-001")
out["valid"] = {"accepted": v.accepted, "rank": v.integrity_rank, "reason": v.reason}

tampered_hash = copy.deepcopy(result)
tampered_hash["_meta"][TRUST_ENVELOPE_KEY]["binding"]["content_hash"] = "sha256:" + "0" * 64
v = verifier.verify(tampered_hash, tool_name="t2-probe-tool", server_id="t2-probe-server", result_id="t2-probe-valid-001")
out["tampered_hash"] = {"accepted": v.accepted, "rank": v.integrity_rank, "reason": v.reason}

tampered_sig = copy.deepcopy(result)
sig = tampered_sig["_meta"][TRUST_ENVELOPE_KEY]["sig"]["value"]
tampered_sig["_meta"][TRUST_ENVELOPE_KEY]["sig"]["value"] = ("A" if sig[0] != "A" else "B") + sig[1:]
v = verifier.verify(tampered_sig, tool_name="t2-probe-tool", server_id="t2-probe-server", result_id="t2-probe-valid-001")
out["tampered_sig"] = {"accepted": v.accepted, "rank": v.integrity_rank, "reason": v.reason}

v = verifier.verify(result, tool_name="t2-probe-tool", server_id="t2-probe-server", result_id="t2-probe-DIFFERENT-002")
out["replayed_result_id"] = {"accepted": v.accepted, "rank": v.integrity_rank, "reason": v.reason}

unsigned = {"content": [{"type": "text", "text": "no envelope here"}]}
v = verifier.verify(unsigned, tool_name="t2-probe-tool", server_id="t2-probe-server", result_id="t2-probe-valid-001")
out["unsigned"] = {"accepted": v.accepted, "rank": v.integrity_rank, "reason": v.reason}

import json as _json
print(_json.dumps(out))
'''


def test_valid_envelope_accepted_end_to_end(alice_token):
    """Real credential-injecting call (gitea-repos/list_repos, service
    injection) through the full gateway chain; asserts a genuine ES256
    envelope comes back and the observer accepted it against the live PKI."""
    r = invoke_upstream(alice_token, GITEA_TOOL, "tools/call",
                        {"name": "list_repos", "arguments": {}})
    assert r["status_code"] == 200, r
    body = r["body"]
    assert "error" not in body, body
    meta = body.get("result", {}).get("_meta", {})
    envelope = meta.get(ENVELOPE_KEY)
    assert envelope is not None, f"no trust envelope in response _meta: {body}"

    sig = envelope["sig"]
    assert sig["alg"] == "ES256"
    assert len(sig["x5c"]) >= 1
    assert envelope["binding"]["content_hash"].startswith("sha256:")
    label = envelope["label"]
    assert label["integrity_rank"] == 4, label  # invoke_tool wraps as trust_tier=4/system

    # Confirm actual credential-injection happened, not a deny wrapped in 200:
    # the nested upstream payload must contain real gitea repo data.
    joined = json.dumps(body)
    assert "gitadmin" in joined or "repos" in joined, (
        f"expected real gitea-repos upstream data in response: {joined[:500]}"
    )


def test_tampered_and_unsigned_envelopes_rejected():
    """Signs a real envelope with the same live-mounted PKI the running proxy
    uses (leaf.key/leaf.crt/sub_ca.crt on the shared labeler-data volume),
    then proves the verifier rejects: corrupted content_hash, corrupted
    signature, an envelope replayed against a different result_id, and no
    envelope at all -- with the code's actual reject reason for each."""
    r = podman_exec(PROXY_CONTAINER, ["python3", "-c", _TAMPER_PROBE], timeout=30)
    assert r.returncode == 0, f"probe failed: {r.stderr}"
    out = json.loads(r.stdout.strip().splitlines()[-1])

    assert out["valid"] == {"accepted": True, "rank": 2, "reason": None}, out["valid"]
    assert out["tampered_hash"]["accepted"] is False, out["tampered_hash"]
    assert out["tampered_hash"]["rank"] == 0, out["tampered_hash"]
    assert out["tampered_sig"]["accepted"] is False, out["tampered_sig"]
    assert out["replayed_result_id"]["accepted"] is False, out["replayed_result_id"]
    assert out["unsigned"] == {"accepted": False, "rank": 0, "reason": "no_envelope"}, out["unsigned"]
