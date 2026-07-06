"""
MCP Security Platform — same-platform-IdP token validation probe (WP-A6, Finding 2)

Finding 2 asks for "a verify check confirming the deployed server actually
rejects missing/wrong-audience/expired tokens." The full apply/deploy/verify
pipeline (WP-B3) has landed only its schema/state-machine substrate so far
(server_registry.verification_report etc. — see V068) — the actual verify
WORKER that would run this automatically does not exist yet. Per this
package's scope note, this is therefore built as a STANDALONE,
acceptance-test-able probe against a live MCP server URL, not wired into the
not-yet-existing verify pipeline.

Follow-up (for whoever finishes WP-B3): call `run_same_idp_verify_probe()`
from the verify-phase worker once it exists, and persist its result into
`server_registry.verification_report` alongside whatever else that phase
checks.

What this actually proves: for a same-platform-IdP (kc_token_exchange)
server, three requests MUST all be rejected by the upstream MCP server
itself (not by the proxy — this probe talks to the upstream URL directly,
bypassing the proxy's own gate chain, precisely so it measures the
upstream's OWN validation, per Finding 2's "Required MCP server behavior:
validate issuer / audience / expiry / signature"):

  1. no Authorization header at all
  2. a syntactically well-formed but garbage-signed bearer token whose `aud`
     claim does not match this server's approved audience
  3. an intentionally-expired bearer token (exp in the past)

A conforming same-IdP server rejects all three (non-2xx HTTP status, or a
JSON-RPC error response body — never a normal tools/list or tools/call
result). This probe does NOT attempt to forge a token that would actually
pass the server's real IdP/JWKS validation — it only proves the negative
(bad tokens are rejected), which is the security-relevant property Finding 2
asks for. It cannot prove a GOOD token would be accepted; that is exercised
by the existing invoke path/acceptance tests.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

import httpx
import jwt as _jwt

logger = logging.getLogger(__name__)

_PROBE_TIMEOUT_SECONDS = 10.0

_TOOLS_LIST_REQUEST: dict = {
    "jsonrpc": "2.0",
    "id": "same-idp-verify-probe",
    "method": "tools/list",
    "params": {},
}


@dataclass(frozen=True)
class ProbeResult:
    name: str
    rejected: bool
    status_code: int | None
    detail: str


@dataclass(frozen=True)
class SameIdpVerifyResult:
    server_url: str
    probes: list[ProbeResult] = field(default_factory=list)

    @property
    def all_rejected(self) -> bool:
        """True only if every probe was rejected — the pass/fail verdict."""
        return bool(self.probes) and all(p.rejected for p in self.probes)


def _make_garbage_token(*, audience: str, expired: bool = False) -> str:
    """
    Builds a syntactically valid JWT signed with a random (never-trusted) key,
    so it always fails real signature verification regardless of claims —
    this is deliberate: the probe proves "the server rejects bad tokens", not
    "the server correctly validates a specific claim in isolation". A server
    that DOES only check claims without verifying the signature is itself a
    finding this probe surfaces (rejected=False when it should be True).
    """
    now = int(time.time())
    exp = now - 3600 if expired else now + 3600
    claims = {
        "iss": "https://not-a-real-issuer.invalid/realms/probe",
        "aud": audience,
        "sub": "same-idp-verify-probe",
        "iat": now,
        "exp": exp,
    }
    # HS256 with a throwaway secret — never derived from any real platform key.
    return _jwt.encode(claims, "probe-only-never-trusted-secret", algorithm="HS256")


def _looks_rejected(resp: httpx.Response) -> bool:
    """A conforming upstream rejects with a non-2xx HTTP status, OR (MCP
    JSON-RPC over HTTP 200 convention) a JSON-RPC `error` body rather than a
    `result`. Mirrors the same "HTTP 200 + JSON-RPC error is still a deny"
    convention documented in docs/spec for the proxy's own /mcp endpoint."""
    if resp.status_code >= 400:
        return True
    try:
        body = resp.json()
    except Exception:
        # Non-JSON 2xx body is not a valid tools/list success response either.
        return True
    return isinstance(body, dict) and "error" in body and "result" not in body


async def run_same_idp_verify_probe(
    *,
    server_url: str,
    approved_audience: str,
    header_name: str = "Authorization",
    header_prefix: str = "Bearer",
) -> SameIdpVerifyResult:
    """
    Runs the three probes against `server_url` directly (bypassing the proxy).

    Args:
        server_url: the upstream MCP server's own URL (server_registry.runtime_url
            or upstream_url) — NOT the platform proxy's /mcp endpoint.
        approved_audience: the server_registry.approved_token_audience value
            this server was reviewed/approved for — used to build the
            wrong-shape-but-plausible garbage tokens.
    """
    probes: list[ProbeResult] = []
    handshake_headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient(timeout=_PROBE_TIMEOUT_SECONDS) as client:
        # Probe 1: no Authorization header at all.
        try:
            resp = await client.post(server_url, json=_TOOLS_LIST_REQUEST, headers=handshake_headers)
            probes.append(ProbeResult("missing_token", _looks_rejected(resp), resp.status_code, "no Authorization header sent"))
        except Exception as exc:
            # A connection failure is NOT evidence the server validates tokens —
            # it's an infrastructure problem. Record as not-rejected (fail the
            # probe) so a broken/unreachable server doesn't read as "verified".
            probes.append(ProbeResult("missing_token", False, None, f"probe request failed: {exc}"))

        # Probe 2: wrong-audience garbage token.
        wrong_aud_token = _make_garbage_token(audience="not-the-approved-audience")
        try:
            headers = {**handshake_headers, header_name: f"{header_prefix} {wrong_aud_token}"}
            resp = await client.post(server_url, json=_TOOLS_LIST_REQUEST, headers=headers)
            probes.append(ProbeResult("wrong_audience", _looks_rejected(resp), resp.status_code, f"aud=not-the-approved-audience (server approved={approved_audience!r})"))
        except Exception as exc:
            probes.append(ProbeResult("wrong_audience", False, None, f"probe request failed: {exc}"))

        # Probe 3: expired token (correct audience, but exp in the past).
        expired_token = _make_garbage_token(audience=approved_audience, expired=True)
        try:
            headers = {**handshake_headers, header_name: f"{header_prefix} {expired_token}"}
            resp = await client.post(server_url, json=_TOOLS_LIST_REQUEST, headers=headers)
            probes.append(ProbeResult("expired_token", _looks_rejected(resp), resp.status_code, "exp 1 hour in the past"))
        except Exception as exc:
            probes.append(ProbeResult("expired_token", False, None, f"probe request failed: {exc}"))

    return SameIdpVerifyResult(server_url=server_url, probes=probes)
