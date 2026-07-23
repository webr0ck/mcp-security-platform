"""mcp-trust-verifier — the shipped, independent trust-envelope verifier.

An out-of-tree consumer (e.g. a fast-agent hook) imports THIS to verify a signed
MCP trust envelope it received through the gateway, holding only: the pinned sub-CA
anchor, its own call context, and the result. Same code as the platform proxy runs.

    from mcp_trust_verifier import TrustVerifier, TRUST_ENVELOPE_KEY

    verifier = TrustVerifier.from_pem(sub_ca_pem)
    verdict = verifier.verify(result, tool_name=tool, result_id=req_id)  # server_id from A6 hint
    if not verdict.accepted or verdict.integrity_rank < floor:
        ...  # refuse the downstream privileged action
"""
from mcp_trust_verifier.verifier import (
    TRUST_ENVELOPE_KEY,
    TrustVerifier,
    VerifierVerdict,
)

__all__ = ["TrustVerifier", "VerifierVerdict", "TRUST_ENVELOPE_KEY"]
