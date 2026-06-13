"""Passive trust-envelope observer (PRD-0001 M4 / W4.2).

Consumes a tool result, calls TrustVerifier, and logs a verdict.
Never blocks or raises — the observer is advisory (demonstrations D4/D5/D6 only).
"""
from __future__ import annotations

import logging

from app.services.trust_verifier import TrustVerifier, VerifierVerdict

logger = logging.getLogger(__name__)


def observe_result(
    result,
    *,
    verifier: TrustVerifier | None,
    tool_name: str,
    server_id: str,
    result_id: str,
) -> VerifierVerdict:
    """Verify the envelope in result and log the verdict. Never raises (W4.2).

    Returns VerifierVerdict(accepted=False, integrity_rank=0) when the verifier
    is not configured or the result is not a dict.
    """
    if verifier is None:
        return VerifierVerdict(accepted=False, integrity_rank=0, reason="observer_disabled")

    if not isinstance(result, dict):
        logger.warning(
            "TrustObserver: result is not a dict (tool=%s server=%s) — rank=0",
            tool_name, server_id,
        )
        return VerifierVerdict(accepted=False, integrity_rank=0, reason="result_not_dict")

    verdict = verifier.verify(result, tool_name=tool_name, server_id=server_id, result_id=result_id)

    if verdict.accepted:
        logger.info(
            "TrustObserver accepted tool=%s server=%s result_id=%s rank=%d",
            tool_name, server_id, result_id, verdict.integrity_rank,
        )
    else:
        logger.warning(
            "TrustObserver rejected tool=%s server=%s result_id=%s reason=%s",
            tool_name, server_id, result_id, verdict.reason,
        )
    return verdict
