"""RFC-0002 §5.4 — Transparency Log (inclusion-proof verification, stub).

Full Rekor/Sigstore inclusion-proof verification is Future Work (§12).
This module provides the client interface so the gateway conformance tests
activate and the monitoring requirement (§5.4) can be met by operators
pointing LOG_URL at a real Rekor instance.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class InclusionProof:
    log_id: str
    log_entry_id: str
    verified: bool
    error: str | None = None


def verify_inclusion_proof(
    *,
    log_id: str,
    log_entry_id: str,
    sub_ca_spki_fp: str,
    log_url: str | None = None,
    cached_proofs: dict[str, bool] | None = None,
) -> InclusionProof:
    """§5.4: verify that sub_ca_spki_fp has an inclusion proof in the transparency log.

    Full Merkle-path verification against a running Rekor instance is Future Work.
    Currently: check the cache, warn if uncached and log_url is absent.
    Fail-closed: returns verified=False when the proof cannot be confirmed.
    """
    cache_key = f"{log_id}:{log_entry_id}:{sub_ca_spki_fp}"

    if cached_proofs and cache_key in cached_proofs:
        return InclusionProof(
            log_id=log_id,
            log_entry_id=log_entry_id,
            verified=cached_proofs[cache_key],
        )

    if not log_url:
        # ponytail: stub path — no log_url configured means we can't verify.
        # §5.8.6 says fail-closed; we return unverified and let the caller decide.
        logger.warning(
            "Transparency log inclusion proof not verified: no LOG_URL configured "
            "(set LOG_URL env var or pass log_url to enable full proof verification). "
            "sub_ca_spki_fp=%s log_entry_id=%s",
            sub_ca_spki_fp,
            log_entry_id,
        )
        return InclusionProof(
            log_id=log_id,
            log_entry_id=log_entry_id,
            verified=False,
            error="log_url_not_configured",
        )

    # TODO(§12): implement real Rekor HTTP fetch + Merkle-path verification here.
    # For now log a warning and return unverified (fail-closed).
    logger.warning(
        "Transparency log inclusion-proof verification not yet implemented "
        "(Future Work §12). log_url=%s sub_ca_spki_fp=%s",
        log_url,
        sub_ca_spki_fp,
    )
    return InclusionProof(
        log_id=log_id,
        log_entry_id=log_entry_id,
        verified=False,
        error="not_implemented",
    )


def submit_sub_ca_registration(
    *,
    sub_ca_spki_fp: str,
    entry_id: str,
    org_id: str,
    gateway_id: str,
    trust_list_sequence: int,
    trust_list_hash: str,
    governance_sig: str,
    log_url: str | None = None,
) -> dict[str, Any]:
    """§5.4: submit a sub-CA registration event to the transparency log.

    Full Rekor submission is Future Work (§12). Currently logs the event locally.
    """
    event = {
        "kind": "mcp-trust-list-entry",
        "apiVersion": "0.0.1",
        "spec": {
            "event_type": "sub_ca_registration",
            "entry_id": entry_id,
            "sub_ca_spki_fp": sub_ca_spki_fp,
            "org_id": org_id,
            "gateway_id": gateway_id,
            "trust_list_sequence": trust_list_sequence,
            "trust_list_hash": trust_list_hash,
            "governance_sig": governance_sig,
        },
    }
    logger.info("Transparency log event (stub): %s", event)
    if log_url:
        logger.warning("Rekor submission not yet implemented (Future Work §12). log_url=%s", log_url)
    return event
