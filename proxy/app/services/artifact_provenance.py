"""RFC-0002 §7 — Artifact Provenance Envelope (APE).

sign_artifact() produces a signed APE for any AI-generated artifact
(llm-response, agent-document, ai-generated code, pipeline-report).
Uses the same ES256 + JCS infrastructure as TrustLabeler.
"""
from __future__ import annotations

import hashlib
import json
import logging
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)

APE_SCHEMA = "io.mcp-security-platform/artifact-provenance/v0.1"

_VALID_ARTIFACT_TYPES = {
    "llm-response",
    "agent-document",
    "ai-generated-code",
    "pipeline-report",
    "model-output",
}


@dataclass
class ModelProvenance:
    model_id: str
    model_version: str = ""
    inference_endpoint: str = ""
    model_commitment_hash: str = ""
    generation_params_hash: str = ""


@dataclass
class PipelineStep:
    agent_id: str
    action: str
    integrity_rank: int
    timestamp: str = ""


@dataclass
class ArtifactProvenanceEnvelope:
    schema: str
    artifact_id: str
    artifact_type: str
    artifact_hash: dict[str, str]
    content_class: dict[str, Any]
    integrity_rank: int
    model_provenance: dict[str, Any]
    pipeline_path: list[dict[str, Any]]
    labeler_id: str
    signed_at: str
    nonce: str
    c2pa: dict[str, str]
    sig: str = ""


def _pipeline_integrity_rank(pipeline_path: list[PipelineStep]) -> int:
    """§7.6: output rank = min across all pipeline steps."""
    if not pipeline_path:
        return 0
    return min(s.integrity_rank for s in pipeline_path)


def _artifact_hash(artifact_bytes: bytes) -> dict[str, str]:
    return {"alg": "sha256", "value": hashlib.sha256(artifact_bytes).hexdigest()}


def sign_artifact(
    *,
    artifact_bytes: bytes,
    artifact_type: str,
    labeler_id: str,
    pipeline_path: list[PipelineStep] | None = None,
    model_provenance: ModelProvenance | None = None,
    content_class_primary: str = "ai-output/llm-response",
    additional_content_classes: list[str] | None = None,
    trust_labeler: Any = None,  # optional TrustLabeler for real signing
) -> ArtifactProvenanceEnvelope | None:
    """Build and sign an APE. Returns None on error (consistent with TrustLabeler.sign_result).

    When trust_labeler is None, the APE is unsigned (advisory mode / Layer B).
    When trust_labeler is provided, sign the canonical APE JSON with it.
    """
    try:
        return _sign(
            artifact_bytes=artifact_bytes,
            artifact_type=artifact_type,
            labeler_id=labeler_id,
            pipeline_path=pipeline_path or [],
            model_provenance=model_provenance,
            content_class_primary=content_class_primary,
            additional_content_classes=additional_content_classes or [],
            trust_labeler=trust_labeler,
        )
    except Exception:  # noqa: BLE001
        logger.warning("sign_artifact failed (APE omitted)", exc_info=True)
        return None


def _sign(
    *,
    artifact_bytes: bytes,
    artifact_type: str,
    labeler_id: str,
    pipeline_path: list[PipelineStep],
    model_provenance: ModelProvenance | None,
    content_class_primary: str,
    additional_content_classes: list[str],
    trust_labeler: Any,
) -> ArtifactProvenanceEnvelope:
    if artifact_type not in _VALID_ARTIFACT_TYPES:
        logger.warning("Unknown artifact type %r — using model-output", artifact_type)
        artifact_type = "model-output"

    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    nonce = secrets.token_urlsafe(16)
    integrity_rank = _pipeline_integrity_rank(pipeline_path)

    # §7.4 C2PA assertion metadata
    c2pa = {
        "assertion_type": "io.mcp-security-platform.ai-provenance",
        "assertion_oid": "1.3.6.1.4.1.60000.mcp.c2pa.ai-provenance",
        "claim_generator": "mcp-security-platform/0.1",
    }

    mp = {
        "model_id": model_provenance.model_id if model_provenance else "",
        "model_version": model_provenance.model_version if model_provenance else "",
        "model_commitment_hash": model_provenance.model_commitment_hash if model_provenance else "",
        "generation_params_hash": model_provenance.generation_params_hash if model_provenance else "",
        "inference_endpoint": model_provenance.inference_endpoint if model_provenance else "",
    }

    pipeline_list = [
        {"agent_id": s.agent_id, "action": s.action, "integrity_rank": s.integrity_rank, "timestamp": s.timestamp}
        for s in pipeline_path
    ]

    # Derive effective class (strictest floor across primary + additional)
    from app.services.content_class import effective_class as _eff_class
    eff = _eff_class(content_class_primary, additional_content_classes)
    content_class_dict = {
        "primary": content_class_primary,
        "additional": additional_content_classes,
        "effective": eff.effective,
        "conf_floor": eff.conf_floor,
        "allowlist_required": eff.allowlist_required,
        "assigned_by": labeler_id,
        "assigned_at": now,
    }

    import uuid
    artifact_id = str(uuid.uuid4())

    ape = ArtifactProvenanceEnvelope(
        schema=APE_SCHEMA,
        artifact_id=artifact_id,
        artifact_type=artifact_type,
        artifact_hash=_artifact_hash(artifact_bytes),
        content_class=content_class_dict,
        integrity_rank=integrity_rank,
        model_provenance=mp,
        pipeline_path=pipeline_list,
        labeler_id=labeler_id,
        signed_at=now,
        nonce=nonce,
        c2pa=c2pa,
    )

    if trust_labeler is not None:
        # Sign the canonical JSON (all fields except sig) with the labeler.
        # We reuse the JCS canonicalization from trust_labeler.
        payload = {
            "schema": ape.schema,
            "artifact_id": ape.artifact_id,
            "artifact_type": ape.artifact_type,
            "artifact_hash": ape.artifact_hash,
            "content_class": ape.content_class,
            "integrity_rank": ape.integrity_rank,
            "model_provenance": ape.model_provenance,
            "pipeline_path": ape.pipeline_path,
            "labeler_id": ape.labeler_id,
            "signed_at": ape.signed_at,
            "nonce": ape.nonce,
            "c2pa": ape.c2pa,
        }
        # ponytail: use JSON canonical sort as a cheap stand-in for JCS until
        # the full JCS library is wired into the signing path; replace with
        # jcs.canonicalize() when APE signing is promoted to Layer A.
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        try:
            sig_result = trust_labeler.sign_result(
                content=[{"type": "text", "text": canonical.hex()}],
                structured_content=None,
                tool_name="__ape__",
                server_id="__ape__",
                result_id=artifact_id,
                trust_tier=integrity_rank,
                sensitivity_label=eff.conf_floor,
            )
            ape.sig = sig_result.get("sig", "") if sig_result else ""
        except Exception:  # noqa: BLE001
            logger.warning("APE signing failed; envelope unsigned", exc_info=True)

    return ape
