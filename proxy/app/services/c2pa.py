"""RFC-0002 §7.4 — C2PA interoperability.

Builds C2PA assertion objects embedding APE provenance so that downstream
content authenticity systems (C2PA validators) can verify AI provenance
alongside camera and tool provenance.

Only the assertion structure is built here; actual C2PA manifest signing
requires a C2PA-SDK integration (out of scope for lab POC — Future Work §12).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


C2PA_ASSERTION_TYPE = "io.mcp-security-platform.ai-provenance"
C2PA_ASSERTION_OID = "1.3.6.1.4.1.60000.mcp.c2pa.ai-provenance"


@dataclass
class C2PAAssertion:
    """A C2PA assertion embedding an APE."""
    label: str
    data: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"label": self.label, "data": self.data}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def build_assertion(ape: Any) -> C2PAAssertion:
    """Build a C2PA assertion from an ArtifactProvenanceEnvelope.

    Per §7.4: the assertion embeds the APE artifact_hash, model_provenance,
    pipeline_path, and integrity_rank so that C2PA validators can inspect
    AI provenance without understanding the APE schema directly.
    """
    return C2PAAssertion(
        label=C2PA_ASSERTION_TYPE,
        data={
            "oid": C2PA_ASSERTION_OID,
            "schema": getattr(ape, "schema", ""),
            "artifact_id": getattr(ape, "artifact_id", ""),
            "artifact_hash": getattr(ape, "artifact_hash", {}),
            "integrity_rank": getattr(ape, "integrity_rank", 0),
            "content_class": getattr(ape, "content_class", {}),
            "model_provenance": getattr(ape, "model_provenance", {}),
            "pipeline_path": getattr(ape, "pipeline_path", []),
            "labeler_id": getattr(ape, "labeler_id", ""),
            "signed_at": getattr(ape, "signed_at", ""),
        },
    )
