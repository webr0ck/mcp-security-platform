"""
MCP Security Platform — SBOM Generator Service

Generates CycloneDX 1.5 SBOM documents for registered MCP tools.

Per docs/ARCHITECTURE.md Section 11:
- Each tool registration produces a CycloneDX 1.5 SBOM component
- SBOM document is signed with HMAC-SHA-256 (SBOM_SIGNING_KEY) — INV-006
- Signature is stored in sbom_records.signature (NOT NULL constraint)
- SBOM is also posted to Artifactory if ARTIFACTORY_ENABLED=true

The SBOM treats each MCP tool as a CycloneDX "library" component.
purl format: pkg:mcp/<tool-name>@<version>
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from app.core.config import settings
from app.core.security import sha256_of, sign_sbom

logger = logging.getLogger(__name__)

AUDITOR_TOOL_NAME = "mcp-security-platform"
CYCLONEDX_SPEC_VERSION = "1.5"
SPDX_SPEC_VERSION = "SPDX-2.3"


def generate_cyclonedx_sbom(
    tool_id: str,
    tool_name: str,
    tool_version: str,
    description: str,
    schema: dict[str, Any],
    source_repo: str | None,
    source_commit: str | None,
    tags: list[str],
    risk_score: int,
    risk_level: str,
) -> tuple[dict[str, Any], str, str]:
    """
    Generate a CycloneDX 1.5 SBOM document for a registered MCP tool.

    Args:
        tool_id: UUID of the tool.
        tool_name: Tool identifier name.
        tool_version: Semantic version string.
        description: Tool description.
        schema: JSON Schema object (used to compute schema_hash).
        source_repo: Source repository URL or None.
        source_commit: Git commit SHA or None.
        tags: Taxonomy tags.
        risk_score: Combined risk score (0-100).
        risk_level: Risk level string (low/medium/high/critical).

    Returns:
        Tuple of (bom_document dict, schema_hash str, sbom_signature str)
    """
    serial_number = f"urn:uuid:{uuid4()}"
    bom_ref = f"sbom_{uuid4().hex[:16]}"
    schema_json = json.dumps(schema, sort_keys=True)
    schema_hash = sha256_of(schema_json)
    audit_timestamp = datetime.now(timezone.utc).isoformat()

    external_refs = []
    if source_repo:
        ref = {"type": "vcs", "url": source_repo, "comment": "Source repository"}
        if source_commit:
            ref["comment"] = f"Source repository @ {source_commit[:12]}"
        external_refs.append(ref)

    component: dict[str, Any] = {
        "type": "library",
        "bom-ref": bom_ref,
        "name": tool_name,
        "version": tool_version,
        "description": description,
        "purl": f"pkg:mcp/{tool_name}@{tool_version}",
        "hashes": [{"alg": "SHA-256", "content": schema_hash}],
        "externalReferences": external_refs,
        "properties": [
            {"name": "mcp:risk_score", "value": str(risk_score)},
            {"name": "mcp:risk_level", "value": risk_level},
            {"name": "mcp:audit_timestamp", "value": audit_timestamp},
            {"name": "mcp:tool_id", "value": tool_id},
            {"name": "mcp:tags", "value": ",".join(tags)},
        ],
    }

    if source_commit:
        component["properties"].append(
            {"name": "mcp:source_commit", "value": source_commit}
        )

    bom_document: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "version": 1,
        "serialNumber": serial_number,
        "metadata": {
            "timestamp": audit_timestamp,
            "tools": [
                {
                    "name": AUDITOR_TOOL_NAME,
                    "version": settings.PLATFORM_VERSION,
                }
            ],
        },
        "components": [component],
    }

    # Sign the SBOM document (INV-006)
    bom_json = json.dumps(bom_document, sort_keys=True)
    sbom_signature = sign_sbom(bom_json)

    # Embed signature in response (not in the signed document itself).
    # The `value` field carries only the hex digest; the `algorithm` field
    # encodes the scheme. Strip the "hmac-sha256:" prefix before embedding.
    _PREFIX = "hmac-sha256:"
    sig_hex = sbom_signature[len(_PREFIX):] if sbom_signature.startswith(_PREFIX) else sbom_signature
    bom_document["signature"] = {
        "algorithm": "HMAC-SHA256",
        "value": sig_hex,
    }

    return bom_document, schema_hash, sbom_signature


async def publish_to_artifactory(
    tool_name: str,
    tool_version: str,
    bom_document: dict[str, Any],
) -> bool:
    """
    Publish SBOM to Artifactory if ARTIFACTORY_ENABLED=true.
    Returns True on success, False on failure (non-blocking).
    """
    if not settings.ARTIFACTORY_ENABLED:
        return False

    import httpx

    artifact_path = f"{settings.ARTIFACTORY_REPO}/mcp/tools/{tool_name}/{tool_version}/sbom.json"
    url = f"{settings.ARTIFACTORY_BASE_URL}/{artifact_path}"

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.put(
                url,
                content=json.dumps(bom_document).encode(),
                headers={
                    "X-JFrog-Art-Api": settings.ARTIFACTORY_API_KEY,
                    "Content-Type": "application/json",
                },
            )
            if resp.is_success:
                logger.info("SBOM published to Artifactory: %s", url)
                return True
            logger.warning(
                "Artifactory publish failed: status=%s body=%s",
                resp.status_code,
                resp.text[:200],
            )
            return False
    except Exception as exc:
        logger.warning("Artifactory publish error: %s", exc)
        return False
