"""
Unit Test — SBOM Generator Service (INV-006)

Tests proxy/app/services/sbom.py and proxy/app/core/security.py signing utilities.
No network calls, no Docker. All external services are either not called (pure
computation) or patched.

Invariants covered:
  INV-006: SBOM signing is MANDATORY. Unsigned SBOMs must not be producible.
           Tampered SBOMs must fail signature verification.

Tamper tests are labeled [TAMPER] in test names per the test plan.

Run: pytest tests/unit/test_sbom.py -m unit
"""
from __future__ import annotations

import json
import os
from typing import Any
from unittest.mock import patch, MagicMock

import pytest

# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

SAMPLE_TOOL_ID = "550e8400-e29b-41d4-a716-446655440000"
SAMPLE_TOOL_NAME = "file_reader"
SAMPLE_TOOL_VERSION = "1.2.0"
SAMPLE_DESCRIPTION = "Reads files from the local filesystem."
SAMPLE_SOURCE_REPO = "https://github.com/example/mcp-tools"
SAMPLE_SOURCE_COMMIT = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
SAMPLE_TAGS = ["filesystem", "read"]
SAMPLE_RISK_SCORE = 72
SAMPLE_RISK_LEVEL = "high"
SAMPLE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "path": {"type": "string", "description": "Absolute file path."}
    },
    "required": ["path"],
}

# Deterministic signing key for all tests — not a real secret
TEST_SIGNING_KEY = "test-sbom-signing-key-32chars!!!"
TEST_API_HMAC_KEY = "test-api-key-hmac-32characters!!"
TEST_AUDIT_HMAC_KEY = "test-audit-hmac-key-32characters"
TEST_WEBHOOK_KEY = "test-webhook-signing-key-32chars"


@pytest.fixture(autouse=True)
def mock_settings():
    """
    Patch settings for all SBOM tests to inject test signing keys.
    This prevents tests from requiring a live .env file.
    """
    settings_mock = MagicMock()
    settings_mock.SBOM_SIGNING_KEY = TEST_SIGNING_KEY
    settings_mock.API_KEY_HMAC_KEY = TEST_API_HMAC_KEY
    settings_mock.AUDIT_LOG_HMAC_KEY = TEST_AUDIT_HMAC_KEY
    settings_mock.WEBHOOK_SIGNING_KEY = TEST_WEBHOOK_KEY
    settings_mock.PLATFORM_VERSION = "1.0.0"
    settings_mock.ARTIFACTORY_ENABLED = False
    settings_mock.ARTIFACTORY_BASE_URL = ""
    settings_mock.ARTIFACTORY_REPO = "mcp-sbom-local"
    settings_mock.ARTIFACTORY_API_KEY = ""

    with (
        patch("app.services.sbom.settings", settings_mock),
        patch("app.core.security.settings", settings_mock),
    ):
        yield settings_mock


def _generate_test_sbom() -> tuple[dict[str, Any], str, str]:
    """
    Helper: Generate a CycloneDX SBOM with test fixture data.
    Returns (bom_document, schema_hash, sbom_signature).
    """
    from app.services.sbom import generate_cyclonedx_sbom

    return generate_cyclonedx_sbom(
        tool_id=SAMPLE_TOOL_ID,
        tool_name=SAMPLE_TOOL_NAME,
        tool_version=SAMPLE_TOOL_VERSION,
        description=SAMPLE_DESCRIPTION,
        schema=SAMPLE_SCHEMA,
        source_repo=SAMPLE_SOURCE_REPO,
        source_commit=SAMPLE_SOURCE_COMMIT,
        tags=SAMPLE_TAGS,
        risk_score=SAMPLE_RISK_SCORE,
        risk_level=SAMPLE_RISK_LEVEL,
    )


# ---------------------------------------------------------------------------
# CycloneDX schema shape tests
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_cyclonedx_schema_shape():
    """
    Covers: CycloneDX 1.5 SBOM document must contain all required top-level fields.

    Required fields per CycloneDX 1.5 spec and INV-006:
      bomFormat, specVersion, version, serialNumber, metadata, components, signature
    """
    bom_document, schema_hash, sbom_signature = _generate_test_sbom()

    required_top_level_fields = [
        "bomFormat",
        "specVersion",
        "version",
        "serialNumber",
        "metadata",
        "components",
        "signature",
    ]
    for field in required_top_level_fields:
        assert field in bom_document, (
            f"CycloneDX SBOM missing required top-level field: '{field}'"
        )

    assert bom_document["bomFormat"] == "CycloneDX"
    assert bom_document["specVersion"] == "1.5"
    assert isinstance(bom_document["version"], int)
    assert bom_document["serialNumber"].startswith("urn:uuid:")


@pytest.mark.unit
def test_cyclonedx_metadata_shape():
    """
    Covers: SBOM metadata block must include timestamp and tools list.
    """
    bom_document, _, _ = _generate_test_sbom()

    metadata = bom_document["metadata"]
    assert "timestamp" in metadata, "metadata.timestamp is required"
    assert "tools" in metadata, "metadata.tools is required"
    assert len(metadata["tools"]) >= 1

    tool_entry = metadata["tools"][0]
    assert "name" in tool_entry
    assert tool_entry["name"] == "mcp-security-platform"
    assert "version" in tool_entry


@pytest.mark.unit
def test_cyclonedx_component_shape():
    """
    Covers: Each CycloneDX component must have required fields per spec.
    """
    bom_document, _, _ = _generate_test_sbom()

    assert len(bom_document["components"]) == 1
    component = bom_document["components"][0]

    required_component_fields = ["type", "bom-ref", "name", "version", "purl", "hashes", "properties"]
    for field in required_component_fields:
        assert field in component, (
            f"CycloneDX component missing required field: '{field}'"
        )

    assert component["type"] == "library"
    assert component["name"] == SAMPLE_TOOL_NAME
    assert component["version"] == SAMPLE_TOOL_VERSION
    assert component["purl"] == f"pkg:mcp/{SAMPLE_TOOL_NAME}@{SAMPLE_TOOL_VERSION}"

    # Must have SHA-256 hash of the schema
    assert len(component["hashes"]) >= 1
    sha256_hash = next(
        (h for h in component["hashes"] if h["alg"] == "SHA-256"), None
    )
    assert sha256_hash is not None, "Component must include SHA-256 hash of tool schema"
    assert len(sha256_hash["content"]) == 64, "SHA-256 hash must be 64 hex characters"


@pytest.mark.unit
def test_cyclonedx_mcp_properties_present():
    """
    Covers: MCP-specific properties (risk_score, risk_level, tool_id, etc.)
    must be present in the component properties list.
    """
    bom_document, _, _ = _generate_test_sbom()

    component = bom_document["components"][0]
    props = {p["name"]: p["value"] for p in component["properties"]}

    assert "mcp:risk_score" in props, "mcp:risk_score property required"
    assert "mcp:risk_level" in props, "mcp:risk_level property required"
    assert "mcp:audit_timestamp" in props, "mcp:audit_timestamp property required"
    assert "mcp:tool_id" in props, "mcp:tool_id property required"

    assert props["mcp:risk_score"] == str(SAMPLE_RISK_SCORE)
    assert props["mcp:risk_level"] == SAMPLE_RISK_LEVEL
    assert props["mcp:tool_id"] == SAMPLE_TOOL_ID


@pytest.mark.unit
def test_cyclonedx_external_references_include_vcs():
    """
    Covers: When source_repo is provided, it must appear in externalReferences.
    """
    bom_document, _, _ = _generate_test_sbom()

    component = bom_document["components"][0]
    ext_refs = component.get("externalReferences", [])
    vcs_ref = next((r for r in ext_refs if r["type"] == "vcs"), None)
    assert vcs_ref is not None, "External VCS reference is required when source_repo is provided"
    assert SAMPLE_SOURCE_REPO in vcs_ref["url"]


@pytest.mark.unit
def test_cyclonedx_no_external_ref_without_source_repo():
    """
    Covers: When source_repo is None, no VCS external reference must be added.
    """
    from app.services.sbom import generate_cyclonedx_sbom

    bom_document, _, _ = generate_cyclonedx_sbom(
        tool_id=SAMPLE_TOOL_ID,
        tool_name=SAMPLE_TOOL_NAME,
        tool_version=SAMPLE_TOOL_VERSION,
        description=SAMPLE_DESCRIPTION,
        schema=SAMPLE_SCHEMA,
        source_repo=None,
        source_commit=None,
        tags=[],
        risk_score=10,
        risk_level="low",
    )

    component = bom_document["components"][0]
    ext_refs = component.get("externalReferences", [])
    assert ext_refs == [], (
        f"No external references expected when source_repo=None, got: {ext_refs}"
    )


# ---------------------------------------------------------------------------
# [TAMPER] Signature tests (INV-006)
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_hmac_signature_roundtrip():
    """
    [TAMPER] Covers INV-006: SBOM signature roundtrip.

    A signature produced by sign_sbom() over the BOM document JSON must verify
    correctly with verify_sbom_signature() using the same key. This is the
    baseline that proves the signing and verification paths are consistent.
    """
    from app.core.security import sign_sbom, verify_sbom_signature

    bom_document, schema_hash, sbom_signature = _generate_test_sbom()

    # Extract the document without the embedded signature for verification
    # (signature is computed over the unsigned document)
    doc_without_sig = {k: v for k, v in bom_document.items() if k != "signature"}
    bom_json = json.dumps(doc_without_sig, sort_keys=True)

    # The stored signature must verify against the document
    assert verify_sbom_signature(bom_json, sbom_signature), (
        "INV-006: SBOM signature verification failed on an unmodified document. "
        "sign_sbom() and verify_sbom_signature() are not consistent."
    )


@pytest.mark.unit
def test_signature_rejects_tampered_sbom():
    """
    [TAMPER] Covers INV-006: Tampered SBOM must fail signature verification.

    After generating a valid SBOM and its HMAC signature, mutate one field
    in the document. The stored signature must no longer verify.

    This is the core tamper resistance test for the SBOM pipeline.
    """
    from app.core.security import verify_sbom_signature

    bom_document, schema_hash, sbom_signature = _generate_test_sbom()

    # Extract unsigned document and compute valid signature reference
    doc_without_sig = {k: v for k, v in bom_document.items() if k != "signature"}

    # --- TAMPER: mutate the specVersion field ---
    tampered_doc = json.loads(json.dumps(doc_without_sig))
    tampered_doc["specVersion"] = "1.4"  # Changed from 1.5

    tampered_json = json.dumps(tampered_doc, sort_keys=True)

    # Tampered document must NOT verify against the original signature
    assert not verify_sbom_signature(tampered_json, sbom_signature), (
        "INV-006 [TAMPER]: Tampered SBOM document passed signature verification. "
        "This is a critical security failure — signatures must reject any modification."
    )


@pytest.mark.unit
def test_signature_rejects_tampered_component_hash():
    """
    [TAMPER] Covers INV-006: Mutating the component SHA-256 hash must fail verification.

    An attacker who modifies the schema_hash within the SBOM component (to cover
    a schema substitution) must be detected by signature verification.
    """
    from app.core.security import verify_sbom_signature

    bom_document, schema_hash, sbom_signature = _generate_test_sbom()
    doc_without_sig = {k: v for k, v in bom_document.items() if k != "signature"}

    # --- TAMPER: replace the SHA-256 hash with a forged value ---
    tampered_doc = json.loads(json.dumps(doc_without_sig))
    tampered_doc["components"][0]["hashes"][0]["content"] = "a" * 64  # forged hash

    tampered_json = json.dumps(tampered_doc, sort_keys=True)

    assert not verify_sbom_signature(tampered_json, sbom_signature), (
        "INV-006 [TAMPER]: Forged component hash passed signature verification."
    )


@pytest.mark.unit
def test_signature_rejects_tampered_risk_score():
    """
    [TAMPER] Covers INV-006: Mutating the mcp:risk_score property must fail verification.

    An attacker downgrading a 'critical' tool's risk_score to 'low' in the SBOM
    to circumvent quarantine must be detected.
    """
    from app.core.security import verify_sbom_signature

    bom_document, schema_hash, sbom_signature = _generate_test_sbom()
    doc_without_sig = {k: v for k, v in bom_document.items() if k != "signature"}

    # --- TAMPER: downgrade risk_score from 72 to 5 ---
    tampered_doc = json.loads(json.dumps(doc_without_sig))
    properties = tampered_doc["components"][0]["properties"]
    for prop in properties:
        if prop["name"] == "mcp:risk_score":
            prop["value"] = "5"

    tampered_json = json.dumps(tampered_doc, sort_keys=True)

    assert not verify_sbom_signature(tampered_json, sbom_signature), (
        "INV-006 [TAMPER]: Risk score tampering was not detected by signature verification."
    )


@pytest.mark.unit
@pytest.mark.xfail(
    strict=True,
    reason=(
        "# TICKET-001: sign_sbom() does not yet validate that SBOM_SIGNING_KEY is non-empty. "
        "hmac.new() accepts an empty key, producing a weak but valid HMAC. "
        "Fix: add `if not settings.SBOM_SIGNING_KEY: raise ValueError('SBOM_SIGNING_KEY must not be empty')` "
        "at the start of sign_sbom() in proxy/app/core/security.py. "
        "This xfail documents the gap per INV-006 and docs/test-plan.md Gap Items."
    ),
)
def test_missing_signing_key_raises():
    """
    [TAMPER] Covers INV-006: Attempting to sign an SBOM when SBOM_SIGNING_KEY
    is empty must raise a clear error, not silently produce a weakly-signed SBOM.

    An empty signing key produces an HMAC keyed over empty bytes, which any
    adversary who discovers the key is empty can forge for any arbitrary document.
    The platform must enforce non-empty key configuration at the signing call site.

    CURRENT STATE: sign_sbom() silently accepts an empty key (xfail).
    REQUIRED: Raise ValueError with a descriptive message.

    Remove the xfail marker once TICKET-001 is resolved and sign_sbom()
    validates the key length.
    """
    from app.core.security import sign_sbom

    settings_no_key = MagicMock()
    settings_no_key.SBOM_SIGNING_KEY = ""  # Empty key — misconfiguration

    with patch("app.core.security.settings", settings_no_key):
        # This must raise — currently it doesn't (hence xfail).
        with pytest.raises((ValueError, RuntimeError)) as exc_info:
            sign_sbom('{"bomFormat": "CycloneDX"}')

        error_msg = str(exc_info.value).lower()
        assert any(keyword in error_msg for keyword in ("key", "sign", "config", "empty", "missing")), (
            f"INV-006: Expected a clear error about missing signing key, got: '{exc_info.value}'"
        )


@pytest.mark.unit
def test_wrong_key_fails_verification():
    """
    [TAMPER] Covers INV-006: Signature produced with one key must not verify
    with a different key. Prevents key confusion attacks.
    """
    import hmac as hmac_module
    import hashlib

    from app.core.security import verify_sbom_signature

    bom_document, _, sbom_signature = _generate_test_sbom()
    doc_without_sig = {k: v for k, v in bom_document.items() if k != "signature"}
    bom_json = json.dumps(doc_without_sig, sort_keys=True)

    # Compute signature with a DIFFERENT key
    wrong_key_sig = "hmac-sha256:" + hmac_module.new(
        b"totally-wrong-key",
        bom_json.encode(),
        hashlib.sha256,
    ).hexdigest()

    # Must fail verification (original doc, wrong key signature)
    assert not verify_sbom_signature(bom_json, wrong_key_sig), (
        "[TAMPER] Signature from a different key must not verify. "
        "Key confusion attack not caught."
    )


# ---------------------------------------------------------------------------
# Schema hash tests
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_schema_hash_is_deterministic():
    """
    Covers: Schema hash (SHA-256 of JSON-serialized schema) must be deterministic.
    Two calls with the same schema must produce the same hash.
    This is required for SBOM reproducibility and compliance audits.
    """
    from app.services.sbom import generate_cyclonedx_sbom

    _, hash1, _ = generate_cyclonedx_sbom(
        tool_id=SAMPLE_TOOL_ID,
        tool_name=SAMPLE_TOOL_NAME,
        tool_version=SAMPLE_TOOL_VERSION,
        description=SAMPLE_DESCRIPTION,
        schema=SAMPLE_SCHEMA,
        source_repo=None,
        source_commit=None,
        tags=[],
        risk_score=10,
        risk_level="low",
    )

    _, hash2, _ = generate_cyclonedx_sbom(
        tool_id=SAMPLE_TOOL_ID,
        tool_name=SAMPLE_TOOL_NAME,
        tool_version=SAMPLE_TOOL_VERSION,
        description=SAMPLE_DESCRIPTION,
        schema=SAMPLE_SCHEMA,
        source_repo=None,
        source_commit=None,
        tags=[],
        risk_score=10,
        risk_level="low",
    )

    assert hash1 == hash2, (
        f"Schema hash is not deterministic: first={hash1}, second={hash2}"
    )


@pytest.mark.unit
def test_schema_hash_changes_with_schema():
    """
    Covers: Different schemas must produce different SHA-256 hashes.
    Verifies that schema_hash is a meaningful integrity check.
    """
    from app.services.sbom import generate_cyclonedx_sbom

    schema_a = {"type": "object", "properties": {"x": {"type": "string"}}}
    schema_b = {"type": "object", "properties": {"y": {"type": "integer"}}}

    _, hash_a, _ = generate_cyclonedx_sbom(
        tool_id=SAMPLE_TOOL_ID,
        tool_name=SAMPLE_TOOL_NAME,
        tool_version=SAMPLE_TOOL_VERSION,
        description=SAMPLE_DESCRIPTION,
        schema=schema_a,
        source_repo=None,
        source_commit=None,
        tags=[],
        risk_score=10,
        risk_level="low",
    )

    _, hash_b, _ = generate_cyclonedx_sbom(
        tool_id=SAMPLE_TOOL_ID,
        tool_name=SAMPLE_TOOL_NAME,
        tool_version=SAMPLE_TOOL_VERSION,
        description=SAMPLE_DESCRIPTION,
        schema=schema_b,
        source_repo=None,
        source_commit=None,
        tags=[],
        risk_score=10,
        risk_level="low",
    )

    assert hash_a != hash_b, (
        "Different schemas must produce different SHA-256 hashes. "
        "Collision detected — schema integrity check is broken."
    )


# ---------------------------------------------------------------------------
# SBOM signature format tests
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_signature_format_prefix():
    """
    Covers: SBOM signature must be prefixed with 'hmac-sha256:' per the
    API spec (docs/API.md Section 2.3 GET /tools/{id}/sbom).
    """
    _, _, sbom_signature = _generate_test_sbom()

    assert sbom_signature.startswith("hmac-sha256:"), (
        f"SBOM signature must start with 'hmac-sha256:', got: {sbom_signature[:30]}"
    )

    hex_part = sbom_signature[len("hmac-sha256:"):]
    assert len(hex_part) == 64, (
        f"HMAC-SHA-256 signature must be 64 hex chars, got {len(hex_part)}"
    )
    assert all(c in "0123456789abcdef" for c in hex_part), (
        "HMAC-SHA-256 signature must be lowercase hex"
    )


@pytest.mark.unit
def test_embedded_signature_in_document():
    """
    Covers: The returned bom_document must contain the 'signature' block
    per the CycloneDX response format in docs/API.md.
    """
    bom_document, _, sbom_signature = _generate_test_sbom()

    assert "signature" in bom_document
    sig_block = bom_document["signature"]
    assert sig_block["algorithm"] == "HMAC-SHA256"
    assert sig_block["value"] == sbom_signature[len("hmac-sha256:"):]
