"""RFC 8785 JCS canonicalization helpers for the trust envelope (PRD-0001 M3).

Uses the `jcs` package (RFC 8785) — never use json.dumps for canonicalization.
The two helpers produce the exact byte strings defined in RFC-0001 §5.2–5.3.
"""
from __future__ import annotations

from jcs import canonicalize  # type: ignore[import-untyped]


def jcs_tool_result(
    *,
    content: list,
    structured_content: dict | None,
) -> bytes:
    """Canonical bytes for the content-hash input (RFC-0001 §5.2).

    structuredContent is ALWAYS emitted explicitly (as null when absent) to
    prevent a hash mismatch between signer and verifier.
    """
    payload = {
        "content": content,
        "structuredContent": structured_content,
    }
    return canonicalize(payload)


def jcs_signed_input(
    *,
    label: dict,
    content_hash: str,
    nonce: str,
    signed_at: str,
    result_id: str,
    tool_name: str,
    server_id: str,
) -> bytes:
    """Canonical bytes for the ES256 signature input (RFC-0001 §5.3)."""
    payload = {
        "content_hash": content_hash,
        "label": label,
        "nonce": nonce,
        "result_id": result_id,
        "server_id": server_id,
        "signed_at": signed_at,
        "tool_name": tool_name,
    }
    return canonicalize(payload)
