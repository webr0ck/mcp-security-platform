"""
MCP Security Platform — SBOM Signature Verification CLI

Usage: python -m app.cli.sbom_verify --tool-id <uuid>
Also exposed as: make sbom-verify TOOL_ID=<uuid>

Fetches the SBOM for a given tool from the database and verifies its
HMAC-SHA-256 signature against the current SBOM_SIGNING_KEY.

Exit codes:
  0 — Signature valid
  1 — Signature invalid (INV-006 violation)
  2 — Tool not found
  3 — Configuration error
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys


async def verify_sbom_for_tool(tool_id: str) -> int:
    """
    Verify SBOM signature for a given tool_id.
    Returns exit code (0=pass, 1=fail, 2=not found, 3=config error).
    """
    try:
        from app.core.config import settings
        from app.core.security import verify_sbom_signature
    except ImportError as exc:
        print(f"ERROR: Cannot import app modules. Run from proxy container: {exc}", file=sys.stderr)  # noqa: T201
        return 3

    try:
        from sqlalchemy import text
        from app.core.database import AsyncSessionLocal

        async with AsyncSessionLocal() as session:
            result = await session.execute(
                text(
                    """
                    SELECT s.sbom_id, s.bom_document, s.signature, s.schema_hash,
                           t.name, t.version
                    FROM sbom_records s
                    JOIN tool_registry t ON s.tool_id = t.tool_id
                    WHERE s.tool_id = :tool_id
                    ORDER BY s.created_at DESC
                    LIMIT 1
                    """
                ),
                {"tool_id": tool_id},
            )
            row = result.fetchone()
    except Exception as exc:
        print(f"ERROR: Database query failed: {exc}", file=sys.stderr)  # noqa: T201
        return 3

    if row is None:
        print(f"ERROR: No SBOM found for tool_id={tool_id}", file=sys.stderr)  # noqa: T201
        return 2

    sbom_id = row.sbom_id
    bom_document = row.bom_document
    stored_signature = row.signature
    tool_name = row.name
    tool_version = row.version

    # Reconstruct the signed document (without the signature field, which was added after signing)
    doc_to_verify = {k: v for k, v in bom_document.items() if k != "signature"}
    doc_json = json.dumps(doc_to_verify, sort_keys=True)

    is_valid = verify_sbom_signature(doc_json, stored_signature)

    if is_valid:
        print(  # noqa: T201
            f"PASS: SBOM signature valid for tool '{tool_name}' v{tool_version} "
            f"(sbom_id={sbom_id})"
        )
        return 0
    else:
        print(  # noqa: T201
            f"FAIL: SBOM signature INVALID for tool '{tool_name}' v{tool_version} "
            f"(sbom_id={sbom_id}). INV-006 violation.",
            file=sys.stderr,
        )
        return 1


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify SBOM signature for a registered tool.")
    parser.add_argument("--tool-id", required=True, help="UUID of the tool to verify.")
    args = parser.parse_args()

    exit_code = asyncio.run(verify_sbom_for_tool(args.tool_id))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
