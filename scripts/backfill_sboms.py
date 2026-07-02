"""
scripts/backfill_sboms.py
=========================
Generate and persist SBOM records for any tool_registry rows that lack one.
Idempotent — skips tools that already have an sbom_records entry.

Run inside the proxy container:
  podman exec mcp-proxy python /scripts/backfill_sboms.py

Or via make:
  make lab-backfill-sboms
"""
from __future__ import annotations

import asyncio
import json
import logging
import sys
from datetime import datetime, timezone
from uuid import uuid4

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("backfill_sboms")


async def main() -> None:
    from sqlalchemy import text
    from app.core.database import AsyncSessionLocal
    from app.services.sbom import generate_cyclonedx_sbom

    async with AsyncSessionLocal() as db:
        result = await db.execute(text("""
            SELECT t.tool_id, t.name, t.version, t.description,
                   t.schema, t.source_repo, t.source_commit,
                   t.tags, t.risk_score, t.risk_level
            FROM tool_registry t
            LEFT JOIN sbom_records s ON s.tool_id = t.tool_id
            WHERE t.deleted_at IS NULL AND s.sbom_id IS NULL
        """))
        tools = result.fetchall()

    if not tools:
        log.info("All tools already have SBOM records — nothing to do.")
        return

    log.info("Backfilling SBOMs for %d tool(s)...", len(tools))
    ok = err = 0

    async with AsyncSessionLocal() as db:
        for t in tools:
            try:
                tags = t.tags if isinstance(t.tags, list) else []
                schema = (t.schema if isinstance(t.schema, dict)
                          else json.loads(t.schema) if t.schema else {})
                doc, schema_hash, sig = generate_cyclonedx_sbom(
                    tool_id=str(t.tool_id),
                    tool_name=t.name or "",
                    tool_version=t.version or "0.0.0",
                    description=t.description or "",
                    schema=schema,
                    source_repo=t.source_repo,
                    source_commit=t.source_commit,
                    tags=tags,
                    risk_score=float(t.risk_score or 0.0),
                    risk_level=t.risk_level or "low",
                )
                sbom_id = str(uuid4())
                serial = doc.get("serialNumber", "")
                bom_ref = serial.replace("urn:uuid:", "") if serial.startswith("urn:uuid:") else sbom_id
                await db.execute(text("""
                    INSERT INTO sbom_records
                      (sbom_id, tool_id, bom_ref, cyclonedx_json,
                       schema_hash, signature, auditor_version, generated_at)
                    VALUES
                      (:sbom_id, :tool_id, :bom_ref, CAST(:cyclonedx_json AS jsonb),
                       :schema_hash, :signature, :auditor_version, :generated_at)
                    ON CONFLICT DO NOTHING
                """), {
                    "sbom_id": sbom_id,
                    "tool_id": str(t.tool_id),
                    "bom_ref": bom_ref,
                    "cyclonedx_json": json.dumps(doc),
                    "schema_hash": schema_hash,
                    "signature": sig,
                    "auditor_version": "1.0.0-backfill",
                    "generated_at": datetime.now(timezone.utc),
                })
                comps = len(doc.get("components", []))
                log.info("  OK  %s (%s) → %d component(s)", t.name, t.version, comps)
                ok += 1
            except Exception as exc:
                log.error("  ERR %s: %s", t.name, exc)
                err += 1

        await db.commit()

    log.info("Done: %d OK, %d errors", ok, err)
    sys.exit(1 if err else 0)


if __name__ == "__main__":
    asyncio.run(main())
