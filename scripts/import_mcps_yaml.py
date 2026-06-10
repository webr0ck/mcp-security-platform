#!/usr/bin/env python3
"""
One-shot migration: import existing mcps.yaml servers into server_registry (V026+).
Idempotent: re-run skips servers already imported (matched by name).

DESIGN NOTES:
  - Fail-fast: first INSERT error aborts the import (returned as exit code 1).
    This is intentional — partial imports with undetected failures are unsafe.
    Use --dry-run to validate before running live.
  - Connection: uses bare asyncpg.connect (no pooling) because this is a one-off
    migration tool intended to run once per deployment. Not suitable for
    high-concurrency scenarios.

Usage:
  python scripts/import_mcps_yaml.py --yaml mcps.yaml --db-url postgresql://... [--imported-by admin]

Example:
  python scripts/import_mcps_yaml.py --yaml mcps.yaml \
    --db-url "postgresql://mcp_app:password@localhost/mcp_gateway" \
    --imported-by "deployment-v1.0"
"""
import yaml
import argparse
import sys
from pathlib import Path
import asyncpg
import logging
import asyncio

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def import_mcps_yaml(yaml_path: str, db_url: str, dry_run: bool = False, imported_by: str = "system-import"):
    """
    Load mcps.yaml servers. For each:
    - If name already exists in server_registry: skip (idempotent)
    - Else: INSERT new row with status='approved' (Phase 1 legacy, no IdP config)

    Args:
        yaml_path: Path to mcps.yaml file
        db_url: PostgreSQL connection URL
        dry_run: If True, log actions but don't commit to DB
        imported_by: Identity to record in approved_by for audit trail

    Returns:
        0 on success, 1 on error
    """
    yaml_file = Path(yaml_path)
    if not yaml_file.exists():
        logger.error(f"mcps.yaml not found: {yaml_path}")
        return 1

    with open(yaml_file) as f:
        config = yaml.safe_load(f)

    if not config or 'servers' not in config:
        logger.error(f"Invalid mcps.yaml: missing 'servers' key")
        return 1

    servers = config.get("servers", {})
    logger.info(f"Found {len(servers)} servers in {yaml_path}")

    conn = await asyncpg.connect(db_url)
    try:
        imported_count = 0
        skipped_count = 0
        skipped_reasons = []  # Track reasons for skipped servers

        for service_name, server_config in servers.items():
            if not service_name:
                logger.warning(f"Skipping server with no name: {server_config}")
                skipped_reasons.append(("(unnamed)", "missing name"))
                skipped_count += 1
                continue

            # Check if already imported
            existing = await conn.fetchval(
                "SELECT server_id FROM server_registry WHERE name = $1",
                service_name
            )
            if existing:
                logger.info(f"  {service_name}: already imported (id={existing}), skipping")
                skipped_reasons.append((service_name, "already imported"))
                skipped_count += 1
                continue

            # Extract fields from mcps.yaml format
            upstream_url = server_config.get("url")
            if not upstream_url:
                logger.warning(f"  {service_name}: missing 'url', skipping")
                skipped_reasons.append((service_name, "missing 'url'"))
                skipped_count += 1
                continue

            enabled = server_config.get("enabled", True)
            adapter_name = None
            if "credential" in server_config:
                cred = server_config["credential"]
                adapter_name = cred.get("adapter")

            if dry_run:
                logger.info(
                    f"  {service_name} [DRY RUN]: would insert with "
                    f"url={upstream_url}, adapter={adapter_name}, enabled={enabled}"
                )
                imported_count += 1
                continue

            # Import as legacy approved server (no IdP config, V026 columns NULL)
            # owner_sub is required; use a placeholder for legacy imports
            try:
                await conn.execute(
                    """
                    INSERT INTO server_registry
                      (name, service_name, upstream_url, status, owner_sub, injection_mode,
                       adapter_name, upstream_idp_type, upstream_idp_config,
                       credential_approach, owner_max_risk_level,
                       approved_at, approved_by)
                    VALUES
                      ($1, $2, $3, 'approved', 'legacy-import', 'none',
                       $4, NULL, NULL, NULL, 'medium', now(), $5)
                    """,
                    service_name,  # name (unique)
                    service_name,  # service_name (optional duplicate, for backward compat)
                    upstream_url,
                    adapter_name,
                    imported_by,  # approved_by (audit trail identity)
                )
                logger.info(f"  {service_name}: imported as approved legacy server")
                imported_count += 1
            except asyncpg.UniqueViolationError:
                # Race condition: another import process inserted it
                logger.info(f"  {service_name}: duplicate insert detected, skipping")
                skipped_reasons.append((service_name, "duplicate insert (race condition)"))
                skipped_count += 1
            except Exception as e:
                logger.error(f"  {service_name}: INSERT failed: {e}")
                return 1

        logger.info(f"\nImport summary:")
        logger.info(f"  Imported: {imported_count}")
        logger.info(f"  Skipped:  {skipped_count}")
        logger.info(f"  Total:    {len(servers)}")
        if skipped_reasons:
            logger.info(f"\nSkipped servers:")
            for name, reason in skipped_reasons:
                logger.info(f"  - {name}: {reason}")
        return 0

    finally:
        await conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Import mcps.yaml servers into server_registry"
    )
    parser.add_argument(
        "--yaml",
        default="mcps.yaml",
        help="Path to mcps.yaml (default: mcps.yaml)"
    )
    parser.add_argument(
        "--db-url",
        required=True,
        help="PostgreSQL connection URL (e.g., postgresql://user:pass@host/db)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Log what would be imported without modifying DB"
    )
    parser.add_argument(
        "--imported-by",
        default="system-import",
        help="Identity to record as importer in audit trail (default: system-import)"
    )
    args = parser.parse_args()

    exit_code = asyncio.run(import_mcps_yaml(args.yaml, args.db_url, args.dry_run, args.imported_by))
    sys.exit(exit_code)
