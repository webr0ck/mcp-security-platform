# MCP Security Platform — Operational Runbook

Operational procedures for running and maintaining the platform. Lab-specific
setup and troubleshooting live in [LAB-HOWTO.md](LAB-HOWTO.md); this runbook
collects the recurring operator workflows.

### Per-tool registry expansion (lab)

    make lab-migrate-per-tool-dry         # 1. preview discovered tool names
    make lab-migrate-per-tool-activate    # 2. first bootstrap: expand + activate (after reviewing the dry-run)
    make lab-migrate-per-tool             # routine: new upstream tools land QUARANTINED for review

Idempotent, additive, never wipes. --activate-discovered activates EVERY tool discovered
this run, so only use it after reviewing the dry-run. Routine syncs quarantine new names;
re-running --activate-discovered promotes them once reviewed (ON CONFLICT promotes
quarantined->active and never downgrades active). Aliases (echo-ping, ...) are marked
metadata.hidden=true once an active per-tool row exists: hidden from tools/list but still
callable via invoke_tool (which now enforces the per-tool row's quarantine/OPA).

Reverse a hide:     UPDATE tool_registry SET metadata = metadata - 'hidden' WHERE name='<alias>';
Reverse expansion:  UPDATE tool_registry SET deleted_at = NOW() WHERE metadata->>'kind'='per-tool';
                    UPDATE tool_registry SET metadata = metadata - 'hidden' WHERE metadata ? 'hidden';
