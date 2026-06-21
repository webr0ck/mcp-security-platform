# Wazuh Runtime Rules

Source of truth: `detections/*.yml` (Sigma format, ATR-aligned).

The XML files here are compiled from the Sigma rules for Wazuh's native rule engine.
To recompile after updating a Sigma rule:

```bash
# Install sigma-cli with opensearch/wazuh backend
pip install sigma-cli
sigma convert -t wazuh -p wazuh detections/ -o deployments/poc/wazuh/rules/
```

The `mcp-audit-rules.xml` is the compiled runtime artifact — do not edit directly.

## Rule ID Allocation Table

| Range         | File                     | Purpose                                    |
|---------------|--------------------------|--------------------------------------------|
| 100001-100003 | mcp-taint-floor.xml      | Taint floor injection detection            |
| 100500-100599 | mcp-audit-rules.xml      | General MCP audit / policy / quarantine    |
| 100600-100699 | 0960-mcp-ai-attacks.xml  | AI-specific attack patterns                |

**Namespace rules:**
- Never reuse a retired ID — Wazuh loads the last-seen definition on ID collision, silently.
- If adding a new rule file, claim a new range here first and get it reviewed.
- Sigma-generated files must not auto-assign IDs in the 100001-100003 range.

## Load Order

Wazuh loads XML rule files in filename lexicographic order. The `if_sid` directive
creates a forward-reference dependency: a child rule's `if_sid` must point to a rule
that is already loaded.

Current dependency: `mcp-taint-floor.xml` (rules 100001-100003) depends on
`mcp-audit-rules.xml` (rule 100500 — the Filebeat base event anchor).

The hyphen in `mcp-audit-rules.xml` sorts before `mcp-taint-floor.xml` in ASCII order
(hyphen 0x2D < all letters), ensuring the base rule 100500 is defined before the
taint floor rules reference it via `<if_sid>100500</if_sid>`.

**WARNING:** Do not rename either file without verifying that load order is preserved.
A rename that causes `mcp-taint-floor.xml` to load before `mcp-audit-rules.xml` will
silently break rules 100001-100003 (Wazuh will reject the forward-reference at startup
or silently ignore the `if_sid` dependency). Consider migrating to numeric prefixes
(e.g. `0100-mcp-audit-rules.xml`, `0200-mcp-taint-floor.xml`) if filenames are ever
reorganised by a Sigma CI pipeline.

## Issue 9 — INTERNAL_TOOL_INVOCATION taint denials

Rule 100001 guards on `json.event_type=^TOOL_INVOCATION$`. `INTERNAL_TOOL_INVOCATION`
events are emitted only when `tool_id is None` (auth-failure rows from AuditMiddleware,
or meta-tool calls from the /mcp dispatch path). The taint floor check in
`invocation.py` runs after tool lookup — so it always has a valid `tool_id` and always
emits `TOOL_INVOCATION`. Taint floor denials can therefore never produce
`INTERNAL_TOOL_INVOCATION` events, and the existing rules cover the full taint floor
signal. No separate rule for `INTERNAL_TOOL_INVOCATION` is required.
