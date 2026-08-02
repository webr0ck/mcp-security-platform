-- R6.1: continuous attestation baseline for self-hosted servers.
--
-- A self-hosted server is approved on a point-in-time check (repo scanned, reviewer
-- approved, verification probes passed once at provide-url time) and then trusted
-- indefinitely. Changing the registered URL is guarded by request-change, but swapping
-- what is served AT THE SAME URL was invisible: tool discovery is idempotent-skip, so a
-- name already in tool_registry is never re-read.
--
-- The baseline must be captured by the SAME probe that later reads it
-- (server_lifecycle.fetch_live_tool_schema). It deliberately does NOT reuse
-- last_good_tool_schema: that column is filled from snapshot_tool_schema, i.e. from
-- tool_registry, whose `name` is a platform-side alias and whose `schema` is a
-- normalized rewrite of the upstream inputSchema. Those two shapes are not comparable —
-- diffing them reports drift for every server, always.
ALTER TABLE server_registry
    ADD COLUMN IF NOT EXISTS attested_tool_schema jsonb,
    ADD COLUMN IF NOT EXISTS attested_at          timestamptz;

COMMENT ON COLUMN server_registry.attested_tool_schema IS
    'R6.1: last attested LIVE tool surface, as returned by fetch_live_tool_schema. '
    'Compared against a fresh probe by the periodic attestation sweep. Live-vs-live — '
    'never populate this from tool_registry (see V087 header).';
COMMENT ON COLUMN server_registry.attested_at IS
    'R6.1: when attested_tool_schema was captured. NULL means never attested; the sweep '
    'records a trust-on-first-use baseline and logs it.';
