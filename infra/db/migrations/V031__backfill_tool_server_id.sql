-- V031__backfill_tool_server_id.sql
-- Task 4.4a — backfill tool_registry.server_id for legacy (NULL server_id) tools.
--
-- Strategy: URL-prefix match.
--   UPDATE tool_registry SET server_id = sr.server_id
--   WHERE tool_registry.server_id IS NULL
--     AND tool_registry.upstream_url LIKE (sr.upstream_url || '%')
--   Joining on the closest / longest matching server_registry.upstream_url.
--
-- Why URL prefix?
--   V023 added the server_id FK column but left all existing rows NULL. The
--   seeder inserts tools with upstream_url = '<base>/mcp' (e.g.
--   'http://lab-mcp-echo:8000/mcp') and server_registry rows use the base URL
--   without path (e.g. 'http://mcp-echo:8000').  A LIKE prefix match on
--   server_registry.upstream_url covers both cases (exact match and
--   base-url-is-prefix-of-tool-url).  The DISTINCT ON server_id subquery
--   picks the single longest matching server row to avoid ambiguity.
--
-- Tools with NO plausible server match (no server_registry row whose upstream_url
-- is a prefix of the tool's upstream_url, or vice-versa) are intentionally left
-- NULL.  As of 2026-06-11, the lab seeder does NOT insert server_registry rows,
-- so all lab tools (grafana-query, netbox-query, dex-calendar, gitea-repos,
-- m365-graph, rag-assistant, echo-ping, notes-store, search-kb, self-service-mcp)
-- will remain NULL after this migration.
--
-- The only known server_registry rows at migration time are those seeded by
-- deployments/poc/seed/poc-seed.sql:
--   poc-echo-server   → http://mcp-echo:8000
--   poc-notes-server  → http://mcp-notes:8000
--   poc-search-server → http://mcp-search:8000
--
-- These do NOT match any lab tool upstream URLs (lab uses 'lab-mcp-*' hostnames).
-- The verification query at the end asserts zero NULLs ONLY for tools whose
-- upstream_url matches a registered server — it DOES NOT assert that all tools
-- have a server_id (that would incorrectly fail on legitimately unlinked tools
-- until the lab seeder is extended to insert server_registry rows).
--
-- To link lab tools once their server_registry rows are created, run:
--   UPDATE tool_registry tr
--   SET server_id = sr.server_id
--   FROM server_registry sr
--   WHERE tr.server_id IS NULL
--     AND tr.deleted_at IS NULL
--     AND (tr.upstream_url LIKE (sr.upstream_url || '%')
--          OR sr.upstream_url LIKE (tr.upstream_url || '%'));

-- ── Backfill: update tool_registry rows whose upstream_url matches a server ──

UPDATE tool_registry AS tr
SET server_id = matched.server_id
FROM (
    -- For each tool URL, find the server_registry row whose upstream_url is the
    -- longest prefix of the tool URL (or exact match).  Longest-prefix wins to
    -- avoid mapping to an overly broad entry if multiple servers share a hostname.
    SELECT DISTINCT ON (tool_id)
        tr_inner.tool_id,
        sr.server_id
    FROM tool_registry   AS tr_inner
    JOIN server_registry AS sr
      ON (
            -- Case 1: server upstream_url is a prefix of the tool URL
            tr_inner.upstream_url LIKE (sr.upstream_url || '%')
            -- Case 2: exact match (both point to the same base URL)
         OR tr_inner.upstream_url = sr.upstream_url
         -- Case 3: tool URL is a prefix of the server URL
         --         (e.g. tool='http://host:8000', server='http://host:8000/mcp')
         OR sr.upstream_url LIKE (tr_inner.upstream_url || '%')
      )
    WHERE tr_inner.server_id IS NULL
      AND tr_inner.deleted_at IS NULL
      AND sr.deleted_at IS NULL
      AND sr.status = 'approved'
    ORDER BY
        tr_inner.tool_id,
        -- Prefer the longest matching upstream_url (most specific)
        LENGTH(sr.upstream_url) DESC
) AS matched
WHERE tr.tool_id = matched.tool_id;

-- ── Verification: assert no matchable tool was left NULL ──────────────────────
--
-- This DO block raises an exception if any tool_registry row STILL has
-- server_id IS NULL AND has a server_registry row that matches its upstream_url.
-- In other words: if the UPDATE above failed to link a linkable tool, the
-- migration fails loudly rather than silently leaving a gap.
--
-- Tools that have NO matching server_registry row are not asserted on — leaving
-- them NULL is the correct, documented outcome for unlinked / legacy tools.

DO $$
DECLARE
    missed_count INTEGER;
BEGIN
    SELECT COUNT(*)
    INTO missed_count
    FROM tool_registry   AS tr
    JOIN server_registry AS sr
      ON (
            tr.upstream_url LIKE (sr.upstream_url || '%')
         OR tr.upstream_url = sr.upstream_url
         OR sr.upstream_url LIKE (tr.upstream_url || '%')
      )
    WHERE tr.server_id   IS NULL
      AND tr.deleted_at  IS NULL
      AND sr.deleted_at  IS NULL
      AND sr.status      = 'approved';

    IF missed_count > 0 THEN
        RAISE EXCEPTION
            'V031 backfill verification failed: % tool(s) with a matching server_registry '
            'row still have server_id IS NULL after backfill. '
            'Check tool upstream_url vs server_registry upstream_url for those rows.',
            missed_count;
    END IF;

    RAISE NOTICE 'V031 backfill verification passed: no matchable tools left with NULL server_id.';
END
$$;

-- ── INV-011: GRANT ─────────────────────────────────────────────────────────────
-- No new objects are created; the UPDATE modifies tool_registry which proxy_app
-- already holds SELECT, INSERT, UPDATE on (V001/V003 + re-asserted in V023).
-- Re-assert SELECT idempotently so this migration is self-documenting.
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'proxy_app') THEN
        GRANT SELECT ON tool_registry TO proxy_app;
    END IF;
END
$$;
