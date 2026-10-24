-- V088__backfill_server_owner_grants.sql
-- F-CX-003: server_role_grant was never populated for self-service
-- submissions (only owner_sub on server_registry was set), so every
-- existing submission owner is 403'd by _require_server_owner even after
-- their server is approved and active. Backfill a server_owner grant for
-- every non-deleted server from its existing owner_sub. New submissions get
-- this row at draft-creation time (see app/routers/submission.py).
INSERT INTO server_role_grant (server_id, principal_id, principal_type, role, granted_by)
SELECT server_id, owner_sub, 'human', 'server_owner', owner_sub
FROM server_registry
WHERE deleted_at IS NULL
  AND owner_sub IS NOT NULL
  AND owner_sub <> ''
ON CONFLICT (server_id, principal_id, principal_type, role) DO NOTHING;
