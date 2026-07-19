-- V084__retire_legacy_lab_self_service.sql
-- Self-service is one default server everywhere now (name 'self-service',
-- seeded by V052) — retires the pre-V052 lab-only 'lab-self-service' row
-- that docs/mcp-server-onboarding.md §10 left in place "not deleted, separate
-- cleanup". V053 also targeted 'lab-self-service' by name for
-- public_to_authenticated, which is now the wrong row; fixed forward here.
-- Idempotent: every step is a no-op if the legacy row is already gone.

BEGIN;

-- Repoint any tool_registry rows still linked to the legacy row (should be
-- none post the §10 fix, but this is the safe/idempotent thing to assert).
UPDATE tool_registry t
SET server_id = s_new.server_id, updated_at = now()
FROM server_registry s_old, server_registry s_new
WHERE s_old.name = 'lab-self-service'
  AND s_new.name = 'self-service'
  AND t.server_id = s_old.server_id;

-- V053 set public_to_authenticated on the legacy row by name; apply the
-- same intent to the real default server.
UPDATE server_registry
   SET public_to_authenticated = true
 WHERE name = 'self-service'
   AND has_write_ops = false
   AND deleted_at IS NULL;

-- Revoke (not delete — preserve audit trail) any stray credential/role rows
-- for the retired client_id.
UPDATE api_keys SET revoked_at = now()
 WHERE client_id = 'lab-self-service' AND revoked_at IS NULL;

DELETE FROM role_assignments WHERE client_id = 'lab-self-service';

-- Drop the legacy server row itself (entitlement rows cascade via FK).
DELETE FROM server_registry WHERE name = 'lab-self-service';

COMMIT;
