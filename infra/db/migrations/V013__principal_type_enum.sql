-- V013__principal_type_enum.sql
-- Typed principal namespace for human/agent/kc_group separation (v3 spec).
-- human: OIDC users authenticated via Keycloak or session JWT.
-- agent: machine principals authenticated via mTLS client certificate.
-- kc_group: Keycloak group identifier (used in server_role_grant for group-level grants).
DO $$ BEGIN
    CREATE TYPE principal_type_enum AS ENUM ('human', 'agent', 'kc_group');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
