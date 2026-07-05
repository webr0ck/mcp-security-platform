-- V059__tool_registry_credential_id_fk.sql
-- Validation-2026-07-05 Secondary-High: tool_registry.credential_id had no FK
-- constraint, so nothing structurally prevented binding a tool to a
-- non-existent (or stale/dangling) credential_store row.
--
-- V027 deliberately omitted the FK, but its stated reasons don't hold:
--   * "credentials may be rotated without changing tool_id" — rotation UPDATEs
--     credential_store.encrypted_blob; the PK `id` is unchanged, so the FK stays valid.
--   * "tools may be deleted without removing their credentials" — deleting a
--     tool_registry row does not touch credential_store; the FK is on the tool side.
--   * The one real concern (a credential_store row being deleted while referenced)
--     is handled by ON DELETE SET NULL: the tool's credential_id drops to NULL and
--     the dispatcher fails closed (dispatcher.py: "no credential_id -> raise"),
--     which is the safe outcome, not a dangling pointer.
-- Verified: zero orphaned tool_registry.credential_id rows before adding this.

ALTER TABLE tool_registry
    DROP CONSTRAINT IF EXISTS fk_tool_registry_credential_id;
ALTER TABLE tool_registry
    ADD CONSTRAINT fk_tool_registry_credential_id
    FOREIGN KEY (credential_id) REFERENCES credential_store (id) ON DELETE SET NULL;
