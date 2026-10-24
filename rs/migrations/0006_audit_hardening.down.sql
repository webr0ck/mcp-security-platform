-- 0006_audit_hardening.down.sql — reverse of 0006_audit_hardening.up.sql

ALTER TABLE audit_events DROP CONSTRAINT audit_events_tool_id_fkey;
ALTER TABLE audit_events
    ADD CONSTRAINT audit_events_tool_id_fkey
    FOREIGN KEY (tool_id) REFERENCES tool_registry (tool_id) ON DELETE SET NULL;

ALTER TABLE audit_events DROP CONSTRAINT audit_events_server_id_fkey;
ALTER TABLE audit_events
    ADD CONSTRAINT audit_events_server_id_fkey
    FOREIGN KEY (server_id) REFERENCES servers (server_id) ON DELETE SET NULL;

DROP TRIGGER IF EXISTS trg_audit_events_no_truncate ON audit_events;
