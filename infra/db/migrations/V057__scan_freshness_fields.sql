-- V057__scan_freshness_fields.sql
-- PRD-0006 R-1: record WHEN a submission scan ran and against WHICH commit, so
-- the registration-time audit can (a) apply a code-scan risk floor and (b)
-- surface staleness when that floor fires on a scan that may predate a repo fix.
--
-- 3-critic F-3: scan_report (V044) has no commit SHA / no scanned_at, so a
-- block-tier finding from a superseded scan would floor a fixed tool with no
-- staleness signal. These two columns provide that signal.

ALTER TABLE server_registry
    ADD COLUMN IF NOT EXISTS scanned_at  TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS scan_commit TEXT;

COMMENT ON COLUMN server_registry.scanned_at IS
    'PRD-0006 R-1: when the submission scanner last ran for this server.';
COMMENT ON COLUMN server_registry.scan_commit IS
    'PRD-0006 R-1: git commit SHA the last scan ran against (for staleness detection at re-audit).';
