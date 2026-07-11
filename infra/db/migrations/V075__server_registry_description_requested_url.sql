-- V075__server_registry_description_requested_url.sql
-- Submission review gap: the wizard's "What does this server do?" answer
-- (description) was collected client-side and even sent in the
-- POST /api/v1/submissions body, but server_registry had no `description`
-- column — it was silently dropped before ever reaching a reviewer. A
-- reviewer approving a submission could not see what it claimed to do.
--
-- Also adds requested_upstream_url: an informational, submitter-supplied
-- statement of where the backend will run, shown to reviewers ahead of
-- approval. This is NOT the SSRF-gated, invocation-authoritative
-- upstream_url column (that stays empty until POST .../provide-url runs
-- the real validate_upstream_url_ssrf check post-approval) — it exists so
-- a reviewer isn't approving a server whose intended backend is a total
-- unknown, mirroring the existing requested-vs-approved pattern already
-- used for upstream_idp_config/approved_upstream_idp_config.
--
-- Additive/nullable, INV-011.

ALTER TABLE server_registry ADD COLUMN IF NOT EXISTS
    description TEXT;

ALTER TABLE server_registry ADD COLUMN IF NOT EXISTS
    requested_upstream_url TEXT;

COMMENT ON COLUMN server_registry.description IS
    'Submitter-supplied "what does this server do" — collected by the wizard, shown to reviewers.';

COMMENT ON COLUMN server_registry.requested_upstream_url IS
    'Submitter-stated intended backend URL, informational only. NOT SSRF-validated and NOT used for '
    'invocation — the authoritative upstream_url is only set post-approval via provide-url/apply.';
