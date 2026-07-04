-- V049__server_registry_sbom_components.sql
-- R-9: textual manifest-parsed SBOM inventory (declared, unresolved deps).
--
-- submission_scanner.py already clones repo submissions to run trufflehog/
-- pip-audit (R-0's accepted proxy-container trust boundary). This column
-- lets it also stash a best-effort, regex/stdlib-only parse of
-- requirements.txt / pyproject.toml / package.json (name/version/purl,
-- no resolution, no code execution) so that later, when a tool_registry row
-- is created for this server (discover-tools today; R-10's auto-provision
-- path tomorrow — same insertion point), the parsed components can be
-- merged into that tool's CycloneDX SBOM instead of shipping only the
-- single schema-digest attestation component.
--
-- NULL means "never scanned with a repo" (no-code submission, or scanned
-- before this migration). Empty array '[]' means "scanned, no manifest
-- file found". This distinction is deliberately preserved, not collapsed.

ALTER TABLE server_registry
    ADD COLUMN IF NOT EXISTS sbom_components JSONB;

COMMENT ON COLUMN server_registry.sbom_components IS
    'R-9: best-effort manifest-parsed dependency list ([{name,version,purl}]) '
    'from the submission repo scan. NULL = never scanned; [] = scanned, no '
    'manifest found. Declared/unresolved only -- not a transitive graph.';
