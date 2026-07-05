-- V052__wizard_prompts.sql
-- Admin-editable overrides for the self-service submission wizard's design
-- prompts (the "what should the server provide / what to ask the user" text).
--
-- Absent row = use the code default (app/services/scaffold_generator.py
-- _PROMPTS/_SHARED_PROMPTS). Only overrides are stored here, mirroring the
-- NULL/absent = default convention used by client_limits (V040).
--
-- prompt_key format: "<mode>.<id>" for mode-specific prompts, "shared.<id>"
-- for the shared block (see prompt_store.default_prompts()).

CREATE TABLE IF NOT EXISTS wizard_prompts (
    prompt_key  TEXT PRIMARY KEY,
    prompt_text TEXT NOT NULL CHECK (length(prompt_text) BETWEEN 1 AND 4000),
    updated_by  TEXT,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE wizard_prompts IS
    'Admin overrides for self-service wizard design prompts; absent row = code default.';
