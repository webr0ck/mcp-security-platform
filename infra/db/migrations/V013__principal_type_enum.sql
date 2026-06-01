-- V013__principal_type_enum.sql
-- Typed principal namespace for human/agent/kc_group separation (v3 spec)
CREATE TYPE principal_type_enum AS ENUM ('human', 'agent', 'kc_group');
