# Archived docs — historical, do not rely on

These documents are **superseded or point-in-time snapshots**. They are kept for provenance and to
show how the design evolved, but they do **not** describe the current system. For the current state
see [`../ARCHITECTURE-v2.md`](../ARCHITECTURE-v2.md) and the root [`README.md`](../../README.md)
Enforced-vs-Roadmap table.

| File | Why archived |
|---|---|
| `ARCHITECTURE-v1.md` | v1.0.0 architecture — explicitly superseded by `ARCHITECTURE-v2.md`; omits the credential broker, Vault, `credential_store`, and OAuth router. |
| `REVIEW-2026-05-16.md` | Dated AppSec review snapshot. Its CRITICAL/HIGH findings have since been fixed and tested (tracked in `ARCHITECTURE-v2.md` Phase 0). |
| `SHIP-v0.1.md` | One-time v0.1 ship checklist. Superseded by `make ship-check` (`scripts/ship-check.sh`). |
