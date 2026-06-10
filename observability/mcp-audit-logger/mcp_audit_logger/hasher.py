"""
MCP Audit Logger — SHA-256 Hasher

Computes a SHA-256 hash over the canonical JSON representation of an audit entry.
The hash is computed BEFORE redaction so it covers the original field values.
This ensures that compliance checkers can verify log integrity independently.

Per INV-001: every audit event must have an integrity hash.
Per INV-007: hashes stored in PostgreSQL are verified by the compliance checker.

Single source of truth for canonicalization (Task 0.2):
  Both the writer (MCPAuditLogger.emit) and the verifier (compliance-checker
  verify_hash_integrity) import canonical_audit_json() from this module.
  No duplicate canonicalization logic may exist elsewhere.

Canonical fields (ordered for stability):
  event_id, event_type, timestamp, client_id, tool_name, tool_id,
  outcome, request_id, platform_version

The "outcome" field used for hashing is the PRE-remap value (e.g. "error"),
stored in the `original_outcome` column alongside the DB-constraint-safe
remapped `outcome` column.  The compliance checker reads `original_outcome`
when recomputing (see verify_hash_integrity in checker.py).
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

# Ordered list of fields included in the canonical form.  The order is fixed
# so that future additions never silently change the hash for existing rows
# (new fields are appended; they affect only rows written after the change).
CANONICAL_FIELDS: tuple[str, ...] = (
    "event_id",
    "event_type",
    "timestamp",
    "client_id",
    "tool_name",
    "tool_id",
    "outcome",
    "request_id",
    "platform_version",
)


def canonical_json(data: dict[str, Any]) -> str:
    """
    Serialize a dictionary to canonical JSON (sorted keys, no extra whitespace).

    Canonical form is required so that the same data always produces the same hash,
    regardless of key insertion order.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def sha256_hash(data: dict[str, Any]) -> str:
    """
    Compute SHA-256 over the canonical JSON representation of a dictionary.

    Returns a hex-encoded digest string (64 characters).
    """
    serialized = canonical_json(data)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def canonical_audit_json(entry_dict: dict[str, Any]) -> str:
    """
    Return the canonical JSON string for an audit entry.

    This is the SINGLE authoritative serialization used by both the writer
    (emit path) and the verifier (compliance-checker).  Import this function
    — never inline the field selection or json.dumps call.

    The "outcome" field is read from `original_outcome` if present (pre-remap
    value); otherwise falls back to `outcome`.  This handles the invocation.py
    error→deny remap transparently for both writer and verifier.
    """
    # Use original_outcome when present so error-outcome rows hash correctly
    # even after the DB-constraint remap to "deny".
    outcome_value = entry_dict.get("original_outcome") or entry_dict.get("outcome")

    core_fields = {
        "event_id": entry_dict.get("event_id"),
        "event_type": entry_dict.get("event_type"),
        "timestamp": entry_dict.get("timestamp"),
        "client_id": entry_dict.get("client_id"),
        "tool_name": entry_dict.get("tool_name"),
        "tool_id": entry_dict.get("tool_id"),
        "outcome": outcome_value,
        "request_id": entry_dict.get("request_id"),
        "platform_version": entry_dict.get("platform_version"),
    }
    return canonical_json(core_fields)


def hash_audit_entry(entry_dict: dict[str, Any]) -> str:
    """
    Compute the integrity hash for an audit log entry.

    Uses only the stable identity fields — not derived or mutable fields —
    so the hash can be independently recomputed from core event data.

    Delegates to canonical_audit_json() to guarantee a single canonicalization.
    """
    return hashlib.sha256(
        canonical_audit_json(entry_dict).encode("utf-8")
    ).hexdigest()
