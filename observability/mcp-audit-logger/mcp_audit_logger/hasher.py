"""
MCP Audit Logger — SHA-256 Hasher

Computes a SHA-256 hash over the canonical JSON representation of an audit entry.
The hash is computed BEFORE redaction so it covers the original field values.
This ensures that compliance checkers can verify log integrity independently.

Per INV-001: every audit event must have an integrity hash.
Per INV-007: hashes stored in PostgreSQL are verified by the compliance checker.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any


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


def hash_audit_entry(entry_dict: dict[str, Any]) -> str:
    """
    Compute the integrity hash for an audit log entry.

    Uses only the stable identity fields — not derived or mutable fields —
    so the hash can be independently recomputed from core event data.
    """
    core_fields = {
        "event_id": entry_dict.get("event_id"),
        "event_type": entry_dict.get("event_type"),
        "timestamp": entry_dict.get("timestamp"),
        "client_id": entry_dict.get("client_id"),
        "tool_name": entry_dict.get("tool_name"),
        "tool_id": entry_dict.get("tool_id"),
        "outcome": entry_dict.get("outcome"),
        "request_id": entry_dict.get("request_id"),
        "platform_version": entry_dict.get("platform_version"),
    }
    return sha256_hash(core_fields)
