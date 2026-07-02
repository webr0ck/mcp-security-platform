"""RFC-0002 §5 — Federated Trust Architecture.

Minimal Trust List loader + trust-scope enforcer.
Federation is SPECIFIED for the lab; full M-of-N governance, transparency-log
inclusion-proof verification, and cross-gateway forwarding are Future Work (§12).
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_LAST_ACCEPTED_SEQUENCE: dict[str, int] = {}  # ponytail: in-memory; persist if needed


@dataclass
class TrustEntry:
    entry_id: str
    org_id: str
    gateway_id: str
    sub_ca_spki_fp: str
    valid_from: str
    valid_until: str
    trust_scope: dict[str, Any]
    transparency_log: dict[str, Any] = field(default_factory=dict)


@dataclass
class TrustList:
    schema_version: str
    list_id: str
    sequence: int
    issued_at: str
    expires_at: str
    governance_root_key_id: str
    entries: list[TrustEntry]
    revoked_entries: list[dict[str, Any]] = field(default_factory=list)


def load_trust_list(source: str | Path | dict) -> TrustList:
    """Load a Trust List from a file path or a pre-parsed dict.

    Validates the sequence monotonicity (§5.2 anti-rollback).
    Full signature verification over the trust list body is Future Work.
    """
    if isinstance(source, (str, Path)):
        data = json.loads(Path(source).read_text())
    else:
        data = source

    list_id = data["list_id"]
    sequence = int(data["sequence"])

    last = _LAST_ACCEPTED_SEQUENCE.get(list_id, -1)
    if sequence <= last:
        raise ValueError(
            f"Trust List rollback rejected: list_id={list_id!r} "
            f"sequence={sequence} <= last_accepted={last}"
        )
    _LAST_ACCEPTED_SEQUENCE[list_id] = sequence

    entries = [
        TrustEntry(
            entry_id=e["entry_id"],
            org_id=e["org_id"],
            gateway_id=e["gateway_id"],
            sub_ca_spki_fp=e["sub_ca_spki_fp"],
            valid_from=e["valid_from"],
            valid_until=e["valid_until"],
            trust_scope=e.get("trust_scope", {}),
            transparency_log=e.get("transparency_log", {}),
        )
        for e in data.get("entries", [])
    ]

    return TrustList(
        schema_version=data.get("schema_version", "0.1"),
        list_id=list_id,
        sequence=sequence,
        issued_at=data["issued_at"],
        expires_at=data["expires_at"],
        governance_root_key_id=data.get("governance_root_key_id", ""),
        entries=entries,
        revoked_entries=data.get("revoked_entries", []),
    )


def _glob_match(value: str, patterns: list[str]) -> bool:
    return any(fnmatch(value, p) for p in patterns)


def check_trust_scope(
    *,
    envelope_server_id: str,
    envelope_integrity_rank: int,
    envelope_content_class: str,
    trust_scope: dict[str, Any],
) -> tuple[bool, str]:
    """§5.3 trust-scope enforcement. Returns (ok, deny_reason)."""
    server_ids: list[str] = trust_scope.get("tool_server_ids", [])
    server_pattern: str | None = trust_scope.get("tool_server_id_pattern")
    max_rank: int = trust_scope.get("max_integrity_rank", 4)
    allowed_classes: list[str] = trust_scope.get("content_classes", [])
    excluded_classes: list[str] = trust_scope.get("content_classes_excluded", [])

    if server_ids and envelope_server_id not in server_ids:
        if server_pattern and not fnmatch(envelope_server_id, server_pattern):
            return False, "trust_scope_violation"
        if not server_pattern:
            return False, "trust_scope_violation"

    if envelope_integrity_rank > max_rank:
        return False, "trust_scope_violation"

    if allowed_classes and not _glob_match(envelope_content_class, allowed_classes):
        return False, "trust_scope_violation"

    if excluded_classes and _glob_match(envelope_content_class, excluded_classes):
        return False, "trust_scope_violation"

    return True, "ok"
