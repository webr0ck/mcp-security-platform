"""RFC-0002 §4 — Content Classification (BLP axis).

evaluate_sink_policy() is the gateway's authoritative BLP + Biba two-axis
policy enforcer. Logic mirrors spec_oracle.evaluate_sink_policy exactly so the
conformance tests can assert parity.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path

_REGISTRY_PATH = Path(__file__).parents[2] / "config" / "content-class-registry.json"

_CONF_ORDER = ["public", "internal", "restricted", "secret", "top-secret"]

_UNKNOWN_CLASS_DEFAULT = "external-content/raw"


def _load_registry() -> dict[str, tuple[str, bool]]:
    data = json.loads(_REGISTRY_PATH.read_text())
    return {k: (v["conf_floor"], v["allowlist_required"]) for k, v in data.items()}


_REGISTRY: dict[str, tuple[str, bool]] = _load_registry()


def _conf_index(level: str) -> int:
    return _CONF_ORDER.index(level)


def normalise_class(class_id: str | None) -> str:
    """§4.1 P5 — absent or unrecognised class → restrictive default."""
    if not class_id or class_id not in _REGISTRY:
        return _UNKNOWN_CLASS_DEFAULT
    return class_id


@dataclass
class EffectiveClass:
    effective: str
    conf_floor: str
    allowlist_required: bool
    members: list[str]


def effective_class(primary: str, additional: list[str] | None = None) -> EffectiveClass:
    """§4.5 union: strictest floor wins; allowlist_required = OR across members."""
    members = [normalise_class(primary)] + [normalise_class(c) for c in (additional or [])]
    eff = max(members, key=lambda c: _conf_index(_REGISTRY[c][0]))
    floor = _REGISTRY[eff][0]
    allow_req = any(_REGISTRY[c][1] for c in members)
    return EffectiveClass(effective=eff, conf_floor=floor, allowlist_required=allow_req, members=members)


@dataclass
class SinkPolicy:
    required_integrity: int
    conf_level: str
    content_class_allowlist: list[str] = field(default_factory=list)
    content_class_denylist: list[str] = field(default_factory=list)
    require_content_class: bool = False
    max_additional_classes: int | None = None


@dataclass
class Decision:
    allow: bool
    reason: str


def _matches(class_id: str, patterns: list[str]) -> bool:
    return any(p == "*" or p == class_id or fnmatch(class_id, p) for p in patterns)


def evaluate_sink_policy(
    *,
    effective_integrity: int,
    eff: EffectiveClass | None,
    policy: SinkPolicy,
) -> Decision:
    """§4.6 six-step evaluation. Returns first failing step's deny_reason."""
    if eff is None:
        if policy.require_content_class:
            return Decision(False, "content_class_missing")
        eff = effective_class(_UNKNOWN_CLASS_DEFAULT)

    if effective_integrity < policy.required_integrity:
        return Decision(False, "biba_floor")

    if _conf_index(eff.conf_floor) > _conf_index(policy.conf_level):
        return Decision(False, "blp_floor")

    for c in eff.members:
        if _matches(c, policy.content_class_denylist):
            return Decision(False, "content_class_denylist")

    allowlist_active = eff.allowlist_required or bool(policy.content_class_allowlist)
    if allowlist_active:
        if not policy.content_class_allowlist:
            return Decision(False, "content_class_allowlist")
        if not _matches(eff.effective, policy.content_class_allowlist):
            return Decision(False, "content_class_allowlist")

    if policy.max_additional_classes is not None:
        if max(0, len(eff.members) - 1) > policy.max_additional_classes:
            return Decision(False, "content_class_count")

    return Decision(True, "allow")
