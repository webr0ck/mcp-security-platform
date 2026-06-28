"""RFC-0002 SPECIFICATION ORACLE — reference decision logic for §4–§6.

THIS IS NOT THE GATEWAY IMPLEMENTATION. As of this draft, the gateway implements
only the RFC-0001 / §3.2 signed-envelope substrate (TrustLabeler, TrustVerifier,
taint floor). RFC-0002 §4 (content classification / BLP), §5 (federation / trust
list / trust scope), and §6 (AI provenance / pipeline taint) have NO code in the
gateway yet.

This module encodes the *normative decision logic* of those sections as pure,
deterministic functions so that:

  1. The spec's own Appendix B test vectors (B.1 policy eval, B.2 pipeline rank,
     B.3 trust scope) can be verified for internal self-consistency — proving the
     paper's algorithms actually produce the outcomes the paper claims.
  2. The malicious-vs-normal scenarios in the verification plan have an executable
     judge.
  3. When the gateway eventually implements §4–§6, this oracle is the conformance
     target: the gateway's decisions MUST match the oracle's for every vector.

Everything here is traceable to a section of
docs/rfc/RFC-0002-mcp-content-classification-federated-trust-ai-provenance.md.
No gateway/runtime dependency — pure stdlib.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch

# ─────────────────────────────────────────────────────────────────────────────
# §4.2 Content Class Registry (subset sufficient for the test vectors + scenarios)
# Each entry: confidentiality floor + whether the class requires explicit sink
# allowlisting. The registry is the AUTHORITATIVE source — content classes are
# proxy-assigned, never read from the tool result (§4.1 P1).
# ─────────────────────────────────────────────────────────────────────────────

# §4.2 confidentiality lattice, least → most restrictive.
CONF_ORDER: list[str] = ["public", "internal", "restricted", "secret", "top-secret"]


def conf_index(level: str) -> int:
    """Numeric rank of a confidentiality level for <=/> comparisons."""
    try:
        return CONF_ORDER.index(level)
    except ValueError as exc:  # pragma: no cover - guards against typos in vectors
        raise ValueError(f"unknown confidentiality level: {level!r}") from exc


# class_id -> (conf_floor, allowlist_required)
CONTENT_CLASS_REGISTRY: dict[str, tuple[str, bool]] = {
    # pii/*
    "pii/email": ("restricted", True),
    "pii/name": ("restricted", True),
    "pii/ssn": ("secret", True),
    "pii/dob": ("restricted", True),
    "pii/health": ("secret", True),
    "pii/biometric": ("top-secret", True),
    "pii/generic": ("restricted", True),
    # financial/*
    "financial/trade-order": ("secret", True),
    "financial/balance": ("restricted", True),
    "financial/transaction": ("restricted", True),
    "financial/payment-instrument": ("secret", True),
    "financial/generic": ("restricted", True),
    # medical/*
    "medical/diagnosis": ("secret", True),
    "medical/generic": ("restricted", True),
    # code/*
    "code/source": ("internal", False),
    "code/script": ("internal", True),
    "code/generic": ("internal", False),
    # search-result/*
    "search-result/web": ("public", False),
    "search-result/internal": ("internal", False),
    "search-result/restricted": ("restricted", False),
    # system/* (D1: renamed from system-* to match spec §2 <domain>/<subtype> format)
    "system/config": ("secret", True),
    "system/credential": ("top-secret", True),
    "system/log": ("internal", False),
    "system/generic": ("internal", False),
    # user-data/*
    "user-data/content": ("restricted", True),
    "user-data/generic": ("restricted", True),
    # external-content/*  (P5 unknown-class default lives here)
    "external-content/raw": ("public", False),
    "external-content/processed": ("public", False),
    "external-content/vendor": ("internal", False),
    # ai-output/*
    "ai-output/llm-response": ("public", False),
    "ai-output/agent-document": ("internal", False),
    "ai-output/pipeline-report": ("internal", False),
    "ai-output/code": ("internal", True),
}

# §4.1 P5: fail-closed default for an unknown / unassigned content class.
UNKNOWN_CLASS_DEFAULT = "external-content/raw"


def class_floor(class_id: str) -> str:
    """Confidentiality floor for a class. Unknown classes are NOT silently
    trusted; the caller is expected to substitute the P5 default first via
    `normalise_class`. This raises so a typo in a vector is caught loudly."""
    if class_id not in CONTENT_CLASS_REGISTRY:
        raise KeyError(f"unregistered content class: {class_id!r}")
    return CONTENT_CLASS_REGISTRY[class_id][0]


def class_allowlist_required(class_id: str) -> bool:
    return CONTENT_CLASS_REGISTRY[class_id][1]


def normalise_class(class_id: str | None) -> str:
    """§4.1 P5 — an absent or unrecognised class maps to the restrictive default."""
    if not class_id or class_id not in CONTENT_CLASS_REGISTRY:
        return UNKNOWN_CLASS_DEFAULT
    return class_id


# ─────────────────────────────────────────────────────────────────────────────
# §4.5 Multi-class union — effective class = strictest confidentiality floor.
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class EffectiveClass:
    effective: str
    conf_floor: str
    allowlist_required: bool
    members: list[str]


def effective_class(primary: str, additional: list[str] | None = None) -> EffectiveClass:
    """§4.5 union rule: the effective class is the member with the strictest
    (highest) confidentiality floor; allowlist_required is the OR across members.
    Ties on floor are broken deterministically (first by registry strictness then
    input order) — the floor value is what drives policy (§4.5)."""
    members = [normalise_class(primary)] + [normalise_class(c) for c in (additional or [])]
    # pick the strictest floor; stable on ties (keeps first-seen)
    eff = max(members, key=lambda c: (conf_index(class_floor(c)),))
    floor = class_floor(eff)
    allow_req = any(class_allowlist_required(c) for c in members)
    return EffectiveClass(
        effective=eff, conf_floor=floor, allowlist_required=allow_req, members=members
    )


# ─────────────────────────────────────────────────────────────────────────────
# §4.6 Sink policy + §4.4 two-axis evaluation (CORRECTED matrix: the BLP axis
# compares content floor to the SINK's conf_level, independently of Biba rank).
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SinkPolicy:
    required_integrity: int                       # §3.2 Biba floor
    conf_level: str                               # §4.6 sink clearance
    content_class_allowlist: list[str] = field(default_factory=list)
    content_class_denylist: list[str] = field(default_factory=list)
    require_content_class: bool = False
    max_additional_classes: int | None = None


@dataclass
class Decision:
    allow: bool
    reason: str            # "allow" or the deny_reason code from §4.8.5


def _class_matches(class_id: str, patterns: list[str]) -> bool:
    """Wildcard match per §4.5: `pii/*` matches `pii/<subtype>`, `*` matches any."""
    for p in patterns:
        if p == "*" or p == class_id or fnmatch(class_id, p):
            return True
    return False


def evaluate_sink_policy(
    *,
    effective_integrity: int,
    eff: EffectiveClass | None,
    policy: SinkPolicy,
) -> Decision:
    """§4.6 policy evaluation order. Returns the FIRST failing step's reason.

    Order (MUST, §4.6):
      1. Biba   : effective_integrity >= required_integrity
      2. BLP    : conf_floor(effective_class) <= sink.conf_level
      3. Denylist : effective + every additional class NOT in denylist
      4. Allowlist: if allowlist required (class) OR sink allowlist non-empty,
                    effective class must match an allowlist entry
      5. Require-class: if require_content_class, a class must be present
      6. Max-additional: len(additional) <= max_additional_classes
    """
    # Step 5 is also a presence gate that must run even when eff is None.
    if eff is None:
        if policy.require_content_class:
            return Decision(False, "content_class_missing")
        # No class info — P5 says treat as the restrictive default for BLP.
        eff = effective_class(UNKNOWN_CLASS_DEFAULT)

    # 1. Biba (orthogonal to BLP — §4.4 P4)
    if effective_integrity < policy.required_integrity:
        return Decision(False, "biba_floor")

    # 2. BLP "no write down": content floor must be <= sink clearance.
    if conf_index(eff.conf_floor) > conf_index(policy.conf_level):
        return Decision(False, "blp_floor")

    # 3. Denylist takes precedence over allowlist (§4.6).
    for c in eff.members:
        if _class_matches(c, policy.content_class_denylist):
            return Decision(False, "content_class_denylist")

    # 4. Allowlist gate. Applies if the class requires it OR the sink declares one.
    allowlist_active = eff.allowlist_required or bool(policy.content_class_allowlist)
    if allowlist_active:
        if not policy.content_class_allowlist:
            # allowlist required but the sink lists nothing → deny (B.1 row 5)
            return Decision(False, "content_class_allowlist")
        if not _class_matches(eff.effective, policy.content_class_allowlist):
            return Decision(False, "content_class_allowlist")

    # 5. Require-class (presence already satisfied here).
    # 6. Max-additional.
    if policy.max_additional_classes is not None:
        n_additional = max(0, len(eff.members) - 1)
        if n_additional > policy.max_additional_classes:
            return Decision(False, "content_class_count")

    return Decision(True, "allow")


# ─────────────────────────────────────────────────────────────────────────────
# §6.5 / §6.6 Pipeline taint propagation (Biba minimum across steps) and the
# effective-class inheritance that defeats BLP declassification laundering (§8.6).
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PipelineStep:
    step: int
    agent_own_rank: int
    input_ranks: list[int] = field(default_factory=list)
    tool_ranks: list[int] = field(default_factory=list)
    content_class: str | None = None  # the class this step contributes


def step_rank(s: PipelineStep) -> int:
    """§6.6 formal rule: output rank = min(own, all input ranks, all tool ranks)."""
    candidates = [s.agent_own_rank, *s.input_ranks, *s.tool_ranks]
    return min(candidates)


def pipeline_integrity_rank(steps: list[PipelineStep]) -> int:
    """§6.5: APE top-level integrity_rank = min(step_rank for all steps)."""
    if not steps:
        return 0
    return min(step_rank(s) for s in steps)


def pipeline_effective_class(steps: list[PipelineStep]) -> EffectiveClass:
    """§8.6 Layer 1: the final artifact's effective class is the union (strictest
    floor) across every step's content class — so an `ai-output/llm-response`
    whose pipeline ingested `pii/ssn` inherits `pii/ssn` and cannot be laundered
    down to a public floor."""
    classes = [normalise_class(s.content_class) for s in steps if s.content_class]
    if not classes:
        return effective_class(UNKNOWN_CLASS_DEFAULT)
    return effective_class(classes[0], classes[1:])


# ─────────────────────────────────────────────────────────────────────────────
# §5.3 Trust scope enforcement (federation) + §5.2 rollback check (§8.2 Threat 1).
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class TrustScope:
    max_integrity_rank: int
    tool_server_ids: list[str] | None = None
    tool_server_id_pattern: str | None = None
    content_classes: list[str] | None = None
    content_classes_excluded: list[str] = field(default_factory=list)


@dataclass
class ScopeResult:
    ok: bool
    field: str | None  # which scope field failed (for trust_scope_violation logs)


def check_trust_scope(
    *,
    server_id: str,
    integrity_rank: int,
    effective_content_class: str,
    scope: TrustScope,
) -> ScopeResult:
    """§5.3 enforcement, in spec order. Performed by the RECEIVING verifier."""
    # 3. server_id allowlist
    if scope.tool_server_ids is not None and server_id not in scope.tool_server_ids:
        if not (scope.tool_server_id_pattern and fnmatch(server_id, scope.tool_server_id_pattern)):
            return ScopeResult(False, "server_id")
    # 4. server_id pattern (only enforced as a sole constraint when ids absent)
    if (
        scope.tool_server_ids is None
        and scope.tool_server_id_pattern is not None
        and not fnmatch(server_id, scope.tool_server_id_pattern)
    ):
        return ScopeResult(False, "server_id")
    # 5. max integrity rank
    if integrity_rank > scope.max_integrity_rank:
        return ScopeResult(False, "integrity_rank")
    # 7. excluded classes take precedence
    if _class_matches(effective_content_class, scope.content_classes_excluded):
        return ScopeResult(False, "content_class_excluded")
    # 6. content_classes whitelist
    if scope.content_classes is not None and not _class_matches(
        effective_content_class, scope.content_classes
    ):
        return ScopeResult(False, "content_class_not_in_scope")
    return ScopeResult(True, None)


def trust_list_sequence_ok(*, last_accepted: int, incoming: int) -> bool:
    """§5.2 / §8.2 Threat 1: reject a Trust List whose sequence number is <= the
    last accepted one (rollback prevention)."""
    return incoming > last_accepted
