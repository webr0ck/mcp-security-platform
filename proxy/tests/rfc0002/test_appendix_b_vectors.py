"""RFC-0002 Appendix B test vectors, evaluated against the spec oracle.

These prove the paper's normative algorithms are internally self-consistent —
every Appendix B row produces exactly the decision the paper claims. They run
with no gateway and no containers (pure oracle). A failure here means the SPEC
is wrong (or the oracle drifted from it), not that the gateway is wrong.
"""
from __future__ import annotations

import pytest

from .spec_oracle import (
    EffectiveClass,
    PipelineStep,
    SinkPolicy,
    TrustScope,
    check_trust_scope,
    effective_class,
    evaluate_sink_policy,
    pipeline_integrity_rank,
    trust_list_sequence_ok,
)

pytestmark = pytest.mark.oracle


# ── B.1 Content Class Policy Evaluation (two-axis: Biba ⟂ BLP, §4.4 corrected) ──

# (id, rank, primary, additional, req_int, conf_level, allowlist, expect_allow, reason)
B1_VECTORS = [
    ("B1.1 web→public sink, biba fails",
     0, "search-result/web", [], 1, "public", [], False, "biba_floor"),
    ("B1.2 web→public sink, both pass",
     1, "search-result/web", [], 1, "public", [], True, "allow"),
    ("B1.3 pii/email→public sink, blp fails",
     2, "pii/email", [], 2, "public", [], False, "blp_floor"),
    ("B1.4 pii/email→restricted sink, allowlisted",
     2, "pii/email", [], 2, "restricted", ["pii/email"], True, "allow"),
    ("B1.5 pii/email→restricted sink, allowlist required but empty",
     2, "pii/email", [], 2, "restricted", [], False, "content_class_allowlist"),
    ("B1.6 trade-order→secret sink, allowlisted",
     3, "financial/trade-order", [], 3, "secret", ["financial/trade-order"], True, "allow"),
    ("B1.7 trade-order→secret sink, biba fails",
     1, "financial/trade-order", [], 3, "secret", ["financial/trade-order"], False, "biba_floor"),
    ("B1.8 trade-order→internal sink, blp fails",
     3, "financial/trade-order", [], 3, "internal", ["financial/trade-order"], False, "blp_floor"),
    ("B1.9 pii/email + financial/balance union → secret sink, allowlisted",
     2, "pii/email", ["financial/balance"], 2, "secret", ["pii/email", "financial/*"], True, "allow"),
]


@pytest.mark.parametrize(
    "label,rank,primary,additional,req_int,conf_level,allowlist,expect_allow,reason",
    B1_VECTORS,
    ids=[v[0] for v in B1_VECTORS],
)
def test_b1_content_policy(
    label, rank, primary, additional, req_int, conf_level, allowlist, expect_allow, reason
):
    eff = effective_class(primary, additional)
    policy = SinkPolicy(
        required_integrity=req_int,
        conf_level=conf_level,
        content_class_allowlist=allowlist,
    )
    decision = evaluate_sink_policy(effective_integrity=rank, eff=eff, policy=policy)
    assert decision.allow is expect_allow, f"{label}: {decision.reason}"
    assert decision.reason == reason, label


def test_b1_union_picks_strictest_floor():
    """§4.5 — the union's effective floor is the strictest member's."""
    eff = effective_class("search-result/internal", ["pii/email"])  # internal vs restricted
    assert eff.effective == "pii/email"
    assert eff.conf_floor == "restricted"
    assert eff.allowlist_required is True


# ── B.2 Pipeline Integrity Rank Propagation (§6.6 minimum) ──────────────────────

def test_b2_1_web_taint_propagates():
    steps = [
        PipelineStep(step=1, agent_own_rank=4, tool_ranks=[0]),       # web search → 0
        PipelineStep(step=2, agent_own_rank=2, input_ranks=[0]),      # summarizer
        PipelineStep(step=3, agent_own_rank=2, input_ranks=[0]),      # composer
    ]
    assert pipeline_integrity_rank(steps) == 0


def test_b2_2_all_internal_preserves_rank():
    steps = [
        PipelineStep(step=1, agent_own_rank=4, tool_ranks=[2]),       # internal docs → 2
        PipelineStep(step=2, agent_own_rank=2, input_ranks=[2]),
        PipelineStep(step=3, agent_own_rank=2, input_ranks=[2]),
    ]
    assert pipeline_integrity_rank(steps) == 2


def test_b2_3_one_tainted_step_contaminates_downstream():
    steps = [
        PipelineStep(step=1, agent_own_rank=2, tool_ranks=[2]),       # clean internal → 2
        PipelineStep(step=2, agent_own_rank=2, input_ranks=[2], tool_ranks=[0]),  # web enrich → 0
        PipelineStep(step=3, agent_own_rank=2, input_ranks=[0]),
    ]
    assert pipeline_integrity_rank(steps) == 0


# ── B.3 Trust Scope Enforcement (§5.3) ─────────────────────────────────────────

def test_b3_1_rank_above_max_rejected():
    scope = TrustScope(max_integrity_rank=1)
    r = check_trust_scope(
        server_id="srv", integrity_rank=2,
        effective_content_class="search-result/web", scope=scope,
    )
    assert r.ok is False and r.field == "integrity_rank"


def test_b3_2_excluded_class_rejected():
    scope = TrustScope(
        max_integrity_rank=4,
        content_classes=["search-result/*"],
        content_classes_excluded=["system/credential"],
    )
    r = check_trust_scope(
        server_id="srv", integrity_rank=1,
        effective_content_class="system/credential", scope=scope,
    )
    assert r.ok is False and r.field == "content_class_excluded"


def test_b3_3_class_outside_whitelist_rejected():
    scope = TrustScope(max_integrity_rank=4, content_classes=["search-result/*", "ai-output/*"])
    r = check_trust_scope(
        server_id="srv", integrity_rank=1,
        effective_content_class="pii/email", scope=scope,
    )
    assert r.ok is False and r.field == "content_class_not_in_scope"


def test_b3_4_server_id_not_allowed_rejected():
    scope = TrustScope(max_integrity_rank=4, tool_server_ids=["server-search", "server-kb"])
    r = check_trust_scope(
        server_id="server-financial", integrity_rank=1,
        effective_content_class="search-result/web", scope=scope,
    )
    assert r.ok is False and r.field == "server_id"


def test_b3_valid_envelope_in_scope_accepted():
    scope = TrustScope(
        max_integrity_rank=2,
        tool_server_ids=["server-search"],
        content_classes=["search-result/*"],
    )
    r = check_trust_scope(
        server_id="server-search", integrity_rank=1,
        effective_content_class="search-result/web", scope=scope,
    )
    assert r.ok is True and r.field is None


# ── §5.2 / §8.2 Trust List rollback prevention ─────────────────────────────────

@pytest.mark.parametrize(
    "last,incoming,ok",
    [(47, 48, True), (47, 47, False), (47, 40, False), (0, 1, True)],
)
def test_trust_list_sequence_monotonic(last, incoming, ok):
    assert trust_list_sequence_ok(last_accepted=last, incoming=incoming) is ok
