"""Normal-vs-malicious activity scenarios for RFC-0002 §4–§6 decision logic.

Each malicious scenario maps to a threat in RFC-0002 Appendix C (T-xx) and asserts
the spec's logic DENIES it; each normal scenario asserts a legitimate flow is
ALLOWED (no over-blocking). Pure oracle — runs everywhere, no gateway needed.

These are the policy-layer twin of the cryptographic/substrate scenarios in
test_substrate_rfc0001.py (which exercise the real implemented labeler/verifier).
"""
from __future__ import annotations

import pytest

from .spec_oracle import (
    SinkPolicy,
    TrustScope,
    check_trust_scope,
    effective_class,
    evaluate_sink_policy,
    normalise_class,
    pipeline_effective_class,
    pipeline_integrity_rank,
    PipelineStep,
    trust_list_sequence_ok,
)

pytestmark = pytest.mark.oracle


# ════════════════════════════════════════════════════════════════════════════
# NORMAL ACTIVITY — legitimate flows MUST be allowed (guards against over-blocking)
# ════════════════════════════════════════════════════════════════════════════

def test_normal_internal_search_to_internal_sink():
    eff = effective_class("search-result/internal")
    policy = SinkPolicy(required_integrity=2, conf_level="internal")
    d = evaluate_sink_policy(effective_integrity=2, eff=eff, policy=policy)
    assert d.allow, d.reason


def test_normal_pii_to_cleared_allowlisted_sink():
    eff = effective_class("pii/email")
    policy = SinkPolicy(
        required_integrity=2, conf_level="restricted",
        content_class_allowlist=["pii/email"],
    )
    d = evaluate_sink_policy(effective_integrity=2, eff=eff, policy=policy)
    assert d.allow, d.reason


def test_normal_all_internal_pipeline_keeps_rank_and_flows():
    steps = [
        PipelineStep(step=1, agent_own_rank=2, tool_ranks=[2], content_class="search-result/internal"),
        PipelineStep(step=2, agent_own_rank=2, input_ranks=[2], content_class="ai-output/agent-document"),
    ]
    rank = pipeline_integrity_rank(steps)
    eff = pipeline_effective_class(steps)
    policy = SinkPolicy(required_integrity=2, conf_level="internal")
    d = evaluate_sink_policy(effective_integrity=rank, eff=eff, policy=policy)
    assert rank == 2 and d.allow, (rank, d.reason)


def test_normal_legitimate_trade_order_executes():
    """A user-integrity financial/trade-order to the trade sink is allowed."""
    eff = effective_class("financial/trade-order")
    policy = SinkPolicy(
        required_integrity=3, conf_level="secret",
        content_class_allowlist=["financial/trade-order"],
        content_class_denylist=["search-result/web", "external-content/raw",
                                "external-content/processed"],
        require_content_class=True, max_additional_classes=0,
    )
    d = evaluate_sink_policy(effective_integrity=3, eff=eff, policy=policy)
    assert d.allow, d.reason


# ════════════════════════════════════════════════════════════════════════════
# MALICIOUS ACTIVITY — each maps to an Appendix C threat; MUST be denied
# ════════════════════════════════════════════════════════════════════════════

def test_T01_content_class_spoof_ignored():
    """T-01: a tool self-asserts a favorable class (search-result/internal) while
    actually serving external content. Classes are PROXY-ASSIGNED (§4.1 P1): the
    gateway classifies from the registered server profile, not from the result.
    We model the proxy assignment and confirm the attacker's claimed class never
    enters the decision."""
    tool_self_asserted = "search-result/internal"      # attacker's claim (ignored)
    proxy_assigned = "external-content/raw"             # registry truth for this server
    eff = effective_class(proxy_assigned)               # gateway uses the registry value
    assert tool_self_asserted not in eff.members
    # external content to a financial sink that denylists it → denied
    policy = SinkPolicy(
        required_integrity=3, conf_level="secret",
        content_class_denylist=["external-content/raw", "external-content/processed"],
        content_class_allowlist=["financial/trade-order"],
    )
    d = evaluate_sink_policy(effective_integrity=3, eff=eff, policy=policy)
    assert not d.allow and d.reason == "content_class_denylist"


def test_T03_mixed_class_not_downgraded():
    """T-03: attacker mixes a low-sensitivity class with a high one hoping the
    classifier picks the lower. Union semantics (§4.5) take the STRICTEST floor."""
    eff = effective_class("search-result/web", ["pii/ssn"])  # public + secret
    assert eff.conf_floor == "secret"
    policy = SinkPolicy(required_integrity=2, conf_level="public")
    d = evaluate_sink_policy(effective_integrity=2, eff=eff, policy=policy)
    assert not d.allow and d.reason == "blp_floor"


def test_T05_unclassified_fails_closed():
    """T-05 / §4.1 P5: an unclassified result must not bypass policy. A
    require_content_class sink rejects it; otherwise it defaults to the
    restrictive external-content/raw (still gated by Biba/BLP)."""
    # require_content_class sink → explicit reject
    policy = SinkPolicy(required_integrity=1, conf_level="secret", require_content_class=True)
    d = evaluate_sink_policy(effective_integrity=4, eff=None, policy=policy)
    assert not d.allow and d.reason == "content_class_missing"
    # and the P5 default really is the restrictive class
    assert normalise_class(None) == "external-content/raw"
    assert normalise_class("totally-made-up/class") == "external-content/raw"


def test_blp_declassification_laundering_blocked():
    """§8.6: feed pii/ssn into an LLM, relabel the output ai-output/llm-response
    (public floor) and route to a public logging sink. The pipeline effective
    class inherits pii/ssn (secret), so the public sink is DENIED."""
    steps = [
        PipelineStep(step=1, agent_own_rank=2, tool_ranks=[2], content_class="pii/ssn"),
        PipelineStep(step=2, agent_own_rank=2, input_ranks=[2], content_class="ai-output/llm-response"),
    ]
    eff = pipeline_effective_class(steps)
    assert eff.conf_floor == "secret"          # NOT laundered down to public
    logging_sink = SinkPolicy(required_integrity=1, conf_level="public")
    d = evaluate_sink_policy(
        effective_integrity=pipeline_integrity_rank(steps), eff=eff, policy=logging_sink
    )
    assert not d.allow and d.reason == "blp_floor"


def test_web_search_cannot_drive_trade():
    """The §4.6 worked example: a web search result must never drive a trade,
    even at sufficient integrity rank — the sink denylist blocks it."""
    eff = effective_class("search-result/web")
    trade_sink = SinkPolicy(
        required_integrity=3, conf_level="secret",
        content_class_allowlist=["financial/trade-order"],
        content_class_denylist=["search-result/web", "search-result/internal",
                                "external-content/raw", "external-content/processed"],
        require_content_class=True, max_additional_classes=0,
    )
    d = evaluate_sink_policy(effective_integrity=3, eff=eff, policy=trade_sink)
    assert not d.allow and d.reason == "content_class_denylist"


def test_T16_pipeline_taint_truncation_true_path_is_tainted():
    """T-16 / §8.7: an attacker hides a web-search step to claim a clean origin.
    The TRUE (untruncated) path includes a rank-0 web step, so the honest result
    is rank 0 — any sink with required_integrity>=1 denies it. (Detecting the
    truncation itself is a gateway/append-only-store concern; this asserts the
    correct verdict given the real path.)"""
    true_path = [
        PipelineStep(step=1, agent_own_rank=2, tool_ranks=[2]),
        PipelineStep(step=2, agent_own_rank=2, input_ranks=[2], tool_ranks=[0]),  # hidden web step
        PipelineStep(step=3, agent_own_rank=2, input_ranks=[0]),
    ]
    assert pipeline_integrity_rank(true_path) == 0
    policy = SinkPolicy(required_integrity=1, conf_level="public")
    d = evaluate_sink_policy(effective_integrity=0, eff=effective_class("ai-output/llm-response"), policy=policy)
    assert not d.allow and d.reason == "biba_floor"


def test_T07_T14_trust_scope_evasion_rejected():
    """T-07/T-14: a (possibly compromised) labeler asserts an integrity rank above
    its registered trust scope. The receiving verifier rejects regardless of a
    valid signature."""
    scope = TrustScope(max_integrity_rank=1, content_classes=["search-result/*"])
    r = check_trust_scope(
        server_id="ext-web", integrity_rank=4,        # claims 'system'
        effective_content_class="search-result/web", scope=scope,
    )
    assert not r.ok and r.field == "integrity_rank"


def test_T08_trust_list_rollback_rejected():
    """T-08: rollback the Trust List to re-admit a revoked sub-CA."""
    assert trust_list_sequence_ok(last_accepted=47, incoming=46) is False


def test_aggregation_to_single_type_sink_rejected():
    """max_additional_classes guards a sink that must receive single-type results."""
    eff = effective_class("financial/trade-order", ["pii/email"])
    sink = SinkPolicy(
        required_integrity=3, conf_level="secret",
        content_class_allowlist=["financial/trade-order", "pii/*"],
        max_additional_classes=0,
    )
    d = evaluate_sink_policy(effective_integrity=3, eff=eff, policy=sink)
    assert not d.allow and d.reason == "content_class_count"
