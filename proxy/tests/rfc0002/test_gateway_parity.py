"""RFC-0002 §5/6 BEHAVIOURAL parity: app.services.* MUST match spec_oracle on every
Appendix B vector. This is the test the conformance skip-messages always promised."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.services import content_class as cc
from app.services import trust_list as tl
from app.services.artifact_provenance import PipelineStep, _pipeline_integrity_rank
from .spec_oracle import (
    CONTENT_CLASS_REGISTRY as ORACLE_REG,
    effective_class as oracle_eff,
    evaluate_sink_policy as oracle_eval,
    SinkPolicy as OracleSinkPolicy,
)
from .test_appendix_b_vectors import B1_VECTORS

pytestmark = pytest.mark.conformance


# ── Task 1: B1 content-class parity — MUST go green ─────────────────────────

@pytest.mark.parametrize(
    "label,rank,primary,additional,req_int,conf_level,allowlist,expect_allow,reason",
    B1_VECTORS, ids=[v[0] for v in B1_VECTORS],
)
def test_b1_impl_matches_oracle(label, rank, primary, additional, req_int,
                                conf_level, allowlist, expect_allow, reason):
    o = oracle_eval(
        effective_integrity=rank,
        eff=oracle_eff(primary, additional),
        policy=OracleSinkPolicy(required_integrity=req_int, conf_level=conf_level,
                                content_class_allowlist=allowlist),
    )
    i = cc.evaluate_sink_policy(
        effective_integrity=rank,
        eff=cc.effective_class(primary, additional),
        policy=cc.SinkPolicy(required_integrity=req_int, conf_level=conf_level,
                             content_class_allowlist=allowlist),
    )
    assert (i.allow, i.reason) == (o.allow, o.reason) == (expect_allow, reason), label


def test_b1_union_strictest_floor_impl():
    eff = cc.effective_class("search-result/internal", ["pii/email"])
    assert eff.effective == "pii/email"
    assert eff.conf_floor == "restricted"
    assert eff.allowlist_required is True


# ── Task 2: Pipeline rank parity — MUST go green ─────────────────────────────

# D2: impl PipelineStep carries one integrity_rank/step; the oracle's own/input/tool
# decomposition (B.2) is NOT representable here. We test the impl at its abstraction:
# min across pre-reduced step ranks. Closing D2 (full decomposition) is a Phase-1 design item.
@pytest.mark.parametrize("ranks,expected", [
    ([4, 2, 2], 2), ([2, 0, 2], 0), ([], 0), ([4], 4),
])
def test_pipeline_rank_is_min(ranks, expected):
    steps = [PipelineStep(agent_id=f"a{i}", action="x", integrity_rank=r)
             for i, r in enumerate(ranks)]
    assert _pipeline_integrity_rank(steps) == expected


# ── Task 3: Trust-scope B3 parity — xfail(strict) pinned to N1/N2 ────────────

# B.3 cases mapped to impl API: (label, server_id, rank, eff_class, scope_dict, oracle_ok)
B3_IMPL = [
    ("B3.1 rank>max", "srv", 2, "search-result/web",
     {"max_integrity_rank": 1}, False),
    ("B3.2 excluded", "srv", 1, "system/credential",
     {"max_integrity_rank": 4, "content_classes": ["search-result/*"],
      "content_classes_excluded": ["system/credential"]}, False),
    ("B3.3 not in whitelist", "srv", 1, "pii/email",
     {"max_integrity_rank": 4, "content_classes": ["search-result/*", "ai-output/*"]}, False),
    ("B3.4 server not allowed", "server-financial", 1, "search-result/web",
     {"max_integrity_rank": 4, "tool_server_ids": ["server-search", "server-kb"]}, False),
    ("B3.5 valid in scope", "server-search", 1, "search-result/web",
     {"max_integrity_rank": 2, "tool_server_ids": ["server-search"],
      "content_classes": ["search-result/*"]}, True),
    # N1 trigger: pattern-only scope; oracle rejects evil-server, impl wrongly accepts
    ("N1 pattern-only", "evil-server", 1, "search-result/web",
     {"tool_server_id_pattern": "acme-prod-*", "max_integrity_rank": 4}, False),
]


@pytest.mark.conformance
@pytest.mark.xfail(
    strict=True,
    reason="N1 (pattern-only scope no-op) + N2 (reason/order drift) — fixed in Phase 3; "
           "remove this marker when trust_list.check_trust_scope matches the oracle",
)
def test_b3_impl_ok_matches_oracle():
    """Single function so N1's failure makes the whole test xfail (not a per-case xpass)."""
    for label, sid, rank, cls, scope, oracle_ok in B3_IMPL:
        ok, _reason = tl.check_trust_scope(
            envelope_server_id=sid, envelope_integrity_rank=rank,
            envelope_content_class=cls, trust_scope=scope)
        assert ok is oracle_ok, label


# ── Task 4: Registry drift — MUST go green ───────────────────────────────────

def test_registry_agrees_with_oracle_on_shared_keys():
    impl_raw = json.loads(
        (Path(__file__).resolve().parents[2] / "config" / "content-class-registry.json")
        .read_text()
    )
    impl_norm = {k: (v["conf_floor"], v["allowlist_required"]) for k, v in impl_raw.items()}
    shared = impl_norm.keys() & ORACLE_REG.keys()
    mismatches = {k: (impl_norm[k], ORACLE_REG[k]) for k in shared if impl_norm[k] != ORACLE_REG[k]}
    assert not mismatches, f"registry value drift: {mismatches}"
    # After D1, oracle keys are a subset of impl keys
    missing_from_impl = ORACLE_REG.keys() - impl_norm.keys()
    assert not missing_from_impl, f"oracle classes absent from impl registry: {missing_from_impl}"


def test_registry_classes_are_well_formed():
    impl_raw = json.loads(
        (Path(__file__).resolve().parents[2] / "config" / "content-class-registry.json")
        .read_text()
    )
    for cid in impl_raw:
        assert "/" in cid, f"class id must be <domain>/<subtype>: {cid!r}"
