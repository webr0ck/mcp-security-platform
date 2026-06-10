"""
Unit Tests — LLM Auditor Fail-Closed Posture (Task 0.4 / DET-F1)

Verifies that proxy/app/services/auditor.py and proxy/app/core/config.py
enforce the correct fail-closed posture when Ollama is unavailable.

Finding DET-F1 (HIGH): When Ollama is unreachable the combined risk score is
computed as `0.4 * static_score` instead of `1.0 * static_score`, causing a
tool with a `description_prompt_injection` flag (static_score≥40) to fall
BELOW the quarantine threshold — a targeted DoS of Ollama effectively downgrades
the auditor to static-regex-only at reduced weight.

Invariant covered: INV-005 (quarantine gate integrity)

TDD note: these tests are written BEFORE the implementation; they must FAIL
against the unmodified codebase and PASS after the fix.

Run:
    pytest tests/unit/test_auditor_unavailable.py -m unit -v
"""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ---------------------------------------------------------------------------
# Shared test fixtures
# ---------------------------------------------------------------------------

SAMPLE_TOOL_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "path": {"type": "string", "description": "File path."},
    },
    "required": ["path"],
}

SAMPLE_TOOL_ID = "550e8400-e29b-41d4-a716-446655440001"
SAMPLE_TOOL_NAME = "risky_file_reader"
SAMPLE_DESCRIPTION = "Reads files."
SAMPLE_SOURCE_REPO = "https://github.com/example/risky-tool"
SAMPLE_TAGS = ["filesystem"]

# Ollama fallback result (what run_llm_analysis returns on exception today)
OLLAMA_UNAVAILABLE_RESULT: dict = {
    "risk_score": 0,
    "prompt_injection_detected": False,
    "excessive_scope_detected": False,
    "suspicious_parameter_names": [],
    "summary": "LLM analysis unavailable.",
    "model": "llama3.2",
    "prompt_hash": "deadbeef",
    "llm_unavailable": True,   # required by the fix
}


# ---------------------------------------------------------------------------
# Test A: Ollama unavailable + REQUIRE_LLM_AUDIT=false
#         → combined_score must equal 1.0 * static_score (NOT 0.4 ×)
#         → AuditResult must carry llm_unavailable=True
# ---------------------------------------------------------------------------

@pytest.mark.unit
@pytest.mark.asyncio
async def test_llm_unavailable_uses_full_static_weight():
    """
    DET-F1 core regression test.

    When Ollama is unreachable and REQUIRE_LLM_AUDIT=false:
    - combined_score MUST equal 1.0 * static_score (not 0.4 * static_score)
    - AuditResult.llm_unavailable MUST be True
    - A tool with description_prompt_injection flag at static_score=40
      must reach combined_score=40 (not 16), which crosses the quarantine
      threshold (OLLAMA_HIGH_RISK_THRESHOLD=70 is NOT crossed, but the
      score must be the full weight — the critical boost test is separate).

    Before fix: combined = int(40 * 0.4 + 0 * 0.6) = 16  (fails quarantine)
    After fix:  combined = 1.0 * 40 = 40                  (correct full weight)
    """
    static_result = {
        "risk_flags": ["description_prompt_injection"],
        "static_risk_score": 40,
        "static_risk_level": "medium",
    }

    mock_settings = MagicMock()
    mock_settings.OLLAMA_HIGH_RISK_THRESHOLD = 70
    mock_settings.OLLAMA_CRITICAL_RISK_THRESHOLD = 90
    mock_settings.OLLAMA_MODEL = "llama3.2"
    mock_settings.OLLAMA_TIMEOUT_SECONDS = 30
    mock_settings.ollama_base_url = "http://mock-ollama:11434"
    mock_settings.opa_url = "http://mock-opa:8181"
    mock_settings.OPA_TIMEOUT_SECONDS = 2
    mock_settings.REQUIRE_LLM_AUDIT = False  # dev/staging default

    with (
        patch("app.services.auditor.run_static_analysis", new=AsyncMock(return_value=static_result)),
        patch("app.services.auditor.run_llm_analysis", new=AsyncMock(return_value=OLLAMA_UNAVAILABLE_RESULT)),
        patch("app.services.auditor.settings", mock_settings),
    ):
        from app.services.auditor import run_audit

        result = await run_audit(
            tool_id=SAMPLE_TOOL_ID,
            tool_name=SAMPLE_TOOL_NAME,
            description=SAMPLE_DESCRIPTION,
            schema=SAMPLE_TOOL_SCHEMA,
            source_repo=SAMPLE_SOURCE_REPO,
            tags=SAMPLE_TAGS,
        )

    # Full-weight static: 1.0 * 40 = 40
    assert result.risk_score == 40, (
        f"Expected combined_score=40 (1.0 × static) when LLM unavailable, "
        f"got {result.risk_score}. "
        f"Before fix this would be 16 (0.4 × static)."
    )

    # llm_unavailable flag must be set in the audit result
    assert result.llm_unavailable is True, (
        "AuditResult.llm_unavailable must be True when Ollama is unreachable"
    )


@pytest.mark.unit
@pytest.mark.asyncio
async def test_llm_unavailable_high_static_score_crosses_quarantine_threshold():
    """
    End-to-end quarantine path: static_score=75 (≥ HIGH threshold 70).
    On Ollama outage, full static weight → combined_score=75 → risk_level='high'.

    Before fix: combined = int(75 * 0.4 + 0 * 0.6) = 30 → risk_level='low'
                (tool is NOT quarantined — the security failure)
    After fix:  combined = 75 → risk_level='high'
                (tool correctly reaches high risk level)
    """
    static_result = {
        "risk_flags": ["description_prompt_injection", "filesystem_unrestricted"],
        "static_risk_score": 75,
        "static_risk_level": "high",
    }

    mock_settings = MagicMock()
    mock_settings.OLLAMA_HIGH_RISK_THRESHOLD = 70
    mock_settings.OLLAMA_CRITICAL_RISK_THRESHOLD = 90
    mock_settings.OLLAMA_MODEL = "llama3.2"
    mock_settings.OLLAMA_TIMEOUT_SECONDS = 30
    mock_settings.ollama_base_url = "http://mock-ollama:11434"
    mock_settings.opa_url = "http://mock-opa:8181"
    mock_settings.OPA_TIMEOUT_SECONDS = 2
    mock_settings.REQUIRE_LLM_AUDIT = False

    with (
        patch("app.services.auditor.run_static_analysis", new=AsyncMock(return_value=static_result)),
        patch("app.services.auditor.run_llm_analysis", new=AsyncMock(return_value=OLLAMA_UNAVAILABLE_RESULT)),
        patch("app.services.auditor.settings", mock_settings),
    ):
        from app.services.auditor import run_audit

        result = await run_audit(
            tool_id=SAMPLE_TOOL_ID,
            tool_name=SAMPLE_TOOL_NAME,
            description=SAMPLE_DESCRIPTION,
            schema=SAMPLE_TOOL_SCHEMA,
            source_repo=SAMPLE_SOURCE_REPO,
            tags=SAMPLE_TAGS,
        )

    assert result.risk_score == 75, (
        f"Expected combined_score=75 (1.0 × static=75) on Ollama outage, got {result.risk_score}"
    )
    assert result.risk_level == "high", (
        f"Expected risk_level='high' for score=75, got '{result.risk_level}'"
    )
    assert result.llm_unavailable is True


@pytest.mark.unit
@pytest.mark.asyncio
async def test_normal_llm_result_does_not_set_llm_unavailable():
    """
    Sanity check: when LLM analysis succeeds, llm_unavailable must be False
    (or absent / falsy). Verifies we don't accidentally flag healthy runs.
    """
    static_result = {
        "risk_flags": [],
        "static_risk_score": 20,
        "static_risk_level": "low",
    }
    llm_result = {
        "risk_score": 30,
        "prompt_injection_detected": False,
        "excessive_scope_detected": False,
        "suspicious_parameter_names": [],
        "summary": "All clear.",
        "model": "llama3.2",
        "prompt_hash": "abc123",
        # llm_unavailable NOT present (successful response)
    }

    mock_settings = MagicMock()
    mock_settings.OLLAMA_HIGH_RISK_THRESHOLD = 70
    mock_settings.OLLAMA_CRITICAL_RISK_THRESHOLD = 90
    mock_settings.OLLAMA_MODEL = "llama3.2"
    mock_settings.OLLAMA_TIMEOUT_SECONDS = 30
    mock_settings.ollama_base_url = "http://mock-ollama:11434"
    mock_settings.opa_url = "http://mock-opa:8181"
    mock_settings.OPA_TIMEOUT_SECONDS = 2
    mock_settings.REQUIRE_LLM_AUDIT = False

    with (
        patch("app.services.auditor.run_static_analysis", new=AsyncMock(return_value=static_result)),
        patch("app.services.auditor.run_llm_analysis", new=AsyncMock(return_value=llm_result)),
        patch("app.services.auditor.settings", mock_settings),
    ):
        from app.services.auditor import run_audit

        result = await run_audit(
            tool_id=SAMPLE_TOOL_ID,
            tool_name=SAMPLE_TOOL_NAME,
            description=SAMPLE_DESCRIPTION,
            schema=SAMPLE_TOOL_SCHEMA,
            source_repo=SAMPLE_SOURCE_REPO,
            tags=SAMPLE_TAGS,
        )

    # LLM available — combined = int(20*0.4 + 30*0.6) = int(8+18) = 26
    assert result.risk_score == 26, f"Expected 26, got {result.risk_score}"
    assert result.llm_unavailable is False, (
        "llm_unavailable must be False when LLM analysis succeeds"
    )


# ---------------------------------------------------------------------------
# Test B: REQUIRE_LLM_AUDIT=true → run_audit raises LLMAuditRequiredError
#         The router must convert this to HTTP 503 with no DB row inserted.
#         We test the auditor raise here; the router integration is in
#         tests/integration/ (out of scope for this unit test file).
# ---------------------------------------------------------------------------

@pytest.mark.unit
@pytest.mark.asyncio
async def test_require_llm_audit_true_raises_on_outage():
    """
    DET-F1 production-posture test.

    When REQUIRE_LLM_AUDIT=true and Ollama is unavailable,
    run_audit must raise LLMAuditRequiredError (not return a partial result).

    The router catches this exception and returns HTTP 503 with no row inserted.

    Rationale: an attacker who can DoS Ollama at registration time must not
    downgrade the auditor to static-regex-only. In production, tool registration
    must be unavailable (503) rather than degraded.
    """
    static_result = {
        "risk_flags": ["description_prompt_injection"],
        "static_risk_score": 40,
        "static_risk_level": "medium",
    }

    mock_settings = MagicMock()
    mock_settings.OLLAMA_HIGH_RISK_THRESHOLD = 70
    mock_settings.OLLAMA_CRITICAL_RISK_THRESHOLD = 90
    mock_settings.OLLAMA_MODEL = "llama3.2"
    mock_settings.OLLAMA_TIMEOUT_SECONDS = 30
    mock_settings.ollama_base_url = "http://mock-ollama:11434"
    mock_settings.opa_url = "http://mock-opa:8181"
    mock_settings.OPA_TIMEOUT_SECONDS = 2
    mock_settings.REQUIRE_LLM_AUDIT = True  # production posture

    with (
        patch("app.services.auditor.run_static_analysis", new=AsyncMock(return_value=static_result)),
        patch("app.services.auditor.run_llm_analysis", new=AsyncMock(return_value=OLLAMA_UNAVAILABLE_RESULT)),
        patch("app.services.auditor.settings", mock_settings),
    ):
        from app.services.auditor import run_audit, LLMAuditRequiredError

        with pytest.raises(LLMAuditRequiredError) as exc_info:
            await run_audit(
                tool_id=SAMPLE_TOOL_ID,
                tool_name=SAMPLE_TOOL_NAME,
                description=SAMPLE_DESCRIPTION,
                schema=SAMPLE_TOOL_SCHEMA,
                source_repo=SAMPLE_SOURCE_REPO,
                tags=SAMPLE_TAGS,
            )

    assert "LLM audit required" in str(exc_info.value) or "unavailable" in str(exc_info.value).lower(), (
        "LLMAuditRequiredError message must indicate LLM audit is required/unavailable"
    )


# ---------------------------------------------------------------------------
# Test C: Production validator blocks startup when REQUIRE_LLM_AUDIT=false
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_production_config_blocks_startup_when_require_llm_audit_false():
    """
    DET-F1 production startup gate.

    When ENVIRONMENT=production and REQUIRE_LLM_AUDIT=false, Settings()
    must raise ValueError at startup (never boot a production server with
    the LLM auditor in fail-open mode).

    This enforces the plan Task 0.4 Step 3 mandate.
    """
    import os
    from unittest.mock import patch as _patch

    # Build a minimal set of env vars that would otherwise pass production
    # validation, then set REQUIRE_LLM_AUDIT=false (or absent/default).
    #
    # We need to supply all the mandatory production secrets to avoid
    # triggering earlier validators — the REQUIRE_LLM_AUDIT check must
    # be its own distinct guard.
    _strong_key = "a" * 64  # 64 hex chars = 32 bytes
    production_env = {
        "ENVIRONMENT": "production",
        "REQUIRE_LLM_AUDIT": "false",
        # Satisfy the placeholder/HMAC-key validators:
        "PROXY_SECRET_KEY": _strong_key,
        "API_KEY_HMAC_KEY": _strong_key,
        "SBOM_SIGNING_KEY": _strong_key,
        "AUDIT_LOG_HMAC_KEY": _strong_key,
        "WEBHOOK_SIGNING_KEY": _strong_key,
        "POLICY_SIGNING_KEY": _strong_key,
        "VAULT_TOKEN": _strong_key,
        "OAUTH_STATE_SECRET": _strong_key,
        "DEX_CLIENT_SECRET": _strong_key,
        "DB_PASSWORD": _strong_key,
        "REDIS_PASSWORD": _strong_key,
        "MINIO_ROOT_PASSWORD": _strong_key,
        # Satisfy OIDC audience (OIDC disabled by default, but set it anyway)
        "OIDC_ENABLED": "false",
        # Satisfy SESSION_COOKIE_SECURE
        "SESSION_COOKIE_SECURE": "true",
        # Satisfy VAULT TLS
        "VAULT_ADDR": "https://vault:8200",
    }

    with _patch.dict(os.environ, production_env, clear=False):
        from importlib import reload
        import app.core.config as config_module
        config_module.get_settings.cache_clear()
        try:
            with pytest.raises(ValueError, match="REQUIRE_LLM_AUDIT"):
                config_module.Settings()  # type: ignore[call-arg]
        finally:
            config_module.get_settings.cache_clear()


@pytest.mark.unit
def test_production_config_passes_when_require_llm_audit_true():
    """
    Sanity check: production config must NOT raise when REQUIRE_LLM_AUDIT=true.
    """
    import os
    from unittest.mock import patch as _patch

    _strong_key = "a" * 64
    production_env = {
        "ENVIRONMENT": "production",
        "REQUIRE_LLM_AUDIT": "true",
        "PROXY_SECRET_KEY": _strong_key,
        "API_KEY_HMAC_KEY": _strong_key,
        "SBOM_SIGNING_KEY": _strong_key,
        "AUDIT_LOG_HMAC_KEY": _strong_key,
        "WEBHOOK_SIGNING_KEY": _strong_key,
        "POLICY_SIGNING_KEY": _strong_key,
        "VAULT_TOKEN": _strong_key,
        "OAUTH_STATE_SECRET": _strong_key,
        "DEX_CLIENT_SECRET": _strong_key,
        "DB_PASSWORD": _strong_key,
        "REDIS_PASSWORD": _strong_key,
        "MINIO_ROOT_PASSWORD": _strong_key,
        "OIDC_ENABLED": "false",
        "SESSION_COOKIE_SECURE": "true",
        "VAULT_ADDR": "https://vault:8200",
    }

    with _patch.dict(os.environ, production_env, clear=False):
        from importlib import reload
        import app.core.config as config_module
        config_module.get_settings.cache_clear()
        try:
            # Must not raise
            s = config_module.Settings()  # type: ignore[call-arg]
            assert s.REQUIRE_LLM_AUDIT is True
        finally:
            config_module.get_settings.cache_clear()
