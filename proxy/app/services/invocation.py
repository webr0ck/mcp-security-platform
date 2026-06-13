"""
MCP Security Platform — Tool Invocation Service

Implements the critical invocation path described in docs/ARCHITECTURE.md Section 5.1.

This service orchestrates:
  1. Tool status check (INV-005: quarantine block before OPA)
  2. Anomaly score computation
  3. OPA policy evaluation (INV-004: fail-closed on OPA unreachable)
  4. HTTP forwarding to upstream MCP server
  5. Audit event emission (INV-001: synchronous, before response returned)
  6. Anomaly baseline update (async, post-response)

The invocation handler in routers/tools.py calls invoke_tool() here.
Credentials in upstream responses are redacted by mcp-audit-logger.

See docs/ARCHITECTURE.md data flow 5.1 for the step-by-step sequence.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

import httpx

from app.credential_broker.broker import CredentialBroker
from app.credential_broker.registry import Registry

logger = logging.getLogger(__name__)

# Module-level singletons — initialized by app lifespan, injected for tests.
broker_instance: CredentialBroker | None = None
registry_instance: Registry | None = None

# Test-fixture flag: when True, _emit_audit_event skips the DB INSERT entirely.
# Set to True in unit tests that mock mcp-audit-logger but do not have a live DB.
# This replaces the fragile type-guard (non-UUID event_id / non-str sha256_hash)
# that previously gated the INSERT — the old guard was an emergent side-effect of
# mock return values, not an explicit contract. This flag makes the intent explicit.
# Never set this True in production code paths.
_SKIP_AUDIT_DB_WRITE: bool = False

# Hard cap on bytes read from an upstream MCP server. Guards against a
# malicious upstream streaming unbounded data on the SSE channel.
_MAX_UPSTREAM_BODY_BYTES = 4 * 1024 * 1024  # 4 MiB


_PROFILE_CACHE_TTL_SECONDS = 300  # 5 minutes — mirrors role cache TTL in auth.py


async def _lookup_profile_with_cache(
    client_id: str,
    tool_name: str,
    profile_uuid: str | None = None,
) -> dict | None:
    """
    Look up an mcp_profiles row with Redis caching.

    Task 4.3 update: when ``profile_uuid`` is set, queries by
    ``(profile_uuid, tool_name)`` — the named-profile path.
    Falls back to legacy ``(client_id, tool_name)`` lookup when
    ``profile_uuid`` is None (backward compatible).

    Task 1.10 (SELF-F2): fail-closed semantics — mirrors the role caching
    pattern in middleware/auth.py but with stricter failure posture:

      DB success:            use profile + update Redis cache (TTL 300s)
      DB error + cache hit:  use cached profile (last-known-state)
      DB error + cache miss: raise ProfileLookupError → caller 503s

    Returns:
      dict with {enabled: bool, allowed_functions: list[str]} if a row exists,
      or None if no profile row exists (no restriction, default allow).

    Raises:
      ProfileLookupError: if DB is unreachable and no cached profile available.
    """
    import json as _json
    from app.core.redis_client import redis_pool

    # Cache key disambiguates named-profile path from legacy path.
    if profile_uuid:
        cache_key = f"mcp_profile:uuid:{profile_uuid}:{tool_name}"
    else:
        cache_key = f"mcp_profile:{client_id}:{tool_name}"
    _SENTINEL_NO_ROW = "__NO_PROFILE_ROW__"

    # -----------------------------------------------------------------------
    # Tier 1: Redis cache
    # -----------------------------------------------------------------------
    cached_raw: str | None = None
    redis_available = False
    try:
        redis = redis_pool.client
        cached_raw = await redis.get(cache_key)
        redis_available = True
    except Exception as _redis_exc:
        logger.warning(
            "Profile cache Redis read failed",
            extra={"client_id": client_id, "tool_name": tool_name, "error": str(_redis_exc)},
        )

    if cached_raw is not None:
        if cached_raw == _SENTINEL_NO_ROW:
            return None  # cached "no profile row" — default allow
        try:
            return _json.loads(cached_raw)
        except Exception:
            pass  # malformed cache entry — fall through to DB

    # -----------------------------------------------------------------------
    # Tier 2: PostgreSQL mcp_profiles
    # -----------------------------------------------------------------------
    profile_data: dict | None = None
    db_succeeded = False
    try:
        from app.core.database import AsyncSessionLocal
        from sqlalchemy import text
        async with AsyncSessionLocal() as _db:
            if profile_uuid:
                # Task 4.3: named-profile path — query by profile_uuid FK
                row = await _db.execute(
                    text(
                        "SELECT enabled, allowed_functions "
                        "FROM mcp_profiles "
                        "WHERE profile_uuid=:uuid AND mcp_name=:mname LIMIT 1"
                    ),
                    {"uuid": profile_uuid, "mname": tool_name},
                )
            else:
                # Legacy path — query by profile_id (client identity)
                row = await _db.execute(
                    text(
                        "SELECT enabled, allowed_functions "
                        "FROM mcp_profiles WHERE profile_id=:pid AND mcp_name=:mname LIMIT 1"
                    ),
                    {"pid": client_id, "mname": tool_name},
                )
            prow = row.mappings().first()
            if prow:
                profile_data = {
                    "enabled": prow["enabled"],
                    "allowed_functions": prow["allowed_functions"],
                }
        db_succeeded = True
    except Exception as _db_exc:
        logger.error(
            "mcp_profiles DB lookup failed",
            extra={"client_id": client_id, "tool_name": tool_name, "error": str(_db_exc)},
        )

    if db_succeeded:
        # Update Redis cache with the DB result (best-effort)
        try:
            redis = redis_pool.client
            value = _json.dumps(profile_data) if profile_data is not None else _SENTINEL_NO_ROW
            await redis.setex(cache_key, _PROFILE_CACHE_TTL_SECONDS, value)
        except Exception as _cache_exc:
            logger.warning(
                "Failed to write profile to Redis cache",
                extra={"client_id": client_id, "tool_name": tool_name, "error": str(_cache_exc)},
            )
        return profile_data

    # -----------------------------------------------------------------------
    # DB failed. We have no cached value (cache hit was handled above).
    # Fail-closed: raise ProfileLookupError → caller converts to 503.
    # -----------------------------------------------------------------------
    raise ProfileLookupError(
        f"DB unreachable and no cached profile for {client_id}/{tool_name}"
    )


async def _get_recent_calls_for_opa(client_id: str) -> list[dict]:
    """
    Read the per-client Redis anomaly window and return it in the format
    anomaly.rego expects: [{tool_name: str, timestamp: float}, ...]

    Task 1.7 (DET-F3): populates input.recent_calls for the single combined
    OPA/authz query so anomaly.rego's structural_deny_reasons are evaluated
    within the same authz decision.

    FAIL-CLOSED: raises on Redis failure.  The caller (invoke_tool Step 2.8)
    must convert any exception to OPAUnavailableError → 503. An empty
    recent_calls list is the correct "no prior history" case; a missing or
    unpopulatable list would silently bypass structural deny rules, which is
    the same vulnerability class as INV-004.
    """
    from app.core.redis_client import get_anomaly_window_with_timestamps
    return await get_anomaly_window_with_timestamps(client_id)


async def invoke_tool(
    tool_record: dict[str, Any],
    json_rpc_request: dict[str, Any],
    client_id: str,
    client_roles: list[str],
    is_testing: bool,
    request_id: str,
    inbound_auth: str | None = None,
    principal_id: str | None = None,
    principal_type: str | None = None,
    user_kc_token: str | None = None,
    source_ip: str | None = None,
    session_jti: str | None = None,
    profile_uuid: str | None = None,
) -> dict[str, Any]:
    """
    Execute the full tool invocation pipeline.

    Args:
        tool_record: Full tool_registry record for the target tool.
        json_rpc_request: Parsed MCP JSON-RPC 2.0 request body.
        client_id: Resolved caller identity.
        client_roles: List of roles for the caller.
        is_testing: True if called by admin for testing (bypasses anomaly).
        request_id: Request correlation ID.
        inbound_auth: The client's raw inbound Authorization header value. Used
            only by injection_mode='passthrough' (Case-3 / 3b) to forward a
            downstream-IDP token to the upstream and relay its 401 challenge.
        principal_id: Typed principal id from request.state (6.2 — used for the
            discovery==invoke entitlement gate when the tool is server-linked).
        principal_type: Typed principal type ('human' | 'agent') from
            request.state, paired with principal_id.
        user_kc_token: The caller's raw Keycloak access token (6.3). Threaded to
            the credential dispatcher for injection_mode='oauth_user_token'
            (RFC 8693 on-behalf-of exchange). Set only for direct-OIDC callers;
            None for api_key/mtls/session callers (oauth_user_token then fails
            closed in the dispatcher). Never logged (INV-002).
        source_ip: Originating client IP from X-Forwarded-For / request.client.host
            (Task 1.2 — "who" enrichment for audit trail, LOG-F04).
        session_jti: OIDC session JWT ID (Task 1.2). Present only for
            session-JWT callers; None for mTLS / API-key callers.
        profile_uuid: Named profile UUID from request.state (Task 4.3). When
            set, profile lookup uses (profile_uuid, tool_name) instead of
            (client_id, tool_name). None = legacy mcp_profiles path (backward
            compatible).

    Returns:
        Dict matching the MCP JSON-RPC 2.0 response format with meta.audit_id.

    Raises:
        ToolQuarantinedError: If tool status == 'quarantined' (INV-005).
        NotEntitledError: If the tool is server-linked and the caller is not
            entitled to that server (6.2, discovery==invoke — no role exception).
        OPADenyError: If OPA denies the invocation.
        OPAUnavailableError: If OPA is unreachable (returns 503).
    """
    from app.services.anomaly import evaluate_anomaly
    from app.services.policy import OPADenyError, OPAUnavailableError, evaluate_policy

    tool_id = tool_record["tool_id"]
    tool_name = tool_record["name"]
    tool_status = tool_record["status"]
    tool_risk_level = tool_record.get("risk_level", "low")
    tool_server_id: str = str(tool_record["server_id"]) if tool_record.get("server_id") else ""
    upstream_url = tool_record["upstream_url"]
    params = json_rpc_request.get("params", {}).get("arguments", {})

    # -------------------------------------------------------------------------
    # Step 1: INV-005 — Block quarantined tools before OPA evaluation
    # -------------------------------------------------------------------------
    if tool_status == "quarantined":
        raise ToolQuarantinedError(tool_id, tool_name)

    if tool_status == "deprecated":
        raise ToolDeprecatedError(tool_id, tool_name)

    # -------------------------------------------------------------------------
    # Step 1.5: 6.2 — discovery==invoke. If the tool is linked to a server,
    # the caller must be entitled to that server (same resolver the catalog
    # uses for discovery). No role exception: admin/platform_admin are gated
    # identically. Unlinked tools (server_id is NULL) are unaffected here.
    # App-layer, pre-OPA, fail-closed — like the INV-005 quarantine gate above.
    # INV-001: emit a synchronous deny audit here so the gate is recorded
    # uniformly on every path (REST + both /mcp) before the exception propagates.
    # -------------------------------------------------------------------------
    from app.services.entitlement import NotEntitledError, enforce_tool_entitlement
    try:
        await enforce_tool_entitlement(tool_record, principal_id, principal_type)
    except NotEntitledError as ent_exc:
        await _emit_audit_event(
            tool_id=str(tool_id) if tool_id is not None else None,
            tool_name=tool_name,
            tool_version=tool_record.get("version"),
            client_id=client_id,
            outcome="deny",
            deny_reasons=[f"not_entitled:{ent_exc.reason}"],
            request_id=request_id,
            latency_ms=0,
            anomaly_score=0.0,
            opa_decision_id="",
            is_testing=is_testing,
            source_ip=source_ip,
            principal_type=principal_type,
            roles=client_roles,
            session_jti=session_jti,
        )
        raise

    # -------------------------------------------------------------------------
    # Step 1.6: B-coarse taint floor (RFC-0001 §8.1, PRD-0001 M2).
    # Order: INV-005 quarantine -> taint-floor -> INV-004 OPA. A session tainted
    # by a prior untrusted result cannot invoke a high-sensitivity or credential-
    # injecting sink. Fail-closed (INV-015); the deny is audited (INV-001) before
    # the exception propagates, like the entitlement gate above. Dark unless the
    # TAINT_FLOOR_ENABLED flag is set.
    # -------------------------------------------------------------------------
    from app.core.config import settings as _tf_settings
    _taint_server_trust_tier: int | None = None  # stashed for write-before-forward below
    if _tf_settings.TAINT_FLOOR_ENABLED:
        from app.services.taint_floor import (
            effective_injection_mode,
            effective_required_integrity,
            taint_floor_decision,
        )
        from app.services.taint_store import is_tainted_for_principal

        _taint_server_trust_tier, _server_default_injection = await _lookup_server_trust(
            tool_server_id
        )
        _raw_required = tool_record.get("required_integrity")
        _tool_required = 1 if _raw_required is None else int(_raw_required)
        _eff_injection = effective_injection_mode(
            tool_record.get("injection_mode"),
            _server_default_injection,
        )
        _required = effective_required_integrity(_tool_required, _eff_injection)
        _tainted = await is_tainted_for_principal(principal_id)
        if taint_floor_decision(tainted=_tainted, required_integrity=_required) == "deny":
            await _emit_audit_event(
                tool_id=str(tool_id) if tool_id is not None else None,
                tool_name=tool_name,
                tool_version=tool_record.get("version"),
                client_id=client_id,
                outcome="deny",
                deny_reasons=[f"taint_floor:required_integrity={_required}"],
                request_id=request_id,
                latency_ms=0,
                anomaly_score=0.0,
                opa_decision_id="",
                is_testing=is_testing,
                source_ip=source_ip,
                principal_type=principal_type,
                roles=client_roles,
                session_jti=session_jti,
            )
            raise TaintFloorDenyError(
                str(tool_id) if tool_id is not None else "", tool_name, _required
            )

    # -------------------------------------------------------------------------
    # Step 2: Anomaly detection
    # -------------------------------------------------------------------------
    # Testing bypass: skip anomaly for admin is_testing requests so test suites
    # don't accumulate window state.
    from app.services.anomaly import detect as detect_anomaly

    anomaly_score = 0.0
    if not is_testing:
        try:
            anomaly_result = await detect_anomaly(client_id=client_id, tool_name=tool_name)
            anomaly_score = anomaly_result.anomaly_score
        except Exception as exc:
            # Anomaly detection is non-blocking — a failure here should not
            # block invocation, but must be logged for investigation.
            logger.warning(
                "Anomaly detection failed — defaulting score to 0.0",
                extra={"client_id": client_id, "tool_name": tool_name, "error": str(exc)},
            )

    # -------------------------------------------------------------------------
    # Step 2.3: Fetch recent_calls for OPA anomaly structural evaluation.
    # -------------------------------------------------------------------------
    # Task 1.7 (DET-F3): The anomaly.rego structural rules (credential_then_exec,
    # web_search→bulk_read, etc.) are evaluated WITHIN the single authz OPA query
    # rather than as a separate HTTP round-trip. We populate input.recent_calls
    # from the Redis window (already updated by detect_anomaly above) so that
    # authz.rego can import structural_deny_reasons from data.mcp.anomaly.
    #
    # FAIL-CLOSED (INV-004 parity): if we cannot read the window (Redis failure),
    # we raise OPAUnavailableError → 503. Sending an empty list would silently
    # bypass structural deny rules (same class as INV-004 allow-through on OPA
    # unreachable). The difference from Step 2's anomaly score: the Python scorer
    # is advisory; the structural Rego rules are mandatory policy gates.
    recent_calls: list[dict] = []
    if not is_testing:
        try:
            recent_calls = await _get_recent_calls_for_opa(client_id)
        except Exception as exc:
            logger.error(
                "Failed to fetch recent_calls for OPA anomaly evaluation — "
                "failing closed per INV-004 parity (anomaly path)",
                extra={"client_id": client_id, "tool_name": tool_name, "error": str(exc)},
            )
            raise OPAUnavailableError(
                f"Anomaly recent_calls fetch failed: {exc}"
            ) from exc

    # -------------------------------------------------------------------------
    # Step 2.5: Profile lookup — check mcp_profiles for per-identity permission
    # -------------------------------------------------------------------------
    # If a profile row exists for (client_id, tool_name), inject it into OPA input.
    # OPA then applies mcp_disabled_for_profile / function_not_allowed_for_profile rules.
    # Absence of a row = platform default = no restriction.
    #
    # Task 1.9 (SELF-F2): derive tool_function_name from json_rpc_request.params.name
    # (the JSON-RPC function identifier), NOT from the tool body arguments.
    #
    # On the direct tools/call path (mcp_server.py _route_to_registry), the request
    # is built as: params = {name: <function_name>, arguments: {...}}.
    # Previously function_name = params.arguments.get("tool_name", "") which is
    # always "" for direct calls — silently bypassing allowed_functions restrictions.
    #
    # The correct source is json_rpc_request["params"]["name"]:
    #   - For tools/call: this is the function being invoked (e.g. "write_file")
    #   - For other methods: falls back to "" (no function restriction)
    _jrpc_params = json_rpc_request.get("params", {})
    function_name: str = _jrpc_params.get("name", "") or ""

    # Task 1.10 (SELF-F2): fail-closed profile lookup with Redis last-known-state cache.
    # Task 4.3: when profile_uuid is set, look up by (profile_uuid, tool_name) — named-profile path.
    # DB success → profile used + cache updated
    # DB error + cache hit → cached profile used
    # DB error + cache miss → ProfileLookupError raised → OPAUnavailableError → 503
    profile_data: dict = {}
    try:
        _profile_result = await _lookup_profile_with_cache(
            client_id, tool_name, profile_uuid=profile_uuid
        )
        if _profile_result is not None:
            profile_data = _profile_result
    except ProfileLookupError as _profile_exc:
        logger.error(
            "Profile lookup fail-closed: DB unreachable and no cached profile — "
            "returning 503 per Task 1.10 (SELF-F2) fail-closed mandate",
            extra={"client_id": client_id, "tool_name": tool_name, "error": str(_profile_exc)},
        )
        raise OPAUnavailableError(
            f"Profile lookup failed (DB unreachable, no cache): {_profile_exc}"
        ) from _profile_exc

    # -------------------------------------------------------------------------
    # Step 2.7: Resolve owned server IDs for server_owner/manager OPA rules.
    # Only fetched when the caller holds one of those roles (fast-path for
    # all other roles). Fails open (empty list) so a transient DB/Redis error
    # does not block callers that have explicit grants.
    # -------------------------------------------------------------------------
    # Phase 3 (V025) will add owner_max_risk_level as a DB column on
    # server_registry. Until then, default to "medium" as documented in
    # docs/RBAC.md §server_owner.  # TODO: read from server_registry after V025.
    _OWNER_MAX_RISK_LEVEL_DEFAULT = "medium"
    owned_server_ids: list[str] = []
    owner_max_risk_level: str = _OWNER_MAX_RISK_LEVEL_DEFAULT

    if any(r in {"server_owner", "manager"} for r in client_roles):
        from app.services.entitlement import get_owned_server_ids
        owned_server_ids = await get_owned_server_ids(client_id)

    # -------------------------------------------------------------------------
    # Step 3: OPA policy evaluation (INV-003, INV-004)
    # -------------------------------------------------------------------------
    opa_input = {
        "client_id": client_id,
        "client_roles": client_roles,
        "tool_id": str(tool_id),
        "tool_name": tool_name,
        "tool_status": tool_status,
        "tool_risk_level": tool_risk_level,
        # Phase 2.1: server_owner/manager invoke enrichment.
        # tool_server_id is "" for unlinked tools (no server_id FK).
        # owned_server_ids is computed from server_role_grant — never
        # sourced from the request body (trust boundary enforced here).
        "tool_server_id": tool_server_id,
        "owned_server_ids": owned_server_ids,
        "owner_max_risk_level": owner_max_risk_level,
        "params": params,
        "anomaly_score": anomaly_score,
        "is_testing": is_testing,
        "profile": profile_data,
        "tool_function_name": function_name,
        # Task 1.7: recent_calls for anomaly.rego structural rule evaluation
        # within the single combined authz OPA query (DET-F3).
        "recent_calls": recent_calls,
    }

    opa_result = await evaluate_policy(opa_input)
    # Task 5.1 (LOG-F04): use the real OPA decision_id from the response body
    # (present when --set=decision_logs.console=true is configured in docker-compose.yml).
    # This ID correlates audit_events rows with OPA's own decision log stream in Loki
    # (job: mcp-opa-decisions). Fall back to a locally-generated placeholder only when
    # OPA did not emit a decision_id (e.g. older OPA builds without decision logging).
    opa_decision_id: str = opa_result.get("decision_id") or f"dec_{uuid4().hex[:16]}"

    if not opa_result["allow"]:
        # Emit DENY audit event synchronously (INV-001)
        audit_id = await _emit_audit_event(
            tool_id=str(tool_id),
            tool_name=tool_name,
            tool_version=tool_record.get("version"),
            client_id=client_id,
            outcome="deny",
            deny_reasons=opa_result["reasons"],
            request_id=request_id,
            latency_ms=0,
            anomaly_score=anomaly_score,
            opa_decision_id=opa_decision_id,
            is_testing=is_testing,
            source_ip=source_ip,
            principal_type=principal_type,
            roles=client_roles,
            session_jti=session_jti,
        )
        raise OPADenyError(opa_result["reasons"])

    # -------------------------------------------------------------------------
    # Step 3b: SSRF guard — re-validate upstream URL at call time (C3)
    # Registration-time check alone is insufficient: upstream_url may have been
    # changed via PATCH after approval. Call-time validation is an independent
    # defense-in-depth layer.
    # -------------------------------------------------------------------------
    from app.core.config import settings
    from app.services.ssrf import SSRFError, validate_server_url as _validate_server_url

    try:
        _validate_server_url(
            upstream_url,
            allow_http_localhost=(settings.ENVIRONMENT == "development"),
        )
    except SSRFError as exc:
        raise ValueError(f"SSRF blocked upstream URL at invoke time: {exc}") from exc

    # -------------------------------------------------------------------------
    # Step 3c: Invoke-time DNS-rebind / TOCTOU revalidation (Task 3.1 / ISO-F2.6)
    #
    # Registration-time SSRF checks are necessary but not sufficient — a hostname
    # that resolved to a safe IP at registration time may later re-resolve to an
    # internal address (DNS rebind) or to an IP outside the registered allowlist
    # CIDR.  We resolve here, validate against the registered policy, and fail
    # closed (503) on any anomaly per INV-004 parity.
    #
    # upstream_allowlist_entry: fetched from server_registry using the tool's
    # server_id if available. NULL / empty = registered as a public upstream.
    # -------------------------------------------------------------------------
    from app.services.server_onboarding import (
        UpstreamRevalidationError,
        revalidate_upstream_ip_at_invoke,
    )

    _registered_allowlist_entry: str | None = tool_record.get("upstream_allowlist_entry")
    if _registered_allowlist_entry is None and tool_server_id:
        # upstream_allowlist_entry was not pre-fetched in tool_record (e.g. SELECT *
        # from tool_registry does not carry server_registry columns). Fetch it once.
        try:
            from app.core.database import AsyncSessionLocal as _ASL
            from sqlalchemy import text as _text
            async with _ASL() as _db:
                _sr = await _db.execute(
                    _text(
                        "SELECT upstream_allowlist_entry FROM server_registry "
                        "WHERE server_id = :sid AND deleted_at IS NULL LIMIT 1"
                    ),
                    {"sid": tool_server_id},
                )
                _sr_row = _sr.fetchone()
                if _sr_row is not None:
                    _registered_allowlist_entry = _sr_row[0]  # may still be None (public)
        except Exception as _sr_exc:
            logger.error(
                "invoke Step 3c: failed to fetch upstream_allowlist_entry from server_registry — "
                "failing closed (upstream_revalidation_failed)",
                extra={"tool_server_id": tool_server_id, "error": str(_sr_exc)},
            )
            await _emit_audit_event(
                tool_id=str(tool_id),
                tool_name=tool_name,
                tool_version=tool_record.get("version"),
                client_id=client_id,
                outcome="deny",
                deny_reasons=["upstream_revalidation_failed", "server_registry_lookup_error"],
                request_id=request_id,
                latency_ms=0,
                anomaly_score=anomaly_score,
                opa_decision_id=opa_decision_id,
                is_testing=is_testing,
                source_ip=source_ip,
                principal_type=principal_type,
                roles=client_roles,
                session_jti=session_jti,
            )
            from app.services.policy import OPAUnavailableError
            raise OPAUnavailableError(
                "upstream_revalidation_failed: cannot fetch server allowlist entry"
            ) from _sr_exc

    _pinned_ips: list[str] = []
    try:
        _pinned_ips = await revalidate_upstream_ip_at_invoke(
            upstream_url=upstream_url,
            registered_allowlist_entry=_registered_allowlist_entry,
        )
    except UpstreamRevalidationError as _rebind_exc:
        logger.warning(
            "invoke Step 3c: DNS-rebind or TOCTOU detected — denying invocation",
            extra={
                "upstream_url": upstream_url,
                "registered_allowlist_entry": _registered_allowlist_entry,
                "error": str(_rebind_exc),
            },
        )
        await _emit_audit_event(
            tool_id=str(tool_id),
            tool_name=tool_name,
            tool_version=tool_record.get("version"),
            client_id=client_id,
            outcome="deny",
            deny_reasons=["upstream_revalidation_failed"],
            request_id=request_id,
            latency_ms=0,
            anomaly_score=anomaly_score,
            opa_decision_id=opa_decision_id,
            is_testing=is_testing,
            source_ip=source_ip,
            principal_type=principal_type,
            roles=client_roles,
            session_jti=session_jti,
        )
        raise ValueError(
            f"Upstream revalidation failed (DNS-rebind protection): {_rebind_exc}"
        ) from _rebind_exc

    # -------------------------------------------------------------------------
    # Step 4: Forward to upstream MCP server
    # -------------------------------------------------------------------------
    from app.credential_broker.dispatcher import (
        CredentialInjectionError,
        CredentialEnrollmentRequiredError,
    )

    extra_headers: dict[str, str] = {}
    credential = None
    injection_mode = tool_record.get("injection_mode", "none")
    service_name = tool_record.get("service_name")

    if injection_mode == "passthrough":
        # Case-3 (3b) native passthrough: inject none of OUR credentials. Forward
        # the client's downstream token (if any) and let the upstream challenge
        # (401 + WWW-Authenticate) when it is absent/invalid — the gateway relays
        # that challenge to the client (see the 401-relay below).
        if inbound_auth:
            extra_headers = {"Authorization": inbound_auth}
    elif injection_mode != "none":
        from app.credential_broker.dispatcher import dispatch_credential_injection
        try:
            extra_headers = await dispatch_credential_injection(
                tool_record=tool_record,
                client_id=client_id,
                # 6.3: thread the caller's KC token for oauth_user_token (RFC 8693).
                # None for non-OIDC callers → that mode fails closed downstream.
                user_kc_token=user_kc_token,
            )
        except CredentialInjectionError as _cred_exc:
            # INV-001: a credential refusal on the auth boundary (e.g. user not
            # enrolled for delegated access, missing service secret, broker down)
            # is a security-relevant DENY and MUST be audited — parity with the
            # OPA-stage deny above. Without this the only signal is a -32603 to
            # the caller and no audit trail. Emit, then re-raise so the actionable
            # message still reaches the caller.
            #
            # Task 4: distinguish "user not enrolled" from "broker down / secret
            # missing" so the audit trail (and TTFF metric) can tell them apart.
            # INV-002: injection_mode is kept as the second element; no token value
            # is ever placed in deny_reasons.
            if isinstance(_cred_exc, CredentialEnrollmentRequiredError):
                _deny_primary = "enrollment_required"
            else:
                _deny_primary = "credential_injection_failed"
            await _emit_audit_event(
                tool_id=str(tool_id),
                tool_name=tool_name,
                tool_version=tool_record.get("version"),
                client_id=client_id,
                outcome="deny",
                deny_reasons=[_deny_primary, injection_mode],
                request_id=request_id,
                latency_ms=0,
                anomaly_score=anomaly_score,
                opa_decision_id=opa_decision_id,
                is_testing=is_testing,
                source_ip=source_ip,
                principal_type=principal_type,
                roles=client_roles,
                session_jti=session_jti,
            )
            raise

    start_ts = datetime.now(timezone.utc)
    upstream_response: dict[str, Any] = {}
    upstream_error: Exception | None = None
    upstream_challenge: dict[str, Any] | None = None
    init_failed = False

    # MCP streamable-http requires Accept header to signal JSON or SSE response preference.
    # The initialize handshake does NOT need the upstream credential — only the tools/call
    # forward does. Keeping handshake headers minimal limits credential exposure to the
    # request that actually needs it.
    handshake_headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        # FastMCP's TrustedHostMiddleware rejects container hostnames; override to localhost.
        "Host": "localhost",
    }
    # passthrough: the initialize handshake may also need the downstream token if
    # the upstream is a protected resource that challenges every request.
    if injection_mode == "passthrough" and inbound_auth:
        handshake_headers["Authorization"] = inbound_auth
    # Forward caller identity so MCP servers that implement per-user isolation
    # (notes, self-service) can resolve the user without re-parsing a JWT.
    # X-User-Role carries the highest-privilege role for admin-gate checks.
    # Task 4.2 (SELF-F2): sort by privilege so the upstream always receives the
    # most-privileged role, regardless of the order roles were resolved.
    _ROLE_PRIORITY: dict[str, int] = {
        "admin": 0,
        "platform_admin": 0,
        "agent": 1,
        "auditor": 2,
        "readonly": 3,
    }
    _sorted_roles = sorted(
        client_roles,
        key=lambda r: _ROLE_PRIORITY.get(r, 99),
    )
    primary_role = _sorted_roles[0] if _sorted_roles else "user"

    forward_base_headers = {
        **handshake_headers,
        **extra_headers,
        "X-User-Sub": client_id,
        "X-User-Role": primary_role,
    }

    # Build a PinnedIPTransport from the IP validated in Step 3c so that httpx
    # never re-resolves the hostname between validation and the TCP connect
    # (closes the TOCTOU window identified in appsec finding HIGH-2).
    # _pinned_ips is non-empty when Step 3c succeeds; fall back to a plain
    # transport only if the list is somehow empty (e.g. a raw-IP upstream_url
    # where revalidation was a no-op — should not happen in practice).
    from app.services.pinned_transport import PinnedIPTransport as _PinnedIPTransport

    _upstream_hostname: str = urlparse(upstream_url).hostname or ""
    if _pinned_ips and _upstream_hostname:
        _transport: httpx.AsyncHTTPTransport = _PinnedIPTransport(
            pinned_ip=_pinned_ips[0],
            original_hostname=_upstream_hostname,
        )
    else:
        # Fallback: plain transport (covers raw-IP upstreams; no resolver call
        # needed because there is no hostname to re-resolve).
        _transport = httpx.AsyncHTTPTransport()

    try:
        # Attempt to reuse a cached MCP-Session-Id before opening an HTTP client.
        # On cache hit we skip the 2-request initialize handshake entirely (Bug 1 fix).
        session_id = await _get_or_create_session(upstream_url, client_id, handshake_headers)

        async with httpx.AsyncClient(transport=_transport, timeout=30.0) as client:
            # If no cached session was available, run the full initialize handshake.
            if session_id is None:
                try:
                    session_id = await _mcp_initialize(client, upstream_url, handshake_headers)
                    if session_id:
                        await _store_session(upstream_url, client_id, session_id)
                except Exception as exc:
                    init_failed = True
                    upstream_error = exc
                    logger.error("MCP initialize handshake failed: %s", exc)
                    session_id = None

            if not init_failed:
                forward_headers = dict(forward_base_headers)
                if session_id:
                    forward_headers["Mcp-Session-Id"] = session_id

                resp = await client.post(upstream_url, json=json_rpc_request, headers=forward_headers)

                # Case-3 (3b) relay: a protected-resource upstream answers an
                # un(der)-authenticated call with 401 + WWW-Authenticate. Do NOT
                # swallow it as a JSON parse error — capture the challenge so the
                # client can perform the downstream (e.g. Entra) OAuth itself.
                if resp.status_code == 401:
                    upstream_challenge = {
                        "www_authenticate": resp.headers.get("www-authenticate", ""),
                        "status": 401,
                    }
                    try:
                        upstream_challenge["body"] = json.loads(resp.content[:_MAX_UPSTREAM_BODY_BYTES])
                    except Exception:
                        upstream_challenge["body"] = None
                else:
                    # Defense against unbounded streaming from a malicious upstream.
                    body = resp.content[:_MAX_UPSTREAM_BODY_BYTES]
                    content_type = resp.headers.get("content-type", "")
                    if "text/event-stream" in content_type:
                        for line in body.decode("utf-8", errors="replace").splitlines():
                            if line.startswith("data:"):
                                upstream_response = json.loads(line[5:].strip())
                                break
                    else:
                        upstream_response = json.loads(body)
    except Exception as exc:
        upstream_error = exc
        logger.error("Upstream MCP server error: %s", exc)
    finally:
        if credential is not None:
            credential.zero()

    end_ts = datetime.now(timezone.utc)
    latency_ms = int((end_ts - start_ts).total_seconds() * 1000)

    # -------------------------------------------------------------------------
    # Step 5: Emit audit event synchronously (INV-001).
    # If the upstream call (or init handshake) failed, the policy decision
    # was "allow" but the tool did not actually execute. Record outcome="error"
    # with a reason so audit reviewers can distinguish this from a genuine
    # successful invocation.
    # -------------------------------------------------------------------------
    if upstream_challenge is not None:
        # Auth challenge from a foreign-IDP upstream — not a successful execution,
        # not an internal error. Audit as a deny with a clear reason.
        audit_outcome = "deny"
        audit_reasons = ["downstream_auth_required"]
    elif upstream_error is not None:
        audit_outcome = "error"
        audit_reasons = [
            "upstream_init_failed" if init_failed else "upstream_invocation_failed",
        ]
    else:
        audit_outcome = "allow"
        audit_reasons = []

    audit_id = await _emit_audit_event(
        tool_id=str(tool_id),
        tool_name=tool_name,
        tool_version=tool_record.get("version"),
        client_id=client_id,
        outcome=audit_outcome,
        deny_reasons=audit_reasons,
        request_id=request_id,
        latency_ms=latency_ms,
        anomaly_score=anomaly_score,
        opa_decision_id=opa_decision_id,
        is_testing=is_testing,
        source_ip=source_ip,
        principal_type=principal_type,
        roles=client_roles,
        session_jti=session_jti,
    )

    # -------------------------------------------------------------------------
    # Step 6: Return proxied response
    # -------------------------------------------------------------------------
    if upstream_challenge is not None:
        # Relay the downstream authorization challenge to the client. Code -32001
        # + a structured `data` block carry the WWW-Authenticate value and the
        # resource-metadata URL so the client (or gateway transport layer) can
        # drive the downstream (e.g. Entra) OAuth. The router may promote this to
        # a real HTTP 401 + WWW-Authenticate header.
        return {
            "jsonrpc": "2.0",
            "id": json_rpc_request.get("id"),
            "error": {
                "code": -32001,
                "message": "Downstream authorization required.",
                "data": {
                    "status": 401,
                    "www_authenticate": upstream_challenge.get("www_authenticate", ""),
                    "downstream_challenge": upstream_challenge.get("body"),
                    "audit_id": audit_id,
                },
            },
        }

    if upstream_error or not upstream_response:
        return {
            "jsonrpc": "2.0",
            "id": json_rpc_request.get("id"),
            "error": {
                "code": -32603,
                "message": "Upstream MCP server error.",
                "data": {"audit_id": audit_id},
            },
        }

    # -------------------------------------------------------------------------
    # Write-before-forward (RFC-0001 §8.1, PRD-0001 M2). A real result came back
    # from the upstream server. If that server is untrusted (binary integrity 0;
    # fail-closed when trust_tier is unknown), taint the principal's session BEFORE
    # the result is forwarded — and BEFORE the response-injection screen below, so a
    # BLOCK_ON_MATCH early-return can never skip the taint write (appsec M-1). A
    # write failure raises TaintStoreError -> the request fails closed (500).
    # -------------------------------------------------------------------------
    if _tf_settings.TAINT_FLOOR_ENABLED:
        from app.services.taint_floor import result_taints_session
        from app.services.taint_store import mark_tainted_for_principal

        if result_taints_session(_taint_server_trust_tier):
            await mark_tainted_for_principal(principal_id)

    # -------------------------------------------------------------------------
    # Step 6a: Indirect prompt-injection screen on the tool RESPONSE (MCP-003 /
    # CROSS-001). Perimeter controls cannot intercept tool responses — the LLM
    # processes them as content, so they must be screened here before return.
    # -------------------------------------------------------------------------
    from app.services.response_filter import (
        screen_response,
        BLOCK_ON_MATCH,
        INJECTION_DETECTED_RESPONSE,
    )

    screened_text = json.dumps(upstream_response.get("result", upstream_response))
    filter_result = screen_response(screened_text, tool_name, client_id)
    if filter_result.matched:
        # Synchronous audit of the detection (INV-001), regardless of block mode.
        await _emit_audit_event(
            tool_id=str(tool_id),
            tool_name=tool_name,
            tool_version=tool_record.get("version"),
            client_id=client_id,
            outcome="error",
            deny_reasons=["RESPONSE_FILTER_INJECTION"],
            request_id=request_id,
            latency_ms=latency_ms,
            anomaly_score=anomaly_score,
            opa_decision_id=opa_decision_id,
            is_testing=is_testing,
            source_ip=source_ip,
            principal_type=principal_type,
            roles=client_roles,
            session_jti=session_jti,
        )
        if BLOCK_ON_MATCH:
            return {
                "jsonrpc": "2.0",
                "id": json_rpc_request.get("id"),
                "error": {
                    "code": -32603,
                    "message": INJECTION_DETECTED_RESPONSE["detail"],
                    "data": {"audit_id": audit_id, "filter": "tool_response_injection"},
                },
            }

    upstream_response.setdefault("meta", {})
    upstream_response["meta"]["audit_id"] = audit_id
    upstream_response["meta"]["latency_ms"] = latency_ms
    # Trust envelope context — read by the router signing layer (PRD-0001 M3)
    upstream_response["meta"]["trust_tier"] = _taint_server_trust_tier
    upstream_response["meta"]["server_id"] = tool_server_id
    upstream_response["meta"]["sensitivity_label"] = tool_record.get("sensitivity_label")

    return upstream_response



async def _lookup_server_trust(server_id: str) -> tuple[int | None, str | None]:
    """Fetch (trust_tier, default_injection_mode) for a tool's server (PRD-0001 M2).

    Fail-CLOSED: returns (None, None) for an unlinked tool (empty server_id) or on any
    DB error, so the caller treats the result as untrusted (binary integrity 0) and the
    server's injection-default cannot silently relax the floor.
    """
    if not server_id:
        return (None, None)
    from app.core.database import AsyncSessionLocal
    from sqlalchemy import text

    try:
        async with AsyncSessionLocal() as _db:
            row = (
                await _db.execute(
                    text(
                        "SELECT trust_tier, default_injection_mode FROM server_registry "
                        "WHERE server_id = :sid AND deleted_at IS NULL LIMIT 1"
                    ),
                    {"sid": server_id},
                )
            ).mappings().fetchone()
    except Exception as exc:  # noqa: BLE001 - any DB error must fail closed
        logger.warning("server trust lookup failed (fail-closed untrusted): %s", exc)
        return (None, None)
    if row is None:
        return (None, None)
    dim = row.get("default_injection_mode")
    return (row.get("trust_tier"), str(dim) if dim is not None else None)


async def _get_or_create_session(upstream_url: str, client_id: str, headers: dict) -> str | None:
    """Return cached MCP-Session-Id or None (caller runs full handshake on None).

    Cache key is a SHA-256 hash of (upstream_url, client_id) to prevent cross-client
    session reuse. TTL is 25s — safely below the 30s upstream session timeout.
    Fails open: returns None if Redis is unavailable so caller falls back to fresh handshake.
    """
    from app.core.redis_client import redis_pool
    if redis_pool.client is None:
        return None
    cache_key = (
        "mcp_session:"
        + hashlib.sha256(f"{upstream_url}:{client_id}".encode()).hexdigest()[:16]
    )
    try:
        cached = await redis_pool.client.get(cache_key)
        if cached:
            logger.debug("MCP session cache hit for client=%s", client_id)
            return cached.decode()
    except Exception as exc:
        logger.debug("Redis session cache read failed (fail-open): %s", exc)
    return None


async def _store_session(upstream_url: str, client_id: str, session_id: str) -> None:
    """Persist a newly-created MCP-Session-Id in Redis with 25s TTL (best-effort)."""
    from app.core.redis_client import redis_pool
    if redis_pool.client is None:
        return
    cache_key = (
        "mcp_session:"
        + hashlib.sha256(f"{upstream_url}:{client_id}".encode()).hexdigest()[:16]
    )
    try:
        await redis_pool.client.setex(cache_key, 25, session_id)
    except Exception as exc:
        logger.debug("Redis session cache write failed (non-fatal): %s", exc)


async def _mcp_initialize(
    client: httpx.AsyncClient,
    upstream_url: str,
    headers: dict[str, str],
) -> str | None:
    """
    Perform the MCP initialize handshake and return the Mcp-Session-Id.
    Returns None if the server doesn't require sessions (no header in response).
    """
    init_payload = {
        "jsonrpc": "2.0",
        "method": "initialize",
        "id": 0,
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "mcp-security-proxy", "version": "1.0.0"},
        },
    }
    # Errors propagate to the caller, which records the failure in the audit
    # event with outcome="error" rather than masking it as an "allow".
    resp = await client.post(upstream_url, json=init_payload, headers=headers)
    session_id = resp.headers.get("mcp-session-id") or resp.headers.get("Mcp-Session-Id")

    # MCP spec requires notifications/initialized after initialize before tool calls.
    notify_headers = dict(headers)
    if session_id:
        notify_headers["Mcp-Session-Id"] = session_id
    await client.post(upstream_url, json={
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {},
    }, headers=notify_headers)

    return session_id


def _compute_hmac_signature(sha256_hash: str, event: Any) -> str | None:
    """
    Task 0.2 Step 3 — compute a keyed HMAC-SHA-256 over the canonical audit event.

    Uses the same canonical_audit_json() from mcp_audit_logger.hasher as the
    compliance checker, so both sides use identical serialization.

    Returns None if AUDIT_LOG_HMAC_KEY is not configured (non-production environments
    may omit the key; the checker falls back to plain hash verification).
    """
    try:
        import hmac as _hmac
        import hashlib as _hashlib
        from mcp_audit_logger.hasher import canonical_audit_json as _canonical_audit_json
        from app.core.config import settings as _settings

        # Use settings (not os.environ) so secrets injected via Vault agent,
        # AWS Secrets Manager, or K8s CSI are resolved correctly (IV-002).
        hmac_key = _settings.AUDIT_LOG_HMAC_KEY or ""
        if not hmac_key:
            return None

        # Build the canonical dict the same way the checker will read it
        canonical = _canonical_audit_json({
            "event_id": str(event.event_id),
            "event_type": event.event_type.value,
            "timestamp": event.timestamp.isoformat(),
            "client_id": event.client_id,
            "tool_name": event.tool_name,
            "tool_id": event.tool_id,
            "outcome": event.outcome.value if event.outcome else None,
            "original_outcome": event.outcome.value if event.outcome else None,
            "request_id": event.request_id,
            "platform_version": event.platform_version,
        })
        return _hmac.new(hmac_key.encode(), canonical.encode("utf-8"), _hashlib.sha256).hexdigest()
    except Exception as exc:  # noqa: BLE001
        logger.warning("HMAC signature computation failed (non-fatal): %s", exc)
        return None


async def _emit_audit_event(
    tool_id: str | None,
    tool_name: str,
    tool_version: str | None,
    client_id: str,
    outcome: str,
    deny_reasons: list[str],
    request_id: str,
    latency_ms: int,
    anomaly_score: float,
    opa_decision_id: str,
    is_testing: bool,
    source_ip: str | None = None,
    principal_type: str | None = None,
    roles: list[str] | None = None,
    session_jti: str | None = None,
) -> str:
    """
    Emit a structured audit event via mcp-audit-logger.
    Returns the event_id for embedding in the response.

    This function is called synchronously before the response is returned (INV-001).

    When tool_id is None (e.g. auth-failure 401/403 events from AuditMiddleware),
    the event_type is set to INTERNAL_TOOL_INVOCATION so the schema validator does
    not reject the missing tool_id (that constraint only applies to TOOL_INVOCATION).
    The tool_name carries the redacted "[HTTP_401] METHOD /path" string so the event
    is still machine-readable.

    Args (new in Task 1.1/1.2):
        source_ip: Originating client IP from X-Forwarded-For / request.client.host.
        principal_type: 'human' | 'agent' | 'service' from request.state.
        roles: List of roles held by the caller at invocation time.
        session_jti: OIDC session JWT ID for tracing session-scoped invocations.
    """
    try:
        from mcp_audit_logger import AuditEvent, AuditEventType, AuditOutcome, MCPAuditLogger

        outcome_map = {
            "allow": AuditOutcome.ALLOW,
            "deny": AuditOutcome.DENY,
            "error": getattr(AuditOutcome, "ERROR", AuditOutcome.DENY),
        }
        audit_logger = _get_audit_logger()

        # Auth-failure events (401/403 from AuditMiddleware) have tool_id=None
        # because the invocation never reached the tool-lookup stage.
        # TOOL_INVOCATION requires tool_id, so use INTERNAL_TOOL_INVOCATION for
        # these rows so the schema validator does not reject them.
        if tool_id is None:
            _event_type = AuditEventType.INTERNAL_TOOL_INVOCATION
        else:
            _event_type = AuditEventType.TOOL_INVOCATION

        event = AuditEvent(
            event_type=_event_type,
            client_id=client_id,
            tool_name=tool_name,
            tool_id=tool_id,
            tool_version=tool_version,
            outcome=outcome_map.get(outcome, AuditOutcome.DENY),
            request_id=request_id,
            latency_ms=latency_ms,
            deny_reasons=deny_reasons,
            anomaly_score=anomaly_score,
            opa_decision_id=opa_decision_id,
            is_testing=is_testing,
            source_ip=source_ip,
            principal_type=principal_type,
            roles=roles,
            session_jti=session_jti,
        )
        sha256_hash = audit_logger.emit(event)
        event_id = str(event.event_id)

        # Skip DB write when the test-fixture flag is set.
        # This replaces the fragile type-guard (non-UUID event_id / non-str sha256_hash)
        # and the tool_id-falsy skip that prevented 401/403 auth-failure events from
        # being persisted.  Tests that need to avoid hitting a real DB must set
        # _SKIP_AUDIT_DB_WRITE = True via the module-level flag below.
        if _SKIP_AUDIT_DB_WRITE:
            return event_id

        # Persist to the audit_events index table (INV-001).
        # This allows the compliance API to query events without Loki.
        # tool_id may be None for auth-failure events (401/403) — the column is
        # a nullable UUID FK, so NULL is valid; cast is applied only for non-None.
        try:
            from sqlalchemy import text as _text
            from app.core.database import engine as _db_engine
            async with _db_engine.begin() as conn:
                await conn.execute(
                    _text(
                        """
                        INSERT INTO audit_events (
                            event_id, client_id, tool_name, tool_id,
                            outcome, latency_ms, sha256_hash,
                            anomaly_score, opa_reasons, request_id,
                            event_type, event_ts, event_ts_iso, platform_version,
                            original_outcome, hmac_signature, hmac_key_id,
                            source_ip, principal_type, caller_roles, session_jti,
                            opa_decision_id
                        ) VALUES (
                            :event_id, :client_id, :tool_name, :tool_id,
                            :outcome, :latency_ms, :sha256_hash,
                            :anomaly_score, CAST(:opa_reasons AS jsonb), :request_id,
                            :event_type, :event_ts, :event_ts_iso, :platform_version,
                            :original_outcome, :hmac_signature, :hmac_key_id,
                            CAST(:source_ip AS INET), :principal_type,
                            CAST(:caller_roles AS TEXT[]), :session_jti,
                            :opa_decision_id
                        )
                        """
                    ),
                    {
                        "event_id": event_id,
                        "client_id": client_id,
                        "tool_name": tool_name,
                        "tool_id": tool_id,
                        # DB CHECK constraint only allows 'allow'/'deny'.
                        # An upstream failure means the tool did NOT successfully
                        # execute despite OPA allowing it — mapping to 'allow'
                        # would misrepresent the event in compliance queries.
                        # 'deny' is the conservative choice: the operation did not
                        # complete; opa_reasons records the specific failure cause.
                        # The PRE-remap value is preserved in original_outcome so
                        # the compliance checker can recompute the hash correctly
                        # (the hash was computed over the original "error" outcome).
                        "outcome": "deny" if outcome == "error" else outcome,
                        "latency_ms": latency_ms,
                        "sha256_hash": sha256_hash,
                        "anomaly_score": anomaly_score,
                        "opa_reasons": __import__("json").dumps(deny_reasons),
                        "request_id": request_id,
                        # Task 0.2 — canonical fields for hash recomputation.
                        "event_type": event.event_type.value,
                        "event_ts": event.timestamp,
                        # appsec 0.2-F1: persist verbatim isoformat() string so the
                        # compliance checker can read it without the Postgres
                        # TIMESTAMPTZ::text rendering divergence (space separator,
                        # "+00" instead of "+00:00") that would break SHA-256/HMAC
                        # verification on every post-V028 row.
                        "event_ts_iso": event.timestamp.isoformat(),
                        "platform_version": event.platform_version,
                        # Preserve the original (pre-remap) outcome for hash recomputation.
                        # For non-error outcomes original_outcome == outcome.
                        "original_outcome": outcome,
                        # HMAC signature for tamper-evidence (Step 3).
                        "hmac_signature": _compute_hmac_signature(sha256_hash, event),
                        "hmac_key_id": "default",
                        # Task 1.2 — "who" enrichment fields.
                        "source_ip": source_ip,
                        "principal_type": principal_type,
                        # caller_roles is a TEXT[] column (V029): bind the Python list
                        # directly so asyncpg encodes a Postgres array. (Previously
                        # json.dumps'd to a string, which asyncpg rejects for TEXT[] —
                        # a pre-existing bug surfaced by the PRD-0001 M2 deny-audit path.)
                        "caller_roles": list(roles) if roles else None,
                        "session_jti": session_jti,
                        # Task 5.1 (LOG-F04): real OPA decision_id for cross-stream
                        # correlation between audit_events and the OPA decision log
                        # stream in Loki (job: mcp-opa-decisions).
                        "opa_decision_id": opa_decision_id,
                    },
                )
        except Exception as db_exc:
            # DB write failure must not silently swallow — log and re-raise as AuditEmissionError
            logger.error("CRITICAL: audit_events DB write failed: %s", db_exc)
            raise AuditEmissionError(f"audit_events DB write failed: {db_exc}") from db_exc

        # ---------------------------------------------------------------
        # Secondary: best-effort syslog UDP to Wazuh manager.
        # Runs AFTER the primary audit (PostgreSQL) succeeds.
        # Failure here is non-fatal — must never affect INV-001.
        # ---------------------------------------------------------------
        from app.core.config import get_settings as _get_settings
        _s = _get_settings()
        if _s.WAZUH_SYSLOG_HOST:
            try:
                from app.services import wazuh_syslog as _ws
                _ws.emit(
                    _s.WAZUH_SYSLOG_HOST,
                    _s.WAZUH_SYSLOG_PORT,
                    client_id=client_id,
                    tool_name=tool_name,
                    outcome=outcome,
                    anomaly_score=anomaly_score,
                    risk_level="unknown",  # not available here; rules use json.risk_level from filebeat
                    request_id=request_id,
                    principal_type=principal_type,
                    deny_reasons=deny_reasons or [],
                )
            except Exception:
                pass  # swallow — secondary path must never affect INV-001

        return event_id
    except AuditEmissionError:
        raise
    except Exception as exc:
        # Per INV-001: if audit emission fails, we must surface this.
        # The caller treats a raised exception as a 500 error.
        logger.error("CRITICAL: Audit event emission failed: %s", exc)
        raise AuditEmissionError(f"Audit event emission failed: {exc}") from exc


# Public alias so mcp_server.py can call emit_mcp_access_event directly
# without importing the private _emit_audit_event name.
emit_mcp_access_event = _emit_audit_event


async def emit_internal_tool_event(
    tool_name: str,
    client_id: str,
    outcome: str,
    deny_reasons: list[str],
    request_id: str,
    latency_ms: int,
    opa_decision_id: str,
) -> None:
    """Emit a *fail-closed* audit event for internal platform meta-tools
    (no tool_id/registry entry) on the /mcp dispatch path.

    SR-2 / INV-001: routes through ``_emit_audit_event`` (with ``tool_id=None``,
    which selects ``INTERNAL_TOOL_INVOCATION``) so the event is persisted to
    ``audit_events`` AND an emission failure raises ``AuditEmissionError``.
    The caller is ``_dispatch`` (routers/mcp_server.py); the exception
    propagates through ``mcp_post`` to ``AuditMiddleware``, which converts it to
    an HTTP 500. Previously this swallowed all failures with a warning, leaving
    a meta-tool allow/deny with no durable audit record — a gap an attacker who
    can disrupt the audit store could use to make meta-tool calls invisible.
    """
    await _emit_audit_event(
        tool_id=None,
        tool_name=tool_name,
        tool_version=None,
        client_id=client_id,
        outcome=outcome,
        deny_reasons=deny_reasons,
        request_id=request_id,
        latency_ms=latency_ms,
        anomaly_score=0.0,
        opa_decision_id=opa_decision_id,
        is_testing=False,
    )


# Module-level singleton so we don't re-instantiate on every invocation
# (synchronous audit path is on the hot RTT path — INV-001).
_audit_logger_singleton = None


def _get_audit_logger():
    global _audit_logger_singleton
    if _audit_logger_singleton is None:
        from mcp_audit_logger import MCPAuditLogger

        _audit_logger_singleton = MCPAuditLogger()
    return _audit_logger_singleton


class AuditEmissionError(RuntimeError):
    """Raised when audit event emission fails (INV-001).

    Treated by AuditMiddleware as a 500 with code AUDIT_EMISSION_FAILED.
    Distinct exception type so the middleware does not have to string-match
    on the message (which is fragile — see L1 in the AppSec review).
    """


class ToolQuarantinedError(Exception):
    """Raised when attempting to invoke a quarantined tool (INV-005)."""

    def __init__(self, tool_id: str, tool_name: str) -> None:
        self.tool_id = tool_id
        self.tool_name = tool_name
        super().__init__(f"Tool '{tool_name}' ({tool_id}) is quarantined and cannot be invoked.")


class ToolDeprecatedError(Exception):
    """Raised when attempting to invoke a deprecated tool."""

    def __init__(self, tool_id: str, tool_name: str) -> None:
        self.tool_id = tool_id
        self.tool_name = tool_name
        super().__init__(f"Tool '{tool_name}' ({tool_id}) is deprecated.")


class TaintFloorDenyError(Exception):
    """Raised when the B-coarse taint floor denies a sink in a tainted session.

    RFC-0001 §8.1 / PRD-0001 M2. App-layer deny, pre-OPA, fail-closed — the deny
    is audited (INV-001) before this propagates. Routers map it to a deny response.
    """

    def __init__(self, tool_id: str, tool_name: str, required_integrity: int) -> None:
        self.tool_id = tool_id
        self.tool_name = tool_name
        self.required_integrity = required_integrity
        super().__init__(
            f"Tool '{tool_name}' ({tool_id}) denied by taint floor "
            f"(required_integrity={required_integrity}; session tainted)."
        )


class ProfileLookupError(Exception):
    """
    Raised by _lookup_profile_with_cache when the DB is unreachable AND
    no cached profile exists in Redis.

    Task 1.10 (SELF-F2): profile lookup is fail-closed. DB error + cache miss
    → raise this exception → caller converts to OPAUnavailableError → 503.

    Security rationale: a profile may carry mcp_disabled_for_profile=True or
    a restrictive allowed_functions list. If we cannot verify the profile state,
    allowing the invocation to proceed would bypass those controls — the same
    vulnerability class as INV-004 (OPA unreachable → allow-through).
    """
