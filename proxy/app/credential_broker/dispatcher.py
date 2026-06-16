"""
MCP Security Platform — Credential Injection Dispatcher

Routes credential injection to the correct approach based on tool.injection_mode:

  none                      — no-op; upstream called without injected credentials
  service                   — shared service credential (API key or client secret)
  user                      — per-user credential keyed by Keycloak sub
  service_account           — Keycloak client_credentials token for the tool's KC client
  kc_token_exchange         — RFC 8693 subject token exchange WITHIN the Keycloak realm only.
                              The user's KC access token is exchanged for an upstream-audience
                              token. For cross-IdP injection (e.g. Entra ID as the upstream),
                              use entra_user_token instead — this mode only works when the
                              upstream trusts the same Keycloak realm as the gateway.
  oauth_user_token          — ALIAS for kc_token_exchange (deprecated name; kept for
                              backwards compatibility with existing DB rows and configs).
                              New registrations should use kc_token_exchange.
  passthrough               — forward the caller's inbound Authorization header verbatim
                              to the upstream (Case-3 / 3b). The upstream uses its own IDP.
  entra_client_credentials  — app-only Microsoft Graph token via Azure client_credentials grant
  entra_user_token          — per-user DELEGATED Microsoft Graph token; broker decrypts the
                              caller's stored Entra refresh token (enrolled at /auth/enroll/m365)
                              and refreshes it per call. Acts AS the signed-in user.
                              For cross-IdP flows from KC to Entra. Requires ENTRA_TENANT_ID.

All injection modes return a dict of HTTP headers to merge into the upstream
request, or an empty dict on failure/no-op.

Task 9 (Phase 3): The tool_record received here contains injection_mode and
credential_id populated from the DB-driven server_registry table via the
Registry class (task_8). The dispatcher no longer reads mcps.yaml; all
server/credential metadata comes from the database through invoke_tool().

Task 3.2: Resolution order (server-level credential attachment):
  1. tool_registry.injection_mode (per-tool override)
  2. server_registry.default_injection_mode (server-level default)
  3. fall back to 'none'

Task 3.5: kc_token_exchange is the canonical name. oauth_user_token is an alias
  mapped at dispatch entry for backwards compatibility.

Task 3.6: Entra client_credentials token cache moved to Redis (replaces module-level dict).
  Cache key: entra:cc:{tenant_id}:{client_id}
  Falls through to a fresh fetch on Redis unavailability — auth still works but no caching.
"""
from __future__ import annotations

import json
import logging
import time
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)

# Entra token cache TTL safety margin (seconds): fetch a fresh token this many
# seconds before the cached one actually expires so we never forward a stale token.
_ENTRA_TOKEN_CACHE_MARGIN_SECONDS = 60


class InjectionMode(str, Enum):
    NONE = "none"
    SERVICE = "service"
    USER = "user"
    SERVICE_ACCOUNT = "service_account"
    # AUTH-F11 / AUTH-R4 (Task 3.5): kc_token_exchange is the canonical name.
    # oauth_user_token is an alias kept for backwards compat with existing DB rows.
    KC_TOKEN_EXCHANGE = "kc_token_exchange"
    OAUTH_USER_TOKEN = "oauth_user_token"          # alias → KC_TOKEN_EXCHANGE
    PASSTHROUGH = "passthrough"
    ENTRA_CLIENT_CREDENTIALS = "entra_client_credentials"
    ENTRA_USER_TOKEN = "entra_user_token"


class CredentialInjectionError(RuntimeError):
    """
    Raised when a required credential cannot be injected.
    Callers should treat this as a 424 / 500 and abort the upstream call —
    proceeding without credentials would silently bypass the enforcement boundary.
    """


class CredentialEnrollmentRequiredError(CredentialInjectionError):
    """
    Raised when the user has not yet completed OAuth enrollment for a service.
    Carries the enrollment URL so callers can surface it as an actionable MCP error.
    """

    def __init__(self, service: str, enrollment_url: str) -> None:
        self.service = service
        self.enrollment_url = enrollment_url
        super().__init__(
            f"User is not enrolled for delegated '{service}' access. "
            f"Open in browser to authenticate: {enrollment_url}"
        )


class ServiceCredentialMissingError(CredentialInjectionError):
    """
    Raised when a SERVICE-mode tool has no provisioned shared credential.

    Unlike CredentialEnrollmentRequiredError this is NOT a per-user login
    problem — service credentials are provisioned by a platform admin, not the
    caller. Carries the service name so callers can surface an admin-actionable
    message ("contact platform admin") instead of either a generic internal
    error or a misleading "log in first" prompt.
    """

    def __init__(self, service: str, tool_id: str | None = None) -> None:
        self.service = service
        # tool_id is kept as an attribute for structured logging only — it is
        # deliberately NOT in the exception message so it can never leak to a
        # caller via a generic `f"...: {exc}"` fallthrough handler.
        self.tool_id = tool_id
        super().__init__(
            f"No service credential provisioned for service '{service}'; "
            "refusing to forward unauthenticated request"
        )


async def dispatch_credential_injection(
    tool_record: dict[str, Any],
    client_id: str,
    user_kc_token: str | None = None,
) -> dict[str, str]:
    """
    Returns HTTP headers dict to inject into the upstream call.

    Raises CredentialInjectionError when injection is required but cannot complete
    (broker not ready, missing credential, token exchange failure).
    Returns {} only for injection_mode='none'.
    """
    # Task 3.2: Resolution order
    #   1. tool-level injection_mode (explicit per-tool override)
    #   2. server_default_injection_mode (server-level default)
    #   3. fall back to 'none' (no-op; legitimate when no credential is needed)
    #
    # credential_id follows the same precedence: per-tool credential_id is preferred,
    # server_default_credential_id is the fallback. The per-mode helpers receive
    # whichever credential_id won (the tool_record is already resolved by the
    # invocation layer via _resolve_effective_tool_record below, or at call time
    # by apply_server_defaults() before dispatch_credential_injection is called).
    _raw_mode = tool_record.get("injection_mode")
    # Resolution order (Task 3.2):
    #   1. tool-level injection_mode (per-tool override): use if not None and not empty string
    #   2. server_default_injection_mode (server-level default)
    #   3. fall back to 'none' (no-op; legitimate when no credential is needed)
    #
    # An empty string "" is NOT the same as None/unset — it is treated as an unknown
    # mode string that will fail the InjectionMode() parse and raise CredentialInjectionError.
    # This preserves the fail-closed invariant: "" must not silently become 'none'.
    if _raw_mode is None:
        _raw_mode = tool_record.get("server_default_injection_mode") or "none"

    # Task 3.5 (AUTH-F11 / AUTH-R4): map the deprecated alias to the canonical name
    # at the entry point so all downstream logic only sees kc_token_exchange.
    # The DB enum still stores "oauth_user_token" for existing rows; we normalise here.
    if _raw_mode == "oauth_user_token":
        _raw_mode = "kc_token_exchange"

    mode_str = _raw_mode
    try:
        mode = InjectionMode(mode_str)
    except ValueError:
        raise CredentialInjectionError(
            f"unsupported injection_mode '{mode_str}' for tool {tool_record.get('tool_id')}; "
            "refusing to forward an unauthenticated upstream call (fail-closed)."
        )

    # Fail-closed: if broker is not initialized and injection is required, abort (FIND-002 fix)
    # broker_instance lives on app.services.invocation (set by lifespan). The import is
    # lazy (inside the function) to avoid a circular import at module load time.
    if mode != InjectionMode.NONE:
        try:
            from app.services.invocation import broker_instance
            if broker_instance is None:
                raise CredentialInjectionError(
                    f"Credential broker not initialized; cannot inject '{mode}' credential "
                    f"for tool {tool_record.get('tool_id')}. "
                    "Set BROKER_MASTER_SECRET_PATH and restart."
                )
        except ImportError:
            pass  # invocation module not loaded; fall through to per-mode handling

    inject_header = tool_record.get("inject_header") or "Authorization"
    inject_prefix = tool_record.get("inject_prefix") or "Bearer"
    service_name = tool_record.get("service_name") or tool_record.get("name", "unknown")
    tool_id = tool_record.get("tool_id")

    match mode:
        case InjectionMode.NONE:
            return {}

        case InjectionMode.SERVICE:
            return await _inject_service_credential(
                tool_id=tool_id,
                service_name=service_name,
                inject_header=inject_header,
                inject_prefix=inject_prefix,
            )

        case InjectionMode.USER:
            return await _inject_user_credential(
                tool_id=tool_id,
                user_sub=client_id,
                service_name=service_name,
                inject_header=inject_header,
                inject_prefix=inject_prefix,
            )

        case InjectionMode.SERVICE_ACCOUNT:
            return await _inject_service_account_token(
                tool_record=tool_record,
                inject_header=inject_header,
                inject_prefix=inject_prefix,
            )

        case InjectionMode.KC_TOKEN_EXCHANGE:
            # RFC 8693 subject token exchange WITHIN the Keycloak realm only.
            # For cross-IdP injection use entra_user_token.
            return await _inject_kc_token_exchange(
                tool_record=tool_record,
                user_kc_token=user_kc_token,
                inject_header=inject_header,
                inject_prefix=inject_prefix,
            )

        case InjectionMode.OAUTH_USER_TOKEN:
            # This arm is unreachable in practice: the alias normalisation above
            # maps oauth_user_token → kc_token_exchange before InjectionMode() is
            # called, so the parsed enum value will always be KC_TOKEN_EXCHANGE.
            # Kept as a belt-and-suspenders guard — if the alias normalisation is
            # ever bypassed, we route to the same handler rather than falling
            # through to the fail-closed terminal raise below.
            return await _inject_kc_token_exchange(
                tool_record=tool_record,
                user_kc_token=user_kc_token,
                inject_header=inject_header,
                inject_prefix=inject_prefix,
            )

        case InjectionMode.PASSTHROUGH:
            # Passthrough mode is handled at the invocation layer (invocation.py)
            # before dispatch_credential_injection is called; if we reach here it
            # means the invocation layer did NOT intercept it (e.g. test-time call).
            # Return {} to indicate no additional headers — the inbound header
            # will be forwarded verbatim by the caller.
            return {}

        case InjectionMode.ENTRA_CLIENT_CREDENTIALS:
            return await _inject_entra_client_credentials(
                tool_record=tool_record,
                inject_header=inject_header,
                inject_prefix=inject_prefix,
            )

        case InjectionMode.ENTRA_USER_TOKEN:
            return await _inject_entra_user_token(
                user_sub=client_id,
                service_name=service_name,
                inject_header=inject_header,
                inject_prefix=inject_prefix,
            )

    raise CredentialInjectionError(
        f"injection_mode '{mode.value}' has no handler for tool {tool_record.get('tool_id')} (fail-closed)."
    )


# ---------------------------------------------------------------------------
# Private injection helpers
# ---------------------------------------------------------------------------

async def _inject_service_credential(
    tool_id: str | None,
    service_name: str,
    inject_header: str,
    inject_prefix: str,
) -> dict[str, str]:
    """Decrypt the service-mode credential from credential_store."""
    from app.credential_broker.approaches.approach_a import decrypt_credential

    try:
        plaintext = await decrypt_credential(
            user_sub="__service__",
            service=service_name,
            tool_id=tool_id,
            owner_type="service",
        )
    except Exception as exc:
        raise CredentialInjectionError(
            f"Service credential decryption raised for {service_name}/{tool_id}: {exc}"
        ) from exc

    if not plaintext:
        raise ServiceCredentialMissingError(service=service_name, tool_id=tool_id)
    token = plaintext.strip()
    return {inject_header: f"{inject_prefix} {token}".strip()}


async def _inject_user_credential(
    tool_id: str | None,
    user_sub: str,
    service_name: str,
    inject_header: str,
    inject_prefix: str,
) -> dict[str, str]:
    """Decrypt the per-user credential from credential_store."""
    from app.credential_broker.approaches.approach_a import decrypt_credential

    try:
        plaintext = await decrypt_credential(
            user_sub=user_sub,
            service=service_name,
            tool_id=tool_id,
            owner_type="user",
        )
    except Exception as exc:
        raise CredentialInjectionError(
            f"User credential decryption raised for sub={user_sub} service={service_name}: {exc}"
        ) from exc

    if not plaintext:
        # Fail-closed with an ACTIONABLE enrollment link instead of a cryptic
        # "internal error". Mirrors _inject_entra_user_token's enrollment raise so
        # the MCP layer can surface a "log in first" message to the caller.
        from app.core.config import get_settings
        base = get_settings().PROXY_BASE_URL.rstrip("/")
        enrollment_url = f"{base}/auth/enroll/{service_name}"
        raise CredentialEnrollmentRequiredError(
            service=service_name,
            enrollment_url=enrollment_url,
        )
    token = plaintext.strip()
    return {inject_header: f"{inject_prefix} {token}".strip()}


async def _inject_service_account_token(
    tool_record: dict[str, Any],
    inject_header: str,
    inject_prefix: str,
) -> dict[str, str]:
    """Obtain a Keycloak service-account token for the tool's KC client."""
    from app.credential_broker.keycloak_client import get_service_account_token
    from app.credential_broker.approaches.approach_a import decrypt_credential

    kc_client_id = tool_record.get("kc_client_id")
    service_name = tool_record.get("service_name") or tool_record.get("name", "unknown")

    if not kc_client_id:
        raise CredentialInjectionError(
            f"Tool {tool_record.get('tool_id')} has service_account mode but no kc_client_id configured"
        )

    # Client secret for the KC client is stored encrypted in credential_store
    # under user_sub="__kc_sa__" + service=kc_client_id
    try:
        client_secret = await decrypt_credential(
            user_sub="__kc_sa__",
            service=kc_client_id,
            tool_id=tool_record.get("tool_id"),
            owner_type="service",
        )
    except Exception as exc:
        raise CredentialInjectionError(
            f"KC client secret decryption raised for kc_client_id={kc_client_id}: {exc}"
        ) from exc

    if not client_secret:
        raise CredentialInjectionError(
            f"No KC client secret found for kc_client_id={kc_client_id}; "
            "refusing to forward unauthenticated request"
        )

    token = await get_service_account_token(
        client_id=kc_client_id,
        client_secret=client_secret.strip(),
        scope=tool_record.get("kc_token_audience") or "openid",
    )

    if not token:
        raise CredentialInjectionError(
            f"Keycloak returned no service-account token for kc_client_id={kc_client_id}"
        )

    return {inject_header: f"{inject_prefix} {token}".strip()}


async def _inject_kc_token_exchange(
    tool_record: dict[str, Any],
    user_kc_token: str | None,
    inject_header: str,
    inject_prefix: str,
) -> dict[str, str]:
    """
    RFC 8693 subject token exchange WITHIN the Keycloak realm only.

    Exchanges the user's Keycloak access token for an upstream-audience token.
    This mode ONLY works when the upstream service trusts the same Keycloak realm
    as the gateway. For cross-IdP injection (e.g. Entra ID as the upstream IDP),
    use entra_user_token instead — that mode handles the KC→Entra delegation.

    Formerly named _inject_oauth_user_token (AUTH-F11 / AUTH-R4, Task 3.5).
    """
    from app.credential_broker.keycloak_client import exchange_token

    # Fail-closed (AUTH/CB): every failure path below MUST raise, never return {}.
    # Returning empty headers would let invoke_tool forward the upstream call with
    # NO Authorization header — silently bypassing the credential boundary that is
    # the platform's reason to exist (parity with service/user/service_account modes).
    if not user_kc_token:
        # Fail-closed: no caller KC token → refuse rather than forward unauthenticated.
        # (6.3 wired invoke_tool to pass the real token; this path fires only for
        # non-OIDC callers whose bearer is not a KC subject token.)
        raise CredentialInjectionError(
            f"kc_token_exchange mode: no caller Keycloak access token available for tool "
            f"{tool_record.get('tool_id')}; refusing to forward unauthenticated request"
        )

    audience = tool_record.get("kc_token_audience") or ""
    if not audience:
        raise CredentialInjectionError(
            f"kc_token_exchange mode: no kc_token_audience configured for tool "
            f"{tool_record.get('tool_id')}; refusing to forward unauthenticated request"
        )

    exchanged = await exchange_token(
        subject_token=user_kc_token,
        audience=audience,
    )
    if not exchanged:
        raise CredentialInjectionError(
            f"kc_token_exchange mode: Keycloak token exchange returned no token for tool "
            f"{tool_record.get('tool_id')}; refusing to forward unauthenticated request"
        )

    return {inject_header: f"{inject_prefix} {exchanged}".strip()}


async def _inject_entra_client_credentials(
    tool_record: dict[str, Any],
    inject_header: str,
    inject_prefix: str,
) -> dict[str, str]:
    """
    Obtain an app-only Microsoft Graph access token via Azure AD client_credentials grant.

    Reads Entra client credentials from vault-backed credential_store via credential_id
    in the tool_record. Credentials are stored as encrypted JSON:
      {"tenant_id": "...", "client_id": "...", "client_secret": "..."}

    Task 3.6 (AUTH-F14 / AUTH-R7): Token caching uses Redis instead of a module-level
    dict so the cache is shared across workers and survives process restarts cleanly.
    Cache key: entra:cc:{tenant_id}:{client_id}
    Redis TTL: expires_in - _ENTRA_TOKEN_CACHE_MARGIN_SECONDS (leave a 60s buffer).
    If Redis is unavailable, falls through to a fresh token fetch — auth still works,
    just without caching. Do NOT fail-closed on cache unavailability since the token
    fetch itself can still succeed.

    Fail-closed: if credential_id is missing or credential_store lookup fails, raise.
    """
    import httpx
    from app.services.credential_storage import retrieve_credential
    from app.services.invocation import broker_instance

    # Step 1: Get credential_id from tool_record
    credential_id = tool_record.get("credential_id")
    if not credential_id:
        raise CredentialInjectionError(
            f"entra_client_credentials: tool {tool_record.get('tool_id')} "
            "has no credential_id; refusing to forward unauthenticated request"
        )

    # Step 2: Fetch broker's Vault client and DB pool to retrieve credential
    if broker_instance is None:
        raise CredentialInjectionError(
            "entra_client_credentials: credential broker not initialized; "
            "cannot retrieve Entra credential from vault-backed credential_store"
        )

    vault_client = broker_instance.vault_client
    db_pool = broker_instance.db_pool

    if not vault_client or not db_pool:
        raise CredentialInjectionError(
            "entra_client_credentials: broker has no vault_client or db_pool; "
            "cannot retrieve credential from credential_store"
        )

    # Step 3: Retrieve encrypted credential from credential_store
    try:
        credential_dict = await retrieve_credential(
            credential_id=credential_id,
            user_sub="__service__",  # Service-owned credential
            service="entra",
            tool_id=tool_record.get("tool_id"),
            owner_type="service",
            vault_client=vault_client,
            db_pool=db_pool,
        )
    except KeyError:
        raise CredentialInjectionError(
            f"entra_client_credentials: credential_id {credential_id} not found in credential_store; "
            "refusing to forward unauthenticated request"
        ) from None
    except Exception as exc:
        raise CredentialInjectionError(
            f"entra_client_credentials: credential_store retrieval failed for {credential_id}: {exc}"
        ) from exc

    # Step 4: Extract tenant_id, client_id, client_secret from decrypted credential
    tenant_id = credential_dict.get("tenant_id")
    client_id = credential_dict.get("client_id")
    client_secret = credential_dict.get("client_secret")

    if not all([tenant_id, client_id, client_secret]):
        raise CredentialInjectionError(
            f"entra_client_credentials: credential {credential_id} missing required fields "
            "(tenant_id, client_id, client_secret); refusing to forward unauthenticated request"
        )

    # Step 5: Check Redis cache before calling Entra (Task 3.6 — AUTH-F14 / AUTH-R7).
    # Mirror the pattern used by keycloak_client.py:53-93 for KC service-account tokens.
    # Cache key format: entra:cc:{tenant_id}:{client_id}
    redis_cache_key = f"entra:cc:{tenant_id}:{client_id}"
    try:
        from app.core.redis_client import redis_pool
        redis = redis_pool.client
        cached_raw = await redis.get(redis_cache_key)
        if cached_raw:
            cached_data = json.loads(cached_raw)
            cached_token = cached_data.get("access_token")
            if cached_token:
                logger.debug(
                    "entra_client_credentials: Redis cache hit for tenant=%s client=%s",
                    tenant_id,
                    client_id,
                )
                return {inject_header: f"{inject_prefix} {cached_token}".strip()}
    except Exception as cache_exc:
        # Redis unavailable: fall through to fresh fetch. Auth still works; just no caching.
        logger.warning(
            "entra_client_credentials: Redis cache read failed (falling through to fresh fetch): %s",
            cache_exc,
        )

    # Step 6: Exchange credentials for access token via Entra
    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    try:
        async with httpx.AsyncClient(timeout=10.0) as http_client:
            resp = await http_client.post(
                token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "scope": "https://graph.microsoft.com/.default",
                },
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        raise CredentialInjectionError(
            f"entra_client_credentials token fetch failed: {exc}"
        ) from exc

    access_token = data.get("access_token")
    expires_in = int(data.get("expires_in", 3600))
    if not access_token:
        raise CredentialInjectionError(
            "entra_client_credentials: no access_token in Azure AD response; "
            "refusing to forward unauthenticated request"
        )

    # Step 7: Write fresh token to Redis with TTL = expires_in - margin.
    # On Redis failure: log warning and continue — the token itself is valid.
    redis_ttl = max(1, expires_in - _ENTRA_TOKEN_CACHE_MARGIN_SECONDS)
    try:
        from app.core.redis_client import redis_pool as _redis_pool
        _redis = _redis_pool.client
        await _redis.setex(
            redis_cache_key,
            redis_ttl,
            json.dumps({"access_token": access_token}),
        )
        logger.info(
            "entra_client_credentials: fetched new app-only token and cached in Redis "
            "(expires_in=%d ttl=%d)",
            expires_in,
            redis_ttl,
        )
    except Exception as write_exc:
        logger.warning(
            "entra_client_credentials: Redis cache write failed (token still usable): %s",
            write_exc,
        )

    return {inject_header: f"{inject_prefix} {access_token}".strip()}


async def _inject_entra_user_token(
    user_sub: str,
    service_name: str,
    inject_header: str,
    inject_prefix: str,
) -> dict[str, str]:
    """
    Inject a per-user DELEGATED Microsoft Graph token (acts AS the signed-in user).

    Delegates to the broker's approach-A resolve path, which:
      1. decrypts the caller's Entra refresh_token from credential_store
         (stored at /auth/callback/{service} under the authenticated Keycloak sub),
      2. calls M365Adapter.refresh() to mint a fresh delegated access_token,
      3. re-stores the rotated refresh_token.

    Fail-closed: if the caller has not enrolled, raise so the upstream call is
    aborted with an actionable "enroll first" message — never silently downgrade
    to app-only (which would broaden identity from the user to the application).
    """
    from app.services.invocation import broker_instance
    from app.credential_broker.broker import CredentialNotEnrolledError

    if broker_instance is None:
        raise CredentialInjectionError(
            f"entra_user_token: credential broker not initialized; cannot resolve "
            f"delegated token for sub={user_sub} service={service_name}"
        )

    try:
        # approach 'A' is keyed by user_sub only; session_id is unused for it.
        result = await broker_instance.resolve(
            user_sub=user_sub,
            service=service_name,
            session_id=user_sub,
            approach="A",
        )
    except CredentialNotEnrolledError as exc:
        from app.core.config import get_settings
        base = get_settings().PROXY_BASE_URL.rstrip("/")
        enrollment_url = f"{base}/auth/enroll/{service_name}"
        raise CredentialEnrollmentRequiredError(
            service=service_name,
            enrollment_url=enrollment_url,
        ) from exc
    except Exception as exc:
        raise CredentialInjectionError(
            f"entra_user_token resolve failed for sub={user_sub} service={service_name}: {exc}"
        ) from exc

    if not result or not result.token:
        raise CredentialInjectionError(
            f"entra_user_token: broker returned no delegated token for sub={user_sub} "
            f"service={service_name}; refusing to forward unauthenticated request"
        )

    return {inject_header: f"{inject_prefix} {result.token}".strip()}
