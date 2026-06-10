"""
MCP Security Platform — Credential Injection Dispatcher

Routes credential injection to the correct approach based on tool.injection_mode:

  none                      — no-op; upstream called without injected credentials
  service                   — shared service credential (API key or client secret)
  user                      — per-user credential keyed by Keycloak sub
  service_account           — Keycloak client_credentials token for the tool's KC client
  oauth_user_token          — user's Keycloak access token exchanged for upstream audience
  entra_client_credentials  — app-only Microsoft Graph token via Azure client_credentials grant
  entra_user_token          — per-user DELEGATED Microsoft Graph token; broker decrypts the
                              caller's stored Entra refresh token (enrolled at /auth/enroll/m365)
                              and refreshes it per call. Acts AS the signed-in user.

All injection modes return a dict of HTTP headers to merge into the upstream
request, or an empty dict on failure/no-op.
"""
from __future__ import annotations

import logging
import time
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class InjectionMode(str, Enum):
    NONE = "none"
    SERVICE = "service"
    USER = "user"
    SERVICE_ACCOUNT = "service_account"
    OAUTH_USER_TOKEN = "oauth_user_token"
    ENTRA_CLIENT_CREDENTIALS = "entra_client_credentials"
    ENTRA_USER_TOKEN = "entra_user_token"


# Token cache for entra_client_credentials: {cache_key: (access_token, expires_at)}
_entra_token_cache: dict[str, tuple[str, float]] = {}


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
    mode_str = tool_record.get("injection_mode", "none")
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

        case InjectionMode.OAUTH_USER_TOKEN:
            return await _inject_oauth_user_token(
                tool_record=tool_record,
                user_kc_token=user_kc_token,
                inject_header=inject_header,
                inject_prefix=inject_prefix,
            )

        case InjectionMode.ENTRA_CLIENT_CREDENTIALS:
            return await _inject_entra_client_credentials(
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
        raise CredentialInjectionError(
            f"No service credential found for tool_id={tool_id} service={service_name}; "
            "refusing to forward unauthenticated request"
        )
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
        raise CredentialInjectionError(
            f"No user credential found for sub={user_sub} service={service_name}; "
            "refusing to forward unauthenticated request"
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


async def _inject_oauth_user_token(
    tool_record: dict[str, Any],
    user_kc_token: str | None,
    inject_header: str,
    inject_prefix: str,
) -> dict[str, str]:
    """Exchange the user's Keycloak access token for an upstream audience token."""
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
            f"oauth_user_token mode: no caller Keycloak access token available for tool "
            f"{tool_record.get('tool_id')}; refusing to forward unauthenticated request"
        )

    audience = tool_record.get("kc_token_audience") or ""
    if not audience:
        raise CredentialInjectionError(
            f"oauth_user_token mode: no kc_token_audience configured for tool "
            f"{tool_record.get('tool_id')}; refusing to forward unauthenticated request"
        )

    exchanged = await exchange_token(
        subject_token=user_kc_token,
        audience=audience,
    )
    if not exchanged:
        raise CredentialInjectionError(
            f"oauth_user_token mode: Keycloak token exchange returned no token for tool "
            f"{tool_record.get('tool_id')}; refusing to forward unauthenticated request"
        )

    return {inject_header: f"{inject_prefix} {exchanged}".strip()}


async def _inject_entra_client_credentials(
    inject_header: str,
    inject_prefix: str,
) -> dict[str, str]:
    """
    Obtain an app-only Microsoft Graph access token via Azure AD client_credentials grant.

    Reads AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET from the environment.
    Caches the token for 50 minutes (tokens are valid for 1 hour).
    No credential_store entry needed — credentials come from the runtime environment.
    """
    import os
    import httpx

    tenant_id = os.environ.get("AZURE_TENANT_ID") or os.environ.get("ENTRA_TENANT_ID")
    client_id = os.environ.get("AZURE_CLIENT_ID") or os.environ.get("ENTRA_CLIENT_ID")
    client_secret = os.environ.get("AZURE_CLIENT_SECRET") or os.environ.get("ENTRA_CLIENT_SECRET")

    if not all([tenant_id, client_id, client_secret]):
        raise CredentialInjectionError(
            "entra_client_credentials: AZURE_TENANT_ID / AZURE_CLIENT_ID / "
            "AZURE_CLIENT_SECRET not set in environment; refusing to forward unauthenticated request"
        )

    cache_key = f"{tenant_id}:{client_id}"
    cached = _entra_token_cache.get(cache_key)
    if cached:
        token, expires_at = cached
        if time.monotonic() < expires_at:
            return {inject_header: f"{inject_prefix} {token}".strip()}

    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
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

    # Cache with 10-minute safety margin
    _entra_token_cache[cache_key] = (access_token, time.monotonic() + expires_in - 600)
    logger.info("entra_client_credentials: fetched new app-only token (expires_in=%d)", expires_in)
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
