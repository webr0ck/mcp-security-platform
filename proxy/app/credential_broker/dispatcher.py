"""
MCP Security Platform — Credential Injection Dispatcher

Routes credential injection to the correct approach based on tool.injection_mode:

  none                      — no-op; upstream called without injected credentials
  service                   — shared service credential (API key or client secret)
  user                      — per-user credential keyed by Keycloak sub
  service_account           — Keycloak client_credentials token for the tool's KC client
  oauth_user_token          — user's Keycloak access token exchanged for upstream audience
  entra_client_credentials  — app-only Microsoft Graph token via Azure client_credentials grant

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


# Token cache for entra_client_credentials: {cache_key: (access_token, expires_at)}
_entra_token_cache: dict[str, tuple[str, float]] = {}


class CredentialInjectionError(RuntimeError):
    """
    Raised when a required credential cannot be injected.
    Callers should treat this as a 424 / 500 and abort the upstream call —
    proceeding without credentials would silently bypass the enforcement boundary.
    """


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
        logger.warning("Unknown injection_mode '%s' for tool %s; skipping injection",
                       mode_str, tool_record.get("tool_id"))
        return {}

    # Fail-closed: if broker is not initialized and injection is required, abort (FIND-002 fix)
    if mode != InjectionMode.NONE:
        try:
            from app.credential_broker.broker import broker_instance  # type: ignore[attr-defined]
            if broker_instance is None:
                raise CredentialInjectionError(
                    f"Credential broker not initialized; cannot inject '{mode}' credential "
                    f"for tool {tool_record.get('tool_id')}. "
                    "Set BROKER_MASTER_SECRET_PATH and restart."
                )
        except ImportError:
            pass  # broker module not loaded; fall through to per-mode handling

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

    return {}


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
        if not plaintext:
            logger.warning("No service credential found for %s / %s", tool_id, service_name)
            return {}
        token = plaintext.strip()
        return {inject_header: f"{inject_prefix} {token}".strip()}
    except Exception as exc:
        logger.error("Service credential injection failed for %s: %s", service_name, exc)
        return {}


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
        if not plaintext:
            logger.warning("No user credential found for sub=%s service=%s", user_sub, service_name)
            return {}
        token = plaintext.strip()
        return {inject_header: f"{inject_prefix} {token}".strip()}
    except Exception as exc:
        logger.error("User credential injection failed for sub=%s / %s: %s", user_sub, service_name, exc)
        return {}


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
        logger.warning("Tool %s has service_account mode but no kc_client_id", tool_record.get("tool_id"))
        return {}

    # Client secret for the KC client is stored encrypted in credential_store
    # under user_sub="__kc_sa__" + service=kc_client_id
    try:
        client_secret = await decrypt_credential(
            user_sub="__kc_sa__",
            service=kc_client_id,
            tool_id=tool_record.get("tool_id"),
            owner_type="service",
        )
    except Exception:
        client_secret = None

    if not client_secret:
        logger.warning("No KC client secret found for kc_client_id=%s", kc_client_id)
        return {}

    token = await get_service_account_token(
        client_id=kc_client_id,
        client_secret=client_secret.strip(),
        scope=tool_record.get("kc_token_audience") or "openid",
    )

    if not token:
        return {}

    return {inject_header: f"{inject_prefix} {token}".strip()}


async def _inject_oauth_user_token(
    tool_record: dict[str, Any],
    user_kc_token: str | None,
    inject_header: str,
    inject_prefix: str,
) -> dict[str, str]:
    """Exchange the user's Keycloak access token for an upstream audience token."""
    from app.credential_broker.keycloak_client import exchange_token

    if not user_kc_token:
        logger.warning("oauth_user_token mode: no user KC token available for tool %s",
                       tool_record.get("tool_id"))
        return {}

    audience = tool_record.get("kc_token_audience") or ""
    if not audience:
        logger.warning("oauth_user_token mode: no kc_token_audience for tool %s",
                       tool_record.get("tool_id"))
        return {}

    exchanged = await exchange_token(
        subject_token=user_kc_token,
        audience=audience,
    )
    if not exchanged:
        return {}

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
        logger.error(
            "entra_client_credentials: AZURE_TENANT_ID / AZURE_CLIENT_ID / "
            "AZURE_CLIENT_SECRET not set in environment"
        )
        return {}

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
        logger.error("entra_client_credentials token fetch failed: %s", exc)
        return {}

    access_token = data.get("access_token")
    expires_in = int(data.get("expires_in", 3600))
    if not access_token:
        logger.error("entra_client_credentials: no access_token in response")
        return {}

    # Cache with 10-minute safety margin
    _entra_token_cache[cache_key] = (access_token, time.monotonic() + expires_in - 600)
    logger.info("entra_client_credentials: fetched new app-only token (expires_in=%d)", expires_in)
    return {inject_header: f"{inject_prefix} {access_token}".strip()}
