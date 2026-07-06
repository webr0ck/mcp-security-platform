"""
MCP Security Platform — Credential Injection Dispatcher

Routes credential injection to the correct approach based on tool.injection_mode:

  none                      — no-op; upstream called without injected credentials
  service                   — shared service credential (API key or client secret)
  user                      — per-user credential keyed by Keycloak sub
  basic_auth                — RFC 7617 HTTP Basic; stored {"username","secret"} JSON
                              (shared or per-user), header built at injection time
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

import jwt as _jwt
from app.credential_broker.token_assert import assert_exchanged_token, ExchangedTokenError
from app.credential_broker.keycloak_client import get_public_key_for_token

# S-6(b) / CR-03: proxy-side allowlist of audiences the KC realm may mint tokens
# for via token exchange. Config-driven (KC_TOKEN_EXCHANGE_ALLOWED_AUDIENCES,
# comma-separated) rather than DB-driven, so a malicious/buggy server_registry
# row still cannot widen the mint — only a redeploy/config change can. This
# replaces a Python-literal hardcoded frozenset that required a code change to
# onboard any new same-IdP audience.

logger = logging.getLogger(__name__)

# Entra token cache TTL safety margin (seconds): fetch a fresh token this many
# seconds before the cached one actually expires so we never forward a stale token.
_ENTRA_TOKEN_CACHE_MARGIN_SECONDS = 60


class InjectionMode(str, Enum):
    NONE = "none"
    SERVICE = "service"
    USER = "user"
    # CR-05: RFC 7617 HTTP Basic. Stored as structured JSON {"username", "secret"}
    # in credential_store (shared owner_type='service' or per-user owner_type='user');
    # the Authorization: Basic <b64> header is built at injection time — never stored.
    BASIC_AUTH = "basic_auth"
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


class CrossTypePrincipalFallbackDenied(CredentialInjectionError):
    """
    CR-10 (WP-A1): raised when the per-user credential dual-read misses on the
    typed principal key and the bare-sub fallback row belongs to a DIFFERENT
    principal type than the caller (e.g. an mTLS agent and an OIDC human that
    happen to share a bare subject string). This is deliberately NEVER treated
    as a match — it is caught in services/invocation.py's dispatch_credential_
    injection except block and turned into a distinct audited deny
    ("cross_type_principal_fallback_denied"), never a silent fallback success.

    Wraps app.credential_broker.principal_resolution.CrossTypePrincipalMismatch
    so callers only need to catch CredentialInjectionError.
    """

    def __init__(self, service: str, caller_type: str, row_type: str) -> None:
        self.service = service
        self.caller_type = caller_type
        self.row_type = row_type
        super().__init__(
            f"Credential dual-read for service '{service}' refused: caller "
            f"principal_type={caller_type!r} does not match the existing "
            f"bare-sub row's principal_type={row_type!r}. Re-enrollment under "
            "the typed principal is required; the bare-sub row will NEVER be "
            "matched across principal types."
        )


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
    principal_id: str | None = None,
    principal_type: str | None = None,
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
    # CRITICAL-1 fix (cross-user credential bleed): the credential lookup key must
    # NEVER fall back to the tool's submitter-controlled `name`. That fallback let a
    # malicious self-service tool named/`service_name`d to collide with a victim's
    # enrolled adapter (e.g. "m365") receive the victim's live token injected to the
    # attacker's upstream. `service_name` is now set only via admin/approval paths
    # (constrained to the registered-adapter allowlist); absent ⇒ fail closed below.
    service_name = tool_record.get("service_name")
    tool_id = tool_record.get("tool_id")

    # CRITICAL-1 fail-closed: the stored-credential modes key the credential lookup
    # on service_name. With the submitter-controlled name fallback removed, an
    # unset service_name must NOT silently proceed — refuse rather than risk
    # resolving under an unintended/attacker-influenced key.
    if mode in (
        InjectionMode.SERVICE,
        InjectionMode.USER,
        InjectionMode.BASIC_AUTH,
        InjectionMode.ENTRA_USER_TOKEN,
    ) and not service_name:
        raise CredentialInjectionError(
            f"injection_mode='{mode.value}' requires an approval-set service_name; none configured "
            f"for tool {tool_id}. Fail-closed (CRITICAL-1) — the tool name is no longer a credential key."
        )

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
                principal_id=principal_id,
                principal_type=principal_type,
            )

        case InjectionMode.BASIC_AUTH:
            return await _inject_basic_auth(
                tool_id=tool_id,
                user_sub=client_id,
                service_name=service_name,
                inject_header=inject_header,
                principal_id=principal_id,
                principal_type=principal_type,
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
            # S-1: fail-closed — a delegated tool MUST have a user KC token.
            # Without it we cannot identify the caller; never fall back to app-only.
            if not client_id:
                raise CredentialInjectionError(
                    f"entra_user_token mode: no authenticated user sub for tool "
                    f"{tool_record.get('tool_id')}; refusing to forward (S-1 fail-closed)"
                )
            return await _inject_entra_user_token(
                user_sub=client_id,
                service_name=service_name,
                inject_header=inject_header,
                inject_prefix=inject_prefix,
                principal_id=principal_id,
                principal_type=principal_type,
            )

    raise CredentialInjectionError(
        f"injection_mode '{mode.value}' has no handler for tool {tool_record.get('tool_id')} (fail-closed)."
    )


# ---------------------------------------------------------------------------
# Private injection helpers
# ---------------------------------------------------------------------------

async def _resolve_owner_key_or_none(
    *,
    principal_id: str | None,
    principal_type: str | None,
    bare_sub: str,
    service: str,
) -> str | None:
    """
    CR-10 (WP-A1): shared entry point for the typed-principal dual-read used
    by every per-user credential_store lookup (USER, BASIC_AUTH per-user leg,
    ENTRA_USER_TOKEN).

    Returns the credential_store.user_sub value to decrypt/update under
    (either the typed principal_id or, for a same-type legacy row, the bare
    subject), or None if the caller is not enrolled under either key.

    Raises app.credential_broker.principal_resolution.CrossTypePrincipalMismatch
    if a bare-sub row exists but belongs to a different principal type —
    callers must NOT swallow this; it must become an audited deny.

    principal_id is None only for call sites that predate CR-10 typing (there
    are none left in the production invoke_tool path — AuthMiddleware always
    populates request.state.principal_id for an authenticated request). In
    that case there is no typed key to try; behave exactly as pre-CR-10 code
    did and use the bare subject directly, without an extra DB round trip.
    """
    if principal_id is None:
        return bare_sub

    from app.core.database import AsyncSessionLocal
    from app.credential_broker.principal_resolution import resolve_credential_owner

    async with AsyncSessionLocal() as session:
        resolved = await resolve_credential_owner(
            session,
            principal_id=principal_id,
            principal_type=principal_type,
            bare_sub=bare_sub,
            service=service,
        )
    return resolved.owner_key if resolved is not None else None


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
    principal_id: str | None = None,
    principal_type: str | None = None,
) -> dict[str, str]:
    """Decrypt the per-user credential from credential_store.

    CR-10 (WP-A1): resolves the owner key via the typed-principal dual-read
    (principal_id first, bare user_sub fallback gated to same-type) before
    decrypting. A cross-type fallback raises CrossTypePrincipalFallbackDenied
    (a CredentialInjectionError) instead of silently matching.
    """
    from app.credential_broker.approaches.approach_a import decrypt_credential
    from app.credential_broker.principal_resolution import CrossTypePrincipalMismatch

    try:
        owner_key = await _resolve_owner_key_or_none(
            principal_id=principal_id,
            principal_type=principal_type,
            bare_sub=user_sub,
            service=service_name,
        )
    except CrossTypePrincipalMismatch as _xtype_exc:
        raise CrossTypePrincipalFallbackDenied(
            service=service_name,
            caller_type=_xtype_exc.caller_type,
            row_type=_xtype_exc.row_type,
        ) from _xtype_exc

    if owner_key is None:
        # Not enrolled under either key — fall through to the existing
        # enrollment-required path below (decrypt_credential returns None too,
        # but resolving here first avoids a second, redundant DB round trip
        # when we already know no row exists).
        plaintext = None
    else:
        try:
            plaintext = await decrypt_credential(
                user_sub=owner_key,
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


async def _inject_basic_auth(
    tool_id: str | None,
    user_sub: str | None,
    service_name: str,
    inject_header: str,
    principal_id: str | None = None,
    principal_type: str | None = None,
) -> dict[str, str]:
    """
    RFC 7617 HTTP Basic injection (CR-05).

    The stored secret is structured JSON {"username": ..., "secret": ...}
    (written by admin_credentials / credential_storage with the shared
    approach_a codec) — NEVER a prebuilt header. The Authorization value is
    assembled here, at injection time: "Basic " + base64(username:secret).

    Resolution: a per-user row (owner_type='user', keyed by the caller's sub)
    wins over the shared service row (owner_type='service'). Fail-closed when
    neither exists. inject_prefix is intentionally ignored — RFC 7617 mandates
    the "Basic" scheme; only the header NAME is overridable.

    CR-10 (WP-A1): the per-user leg resolves through the typed-principal
    dual-read (principal_id first, bare-sub fallback gated to same-type).

    REDACTION: neither username:secret nor its base64 form may ever appear in
    logs, audit rows, or exception messages raised from here.
    """
    import base64

    from app.credential_broker.approaches.approach_a import decrypt_credential
    from app.credential_broker.principal_resolution import CrossTypePrincipalMismatch

    plaintext: str | None = None
    try:
        if user_sub:
            try:
                owner_key = await _resolve_owner_key_or_none(
                    principal_id=principal_id,
                    principal_type=principal_type,
                    bare_sub=user_sub,
                    service=service_name,
                )
            except CrossTypePrincipalMismatch as _xtype_exc:
                raise CrossTypePrincipalFallbackDenied(
                    service=service_name,
                    caller_type=_xtype_exc.caller_type,
                    row_type=_xtype_exc.row_type,
                ) from _xtype_exc
            if owner_key is not None:
                plaintext = await decrypt_credential(
                    user_sub=owner_key,
                    service=service_name,
                    tool_id=tool_id,
                    owner_type="user",
                )
        if not plaintext:
            plaintext = await decrypt_credential(
                user_sub="__service__",
                service=service_name,
                tool_id=tool_id,
                owner_type="service",
            )
    except CrossTypePrincipalFallbackDenied:
        raise
    except Exception as exc:
        raise CredentialInjectionError(
            f"basic_auth credential decryption raised for {service_name}/{tool_id}: "
            f"{type(exc).__name__}"
        ) from exc

    if not plaintext:
        raise ServiceCredentialMissingError(service=service_name, tool_id=tool_id)

    try:
        data = json.loads(plaintext)
        username = data["username"]
        secret = data["secret"]
        if not isinstance(username, str) or not isinstance(secret, str) or not username:
            raise KeyError("username/secret")
    except Exception:
        # Deliberately NO exception chaining and NO payload excerpt — the
        # decrypted plaintext must never leak through an error message.
        raise CredentialInjectionError(
            f"basic_auth credential for service '{service_name}' is not the structured "
            '{"username", "secret"} JSON payload; re-provision it (fail-closed).'
        ) from None
    finally:
        plaintext = None

    if ":" in username:
        # RFC 7617 §2: the user-id must not contain a colon (it would be
        # indistinguishable from the password separator).
        raise CredentialInjectionError(
            f"basic_auth credential for service '{service_name}' has a colon in the "
            "username, which RFC 7617 forbids; re-provision it (fail-closed)."
        )

    b64 = base64.b64encode(f"{username}:{secret}".encode("utf-8")).decode("ascii")
    return {inject_header: f"Basic {b64}"}


async def _inject_service_account_token(
    tool_record: dict[str, Any],
    inject_header: str,
    inject_prefix: str,
) -> dict[str, str]:
    """Obtain a Keycloak service-account token for the tool's KC client."""
    from app.credential_broker.keycloak_client import get_service_account_token
    from app.credential_broker.approaches.approach_a import decrypt_credential

    kc_client_id = tool_record.get("kc_client_id")
    # CRITICAL-1 fix (cross-user credential bleed): the credential lookup key must
    # NEVER fall back to the tool's submitter-controlled `name`. That fallback let a
    # malicious self-service tool named/`service_name`d to collide with a victim's
    # enrolled adapter (e.g. "m365") receive the victim's live token injected to the
    # attacker's upstream. `service_name` is now set only via admin/approval paths
    # (constrained to the registered-adapter allowlist); absent ⇒ fail closed below.
    service_name = tool_record.get("service_name")

    if not service_name:
        raise CredentialInjectionError(
            f"Tool {tool_record.get('tool_id')} requires an approval-set service_name for credential "
            "injection; none configured. Fail-closed (CRITICAL-1)."
        )

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

    sa_scope = tool_record.get("kc_token_audience") or "openid"

    # WP-A2 (CR-13): scope-SET validation, independent of kc_token_exchange's
    # audience-string allowlist below (see oauth_policy module docstring —
    # collapsing these into one allowlist previously broke every
    # service_account tool, including this one).
    from app.services.oauth_policy import validate_service_account_scope, ServiceAccountScopeViolation
    from app.core.config import get_settings as _get_sa_settings

    try:
        validate_service_account_scope(
            sa_scope, allowed_scopes=_get_sa_settings().service_account_allowed_scopes_parsed
        )
    except ServiceAccountScopeViolation as exc:
        raise CredentialInjectionError(
            f"service_account mode: scope {sa_scope!r} rejected for tool "
            f"{tool_record.get('tool_id')}: {exc}"
        ) from exc

    token = await get_service_account_token(
        client_id=kc_client_id,
        client_secret=client_secret.strip(),
        scope=sa_scope,
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

    # S-6(b) / CR-03: proxy-side audience allowlist, config-driven — see the
    # module-level comment above _inject_kc_token_exchange's imports. This is
    # the outer/bootstrap ceiling; the per-server enforced value is
    # server_registry.approved_token_audience, which is never read here
    # directly — WP-A2 instead enforces it at the point tool_registry.kc_token_audience
    # is WRITTEN (tools.py discover-tools, sourced from approved_token_audience,
    # never from the submitter-requested upstream_idp_config). By construction,
    # `audience` here can only ever be a value a reviewer approved.
    from app.core.config import get_settings as _get_kc_settings
    _allowed_audiences = _get_kc_settings().kc_token_exchange_allowed_audiences_parsed
    if audience not in _allowed_audiences:
        raise CredentialInjectionError(
            f"kc_token_exchange mode: audience {audience!r} not in allowlist "
            f"{sorted(_allowed_audiences)}"
        )

    exchanged = await exchange_token(
        subject_token=user_kc_token,
        audience=audience,
    )

    # S-5: JWKS-verify the exchanged token before trusting any claim.
    if exchanged:
        # Safe: OIDC middleware already verified user_kc_token's signature and
        # expiry before request reached this code path. Decoding without re-verify
        # here is equivalent to reading a claim the middleware already checked.
        caller_sub = _jwt.decode(user_kc_token, options={"verify_signature": False}).get("sub", "")
        try:
            public_key = await get_public_key_for_token(exchanged)
            assert_exchanged_token(
                exchanged,
                expected_sub=caller_sub,
                expected_aud=audience,
                public_key=public_key,
            )
        except ExchangedTokenError as exc:
            raise CredentialInjectionError(f"exchanged token failed S-5 assertion: {exc}") from exc
        except Exception as exc:
            raise CredentialInjectionError(f"S-5 JWKS fetch failed: {exc}") from exc

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

    # Step 3: Retrieve encrypted credential from credential_store.
    # Context tuple MUST match what admin_credentials.upload_credential wrote
    # (user_sub="__service__", service=tool.service_name or tool.name, tool_id,
    # owner_type="service") — the AAD binds decryption to these exact values.
    cred_service = tool_record.get("service_name") or tool_record.get("name") or ""
    try:
        credential_dict = await retrieve_credential(
            credential_id=credential_id,
            user_sub="__service__",  # Service-owned credential
            service=cred_service,
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

    # Step 6: Exchange credentials for access token via Entra.
    # Honour the ENTRA_TOKEN_URL override (lab points this at the mock IdP); it
    # defaults to the real per-tenant Microsoft endpoint when unset, so prod
    # multi-tenant behaviour is unchanged. Parity with _inject_entra_user_token.
    from app.core.config import get_settings as _get_entra_settings
    token_url = (
        _get_entra_settings().ENTRA_TOKEN_URL
        or f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    )
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
    principal_id: str | None = None,
    principal_type: str | None = None,
) -> dict[str, str]:
    """
    Inject a per-user DELEGATED Microsoft Graph token (acts AS the signed-in user).

    Delegates to the broker's approach-A resolve path, which:
      1. decrypts the caller's Entra refresh_token from credential_store
         (stored at /auth/callback/{service} under the authenticated Keycloak sub),
      2. calls M365Adapter.refresh() to mint a fresh delegated access_token,
      3. re-stores the rotated refresh_token.

    CR-10 (WP-A1): principal_id/principal_type are threaded into the broker's
    dual-read (typed key first, bare-sub fallback gated to same-type).

    Fail-closed: if the caller has not enrolled, raise so the upstream call is
    aborted with an actionable "enroll first" message — never silently downgrade
    to app-only (which would broaden identity from the user to the application).
    """
    from app.services.invocation import broker_instance
    from app.credential_broker.broker import CredentialNotEnrolledError
    from app.credential_broker.principal_resolution import CrossTypePrincipalMismatch

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
            principal_id=principal_id,
            principal_type=principal_type,
        )
    except CrossTypePrincipalMismatch as _xtype_exc:
        raise CrossTypePrincipalFallbackDenied(
            service=service_name,
            caller_type=_xtype_exc.caller_type,
            row_type=_xtype_exc.row_type,
        ) from _xtype_exc
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
