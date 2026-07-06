"""
Canonical auth-mode model (Codex review CR-02).

Auth modes are represented inconsistently across the portal UI, self-service
MCP tools, REST APIs, admin credential forms, dispatcher, and docs. This
module is the START of a single source of truth: one enum, one set of
human-facing labels, and one compatibility/status matrix.

STATUS: additive only. This module does not yet replace the mode lists in
submission.py, server_onboarding.py, admin_credentials.py, portal.py, or the
dispatcher's own InjectionMode enum — those still exist and are the ones
actually enforced at runtime. Migrating each call site to import from here
instead of re-declaring its own list, and adding an approval-time validator
that rejects unsupported mode/IdP combinations at draft/update time (not at
invocation), is tracked as follow-up work in
00_AI/mcp-security-platform/Codex_review/Claude_status.md (CR-02) — a
multi-call-site migration, not something to do in one pass alongside
everything else this module will eventually need to replace.

The canonical values below intentionally match
credential_broker/dispatcher.py::InjectionMode exactly (same strings) so
migrating a call site to use AuthMode instead of a local list, or instead of
InjectionMode directly, is a safe drop-in rename — never a behavior change.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class AuthMode(str, Enum):
    NONE = "none"
    SERVICE_BEARER = "service"
    BASIC_AUTH = "basic_auth"
    USER_BEARER = "user"
    SERVICE_ACCOUNT = "service_account"
    KC_TOKEN_EXCHANGE = "kc_token_exchange"
    OAUTH_USER_TOKEN = "oauth_user_token"  # deprecated alias -> KC_TOKEN_EXCHANGE
    ENTRA_CLIENT_CREDENTIALS = "entra_client_credentials"
    ENTRA_USER_TOKEN = "entra_user_token"
    EXTERNAL_OAUTH_CLIENT_CREDENTIALS = "external_oauth_client_credentials"
    EXTERNAL_OAUTH_USER_TOKEN = "external_oauth_user_token"
    PASSTHROUGH = "passthrough"


@dataclass(frozen=True)
class AuthModeInfo:
    label: str
    description: str
    # "supported" = implemented and reachable via the current admin/self-service UI.
    # "admin_only" = implemented, but only settable through the admin credential
    #   store, not self-service (dispatcher enforces this today for passthrough).
    # "alias" = a deprecated name kept only for backward-compat with existing rows.
    # "roadmap" = not implemented yet (see credential_broker/dispatcher.py — no
    #   dispatcher branch exists for it).
    status: str


# Source of truth for status: cross-checked against
# credential_broker/dispatcher.py's actual `case InjectionMode.X:` branches
# and admin_credentials.py's settable fields, 2026-07-05.
AUTH_MODES: dict[AuthMode, AuthModeInfo] = {
    AuthMode.NONE: AuthModeInfo(
        "No credential injection",
        "The upstream requires no authentication from the platform.",
        "supported",
    ),
    AuthMode.SERVICE_BEARER: AuthModeInfo(
        "Shared service credential",
        "A platform-managed shared API key or static bearer token, the same for every caller.",
        "supported",
    ),
    AuthMode.BASIC_AUTH: AuthModeInfo(
        "Basic auth",
        "Shared or per-user HTTP Basic auth (RFC 7617).",
        "supported",  # CR-05: dispatcher branch InjectionMode.BASIC_AUTH (_inject_basic_auth)
    ),
    AuthMode.USER_BEARER: AuthModeInfo(
        "Per-user identity (no credential injection)",
        "No credential is injected beyond X-User-Sub; the upstream manages its own per-user state.",
        "supported",
    ),
    AuthMode.SERVICE_ACCOUNT: AuthModeInfo(
        "Keycloak service account",
        "A Keycloak client_credentials access token for the tool's registered KC client.",
        "supported",
    ),
    AuthMode.KC_TOKEN_EXCHANGE: AuthModeInfo(
        "Same-IdP token exchange",
        "RFC 8693 token exchange — the caller's Keycloak token is exchanged for an "
        "upstream-audience token. Only works when the upstream trusts this same Keycloak realm.",
        "supported",
    ),
    AuthMode.OAUTH_USER_TOKEN: AuthModeInfo(
        "Same-IdP token exchange (deprecated name)",
        "Alias for kc_token_exchange, kept for backward compatibility with existing rows.",
        "alias",
    ),
    AuthMode.ENTRA_CLIENT_CREDENTIALS: AuthModeInfo(
        "Microsoft Entra app-only",
        "An app-only Microsoft Graph token via Azure client_credentials grant.",
        "supported",
    ),
    AuthMode.ENTRA_USER_TOKEN: AuthModeInfo(
        "Microsoft Entra delegated (per-user)",
        "A delegated Microsoft Graph token acting as the signed-in user; requires per-user enrollment.",
        "supported",
    ),
    AuthMode.EXTERNAL_OAUTH_CLIENT_CREDENTIALS: AuthModeInfo(
        "External OAuth, app-only",
        "Generic external OAuth 2.0 client_credentials grant for a non-Keycloak, non-Entra IdP.",
        "supported",  # WP-A3: credential_broker/dispatcher.py::_inject_external_oauth_client_credentials
    ),
    AuthMode.EXTERNAL_OAUTH_USER_TOKEN: AuthModeInfo(
        "External OAuth, per-user",
        "Generic external OAuth 2.0 per-user delegated/refresh flow for a non-Keycloak, non-Entra IdP "
        "(e.g. Atlassian Jira Cloud OAuth 2.0 3LO).",
        "supported",  # WP-A3: adapters/generic_oauth.py + dynamic_external_oauth.py
    ),
    AuthMode.PASSTHROUGH: AuthModeInfo(
        "Passthrough (admin-only)",
        "Forwards the caller's own inbound Authorization header verbatim to the upstream.",
        "admin_only",
    ),
}


def is_self_service_selectable(mode: AuthMode) -> bool:
    """True only for modes a non-admin self-service submitter may choose today.

    Mirrors dispatcher.py's actual behavior: admin_only and roadmap modes are
    not reachable through the current self-service registration/onboarding
    flow, regardless of what this enum lists as existing.
    """
    return AUTH_MODES[mode].status == "supported"
