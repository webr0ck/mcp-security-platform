//! Credential injection adapters — bearer header, basic auth, custom
//! header, query param. Port of the generic adapter shapes in
//! `proxy/app/credential_broker/dispatcher.py` / `adapters/`, scoped to the
//! subset ARCHITECTURE.md calls out for this component. The Python
//! platform's `InjectionMode` enum additionally has OAuth-exchange,
//! Entra-specific, and service-account modes (`kc_token_exchange`,
//! `entra_user_token`, `external_oauth_user_token`, ...) — those involve a
//! token-exchange round trip against an IDP and are `mcphub-identity`
//! (component 2) territory once that crate's OIDC/token-exchange client
//! exists; flagged here rather than half-ported.
//!
//! Secret material never reaches this module as anything but
//! `mcphub_types::Secret<String>` — by construction, `inject`'s output
//! (`InjectionOutput`) holds plain `String`s, because that output is meant
//! to be sent over the wire to the backend (see `CredentialBroker::inject`'s
//! doc comment in `mcphub-gateway::traits`); nothing upstream of that
//! boundary is ever `{:?}` or `{}` formatted.

use crate::error::CredsError;
use mcphub_types::Secret;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InjectionKind {
    BearerHeader,
    BasicAuth,
    CustomHeader(String),
    QueryParam(String),
}

/// Decrypted credential material, shaped to what each adapter needs.
pub enum CredentialMaterial {
    /// A single opaque secret string — bearer token, custom header value,
    /// or query-param value depending on the paired `InjectionKind`.
    Simple(Secret<String>),
    /// RFC 7617 HTTP Basic — username is not secret, password is.
    Basic { username: String, password: Secret<String> },
}

#[derive(Debug, Default, Clone)]
pub struct InjectionOutput {
    pub headers: HashMap<String, String>,
    pub query_params: HashMap<String, String>,
}

/// Combine decrypted material with an injection kind to produce the
/// wire-ready headers/query params. Returns `AdapterMismatch` if the
/// material shape doesn't match the requested kind (e.g. `Basic` material
/// with a `BearerHeader` kind) — a configuration error, not something to
/// guess through.
pub fn inject(material: &CredentialMaterial, kind: &InjectionKind) -> Result<InjectionOutput, CredsError> {
    let mut out = InjectionOutput::default();
    match (kind, material) {
        (InjectionKind::BearerHeader, CredentialMaterial::Simple(secret)) => {
            out.headers
                .insert("Authorization".to_string(), format!("Bearer {}", secret.expose_secret()));
        }
        (InjectionKind::BasicAuth, CredentialMaterial::Basic { username, password }) => {
            use base64::{engine::general_purpose::STANDARD, Engine as _};
            let raw = format!("{username}:{}", password.expose_secret());
            let encoded = STANDARD.encode(raw.as_bytes());
            out.headers.insert("Authorization".to_string(), format!("Basic {encoded}"));
        }
        (InjectionKind::CustomHeader(name), CredentialMaterial::Simple(secret)) => {
            out.headers.insert(name.clone(), secret.expose_secret().clone());
        }
        (InjectionKind::QueryParam(name), CredentialMaterial::Simple(secret)) => {
            out.query_params.insert(name.clone(), secret.expose_secret().clone());
        }
        _ => return Err(CredsError::AdapterMismatch),
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_header_injects_authorization() {
        let material = CredentialMaterial::Simple(Secret::new("tok123".to_string()));
        let out = inject(&material, &InjectionKind::BearerHeader).unwrap();
        assert_eq!(out.headers.get("Authorization").unwrap(), "Bearer tok123");
    }

    #[test]
    fn basic_auth_injects_base64_pair() {
        let material = CredentialMaterial::Basic {
            username: "svc".into(),
            password: Secret::new("p@ss".to_string()),
        };
        let out = inject(&material, &InjectionKind::BasicAuth).unwrap();
        let header = out.headers.get("Authorization").unwrap();
        assert!(header.starts_with("Basic "));
    }

    #[test]
    fn custom_header_uses_configured_name() {
        let material = CredentialMaterial::Simple(Secret::new("v".to_string()));
        let out = inject(&material, &InjectionKind::CustomHeader("X-Api-Key".into())).unwrap();
        assert_eq!(out.headers.get("X-Api-Key").unwrap(), "v");
    }

    #[test]
    fn query_param_uses_configured_name() {
        let material = CredentialMaterial::Simple(Secret::new("v".to_string()));
        let out = inject(&material, &InjectionKind::QueryParam("api_key".into())).unwrap();
        assert_eq!(out.query_params.get("api_key").unwrap(), "v");
    }

    #[test]
    fn mismatched_material_and_kind_is_rejected() {
        let material = CredentialMaterial::Basic {
            username: "svc".into(),
            password: Secret::new("p".to_string()),
        };
        let err = inject(&material, &InjectionKind::BearerHeader).unwrap_err();
        assert!(matches!(err, CredsError::AdapterMismatch));
    }

    #[test]
    fn secret_debug_and_display_never_print_the_value() {
        let secret = Secret::new("super-secret-api-key".to_string());
        let material = CredentialMaterial::Simple(secret);
        // The `Secret` itself must never leak via Debug/Display, regardless
        // of which adapter later exposes it into a plain-string header.
        if let CredentialMaterial::Simple(ref s) = material {
            let rendered_debug = format!("{s:?}");
            let rendered_display = format!("{s}");
            assert_eq!(rendered_debug, "Secret([REDACTED])");
            assert_eq!(rendered_display, "[REDACTED]");
            assert!(!rendered_debug.contains("super-secret-api-key"));
        }
    }
}
