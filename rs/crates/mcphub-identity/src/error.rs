//! Every failure mode in this crate maps to [`IdentityError`], and every
//! caller in `mcphub-gateway` maps every variant to `Decision::Deny`. There
//! is deliberately no variant that a caller could reasonably treat as
//! "identity unknown but proceed anyway" — ARCHITECTURE.md invariant 1.

use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IdentityError {
    #[error("no bearer token presented")]
    MissingToken,

    #[error("token is malformed")]
    Malformed,

    #[error("token alg {0} is not permitted")]
    AlgNotAllowed(String),

    #[error("token issuer is not a configured IDP")]
    UnknownIssuer,

    #[error("token audience does not match the expected resource")]
    InvalidAudience,

    #[error("token signature verification failed")]
    BadSignature,

    #[error("token is expired")]
    Expired,

    #[error("token is not yet valid (nbf)")]
    NotYetValid,

    #[error("token iat is outside the allowed clock skew window")]
    IatOutOfSkew,

    #[error("token kid does not match any key in the issuer's JWKS")]
    UnknownKid,

    #[error("token is missing a required kid header")]
    MissingKid,

    #[error("discovery document for issuer is invalid or unreachable")]
    DiscoveryFailed,

    #[error("jwks_uri is not pinned to the configured issuer host")]
    JwksHostMismatch,

    #[error("jwks fetch/parse failed")]
    JwksUnavailable,

    #[error("configured issuer does not support RFC 8693 token exchange")]
    ExchangeUnsupported,

    #[error("token exchange request failed")]
    ExchangeFailed,

    #[error("requested exchange scope/audience exceeds what is permitted for this server")]
    ExchangeScopeEscalation,

    #[error("PKCE state or nonce validation failed")]
    PkceStateMismatch,

    #[error("redirect_uri is not on the configured allowlist")]
    RedirectUriNotAllowed,

    #[error("dynamic client registration failed")]
    RegistrationFailed,

    #[error("no dedicated port range configured / range exhausted")]
    PortRangeExhausted,

    #[error("server's IDP {0:?} is configured for dedicated_port but has no port allocated — refusing to fall back to the shared listener")]
    DedicatedPortNotAllocated(String),

    #[error("dependency unavailable: {0}")]
    DependencyUnavailable(&'static str),

    #[error("response body exceeded the maximum allowed size")]
    ResponseTooLarge,

    #[error("endpoint URL from discovery is invalid or not permitted")]
    InvalidEndpointUrl,

    #[error("issuer or issuer alias is already claimed by another configured IDP")]
    DuplicateIssuerConfig(String),

    #[error("role string {0:?} is mapped to a privileged role by IDPs with different max_assertable_role ceilings")]
    PrivilegedRoleStringCollision(String),

    #[error("internal identity error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, IdentityError>;
