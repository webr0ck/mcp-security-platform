//! SSRF guard — call-time re-validation of the upstream host, independent of
//! whatever was checked at server-registration time. Registration-time
//! checks alone are insufficient (the upstream host string can be edited
//! after approval, or re-resolve to a different address — DNS rebind), so
//! this runs on every `invoke`, not just at onboarding.
//!
//! This is deliberately pure/local (string-level host classification, no
//! DNS resolution) so it has zero I/O dependencies and is trivially unit
//! testable; the real gateway wiring in `mcphubd` is expected to pair this
//! with an actual DNS-pinning check in the dispatcher before opening a TCP
//! connection. TODO: confirm with architect whether DNS-rebind pinning
//! belongs in this crate or in `mcphub-store`'s dispatcher implementation.

use crate::traits::ToolMeta;
use mcphub_types::DenyReason;

pub fn validate(meta: &ToolMeta) -> Result<(), DenyReason> {
    let host = meta.upstream_host.trim();
    if host.is_empty() {
        return Err(DenyReason::PolicyDenied);
    }

    // The cloud-metadata floor is never exempted, allowlisted CIDR or not.
    if is_metadata_host(host) {
        return Err(DenyReason::PolicyDenied);
    }

    if meta.allowed_cidr.is_some() {
        // A scoped allowlist entry exists — registration explicitly opted
        // this server into resolving a private/reserved range. The actual
        // CIDR-membership check (needs a resolved IP) runs in the
        // dispatcher at connect time; here we only enforce the metadata
        // floor and reject obviously malformed hosts.
        return Ok(());
    }

    if is_private_or_reserved_literal(host) {
        return Err(DenyReason::PolicyDenied);
    }

    Ok(())
}

fn is_metadata_host(host: &str) -> bool {
    // 169.254.169.254 (AWS/GCP/Azure IMDS) and the IPv6 link-local metadata
    // range are never reachable, allowlist or not.
    host == "169.254.169.254" || host == "metadata.google.internal" || host.starts_with("fd00:ec2::254")
}

fn is_private_or_reserved_literal(host: &str) -> bool {
    if host == "localhost" || host == "127.0.0.1" || host == "::1" {
        return true;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
            }
            std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
        };
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcphub_types::ServerId;
    use uuid::Uuid;

    fn meta(host: &str, allowed_cidr: Option<&str>) -> ToolMeta {
        ToolMeta {
            server: ServerId(Uuid::nil()),
            server_enabled: true,
            quarantined: false,
            required_role: None,
            trust_tier: 5,
            upstream_host: host.into(),
            allowed_cidr: allowed_cidr.map(|s| s.to_string()),
            tool_id: None,
        }
    }

    #[test]
    fn public_host_is_allowed() {
        assert!(validate(&meta("api.example.com", None)).is_ok());
    }

    #[test]
    fn loopback_without_allowlist_is_denied() {
        assert_eq!(validate(&meta("127.0.0.1", None)), Err(DenyReason::PolicyDenied));
    }

    #[test]
    fn private_ip_with_scoped_allowlist_is_permitted() {
        assert!(validate(&meta("10.0.5.9", Some("10.0.0.0/16"))).is_ok());
    }

    #[test]
    fn metadata_host_is_denied_even_with_allowlist() {
        assert_eq!(
            validate(&meta("169.254.169.254", Some("169.254.0.0/16"))),
            Err(DenyReason::PolicyDenied)
        );
    }

    #[test]
    fn empty_host_is_denied() {
        assert_eq!(validate(&meta("", None)), Err(DenyReason::PolicyDenied));
    }
}
