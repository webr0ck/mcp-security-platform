//! Response filter — the last gate before a backend result reaches the
//! caller. Runs only when `Obligations::requires_response_filter` is set by
//! the policy engine. Redaction of secret-shaped content in responses is
//! primarily `mcphub-creds`'/`mcphub-store`'s concern (they own what a
//! "secret-shaped" pattern is); this crate only guarantees the obligation
//! is honored structurally — every path through `invoke` that sets the
//! obligation flag passes the result through this function before
//! returning it.
//!
//! TODO: confirm with architect whether pattern-based redaction should live
//! here (crate-local, no I/O) or be injected as an eighth trait so
//! `mcphub-creds` can own the pattern list without a crate dependency
//! inversion. Kept as a plain function for now since the invariant that
//! matters structurally — obligation set implies filter runs — does not
//! depend on where the pattern list is defined.

use serde_json::Value;

pub fn filter(value: Value) -> Value {
    redact_secret_shaped_strings(value)
}

fn redact_secret_shaped_strings(value: Value) -> Value {
    match value {
        Value::String(s) if looks_like_secret(&s) => Value::String("[REDACTED]".to_string()),
        Value::Array(items) => Value::Array(items.into_iter().map(redact_secret_shaped_strings).collect()),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(k, v)| (k, redact_secret_shaped_strings(v)))
                .collect(),
        ),
        other => other,
    }
}

/// Coarse heuristic only (mirrors the Python platform's log-redaction
/// filter, not a full secret scanner): long high-entropy-looking bearer
/// tokens and common credential prefixes.
fn looks_like_secret(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    lower.starts_with("bearer ")
        || lower.starts_with("sk-")
        || lower.starts_with("ghp_")
        || lower.starts_with("xox")
        || (s.len() > 32 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn redacts_bearer_like_string_fields() {
        let input = json!({"token": "Bearer abc.def.ghi", "note": "hello"});
        let out = filter(input);
        assert_eq!(out["token"], json!("[REDACTED]"));
        assert_eq!(out["note"], json!("hello"));
    }

    #[test]
    fn redacts_nested_secret_shaped_values() {
        let input = json!({"nested": {"list": ["sk-abcdefghijklmnopqrstuvwxyz0123456789"]}});
        let out = filter(input);
        assert_eq!(out["nested"]["list"][0], json!("[REDACTED]"));
    }

    #[test]
    fn leaves_ordinary_short_strings_alone() {
        let input = json!({"status": "ok"});
        assert_eq!(filter(input), json!({"status": "ok"}));
    }
}
