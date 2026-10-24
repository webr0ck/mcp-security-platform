//! Cache-key derivation for the decision cache in `engine.rs`.
//!
//! Rego evaluation is a pure function of (compiled policy, data, input):
//! identical policy + identical data + identical input always yields the
//! identical decision. That makes it memoizable with zero semantic change
//! — but only if the cache key is EXACTLY the security argument, no more,
//! no less. The key here is derived FROM the input `serde_json::Value`
//! itself (never a hand-picked field list) so a field added to the input
//! struct automatically participates in the key; there is no parallel list
//! to forget to update.
//!
//! ## The two named exclusions
//!
//! `authz_cache_key` (below) excludes exactly two fields —
//! [`AUTHZ_CACHE_KEY_EXCLUDED_FIELDS`] — from that rule. This is NOT a
//! relaxation of "derive from the whole input"; it's a separate, narrower
//! cache that covers only `authz.rego`'s own decision, which genuinely does
//! not depend on these two fields. `engine.rs`'s `anomaly_policy` (the sole
//! consumer of `recent_calls`/`window_seconds`) is evaluated fresh on
//! EVERY call, never cached at all — so excluding them here cannot produce
//! a stale anomaly verdict; there is no cache entry for the anomaly result
//! to go stale in. Without this exclusion, `recent_calls` — which changes
//! on nearly every call (each invocation appends to the sliding window) —
//! poisons the key for every field, collapsing the hit rate to ~0% the
//! moment anomaly detection is live, which is exactly what was measured
//! before this split existed (see `PERFORMANCE.md`).
//!
//! This is safe only as long as `authz.rego` itself never reads either
//! field — `policy_never_reads_the_excluded_cache_fields` below greps the
//! embedded policy source (comment-stripped) to keep that claim honest as
//! the policy evolves; it is not a promise anyone has to remember to
//! re-verify by hand.

use aws_lc_rs::digest;

/// Fields deliberately excluded from `authz_cache_key`. See this module's
/// doc comment for why these two, specifically, and why the exclusion list
/// must never grow without also updating
/// `policy_never_reads_the_excluded_cache_fields`'s literal search terms
/// below.
const AUTHZ_CACHE_KEY_EXCLUDED_FIELDS: &[&str] = &["recent_calls", "window_seconds"];

/// Canonical, deterministic string form of a JSON value: object keys
/// sorted, no incidental whitespace, escapes normalized. Two
/// `serde_json::Value`s that are `==` always canonicalize to the same
/// string regardless of the (irrelevant, non-semantic) order their keys
/// happened to be inserted in.
fn canonicalize(value: &serde_json::Value, out: &mut String) {
    match value {
        serde_json::Value::Null => out.push_str("null"),
        serde_json::Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        serde_json::Value::Number(n) => out.push_str(&n.to_string()),
        serde_json::Value::String(s) => canonicalize_string(s, out),
        serde_json::Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonicalize(item, out);
            }
            out.push(']');
        }
        serde_json::Value::Object(map) => {
            out.push('{');
            let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
            keys.sort_unstable();
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonicalize_string(k, out);
                out.push(':');
                // Safe: `k` came from `map.keys()`, so the lookup always hits.
                canonicalize(&map[*k], out);
            }
            out.push('}');
        }
    }
}

fn canonicalize_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// The authz decision cache key: SHA-256 over `<generation>|<canonical
/// input JSON, minus AUTHZ_CACHE_KEY_EXCLUDED_FIELDS>`.
///
/// `generation` is bumped by BOTH `load_bundle` and `sync_data` in
/// `engine.rs` (bundle change and data change alike). Folding it into the
/// key — rather than maintaining a separate "clear the cache on reload"
/// step — makes every previously cached entry unreachable the instant
/// either changes: there is no invalidation code path to get wrong,
/// because there is no invalidation code path at all. Old entries simply
/// age out via the cache's TTL/capacity eviction.
///
/// This key covers ONLY `authz.rego`'s own decision (`authz_allow`/
/// `authz_reasons` in `engine.rs`), not the final merged
/// `EvalResult` — see this module's doc comment for why two fields are
/// excluded and why that's safe.
pub fn authz_cache_key(input: &serde_json::Value, generation: u64) -> [u8; 32] {
    let mut buf = String::new();
    buf.push_str(&generation.to_string());
    buf.push('|');
    match input {
        serde_json::Value::Object(map) => {
            let filtered: serde_json::Map<String, serde_json::Value> = map
                .iter()
                .filter(|(k, _)| !AUTHZ_CACHE_KEY_EXCLUDED_FIELDS.contains(&k.as_str()))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            canonicalize(&serde_json::Value::Object(filtered), &mut buf);
        }
        other => canonicalize(other, &mut buf),
    }
    let d = digest::digest(&digest::SHA256, buf.as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(d.as_ref());
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn identical_values_produce_identical_keys_regardless_of_key_order() {
        let a = json!({"a": 1, "b": 2, "c": [1, 2, 3]});
        let b = json!({"c": [1, 2, 3], "b": 2, "a": 1});
        assert_eq!(authz_cache_key(&a, 1), authz_cache_key(&b, 1));
    }

    #[test]
    fn different_generation_produces_different_key_for_identical_input() {
        let v = json!({"a": 1});
        assert_ne!(authz_cache_key(&v, 1), authz_cache_key(&v, 2));
    }

    #[test]
    fn different_input_produces_different_key() {
        let a = json!({"a": 1});
        let b = json!({"a": 2});
        assert_ne!(authz_cache_key(&a, 1), authz_cache_key(&b, 1));
    }

    #[test]
    fn nested_object_key_order_does_not_affect_the_key() {
        let a = json!({"outer": {"x": 1, "y": 2}});
        let b = json!({"outer": {"y": 2, "x": 1}});
        assert_eq!(authz_cache_key(&a, 1), authz_cache_key(&b, 1));
    }

    /// The inverse of "every field participates in the key" —
    /// `engine.rs`'s general mutation-loop test proves everything ELSE is
    /// covered; this proves these two, specifically, are NOT, on purpose.
    /// Must fail if a third field is ever added to the exclusion list
    /// without this test being updated to match.
    #[test]
    fn recent_calls_and_window_seconds_do_not_affect_the_authz_cache_key() {
        let base = json!({
            "client_id": "alice",
            "tool_name": "tool_a",
            "recent_calls": [{"tool_name": "ping", "timestamp": 1.0}],
            "window_seconds": 300,
        });
        let mut mutated = base.clone();
        mutated["recent_calls"] = json!([
            {"tool_name": "file_read_1", "timestamp": 2.0},
            {"tool_name": "file_read_2", "timestamp": 3.0},
        ]);
        mutated["window_seconds"] = json!(60);

        assert_eq!(
            authz_cache_key(&base, 1),
            authz_cache_key(&mutated, 1),
            "recent_calls/window_seconds must be excluded from the authz cache key"
        );

        // Sanity: a field that ISN'T excluded still changes the key, so
        // this test isn't accidentally passing because the whole function
        // is broken.
        let mut different_client = base.clone();
        different_client["client_id"] = json!("bob");
        assert_ne!(authz_cache_key(&base, 1), authz_cache_key(&different_client, 1));
    }

    /// Defense-in-depth: keeps the exclusion in `authz_cache_key` honest as
    /// the policy evolves. Excluding `recent_calls`/`window_seconds` from
    /// the authz cache key is safe ONLY because `authz.rego` never reads
    /// them (only `anomaly.rego` does, and that's evaluated fresh on every
    /// call — never cached at all, see `engine.rs`'s `anomaly_policy`). If
    /// a future authz.rego change reintroduces a reference to either field,
    /// the exclusion silently becomes a correctness bug (a cached decision
    /// that ignored a field it should have depended on). This greps the
    /// embedded policy source, with comment lines stripped (so the
    /// documentation of this very divergence, which necessarily mentions
    /// both field names, doesn't trip it), for any remaining reference.
    #[test]
    fn policy_never_reads_the_excluded_cache_fields() {
        let source = crate::bundle::PolicyBundle::EMBEDDED_AUTHZ_REGO;
        let code_only: String = source
            .lines()
            .map(|line| match line.find('#') {
                Some(idx) => &line[..idx],
                None => line,
            })
            .collect::<Vec<_>>()
            .join("\n");

        for field in AUTHZ_CACHE_KEY_EXCLUDED_FIELDS {
            assert!(
                !code_only.contains(field),
                "authz.rego appears to reference excluded cache field '{field}' outside a \
                 comment — the authz_cache_key exclusion for this field is no longer safe; \
                 remove it from AUTHZ_CACHE_KEY_EXCLUDED_FIELDS and let the field participate \
                 in the key again"
            );
        }
    }
}
