//! Numeric anomaly-score heuristic — direct port of
//! `proxy/app/services/anomaly.py`'s `_score_window`.
//!
//! In the Python platform this computation lived in APPLICATION code, not
//! Rego: `anomaly.py`'s `detect()` computed the score before ever calling
//! OPA, and `authz.rego` only compared the resulting number against a
//! cutoff (`policies/rego/anomaly.rego`'s own header comment: "The proxy
//! evaluates the anomaly score independently; this policy provides
//! structured Rego-based rules for specific known-bad invocation
//! sequences" — i.e. the STRUCTURAL rules, not the score, were ever in
//! Rego). This port preserves that architecture rather than moving scoring
//! into `anomaly.rego`: the score is computed here, in Rust, fresh on
//! every call (never cached — same reasoning as `anomaly.rego`'s own
//! evaluation in `engine.rs`'s `evaluate_raw`), from the same
//! `input.recent_calls` the structural rules read.
//!
//! STATUS (matches the Python original's own label — carried forward
//! verbatim, this has not changed): this is an ADVISORY heuristic, not a
//! learned behavioural model. Scoring is static keyword/window matching
//! only — the literal tool-name rules below are evadable by renaming a
//! tool, and there is no per-client statistical baseline.

const EXFIL_SEARCH_TOOLS: &[&str] = &["web_search", "search", "web_browse", "internet_search"];
const EXFIL_FILE_TOOLS: &[&str] = &[
    "file_reader",
    "file_read",
    "read_file",
    "bulk_file_read",
    "filesystem_read",
    "read_files",
];
const EXFIL_AUTH_TOOLS: &[&str] = &["auth", "authenticate", "login", "get_token", "oauth"];
const EXFIL_EXPORT_TOOLS: &[&str] = &["data_export", "export", "export_data", "dump", "bulk_export"];

/// Score a sliding window of tool names, exactly matching Python's
/// `_score_window`. Returns `(score in [0.0, 1.0], pattern name)`;
/// `pattern` is `None` iff `score == 0.0`.
pub fn score_window(tool_names: &[String]) -> (f64, Option<&'static str>) {
    if tool_names.is_empty() {
        return (0.0, None);
    }

    let total = tool_names.len();
    let search_count = tool_names.iter().filter(|t| EXFIL_SEARCH_TOOLS.contains(&t.as_str())).count();
    let file_read_count = tool_names.iter().filter(|t| EXFIL_FILE_TOOLS.contains(&t.as_str())).count();
    let auth_count = tool_names.iter().filter(|t| EXFIL_AUTH_TOOLS.contains(&t.as_str())).count();
    let export_count = tool_names.iter().filter(|t| EXFIL_EXPORT_TOOLS.contains(&t.as_str())).count();

    let mut score = 0.0f64;
    let mut pattern: Option<&'static str> = None;

    // Pattern 1: web_search -> bulk_file_read.
    if search_count >= 1 && file_read_count >= 3 {
        let raw = 0.7 + (file_read_count as f64 * 0.05).min(0.25);
        if raw > score {
            score = raw;
            pattern = Some("web_search_then_bulk_read");
        }
    }

    // Pattern 2: auth -> data_export.
    if auth_count >= 1 && export_count >= 1 {
        let raw = 0.80;
        if raw > score {
            score = raw;
            pattern = Some("auth_then_data_export");
        }
    }

    // Pattern 3: rapid successive invocations (>10 in the window).
    if total > 10 {
        let raw = (0.5 + (total as f64 - 10.0) * 0.035).min(0.90);
        if raw > score {
            score = raw;
            pattern = Some("rapid_successive_invocations");
        }
    }

    (round4(score), pattern)
}

fn round4(v: f64) -> f64 {
    (v * 10_000.0).round() / 10_000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(n: &[&str]) -> Vec<String> {
        n.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn empty_window_scores_zero() {
        assert_eq!(score_window(&[]), (0.0, None));
    }

    #[test]
    fn benign_window_scores_zero() {
        let w = names(&["ping", "ping", "echo_args"]);
        assert_eq!(score_window(&w), (0.0, None));
    }

    #[test]
    fn web_search_then_bulk_read_matches_python_formula() {
        // 1 search + 3 file reads: raw = 0.7 + min(3*0.05, 0.25) = 0.85
        let w = names(&["web_search", "file_read", "file_read", "file_read"]);
        let (score, pattern) = score_window(&w);
        assert_eq!(score, 0.85);
        assert_eq!(pattern, Some("web_search_then_bulk_read"));
    }

    #[test]
    fn web_search_pattern_caps_at_0_95() {
        // file_read_count large enough that 0.05*count would exceed 0.25 — capped.
        let mut calls = vec!["web_search".to_string()];
        calls.extend((0..20).map(|_| "file_read".to_string()));
        let (score, _) = score_window(&calls);
        assert_eq!(score, 0.95); // 0.7 + 0.25 (capped)
    }

    #[test]
    fn auth_then_export_scores_exactly_point_eight() {
        let w = names(&["auth", "export"]);
        let (score, pattern) = score_window(&w);
        assert_eq!(score, 0.80);
        assert_eq!(pattern, Some("auth_then_data_export"));
    }

    #[test]
    fn rapid_invocations_scores_by_python_formula() {
        // 11 calls: raw = 0.5 + (11-10)*0.035 = 0.535
        let w: Vec<String> = (0..11).map(|i| format!("tool_{i}")).collect();
        let (score, pattern) = score_window(&w);
        assert_eq!(score, 0.535);
        assert_eq!(pattern, Some("rapid_successive_invocations"));
    }

    #[test]
    fn rapid_invocations_caps_at_0_90() {
        let w: Vec<String> = (0..30).map(|i| format!("tool_{i}")).collect();
        let (score, _) = score_window(&w);
        assert_eq!(score, 0.90);
    }

    #[test]
    fn highest_scoring_pattern_wins_when_multiple_match() {
        // auth+export (0.80) AND rapid (>10 calls, would score higher) both present —
        // the higher score must win, matching Python's "higher score wins" comment.
        let mut w = vec!["auth".to_string(), "export".to_string()];
        w.extend((0..15).map(|i| format!("tool_{i}")));
        let (score, pattern) = score_window(&w);
        // rapid: 0.5 + (17-10)*0.035 = 0.745 > 0.80? no, 0.745 < 0.80, so auth/export wins.
        assert_eq!(score, 0.80);
        assert_eq!(pattern, Some("auth_then_data_export"));
    }
}
