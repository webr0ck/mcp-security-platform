//! `Secret<T>` — a wrapper that guarantees a value never leaks through `Debug`,
//! `Display`, logging, or `tracing` span fields. This is the *only* sanctioned
//! way to carry a credential, token, or other sensitive value through the
//! gateway (invariant 5 in `ARCHITECTURE.md`: no secret ever enters a log, a
//! span field, an error `Display`, or a response body).

use std::fmt;

/// A value that must never be printed. `Debug` and `Display` both redact.
///
/// `T` is intentionally unconstrained beyond what's needed to construct and
/// read the value back out via [`Secret::expose_secret`] — callers must
/// explicitly opt in to seeing the raw value, which makes accidental leaks
/// via `{:?}`/`{}` structurally impossible.
#[derive(Clone)]
pub struct Secret<T>(T);

impl<T> Secret<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Explicit, greppable opt-in to reading the raw value. Never call this
    /// in a `tracing::` field, an `Err` `Display` impl, or anything that ends
    /// up in a log line or HTTP response body.
    pub fn expose_secret(&self) -> &T {
        &self.0
    }

    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}

impl<T> fmt::Display for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T> PartialEq for Secret<T>
where
    T: PartialEq,
{
    /// Constant-ish equality is not attempted here (no timing-safety claim);
    /// this exists only so `Secret<T>` can be used in `#[derive(PartialEq)]`
    /// structs. Do not use this for MAC/token comparisons — use a
    /// constant-time comparator in `mcphub-creds` for that.
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<T> From<T> for Secret<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_and_display_are_redacted() {
        let s: Secret<String> = Secret::new("super-secret-token".to_string());
        assert_eq!(format!("{:?}", s), "Secret([REDACTED])");
        assert_eq!(format!("{}", s), "[REDACTED]");
        assert!(!format!("{:?}", s).contains("super-secret-token"));
    }

    #[test]
    fn expose_secret_returns_the_value() {
        let s: Secret<String> = Secret::new("abc123".to_string());
        assert_eq!(s.expose_secret(), "abc123");
    }
}
