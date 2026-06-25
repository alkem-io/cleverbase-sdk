//! A minimal redacting secret newtype for the OAuth bearer token / one-time `c_nonce` the issuance
//! flow carries (`crate::issuance::obtain`).
//!
//! This is a deliberate, self-contained copy of the ~20-line `Secret` newtype the signing core
//! (`cleverbase-core`) defines. It is *not* a DRY violation: pulling in `cleverbase-core` solely to
//! reuse this trivial leaf type dragged the whole signing stack — including `lopdf` (a PDF library)
//! and `cms` — into this otherwise pure-Rust / WASM-able / minimal verifier (contradicting the
//! `lib.rs` posture). The correct trade-off for a trivial leaf type is a local definition rather
//! than a heavy cross-crate dependency; see the removed-dependency rationale in `Cargo.toml`.
//!
//! Semantics match the core type exactly: the inner value never appears in `Debug` output
//! (Constitution Principle IV — never leak secrets via Debug/log/panic), yet it still
//! (de)serializes transparently so a CBOR-serialized `obtain` session can round-trip its
//! authorization material (the host owns the wire bytes by design in the sans-IO model — only the
//! `Debug` exposure was the leak).

use serde::{Deserialize, Serialize};

/// A secret string whose contents never appear in `Debug` output (Constitution Principle IV).
///
/// It still (de)serializes its inner value so a CBOR-serialized `obtain` session can round-trip its
/// bearer token / one-time nonce; the host is responsible for protecting serialized handles at rest.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Secret(String);

impl Secret {
    /// Wrap a value as a redacted secret.
    pub(crate) fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Reveal the secret. Call sites should keep the result on the server only.
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Debug for Secret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Secret(***)")
    }
}

#[cfg(test)]
mod tests {
    use super::Secret;

    #[test]
    fn debug_redacts_the_inner_value() {
        let s = Secret::new("super-secret-bearer-token");
        let rendered = format!("{s:?}");
        assert_eq!(rendered, "Secret(***)");
        assert!(!rendered.contains("super-secret-bearer-token"));
    }

    #[test]
    fn expose_reveals_the_inner_value() {
        assert_eq!(Secret::new("x").expose(), "x");
        assert_eq!(Secret::new(String::from("abc")).expose(), "abc");
    }

    #[test]
    fn serde_round_trips_the_inner_value() {
        let s = Secret::new("round-trip-me");
        let json = serde_json::to_string(&s).expect("serialize");
        // Serializes transparently (the inner string, not the redacted marker), so a session handle
        // can carry the live token on the wire.
        assert_eq!(json, "\"round-trip-me\"");
        let back: Secret = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.expose(), "round-trip-me");
        assert_eq!(s, back);
    }
}
