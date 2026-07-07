//! # cleverbase-attestation
//!
//! The sans-IO EUDI **attestation** core of the Cleverbase SDK. It verifies presented EUDI
//! credentials in both mandated formats — **SD-JWT VC** (RFC 9901 / draft-16) and **ISO/IEC 18013-5
//! mdoc** — against EU trust anchors, and (forward-looking, gated) drives OpenID4VCI issuance and
//! OpenID4VP holder presentation via the integrator's signer-hook. Like `cleverbase-core` it is
//! **sans-IO** (no network in the core; trust lists are fetched/cached by a host-driven step and
//! passed in as anchors) and **pure-Rust / WASM-able** (no JVM, no OpenSSL-FFI).
//!
//! See `specs/004-attestation-and-verification/` for the spec, plan, data-model, and contracts.
//!
//! ## Design constraints (from the plan)
//!
//! - **No hand-rolled crypto** (Principle IV): signatures and digests go through the SDK's existing
//!   RustCrypto stack (`p256`/`ecdsa`/`rsa`/`sha2`/`x509-cert`) plus `coset` for COSE.
//! - **One Rust core** (Principle III): all attestation logic lives here, surfaced over the existing
//!   `cleverbase-ffi` C-ABI; the bindings stay thin.
//! - **Not a wallet** (Principle IV): holder keys are the integrator's, exercised via the spec-001
//!   signer-hook; the SDK never holds a private key.
//!
//! ## Status
//!
//! User Story 1 (feature 004 — the MVP) is implemented: the global [`verify()`] entry point assembles
//! the always-on bar over both format verifiers ([`sdjwtvc`], [`mdoc`]), the native EU trust-list
//! engine ([`trust`]), the revocation/[`status`] check (fail-closed by default), and the
//! [`openid4vp`] request binding (nonce + audience), surfaced over the `cleverbase-ffi` C-ABI via
//! [`wire`]. The opt-in [`qualified`]-status gate (eIDAS qualified-status determination) is
//! implemented and off by default ([`verify::VerifyContext::qualified_gate`] is the seam); the gated
//! [`issuance`] path (US2 — OpenID4VCI `obtain` + OpenID4VP holder `present` via the signer-hook) is
//! implemented and skips when no issuer backend is configured.

// The workspace pins a strict `restriction` lint set (unwrap/expect/panic/indexing/…) that targets
// library code. Test modules use those same constructs as assertions, where a panic IS the intended
// failure signal, so re-allow them under `cfg(test)` only — `src` stays held to the strict bar.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::unwrap_in_result,
        clippy::string_slice
    )
)]

#[cfg(test)]
mod conformance;
pub mod crypto;
pub mod datetime;
pub mod dcql;
pub mod issuance;
pub mod mdoc;
pub mod openid4vp;
pub mod qualified;
pub mod sdjwtvc;
pub mod secret;
pub mod status;
#[cfg(feature = "test-vectors")]
pub mod test_vectors;
pub mod trust;
pub mod types;
pub mod verify;
pub mod wire;

pub use verify::{detect_format, verify, Presentation, VerifyContext};

/// Serialize a value to CBOR in a fresh in-memory `Vec` — the one authoritative "encode CBOR into a
/// Vec" helper for the crate (DRY — Principle III). Writing CBOR into an in-memory `Vec` writer is
/// **infallible** (a `Vec` never fails a write and the serialized types are plain serde types), so
/// the only possible `into_writer` error is impossible here; this surfaces it via `expect` rather
/// than threading an error channel that can never fire. The three response/transcript encoders that
/// have no error channel (`wire::encode_verify_response`, `issuance::wire::encode_issuance_response`,
/// `openid4vp::oid4vp_handover_transcript`) previously each carried an identical
/// `#[allow(clippy::expect_used)] into_writer(...).expect("infallible")` block; they now share this.
#[allow(clippy::expect_used)] // infallible: serializing a plain serde value into a Vec writer
pub(crate) fn cbor_to_vec<T: serde::Serialize + ?Sized>(value: &T) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).expect("CBOR serialization into a Vec is infallible");
    buf
}

/// The CBOR `#6.24` "encoded CBOR data item" tag (RFC 8949 §3.4.5.1, value `24`) — the **one**
/// authoritative definition for the crate (DRY — Principle III). ISO/IEC 18013-5 wraps each
/// `IssuerSignedItem`, the MSO, the `DeviceNameSpaces`, and the `SessionTranscript` /
/// `DeviceAuthentication` payloads in this tag so the *exact bytes* are what gets hashed/signed (a
/// re-serialization with different map ordering must not change the digest); the SD-JWT VC / mdoc
/// verifiers ([`mdoc`]) and the issuance holder ceremonies ([`issuance::device`],
/// [`issuance::present`]) all reference this single const rather than a re-transcribed `24`.
pub(crate) const TAG_ENCODED_CBOR: u64 = 24;

/// Wrap `inner` bytes in a CBOR `#6.24(bstr)` "encoded CBOR data item" and serialize to a fresh
/// `Vec` — the **one** authoritative `#6.24(bstr)` wrap-then-encode for the crate (DRY — Principle
/// III), built on [`cbor_to_vec`]. The mdoc verifier (which rebuilds + re-signs over these bytes),
/// the holder `DeviceSignature` ceremony ([`issuance::device`]), and the holder presentation splice
/// ([`issuance::present`]) previously each transcribed an identical
/// `Tag(24, Bytes(inner)) → into_writer` step; they now share this, so the byte output is identical
/// across every site (critical — the verifier's digest/signature must reconstruct the same bytes the
/// issuer/holder produced). Encoding a plain serde value into a `Vec` is infallible, so this has no
/// error channel.
pub(crate) fn encode_tagged_cbor(inner: &[u8]) -> Vec<u8> {
    cbor_to_vec(&ciborium::value::Value::Tag(
        TAG_ENCODED_CBOR,
        Box::new(ciborium::value::Value::Bytes(inner.to_vec())),
    ))
}

/// Unwrap a CBOR `#6.24(bstr)` "encoded CBOR data item" to its inner byte string — the **one**
/// authoritative `#6.24(bstr)` unwrap for the crate (DRY — Principle III), the inverse of
/// [`encode_tagged_cbor`]. Returns `None` for any value that is not a [`TAG_ENCODED_CBOR`] tag
/// wrapping a byte string. The inner bytes are the exact serialization that was hashed/signed, so a
/// caller MUST use them verbatim. Both the mdoc verifier ([`mdoc`]) and the holder presentation splice
/// ([`issuance::present`]) unwrap+re-wrap the correctness-sensitive `DeviceNameSpacesBytes` through
/// this single helper (paired with [`encode_tagged_cbor`]), so the bytes both halves produce are
/// byte-identical.
pub(crate) fn unwrap_tagged_cbor_payload(value: &ciborium::value::Value) -> Option<Vec<u8>> {
    match value {
        ciborium::value::Value::Tag(TAG_ENCODED_CBOR, inner) => match inner.as_ref() {
            ciborium::value::Value::Bytes(bytes) => Some(bytes.clone()),
            _ => None,
        },
        _ => None,
    }
}
