//! External-vector conformance tests (Principle VI / FR-013) — verify REAL, independently-authored
//! standards vectors with the SDK's own verifier, not Rust-mint-then-Rust-verify self-consistency.
//!
//! These default-built (`#[cfg(test)]`) tests are the **always-on** external-conformance signal the
//! plan calls for: each consumes a vendored upstream vector from `tests/fixtures/attestation/vectors/`
//! and runs it through the production verifier code path. A vector that fails here is a conformance
//! bug in the SDK (to be fixed at the verifier's root cause), never a reason to weaken the test.
//!
//! ## mdoc — ISO/IEC 18013-5 Annex-D worked example
//!
//! `tests/fixtures/attestation/vectors/mdoc/multipaz-TestVectors.kt` reproduces the ISO/IEC 18013-5
//! **Annex-D** `DeviceResponse` (an `org.iso.18013.5.1.mDL`) and its DS certificate as hex-encoded
//! CBOR. We run the SDK's **issuer-side** mdoc bar against it — the `IssuerAuth` `COSE_Sign1`
//! signature, DS-certificate trust, MSO `digestAlgorithm` / `validityInfo` enforcement, and the
//! in-house `valueDigests` recompute over every disclosed `IssuerSignedItem` — anchored on the
//! Annex-D DS certificate and evaluated at a fixed instant inside the MSO validity window.
//!
//! **Scope: issuer-auth only (documented).** Annex-D's `DeviceAuth` is the ISO device-retrieval
//! `DeviceMac` (an ECDH-derived HMAC over the ISO `SessionTranscript`), not the OID4VP
//! `DeviceSignature` this SDK's holder-binding path verifies (research D8). The holder binding is
//! therefore out of scope for this issuer-signature conformance check; the issuer-signed parts
//! (signature + digests + validity) are exactly what a real, externally-authored vector lets us prove
//! byte-for-byte. The OID4VP `DeviceSignature` holder binding is already covered (against
//! SDK-minted material) in `openid4vp::tests` / `mdoc::tests`.

#![cfg(test)]

use crate::mdoc::{self, MdocVerifyParams};
use crate::status::StatusOutcome;
use crate::trust::StaticTestAnchors;
use crate::types::{AttributeValue, Format, IssuerRole, ReasonCode};

/// The vendored upstream Annex-D vector source, embedded verbatim. The hex constants are sliced out
/// of this exact file (no Kotlin toolchain needed — they are plain `const val` hex strings), so the
/// material the conformance test verifies is byte-identical to the vendored upstream (and the
/// `vectors/README.md` claim that "the conformance test slices the const val hex out of this file" is
/// literally true).
const MULTIPAZ_TEST_VECTORS_KT: &str =
    include_str!("../../../tests/fixtures/attestation/vectors/mdoc/multipaz-TestVectors.kt");

/// Decode a hex string (ASCII whitespace tolerated) into bytes. A test helper: a malformed fixed hex
/// literal is a broken vector and SHOULD panic (the strict library lints are relaxed under
/// `cfg(test)` via the crate root).
fn hex(s: &str) -> Vec<u8> {
    let cleaned: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    assert!(cleaned.len() % 2 == 0, "hex literal has an odd length");
    cleaned
        .chunks_exact(2)
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16).expect("hex digit");
            let lo = (pair[1] as char).to_digit(16).expect("hex digit");
            ((hi << 4) | lo) as u8
        })
        .collect()
}

/// Slice the hex value of a Kotlin `const val <name> = (...)` (or `const val <name> = "..."`) out of
/// the vendored `multipaz-TestVectors.kt`, concatenating the string fragments and stripping all
/// non-hex characters (the Kotlin `(` / `)`, `+`, quotes, and whitespace). This reads the upstream
/// vector verbatim from its committed form — no re-encoding, no parallel copy of the hex.
fn kt_const_hex(name: &str) -> Vec<u8> {
    let needle = format!("const val {name} =");
    let start = MULTIPAZ_TEST_VECTORS_KT
        .find(&needle)
        .unwrap_or_else(|| panic!("const val {name} not found in multipaz-TestVectors.kt"));
    // The value spans from after the `=` up to the start of the NEXT `const val` (or end of file).
    let after_eq = start + needle.len();
    let rest = &MULTIPAZ_TEST_VECTORS_KT[after_eq..];
    let value_region = rest.find("const val ").map_or(rest, |next| &rest[..next]);
    // Keep only hex digits — drops `(`/`)`/`+`/`"`/whitespace/newlines, leaving the concatenated hex.
    let hex_str: String = value_region
        .chars()
        .filter(char::is_ascii_hexdigit)
        .collect();
    assert!(
        !hex_str.is_empty(),
        "no hex extracted for const val {name} (slice/format changed?)"
    );
    hex(&hex_str)
}

/// A fixed verification instant **inside** the Annex-D MSO `validityInfo` window
/// (`validFrom = 2020-10-01T13:30:02Z`, `validUntil = 2021-10-01T13:30:02Z`): 2021-01-01T00:00:00Z.
const ANNEX_D_NOW: i64 = 1_609_459_200;

#[test]
fn iso_18013_5_annex_d_issuer_auth_verifies_under_the_sdk_verifier() {
    let device_response = kt_const_hex("ISO_18013_5_ANNEX_D_DEVICE_RESPONSE");
    let ds_cert = kt_const_hex("ISO_18013_5_ANNEX_D_DS_CERT");

    // Anchor trust on the Annex-D DS certificate (the IssuerAuth x5chain leaf). The mdoc bar resolves
    // the x5chain leaf against this anchor by exact DER equality.
    let anchors = StaticTestAnchors::new().trust(IssuerRole::Pid, Format::Mdoc, &ds_cert);
    let params = MdocVerifyParams {
        now_unix: ANNEX_D_NOW,
        session_transcript: None,
        role: IssuerRole::Pid,
        status: StatusOutcome::NoStatus,
    };

    let disclosed = mdoc::verify_issuer_auth_against_vector(&device_response, &anchors, &params)
        .unwrap_or_else(|reason| {
            panic!(
                "the real ISO 18013-5 Annex-D issuer-auth MUST verify under the SDK verifier; \
                 failed with {reason:?} — this is a CONFORMANCE BUG in the verifier, fix the root \
                 cause (COSE/CBOR/digest/MSO parsing), do NOT weaken the test"
            )
        });

    // The Annex-D mDL discloses these org.iso.18013.5.1 elements (family_name, issue_date,
    // expiry_date, document_number, portrait, driving_privileges) plus the US-namespace elements; the
    // valueDigests recompute proved each one's integrity against the MSO. Assert the canonical ones.
    assert_eq!(
        disclosed.get("family_name"),
        Some(&AttributeValue::Text("Doe".to_owned())),
        "the Annex-D family_name disclosed item verified against its MSO digest"
    );
    assert_eq!(
        disclosed.get("document_number"),
        Some(&AttributeValue::Text("123456789".to_owned())),
        "the Annex-D document_number disclosed item verified against its MSO digest"
    );
    assert!(
        disclosed.contains_key("portrait"),
        "the Annex-D portrait (a large bstr) verified against its MSO digest"
    );
    assert!(
        disclosed.contains_key("driving_privileges"),
        "the Annex-D driving_privileges (a CBOR array) verified against its MSO digest"
    );
}

#[test]
fn iso_18013_5_annex_d_after_validity_window_is_expired() {
    // The same real vector evaluated AFTER its validUntil (2021-10-01) — but after `signed` (so not a
    // future-signed tamper) — must be rejected as Expired, proving the validity enforcement runs
    // against the real MSO window, not a stubbed one. (Evaluating BEFORE validFrom would instead trip
    // the `signed > now` future-signed consistency check → Tamper, since signed == validFrom here.)
    let device_response = kt_const_hex("ISO_18013_5_ANNEX_D_DEVICE_RESPONSE");
    let ds_cert = kt_const_hex("ISO_18013_5_ANNEX_D_DS_CERT");
    let anchors = StaticTestAnchors::new().trust(IssuerRole::Pid, Format::Mdoc, &ds_cert);
    let params = MdocVerifyParams {
        now_unix: 1_672_531_200, // 2023-01-01T00:00:00Z — after validUntil (2021-10-01).
        session_transcript: None,
        role: IssuerRole::Pid,
        status: StatusOutcome::NoStatus,
    };
    let result = mdoc::verify_issuer_auth_against_vector(&device_response, &anchors, &params);
    assert_eq!(
        result.err(),
        Some(ReasonCode::Expired),
        "the real Annex-D vector after its MSO validity window MUST be Expired"
    );
}

#[test]
fn iso_18013_5_annex_d_untrusted_ds_is_untrusted_issuer() {
    // With NO anchor configured the same real, signature-valid vector must be UntrustedIssuer — the
    // signature verifies but the DS is not on any configured anchor (no false-accept on trust).
    let device_response = kt_const_hex("ISO_18013_5_ANNEX_D_DEVICE_RESPONSE");
    let anchors = StaticTestAnchors::new(); // trusts nothing
    let params = MdocVerifyParams {
        now_unix: ANNEX_D_NOW,
        session_transcript: None,
        role: IssuerRole::Pid,
        status: StatusOutcome::NoStatus,
    };
    let result = mdoc::verify_issuer_auth_against_vector(&device_response, &anchors, &params);
    assert_eq!(
        result.err(),
        Some(ReasonCode::UntrustedIssuer),
        "a valid Annex-D vector with no configured anchor MUST be UntrustedIssuer"
    );
}
