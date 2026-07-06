//! Test-only ISO/IEC 18013-5 mdoc issuer helper.
//!
//! Mints a `DeviceResponse` the way a conformant mdoc issuer + holder would, so the verifier (T012)
//! can be driven against well-formed material and the negative paths (T008) constructed by mutating
//! one field at a time. It builds the MSO (with `valueDigests` over the `IssuerSignedItem`s), signs
//! the `IssuerAuth` `COSE_Sign1` with the test Document Signer key (`mdoc-ds.key.pk8`, x5chain =
//! `mdoc-ds` cert), and signs the `DeviceSignature` `COSE_Sign1` with the test holder key
//! (`holder.key.pk8`) over the `DeviceAuthentication` structure.
//!
//! Synthetic test material only — no production use (mirrors `tests/fixtures/attestation/gen.sh`).
//!
//! Test-support code (compiled under `cfg(test)` or the `test-vectors` feature); the strict
//! workspace `restriction` lints (no `unwrap`/`expect`/`panic`/casts in library code) are relaxed
//! here — a panic IS the intended failure signal when the fixed test fixtures are wrong.
//! A few items are deliberately `pub(crate)` for cross-module reuse by the OpenID4VP / verify / wire
//! test suites (and the `test-vectors` feature), so `redundant_pub_crate` is allowed here. The
//! negative-variant builder methods are only exercised by the in-crate `cfg(test)` suite, so when the
//! module is compiled under the `test-vectors` feature (without `cfg(test)`) they are unused —
//! `dead_code` is therefore permitted here.
#![allow(
    dead_code,
    clippy::redundant_pub_crate,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    // Test-builder ergonomics that the in-crate `cfg(test)` suite gets relaxed via lib.rs's
    // `cfg_attr(test, allow(...))`; under the `test-vectors` feature this module is compiled WITHOUT
    // `cfg(test)`, so re-allow them here (the same constructs are intended as test assertions).
    clippy::assigning_clones,
    clippy::indexing_slicing
)]

use ciborium::value::Value as CborValue;
use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder, TaggedCborSerializable};
use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
use pkcs8::DecodePrivateKey as _;
use sha2::{Digest as _, Sha256, Sha384, Sha512};

use super::{
    COSE_HEADER_X5CHAIN, MDOC_QEAA_CATEGORY_ELEMENT, MDOC_QEAA_CATEGORY_NAMESPACE, TAG_ENCODED_CBOR,
};
use crate::qualified::EAA_EU_QUALIFIED_TYPE;

/// A single attribute to embed as an `IssuerSignedItem`.
pub(super) struct Element {
    /// The `digestID` assigned to this element.
    pub digest_id: i64,
    /// The `elementIdentifier` (claim name).
    pub identifier: &'static str,
    /// The `elementValue` (claim value).
    pub value: CborValue,
}

/// A builder for a test mdoc `DeviceResponse`, with knobs the negative tests flip.
pub(crate) struct MdocBuilder {
    doc_type: String,
    namespace: String,
    elements: Vec<Element>,
    signed: String,
    valid_from: String,
    valid_until: String,
    /// The MSO `digestAlgorithm` name; the digests are always computed with the matching hash.
    digest_algorithm: DigestAlg,
    /// When set, corrupt the IssuerAuth signature after signing (tamper case).
    corrupt_issuer_auth: bool,
    /// When set, corrupt the recorded digest of the first element so it mismatches the disclosed
    /// item (valueDigests-mismatch case).
    corrupt_value_digest: bool,
    /// When set, sign the IssuerAuth with the wrong-issuer key + cert (untrusted-DS case).
    use_wrong_issuer: bool,
    /// When set, sign the DeviceSignature with a different (non-holder) key (holder-binding case).
    corrupt_device_signature: bool,
    /// When `Some`, override the MSO `deviceKey` COSE_Key with this CBOR value (malformed-key cases).
    device_key_override: Option<CborValue>,
    /// When `Some`, the SessionTranscript bytes the DeviceSignature is computed over (and that the
    /// verifier must be passed); otherwise [`default_session_transcript`] is used. The verifier no
    /// longer fabricates a transcript (ISO/IEC 18013-5 §9.1.5), so a test MUST pass the SAME transcript
    /// bytes to the verifier's `session_transcript` for the holder binding to verify.
    session_transcript: Option<Vec<u8>>,
    /// When set, sign the DeviceSignature with a non-ES256 (ES384) algorithm header so the verifier's
    /// algorithm gate rejects it.
    device_sig_wrong_alg: bool,
    /// When set, GARBLE the DeviceSignature bytes after signing (truncate to a non-`r‖s` length) so it
    /// is a structurally-broken ES256 signature — a genuine, transcript-INDEPENDENT holder-binding
    /// fault (distinct from a `corrupt_device_signature` wrong-key signature, which stays well-formed).
    mangle_device_signature: bool,
    /// When set, re-emit the (genuine, ES256-signed) DeviceSignature COSE_Sign1 with a NON-NIL
    /// (ATTACHED) payload as its third array element instead of `nil`. ISO/IEC 18013-5 §9.1.3 requires
    /// the DeviceSignature to be a DETACHED COSE_Sign1 (nil payload), so an attached payload is a
    /// malformed holder binding the verifier MUST reject (`HolderBinding`) — and MUST do so WITHOUT
    /// reaching `coset`'s detached-verify path, whose `tbs_detached_data` asserts `payload.is_none()`
    /// and would otherwise PANIC/ABORT on this attacker-controlled input (the DoS this knob probes).
    device_signature_attached_payload: bool,
    /// When set, sign the IssuerAuth with a non-ES256 (ES384) algorithm header (alg-gate reject).
    issuer_auth_wrong_alg: bool,
    /// When set, re-encode the (genuine, ES256) IssuerAuth signature as an ASN.1/DER `SEQUENCE` instead
    /// of the COSE-mandated raw fixed-width `r‖s` (RFC 9053 §2.1). The signature still verifies as a
    /// VALID ECDSA signature over the MSO, but its ENCODING is non-conformant — a reference COSE
    /// validator rejects it, so the SDK's COSE path MUST reject it too (`Tamper`), never accept DER.
    issuer_auth_der_signature: bool,
    /// When set, emit the IssuerAuth as a `#6.18`-tagged COSE_Sign1 (the tagged form the verifier
    /// also accepts).
    tag_issuer_auth: bool,
    /// When set, carry the x5chain as an array of one cert rather than a bare bstr.
    x5chain_as_array: bool,
    /// When set, omit the x5chain header entirely (no DS cert → malformed).
    omit_x5chain: bool,
    /// When set, wrap the `validityInfo` date strings as `#6.0` (tdate) tagged text.
    tdate_tagged: bool,
    /// When set, make the MSO `docType` differ from the document `docType` (tamper).
    mso_doc_type_mismatch: bool,
    /// When `Some`, splice this externally-built `deviceSignature` COSE_Sign1 (CBOR) in place of one
    /// signed in-process — the US2 signer-hook round-trip (the SDK built + spliced it via the hook).
    device_signature_override: Option<Vec<u8>>,
    /// When set, append a SECOND document (a clone of the first with a corrupted IssuerAuth signature)
    /// to drive the multi-document false-accept probe.
    append_forged_document: bool,
    /// When `Some`, append a SECOND fully-VALID document (signed by the SAME trusted DS) whose single
    /// disclosed element collides with a first-document identifier but carries this DIFFERENT value —
    /// the cross-document attribute-shadowing probe (a 2nd authentic doc must not overwrite a claim).
    append_colliding_document: Option<(&'static str, CborValue)>,
    /// When `Some`, append a SECOND fully-VALID document (signed by the SAME trusted DS) disclosing one
    /// element `(identifier → value)` under a DIFFERENT `namespace` than the primary document — the
    /// multi-namespace probe: the SAME `elementIdentifier` in two namespaces is a DISTINCT attribute, so
    /// the response stays VALID and BOTH values are surfaced, namespace-distinguished (never a false
    /// `DisclosureIntegrity` collision). Tuple: `(namespace, identifier, value)`.
    append_document_in_namespace: Option<(&'static str, &'static str, CborValue)>,
    /// When `Some`, append a SECOND fully-VALID document (same trusted DS) disclosing one DISTINCT
    /// (non-colliding) element, signed over the SAME `session_transcript` as the primary document, but
    /// whose `DeviceSignature` is made by a NON-holder (wrong) key. The result is a multi-document
    /// response whose `documents[0]` holder binding verifies (genuine holder signature over the request
    /// transcript) but whose `documents[1]` fails on a WRONG KEY — a transcript-INDEPENDENT
    /// holder-binding fault the OID4VP layer must keep as `HolderBinding`, NEVER launder into `Replay`.
    append_wrong_key_document: Option<(&'static str, CborValue)>,
    /// When `Some`, append a SECOND fully-VALID document signed by the SAME trusted DS, disclosing one
    /// distinct (non-colliding) element, but with its OWN MSO `(signed, validUntil)` issuance window —
    /// the multi-document qualified-status fold probe: a VALID response whose documents[0] is issued in
    /// the grant window (Qualified) and documents[1] is issued after the issuer's withdrawal
    /// (NotQualified), proving the gate reads EACH document at its OWN relevant time and folds.
    append_valid_document_issued_at: Option<(String, String)>,
    /// When `Some`, append a SECOND fully-VALID document signed by the FOREIGN/untrusted `wrong-issuer`
    /// DS (not the IACA-chained `mdoc-ds`), issued in `(signed = validFrom = signed_at, validUntil)` —
    /// the multi-document qualified-status PROVENANCE probe. With the always-on bar configured to ALSO
    /// trust `wrong-issuer` (so the whole response is VALID and the gate runs), this second document's
    /// issuer is absent from the qualified national TL → its per-document status is `Indeterminate`, so
    /// the fold MUST be `Indeterminate` (never a single `Qualified` read off documents[0]).
    append_wrong_issuer_document_issued_at: Option<(String, String)>,
    /// When `Some`, set the top-level `DeviceResponse.status` to this value (non-zero drives the
    /// device-reported-error reject path).
    status_override: Option<i64>,
    /// When set, omit the top-level `DeviceResponse.status` entirely (drives the absent-status reject).
    omit_status: bool,
    /// When set, emit an EMPTY `documents` array (drives the no-documents-to-verify reject).
    empty_documents: bool,
    /// When set, add a top-level `documentErrors` entry for a DIFFERENT docType than the returned
    /// document (the device could not return some OTHER requested docType). ISO/IEC 18013-5 §8.3 makes
    /// this informational, so it must NOT reject the valid returned document.
    add_document_errors: bool,
    /// When set, mark a protected header parameter the verifier does not process (`content type`,
    /// label 3) as CRITICAL in the IssuerAuth COSE_Sign1 `crit` — RFC 9052 §3.1 requires the verifier
    /// to reject a message listing a critical header it does not understand.
    issuer_auth_unknown_crit: bool,
    /// As [`Self::issuer_auth_unknown_crit`] but on the DeviceSignature COSE_Sign1 — the holder-binding
    /// COSE_Sign1 path of the same RFC 9052 §3.1 `crit` enforcement.
    device_sig_unknown_crit: bool,
    /// When `Some`, override the top-level `DeviceResponse.version` text (else `"1.0"`); used to drive
    /// the unrecognized-schema-version reject (ISO/IEC 18013-5 §8.3.2.1.2.2 fixes it to `"1.0"`).
    device_response_version_override: Option<String>,
    /// When set, omit the top-level `DeviceResponse.version` field entirely (absent-version reject).
    omit_device_response_version: bool,
    /// When `Some`, override the MSO `version` text (else `"1.0"`); drives the unrecognized-MSO-schema
    /// reject (ISO/IEC 18013-5 §9.1.2.4 fixes the MobileSecurityObject version to `"1.0"`).
    mso_version_override: Option<String>,
    /// When set, omit the MSO `version` field entirely (absent-MSO-version reject).
    omit_mso_version: bool,
    /// When set, omit the MSO `validityInfo.signed` field (keeping `validFrom`/`validUntil`) — used to
    /// exercise the qualified-gate issuance-time reader's `signed → validFrom` fallback.
    omit_mso_signed: bool,
    /// When `Some`, append a forged `IssuerSignedItem` to the FIRST namespace that REUSES a genuine
    /// element's `digestID` but carries an attacker-chosen `(elementIdentifier, elementValue)` the
    /// issuer never signed — the selective-disclosure-integrity false-accept probe (SC-002). The MSO
    /// `valueDigests` still holds only the genuine item's digest under that `digestID`, so the forged
    /// item's own bytes do NOT hash to the recorded digest. `forged_first = true` places the forged
    /// item BEFORE the genuine one in the on-wire array (so a last-wins capture would let the forged
    /// item's bytes win the slot); `false` places it after. Either ordering MUST be rejected
    /// (`DisclosureIntegrity`) and the forged claim never disclosed.
    append_forged_item: Option<ForgedItem>,
    /// When set, inject an ADDITIONAL namespace group carrying the ETSI TS 119 472-1 cl. 6.2.2
    /// **`category`** data element (value = the QEAA type-indication URN [`EAA_EU_QUALIFIED_TYPE`]) into
    /// the SAME (primary) document — so one document carries TWO namespaces: the primary ISO namespace
    /// PLUS the ETSI `org.etsi.01947201.010101` category namespace, exactly as a conformant QEAA mdoc
    /// does. Both the `issuerSigned.nameSpaces` group AND a matching MSO `valueDigests` entry are added
    /// (each disclosed item MUST have a matching MSO digest — that is how the bar verifies it), mirroring
    /// how the primary namespace's elements are minted. The opt-in qualified gate reads this per-document
    /// `category` as the PRO-4.12.4-03 type indication. Distinct from [`Self::append_document_in_namespace`],
    /// which appends a SECOND document; the `category` MUST live in the SAME document as the ISO elements.
    qeaa_category: bool,
}

/// A forged `IssuerSignedItem` to splice into the on-wire `nameSpaces` array (the false-accept probe):
/// it reuses `digest_id` (a genuine element's id) but discloses an attacker-chosen identifier/value.
pub(crate) struct ForgedItem {
    /// The genuine `digestID` the forged item REUSES (so its slot collides with a real digest).
    pub digest_id: i64,
    /// The attacker-chosen `elementIdentifier` (a claim the issuer never signed).
    pub identifier: &'static str,
    /// The attacker-chosen `elementValue`.
    pub value: CborValue,
    /// When `true`, place the forged item BEFORE the genuine items in the array (else after).
    pub forged_first: bool,
}

/// The hash to compute `valueDigests` with, plus its MSO `digestAlgorithm` name.
#[derive(Clone, Copy)]
pub(super) enum DigestAlg {
    /// SHA-256 (the baseline).
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
    /// An unrecognized name (`"SHA-1"`) the verifier must reject.
    Unsupported,
}

impl DigestAlg {
    /// The MSO `digestAlgorithm` text for this choice.
    fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
            Self::Unsupported => "SHA-1",
        }
    }

    /// Compute the digest of `data` (the unsupported name still hashes with SHA-256 so the bytes are
    /// well-formed; the verifier rejects on the *name*, before any hashing).
    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 | Self::Unsupported => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
}

/// The test PKI material (DER cert + PKCS#8 key), loaded from the committed fixtures.
const MDOC_DS_CERT: &[u8] =
    include_bytes!("../../../../tests/fixtures/attestation/mdoc-ds.cert.der");
const MDOC_DS_KEY: &[u8] = include_bytes!("../../../../tests/fixtures/attestation/mdoc-ds.key.pk8");
const HOLDER_KEY: &[u8] = include_bytes!("../../../../tests/fixtures/attestation/holder.key.pk8");
const WRONG_ISSUER_CERT: &[u8] =
    include_bytes!("../../../../tests/fixtures/attestation/wrong-issuer.cert.der");
const WRONG_ISSUER_KEY: &[u8] =
    include_bytes!("../../../../tests/fixtures/attestation/wrong-issuer.key.pk8");

/// The trusted DS certificate DER (for configuring the test anchors).
pub(crate) fn mdoc_ds_cert_der() -> &'static [u8] {
    MDOC_DS_CERT
}

/// The canonical default `SessionTranscript` the [`MdocBuilder`] signs the `DeviceSignature` over when
/// no explicit transcript is set — a conformant 3-element ISO/IEC 18013-5 §9.1.5 transcript
/// `["DeviceEngagement", EReaderKey, Handover]`. A request-less verify CANNOT fabricate a transcript
/// (it would silently no-op holder binding), so a test that mints a default-transcript mdoc MUST pass
/// these exact bytes to the verifier's `session_transcript` so the holder binding is genuinely
/// confirmed (the issuer signs over, and the verifier reconstructs, the SAME transcript).
pub(crate) fn default_session_transcript() -> Vec<u8> {
    // A concrete, explicit device-retrieval-style transcript (NOT the old fabricated `[null,null,null]`
    // the verifier silently invented): three placeholder elements that stand in for
    // DeviceEngagementBytes / EReaderKeyBytes / Handover. The exact contents are immaterial to the test
    // bar — what matters is that issuer and verifier agree on the SAME bytes.
    encode(&CborValue::Array(vec![
        CborValue::Text("DeviceEngagement".to_owned()),
        CborValue::Text("EReaderKey".to_owned()),
        CborValue::Text("Handover".to_owned()),
    ]))
}

/// The wrong/untrusted issuer certificate DER. `pub(crate)` so the verify-layer multi-document
/// qualified-status test can ALSO trust it on the always-on bar (making a `wrong-issuer`-signed
/// second document VALID) while it stays absent from the qualified national TL → Indeterminate.
pub(crate) fn wrong_issuer_cert_der() -> &'static [u8] {
    WRONG_ISSUER_CERT
}

impl MdocBuilder {
    /// A conformant default: an mDL docType, one namespace with three disclosed elements, and a
    /// validity window around the canonical 2023 instant the tests verify at.
    pub(crate) fn new() -> Self {
        Self {
            doc_type: "org.iso.18013.5.1.mDL".to_owned(),
            namespace: "org.iso.18013.5.1".to_owned(),
            elements: vec![
                Element {
                    digest_id: 0,
                    identifier: "family_name",
                    value: CborValue::Text("Doe".to_owned()),
                },
                Element {
                    digest_id: 1,
                    identifier: "given_name",
                    value: CborValue::Text("Ada".to_owned()),
                },
                Element {
                    digest_id: 2,
                    identifier: "age_over_18",
                    value: CborValue::Bool(true),
                },
            ],
            signed: "2023-01-01T00:00:00Z".to_owned(),
            valid_from: "2023-01-01T00:00:00Z".to_owned(),
            valid_until: "2030-01-01T00:00:00Z".to_owned(),
            digest_algorithm: DigestAlg::Sha256,
            corrupt_issuer_auth: false,
            corrupt_value_digest: false,
            use_wrong_issuer: false,
            corrupt_device_signature: false,
            device_key_override: None,
            session_transcript: None,
            device_sig_wrong_alg: false,
            mangle_device_signature: false,
            device_signature_attached_payload: false,
            issuer_auth_wrong_alg: false,
            issuer_auth_der_signature: false,
            tag_issuer_auth: false,
            x5chain_as_array: false,
            omit_x5chain: false,
            tdate_tagged: false,
            mso_doc_type_mismatch: false,
            device_signature_override: None,
            append_forged_document: false,
            append_colliding_document: None,
            append_document_in_namespace: None,
            append_wrong_key_document: None,
            append_valid_document_issued_at: None,
            append_wrong_issuer_document_issued_at: None,
            status_override: None,
            omit_status: false,
            empty_documents: false,
            add_document_errors: false,
            issuer_auth_unknown_crit: false,
            device_sig_unknown_crit: false,
            device_response_version_override: None,
            omit_device_response_version: false,
            mso_version_override: None,
            omit_mso_version: false,
            omit_mso_signed: false,
            append_forged_item: None,
            qeaa_category: false,
        }
    }

    /// Append a forged `IssuerSignedItem` reusing `digest_id` (a genuine element's id) but disclosing
    /// `(identifier, value)` the issuer never signed — the selective-disclosure-integrity false-accept
    /// probe. `forged_first` places the forged item before the genuine ones (else after). The MSO
    /// `valueDigests` is left untouched (only the genuine digest is recorded under `digest_id`).
    pub(crate) fn append_forged_item(
        mut self,
        digest_id: i64,
        identifier: &'static str,
        value: CborValue,
        forged_first: bool,
    ) -> Self {
        self.append_forged_item = Some(ForgedItem {
            digest_id,
            identifier,
            value,
            forged_first,
        });
        self
    }

    /// Make this a conformant QEAA mdoc: inject the ETSI TS 119 472-1 cl. 6.2.2 **`category`** data
    /// element (value = [`EAA_EU_QUALIFIED_TYPE`]) into a SECOND namespace (`org.etsi.01947201.010101`)
    /// of the SAME (primary) document — alongside the ISO namespace's elements — so the opt-in qualified
    /// gate reads the PRO-4.12.4-03 type indication for this document (`MdocVerifyMeta.categories`). Both
    /// the `issuerSigned.nameSpaces` group and a matching MSO `valueDigests` entry are minted.
    pub(crate) fn qeaa_category(mut self) -> Self {
        self.qeaa_category = true;
        self
    }

    /// Omit the MSO `validityInfo.signed` field (keeping `validFrom`) — drives the issuance-time
    /// reader's `signed → validFrom` fallback.
    pub(crate) fn omit_mso_signed(mut self) -> Self {
        self.omit_mso_signed = true;
        self
    }

    /// Emit an empty `documents` array (no credential to verify → reject).
    pub(super) fn empty_documents(mut self) -> Self {
        self.empty_documents = true;
        self
    }

    /// Add a top-level `documentErrors` entry for a DIFFERENT docType than the returned document (the
    /// device reported it could not return some OTHER requested docType — informational per §8.3).
    pub(super) fn add_document_errors(mut self) -> Self {
        self.add_document_errors = true;
        self
    }

    /// Mark an unknown (unprocessed) header parameter CRITICAL in the IssuerAuth COSE_Sign1 `crit`
    /// (RFC 9052 §3.1) — the verifier must reject the message.
    pub(super) fn issuer_auth_unknown_crit(mut self) -> Self {
        self.issuer_auth_unknown_crit = true;
        self
    }

    /// Mark an unknown (unprocessed) header parameter CRITICAL in the DeviceSignature COSE_Sign1
    /// `crit` (RFC 9052 §3.1) — the verifier must reject the holder-binding message.
    pub(super) fn device_sig_unknown_crit(mut self) -> Self {
        self.device_sig_unknown_crit = true;
        self
    }

    /// Override the top-level `DeviceResponse.version` text (else `"1.0"`).
    pub(super) fn device_response_version(mut self, version: &str) -> Self {
        self.device_response_version_override = Some(version.to_owned());
        self
    }

    /// Omit the top-level `DeviceResponse.version` field entirely.
    pub(super) fn omit_device_response_version(mut self) -> Self {
        self.omit_device_response_version = true;
        self
    }

    /// Override the MSO `version` text (else `"1.0"`).
    pub(super) fn mso_version(mut self, version: &str) -> Self {
        self.mso_version_override = Some(version.to_owned());
        self
    }

    /// Omit the MSO `version` field entirely.
    pub(super) fn omit_mso_version(mut self) -> Self {
        self.omit_mso_version = true;
        self
    }

    /// Append a second, forged document (a clone of the first with a broken IssuerAuth signature) so
    /// the response carries two documents — the multi-document false-accept probe.
    pub(super) fn append_forged_document(mut self) -> Self {
        self.append_forged_document = true;
        self
    }

    /// Append a second, fully-VALID document (signed by the SAME trusted DS) that discloses
    /// `identifier` with `value`. Used both by the cross-document attribute-shadowing probe (a clashing
    /// identifier must not silently overwrite the consumer-visible claim) and, with a DISTINCT
    /// identifier, by the holder-present multi-document reject test (a clean second document making the
    /// response multi-document). `pub(crate)` so the OpenID4VP / present test suites can build a
    /// genuine multi-document `DeviceResponse`.
    pub(crate) fn append_colliding_document(
        mut self,
        identifier: &'static str,
        value: CborValue,
    ) -> Self {
        self.append_colliding_document = Some((identifier, value));
        self
    }

    /// Append a SECOND fully-VALID document (same trusted DS) disclosing one element `identifier →
    /// value` under a DIFFERENT `namespace` than the primary document — the multi-namespace probe. The
    /// SAME `elementIdentifier` in two namespaces is a DISTINCT attribute, so the response stays VALID
    /// and BOTH values are surfaced, grouped under their own namespaces (never a false collision).
    pub(crate) fn append_document_in_namespace(
        mut self,
        namespace: &'static str,
        identifier: &'static str,
        value: CborValue,
    ) -> Self {
        self.append_document_in_namespace = Some((namespace, identifier, value));
        self
    }

    /// Append a SECOND fully-VALID document (same trusted DS) disclosing one DISTINCT element, signed
    /// over the SAME `session_transcript` as the primary document, but whose `DeviceSignature` is made
    /// by a NON-holder (wrong) key. Produces a multi-document response whose `documents[0]` holder
    /// binding verifies (over the request transcript) while `documents[1]` fails on a WRONG KEY — the
    /// probe that the OID4VP Replay re-attribution must NOT launder a genuine multi-document
    /// holder-binding fault into `Replay`. Requires a `session_transcript` to have been set (so both
    /// documents are bound to the same request handover).
    pub(crate) fn append_wrong_key_document(
        mut self,
        identifier: &'static str,
        value: CborValue,
    ) -> Self {
        self.append_wrong_key_document = Some((identifier, value));
        self
    }

    /// Append a second, fully-VALID document signed by the SAME trusted DS (so the always-on bar
    /// accepts the whole response) but with its OWN issuance window `signed = validFrom = signed_at`,
    /// `validUntil = valid_until`. Used by the qualified-status fold probe: documents[0] issued in the
    /// grant window (Qualified) + this documents[1] issued after the issuer's withdrawal (NotQualified)
    /// → the gate reads each document at its OWN relevant time and folds to NotQualified.
    pub(crate) fn append_valid_document_issued_at(
        mut self,
        signed_at: &str,
        valid_until: &str,
    ) -> Self {
        self.append_valid_document_issued_at = Some((signed_at.to_owned(), valid_until.to_owned()));
        self
    }

    /// Append a SECOND fully-VALID document signed by the FOREIGN/untrusted `wrong-issuer` DS (NOT the
    /// IACA-chained `mdoc-ds`), issued in its own `(signed = validFrom = signed_at, validUntil)` window
    /// and disclosing one DISTINCT (non-colliding) element. The always-on bar must be configured to
    /// ALSO trust `wrong-issuer` for the whole response to verify; the qualified national TL does NOT
    /// list `wrong-issuer`, so the gate reads its per-document status as `Indeterminate` and the fold
    /// is `Indeterminate` — the multi-document provenance probe (a foreign issuer must not be folded
    /// into a single `Qualified` read off documents[0]).
    pub(crate) fn append_wrong_issuer_document_issued_at(
        mut self,
        signed_at: &str,
        valid_until: &str,
    ) -> Self {
        self.append_wrong_issuer_document_issued_at =
            Some((signed_at.to_owned(), valid_until.to_owned()));
        self
    }

    /// Set the top-level `DeviceResponse.status` (a non-zero value is a device-reported error).
    pub(super) fn status(mut self, status: i64) -> Self {
        self.status_override = Some(status);
        self
    }

    /// Omit the top-level `DeviceResponse.status` field entirely (a malformed response).
    pub(super) fn omit_status(mut self) -> Self {
        self.omit_status = true;
        self
    }

    /// Splice an externally-built `deviceSignature` COSE_Sign1 (CBOR) — the US2 signer-hook
    /// round-trip, where the SDK built the `DeviceAuthentication` signing input, the host signed it,
    /// and the SDK spliced the detached COSE_Sign1. The builder embeds it verbatim instead of signing
    /// in-process.
    pub(crate) fn with_device_signature_cbor(mut self, device_signature_cbor: Vec<u8>) -> Self {
        self.device_signature_override = Some(device_signature_cbor);
        self
    }

    /// Sign the IssuerAuth with a non-ES256 algorithm header (alg-gate reject → Tamper).
    pub(super) fn issuer_auth_wrong_alg(mut self) -> Self {
        self.issuer_auth_wrong_alg = true;
        self
    }

    /// Re-encode the (genuine, ES256) IssuerAuth signature as ASN.1/DER instead of the COSE-mandated
    /// raw `r‖s` (RFC 9053 §2.1) — the non-conformant-encoding reject probe (must be `Tamper`).
    pub(super) fn issuer_auth_der_signature(mut self) -> Self {
        self.issuer_auth_der_signature = true;
        self
    }

    /// Emit the IssuerAuth as a `#6.18`-tagged COSE_Sign1.
    pub(super) fn tag_issuer_auth(mut self) -> Self {
        self.tag_issuer_auth = true;
        self
    }

    /// Carry the x5chain as a one-element array of certs.
    pub(super) fn x5chain_as_array(mut self) -> Self {
        self.x5chain_as_array = true;
        self
    }

    /// Omit the x5chain header entirely (no DS cert).
    pub(super) fn omit_x5chain(mut self) -> Self {
        self.omit_x5chain = true;
        self
    }

    /// Wrap the validityInfo date strings as `#6.0` tdate-tagged text.
    pub(super) fn tdate_tagged(mut self) -> Self {
        self.tdate_tagged = true;
        self
    }

    /// Make the MSO `docType` differ from the document `docType` (tamper).
    pub(super) fn mso_doc_type_mismatch(mut self) -> Self {
        self.mso_doc_type_mismatch = true;
        self
    }

    /// Replace the disclosed elements (used to exercise the `elementValue` → `AttributeValue`
    /// conversions for integer/bytes/array/map/null values).
    pub(super) fn elements(mut self, elements: Vec<Element>) -> Self {
        self.elements = elements;
        self
    }

    /// Set the ISO/IEC 18013-5 namespace the disclosed elements are minted under (the `nameSpaces` /
    /// `valueDigests` key). Used by the multi-namespace probe: the SAME `elementIdentifier` in two
    /// different namespaces is a DISTINCT attribute and must not collide.
    pub(crate) fn namespace(mut self, namespace: &str) -> Self {
        self.namespace = namespace.to_owned();
        self
    }

    /// Set the document `docType` (and, absent [`Self::mso_doc_type_mismatch`], the matching MSO
    /// `docType`). Used by the DCQL `doctype_value` match + role-derivation tests (e.g. a EUDI PID
    /// `docType` `eu.europa.ec.eudi.pid.1`).
    pub(crate) fn doc_type(mut self, doc_type: &str) -> Self {
        self.doc_type = doc_type.to_owned();
        self
    }

    /// Set the MSO `digestAlgorithm` (SHA-384, or an unsupported name to drive the reject path).
    pub(super) fn digest_algorithm(mut self, alg: DigestAlg) -> Self {
        self.digest_algorithm = alg;
        self
    }

    /// Override the MSO `deviceKey` COSE_Key (malformed-key cases: non-EC2, wrong curve, short
    /// coordinate).
    pub(super) fn device_key_override(mut self, key: CborValue) -> Self {
        self.device_key_override = Some(key);
        self
    }

    /// Set an explicit SessionTranscript the DeviceSignature is bound to (and that the verifier must
    /// be passed verbatim).
    pub(crate) fn session_transcript(mut self, transcript_bytes: Vec<u8>) -> Self {
        self.session_transcript = Some(transcript_bytes);
        self
    }

    /// Sign the DeviceSignature with a non-ES256 algorithm header (drives the alg-gate reject).
    pub(super) fn device_sig_wrong_alg(mut self) -> Self {
        self.device_sig_wrong_alg = true;
        self
    }

    /// Garble the DeviceSignature bytes (truncate to a non-`r‖s` length) so it is a
    /// structurally-broken ES256 signature — a transcript-INDEPENDENT holder-binding fault used to
    /// prove the OID4VP layer keeps `HolderBinding` (does NOT mask it as `Replay`).
    pub(crate) fn mangle_device_signature(mut self) -> Self {
        self.mangle_device_signature = true;
        self
    }

    /// Re-emit the (genuine, ES256-signed) DeviceSignature COSE_Sign1 with a NON-NIL (ATTACHED)
    /// payload instead of `nil` — a malformed, NON-DETACHED holder binding (ISO/IEC 18013-5 §9.1.3
    /// mandates a detached COSE_Sign1). The verifier must reject it as `HolderBinding` WITHOUT
    /// reaching `coset`'s detached-verify assert (which would panic/abort on this attacker input).
    pub(crate) fn device_signature_attached_payload(mut self) -> Self {
        self.device_signature_attached_payload = true;
        self
    }

    /// Set the validity window (RFC 3339 `Z` strings). `signed` is clamped to the EARLIER of the
    /// existing `signed` and the new `valid_from` so the MSO stays internally consistent
    /// (`signed <= validFrom`, which the verifier enforces) without ever pushing `signed` into the
    /// future for a not-yet-valid window. RFC 3339 `Z` strings sort lexicographically by instant, so a
    /// string `min` is a correct instant `min`.
    pub(crate) fn validity(mut self, valid_from: &str, valid_until: &str) -> Self {
        if valid_from < self.signed.as_str() {
            self.signed = valid_from.to_owned();
        }
        self.valid_from = valid_from.to_owned();
        self.valid_until = valid_until.to_owned();
        self
    }

    /// Override the MSO `validityInfo.signed` instant independently (RFC 3339 `Z` string) — used to
    /// drive the future-`signed` reject path (a `signed` after `now`/`validFrom` is a tamper) and to
    /// place a credential's issuance/relevant time inside the qualified-gate's grant window.
    pub(crate) fn signed(mut self, signed: &str) -> Self {
        self.signed = signed.to_owned();
        self
    }

    /// Corrupt the IssuerAuth signature (tamper case).
    pub(super) fn corrupt_issuer_auth(mut self) -> Self {
        self.corrupt_issuer_auth = true;
        self
    }

    /// Corrupt a recorded `valueDigests` entry (disclosure-integrity case).
    pub(super) fn corrupt_value_digest(mut self) -> Self {
        self.corrupt_value_digest = true;
        self
    }

    /// Sign the IssuerAuth with the untrusted wrong-issuer key/cert (untrusted-DS case).
    pub(crate) fn use_wrong_issuer(mut self) -> Self {
        self.use_wrong_issuer = true;
        self
    }

    /// Sign the DeviceSignature with a non-holder key (holder-binding case).
    pub(super) fn corrupt_device_signature(mut self) -> Self {
        self.corrupt_device_signature = true;
        self
    }

    /// Build the CBOR-encoded `DeviceResponse` bytes.
    pub(crate) fn build(self) -> Vec<u8> {
        // Captured before `self` is partially moved below: a second valid document (signed by the
        // same trusted DS) disclosing one colliding identifier with a DIFFERENT value.
        let colliding = self
            .append_colliding_document
            .map(|(identifier, value)| build_single_valid_document(identifier, value));
        // A second VALID document disclosing one element under a DIFFERENT namespace — the
        // multi-namespace probe (same id in two namespaces is a distinct attribute, never a collision).
        let other_namespace_document =
            self.append_document_in_namespace
                .clone()
                .map(|(namespace, identifier, value)| {
                    build_single_valid_document_in_namespace(namespace, identifier, value)
                });
        // A second VALID document (same trusted DS) issued in its OWN window — the multi-document
        // qualified-status fold probe (documents[0] qualified-at-issuance, this one not-qualified).
        let second_valid_issued_at =
            self.append_valid_document_issued_at
                .clone()
                .map(|(signed_at, valid_until)| {
                    build_single_valid_document_issued_at(&signed_at, &valid_until)
                });
        // A second VALID document signed by the FOREIGN/untrusted `wrong-issuer` DS, issued in its own
        // window — the multi-document qualified-status PROVENANCE probe (its issuer is absent from the
        // qualified national TL → Indeterminate, never folded into a single Qualified).
        let second_wrong_issuer_issued_at = self
            .append_wrong_issuer_document_issued_at
            .clone()
            .map(|(signed_at, valid_until)| {
                build_single_wrong_issuer_document_issued_at(&signed_at, &valid_until)
            });
        // A second VALID document signed over the SAME transcript as the primary document but with a
        // WRONG-KEY `DeviceSignature` — the multi-document holder-binding-fault probe. Use the parent's
        // transcript (the one the primary document is bound to) so the only fault on `documents[1]` is
        // the wrong key, never a transcript mismatch.
        let wrong_key_document =
            self.append_wrong_key_document
                .clone()
                .map(|(identifier, value)| {
                    let transcript = self
                        .session_transcript
                        .clone()
                        .unwrap_or_else(default_session_transcript);
                    build_single_wrong_key_document(identifier, value, transcript)
                });

        // --- IssuerSignedItems (#6.24(bstr .cbor IssuerSignedItem)) + their digests. ----------------
        let mut issuer_items = Vec::new();
        let mut value_digests = Vec::new();
        for (idx, el) in self.elements.iter().enumerate() {
            let item = CborValue::Map(vec![
                (
                    CborValue::Text("digestID".to_owned()),
                    CborValue::Integer(el.digest_id.into()),
                ),
                (
                    CborValue::Text("random".to_owned()),
                    CborValue::Bytes(vec![idx as u8; 16]),
                ),
                (
                    CborValue::Text("elementIdentifier".to_owned()),
                    CborValue::Text(el.identifier.to_owned()),
                ),
                (CborValue::Text("elementValue".to_owned()), el.value.clone()),
            ]);
            let item_inner = encode(&item);
            let tagged = CborValue::Tag(
                TAG_ENCODED_CBOR,
                Box::new(CborValue::Bytes(item_inner.clone())),
            );
            let tagged_bytes = encode(&tagged);
            let mut digest = self.digest_algorithm.digest(&tagged_bytes);
            if self.corrupt_value_digest && idx == 0 {
                digest[0] ^= 0xff;
            }
            value_digests.push((
                CborValue::Integer(el.digest_id.into()),
                CborValue::Bytes(digest),
            ));
            issuer_items.push(tagged);
        }

        // --- false-accept probe: splice a forged IssuerSignedItem that REUSES a genuine digestID but
        //     discloses an attacker-chosen identifier/value, WITHOUT recording its own valueDigests
        //     entry. Placed first or last per the knob, so both orderings exercise the integrity tie. ---
        if let Some(forged) = &self.append_forged_item {
            let forged_item = CborValue::Map(vec![
                (
                    CborValue::Text("digestID".to_owned()),
                    CborValue::Integer(forged.digest_id.into()),
                ),
                (
                    CborValue::Text("random".to_owned()),
                    CborValue::Bytes(vec![0xAA; 16]),
                ),
                (
                    CborValue::Text("elementIdentifier".to_owned()),
                    CborValue::Text(forged.identifier.to_owned()),
                ),
                (
                    CborValue::Text("elementValue".to_owned()),
                    forged.value.clone(),
                ),
            ]);
            let forged_inner = encode(&forged_item);
            let forged_tagged =
                CborValue::Tag(TAG_ENCODED_CBOR, Box::new(CborValue::Bytes(forged_inner)));
            if forged.forged_first {
                issuer_items.insert(0, forged_tagged);
            } else {
                issuer_items.push(forged_tagged);
            }
        }

        // --- optional ETSI TS 119 472-1 cl. 6.2.2 `category` element (QEAA type indication) in a SECOND
        //     namespace of the SAME document. A conformant QEAA mdoc carries the qualified-EAA type URN in
        //     the `category` data element under `org.etsi.01947201.010101`, ALONGSIDE the ISO namespace.
        //     The disclosed item AND its MSO `valueDigests` entry are both minted (each disclosed item MUST
        //     have a matching MSO digest — that is how the bar verifies it), mirroring the primary loop. ---
        let (category_item, category_digest) = if self.qeaa_category {
            let item = CborValue::Map(vec![
                (
                    CborValue::Text("digestID".to_owned()),
                    CborValue::Integer(0.into()),
                ),
                (
                    CborValue::Text("random".to_owned()),
                    CborValue::Bytes(vec![0xC0; 16]),
                ),
                (
                    CborValue::Text("elementIdentifier".to_owned()),
                    CborValue::Text(MDOC_QEAA_CATEGORY_ELEMENT.to_owned()),
                ),
                (
                    CborValue::Text("elementValue".to_owned()),
                    CborValue::Text(EAA_EU_QUALIFIED_TYPE.to_owned()),
                ),
            ]);
            let tagged =
                CborValue::Tag(TAG_ENCODED_CBOR, Box::new(CborValue::Bytes(encode(&item))));
            let digest = self.digest_algorithm.digest(&encode(&tagged));
            (Some(tagged), Some(digest))
        } else {
            (None, None)
        };

        // --- holder DeviceKey (COSE_Key) from the holder private key's public point. ----------------
        let holder_key = SigningKey::from_pkcs8_der(HOLDER_KEY).expect("holder key");
        let holder_pub = holder_key.verifying_key().to_encoded_point(false);
        let device_key = self.device_key_override.clone().unwrap_or_else(|| {
            cose_ec2_key(holder_pub.x().expect("x"), holder_pub.y().expect("y"))
        });

        // A tdate value: plain text, or `#6.0`-tagged text when exercising that decode path.
        let tdate = |s: &str| -> CborValue {
            if self.tdate_tagged {
                CborValue::Tag(0, Box::new(CborValue::Text(s.to_owned())))
            } else {
                CborValue::Text(s.to_owned())
            }
        };
        let mso_doc_type = if self.mso_doc_type_mismatch {
            format!("{}.other", self.doc_type)
        } else {
            self.doc_type.clone()
        };

        // --- MSO. ----------------------------------------------------------------------------------
        let mso = CborValue::Map(vec![
            (
                CborValue::Text("version".to_owned()),
                CborValue::Text(
                    self.mso_version_override
                        .clone()
                        .unwrap_or_else(|| "1.0".to_owned()),
                ),
            ),
            (
                CborValue::Text("digestAlgorithm".to_owned()),
                CborValue::Text(self.digest_algorithm.name().to_owned()),
            ),
            (
                CborValue::Text("valueDigests".to_owned()),
                CborValue::Map({
                    let mut namespaces = vec![(
                        CborValue::Text(self.namespace.clone()),
                        CborValue::Map(value_digests),
                    )];
                    // The category element lives in its OWN namespace's `valueDigests` sub-map (a single
                    // digestID → digest), mirroring the primary namespace's entry.
                    if let Some(digest) = &category_digest {
                        namespaces.push((
                            CborValue::Text(MDOC_QEAA_CATEGORY_NAMESPACE.to_owned()),
                            CborValue::Map(vec![(
                                CborValue::Integer(0.into()),
                                CborValue::Bytes(digest.clone()),
                            )]),
                        ));
                    }
                    namespaces
                }),
            ),
            (
                CborValue::Text("deviceKeyInfo".to_owned()),
                CborValue::Map(vec![(CborValue::Text("deviceKey".to_owned()), device_key)]),
            ),
            (
                CborValue::Text("docType".to_owned()),
                CborValue::Text(mso_doc_type),
            ),
            (CborValue::Text("validityInfo".to_owned()), {
                let mut info = Vec::new();
                if !self.omit_mso_signed {
                    info.push((CborValue::Text("signed".to_owned()), tdate(&self.signed)));
                }
                info.push((
                    CborValue::Text("validFrom".to_owned()),
                    tdate(&self.valid_from),
                ));
                info.push((
                    CborValue::Text("validUntil".to_owned()),
                    tdate(&self.valid_until),
                ));
                CborValue::Map(info)
            }),
        ]);
        // Drive the absent-MSO-version reject: strip the `version` entry entirely when requested.
        let mso = if self.omit_mso_version {
            strip_map_key(mso, "version")
        } else {
            mso
        };
        let mso_inner = encode(&mso);
        let mso_payload = encode(&CborValue::Tag(
            TAG_ENCODED_CBOR,
            Box::new(CborValue::Bytes(mso_inner)),
        ));

        // --- IssuerAuth COSE_Sign1 (ES256) over the MSO payload. ------------------------------------
        let (issuer_key_der, issuer_cert_der) = if self.use_wrong_issuer {
            (WRONG_ISSUER_KEY, WRONG_ISSUER_CERT)
        } else {
            (MDOC_DS_KEY, MDOC_DS_CERT)
        };
        let issuer_key = SigningKey::from_pkcs8_der(issuer_key_der).expect("issuer key");
        let issuer_alg = if self.issuer_auth_wrong_alg {
            coset::iana::Algorithm::ES384
        } else {
            coset::iana::Algorithm::ES256
        };
        let mut protected_builder = HeaderBuilder::new().algorithm(issuer_alg);
        if self.issuer_auth_unknown_crit {
            // RFC 9052 §3.1: mark a header the verifier does not process (`content type`, label 3) as
            // critical — the verifier must reject a message listing an unprocessed critical header.
            protected_builder =
                protected_builder.add_critical(coset::iana::HeaderParameter::ContentType);
        }
        let protected = protected_builder.build();
        let mut unprotected = HeaderBuilder::new();
        if !self.omit_x5chain {
            let x5chain = if self.x5chain_as_array {
                coset::cbor::value::Value::Array(vec![coset::cbor::value::Value::Bytes(
                    issuer_cert_der.to_vec(),
                )])
            } else {
                coset::cbor::value::Value::Bytes(issuer_cert_der.to_vec())
            };
            unprotected = unprotected.value(COSE_HEADER_X5CHAIN, x5chain);
        }
        let mut issuer_auth = CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected.build())
            .payload(mso_payload)
            .create_signature(&[], |tbs| es256_sign(&issuer_key, tbs))
            .build();
        if self.corrupt_issuer_auth {
            // Flip a signature byte: the COSE_Sign1 stays structurally valid but the ES256 check
            // must fail (Tamper).
            if let Some(byte) = issuer_auth.signature.first_mut() {
                *byte ^= 0xff;
            }
        }
        if self.issuer_auth_der_signature {
            // Re-encode the raw `r‖s` signature as ASN.1/DER (a valid ECDSA signature, non-conformant
            // COSE encoding). RFC 9053 §2.1 mandates the raw fixed-width form; the COSE path must reject
            // this DER signature (`Tamper`), never accept it via a DER fallback.
            let raw = Signature::from_slice(&issuer_auth.signature).expect("raw r‖s signature");
            issuer_auth.signature = raw.to_der().as_bytes().to_vec();
        }
        let issuer_auth_bytes = if self.tag_issuer_auth {
            issuer_auth
                .to_tagged_vec()
                .expect("encode tagged IssuerAuth")
        } else {
            issuer_auth.to_vec().expect("encode IssuerAuth")
        };
        let issuer_auth_value = decode(&issuer_auth_bytes);

        // --- DeviceSigned: empty DeviceNameSpaces + DeviceSignature over DeviceAuthentication. -------
        let device_name_spaces_inner = encode(&CborValue::Map(vec![]));
        let device_name_spaces_bytes = encode(&CborValue::Tag(
            TAG_ENCODED_CBOR,
            Box::new(CborValue::Bytes(device_name_spaces_inner)),
        ));
        let device_ns_value = decode(&device_name_spaces_bytes);

        // SessionTranscript: the supplied transcript, else the canonical default transcript. The
        // verifier no longer fabricates a transcript (ISO/IEC 18013-5 §9.1.5: it is always supplied),
        // so a default-transcript mdoc is verifiable ONLY when the test passes
        // `default_session_transcript()` to the verifier's `session_transcript` (issuer + verifier sign
        // over / reconstruct the SAME bytes).
        let session_transcript = self
            .session_transcript
            .clone()
            .unwrap_or_else(default_session_transcript);
        let session_transcript = decode(&session_transcript);
        let device_auth_inner = encode(&CborValue::Array(vec![
            CborValue::Text("DeviceAuthentication".to_owned()),
            session_transcript,
            CborValue::Text(self.doc_type.clone()),
            device_ns_value.clone(),
        ]));
        let device_auth_payload = encode(&CborValue::Tag(
            TAG_ENCODED_CBOR,
            Box::new(CborValue::Bytes(device_auth_inner)),
        ));

        let device_signing_key = if self.corrupt_device_signature {
            // A fresh, deterministic non-holder key (the wrong-issuer key doubles as a non-holder
            // P-256 key — its public point is not the MSO DeviceKey, so the binding must fail).
            SigningKey::from_pkcs8_der(WRONG_ISSUER_KEY).expect("non-holder key")
        } else {
            SigningKey::from_pkcs8_der(HOLDER_KEY).expect("holder key")
        };
        let device_alg = if self.device_sig_wrong_alg {
            coset::iana::Algorithm::ES384
        } else {
            coset::iana::Algorithm::ES256
        };
        let mut device_protected_builder = HeaderBuilder::new().algorithm(device_alg);
        if self.device_sig_unknown_crit {
            // RFC 9052 §3.1: an unprocessed critical header on the DeviceSignature COSE_Sign1.
            device_protected_builder =
                device_protected_builder.add_critical(coset::iana::HeaderParameter::ContentType);
        }
        let device_protected = device_protected_builder.build();
        let device_signature_value = self.device_signature_override.as_ref().map_or_else(
            || {
                let mut device_signature = CoseSign1Builder::new()
                    .protected(device_protected)
                    .create_detached_signature(&device_auth_payload, &[], |tbs| {
                        es256_sign(&device_signing_key, tbs)
                    })
                    .build();
                if self.mangle_device_signature {
                    // Truncate the 64-byte `r‖s` to 10 bytes: no longer a well-formed ES256 signature
                    // (neither raw nor DER) — a structurally-broken, transcript-independent binding.
                    device_signature.signature.truncate(10);
                }
                if self.device_signature_attached_payload {
                    // Flip the third COSE_Sign1 array element from `nil` to a NON-NIL (attached) bstr,
                    // leaving the genuine ES256 protected header + `r‖s` signature intact. This is a
                    // malformed, NON-DETACHED DeviceSignature (ISO/IEC 18013-5 §9.1.3 requires a
                    // detached/nil payload) — the verifier must reject it as `HolderBinding` WITHOUT
                    // reaching `coset`'s `tbs_detached_data` assert (which panics on `payload.is_some()`).
                    device_signature.payload = Some(vec![0x01]);
                }
                let device_signature_bytes =
                    device_signature.to_vec().expect("encode DeviceSignature");
                decode(&device_signature_bytes)
            },
            // The US2 signer-hook round-trip: embed the externally-built (SDK-spliced) COSE_Sign1.
            |override_cbor| decode(override_cbor),
        );

        // --- Assemble the document + DeviceResponse. ------------------------------------------------
        let issuer_signed = CborValue::Map(vec![
            (
                CborValue::Text("nameSpaces".to_owned()),
                CborValue::Map({
                    let mut namespaces = vec![(
                        CborValue::Text(self.namespace.clone()),
                        CborValue::Array(issuer_items),
                    )];
                    // The category element is disclosed under its OWN namespace's `IssuerSignedItems`
                    // array (matching the MSO `valueDigests` entry added above), so the SAME document
                    // carries both the ISO namespace and the ETSI category namespace.
                    if let Some(item) = category_item {
                        namespaces.push((
                            CborValue::Text(MDOC_QEAA_CATEGORY_NAMESPACE.to_owned()),
                            CborValue::Array(vec![item]),
                        ));
                    }
                    namespaces
                }),
            ),
            (CborValue::Text("issuerAuth".to_owned()), issuer_auth_value),
        ]);
        let device_signed = CborValue::Map(vec![
            (CborValue::Text("nameSpaces".to_owned()), device_ns_value),
            (
                CborValue::Text("deviceAuth".to_owned()),
                CborValue::Map(vec![(
                    CborValue::Text("deviceSignature".to_owned()),
                    device_signature_value,
                )]),
            ),
        ]);
        let document = CborValue::Map(vec![
            (
                CborValue::Text("docType".to_owned()),
                CborValue::Text(self.doc_type),
            ),
            (CborValue::Text("issuerSigned".to_owned()), issuer_signed),
            (CborValue::Text("deviceSigned".to_owned()), device_signed),
        ]);

        // `documents` is normally a single verified document. The multi-document false-accept probe
        // appends a SECOND document whose IssuerAuth signature is corrupted: if the verifier checks
        // only `documents[0]`, this forged document rides inside a VALID verdict; a correct verifier
        // (verifying every document) rejects it on the IssuerAuth signature.
        let mut documents = if self.empty_documents {
            Vec::new()
        } else {
            vec![document.clone()]
        };
        if self.append_forged_document {
            documents.push(forge_document_with_broken_issuer_auth(&document));
        }
        if let Some(colliding_document) = colliding {
            documents.push(colliding_document);
        }
        if let Some(other_ns_document) = other_namespace_document {
            documents.push(other_ns_document);
        }
        if let Some(second_valid_document) = second_valid_issued_at {
            documents.push(second_valid_document);
        }
        if let Some(second_wrong_issuer_document) = second_wrong_issuer_issued_at {
            documents.push(second_wrong_issuer_document);
        }
        if let Some(wrong_key_doc) = wrong_key_document {
            documents.push(wrong_key_doc);
        }

        let mut response_entries = vec![
            (
                CborValue::Text("version".to_owned()),
                CborValue::Text(
                    self.device_response_version_override
                        .clone()
                        .unwrap_or_else(|| "1.0".to_owned()),
                ),
            ),
            (
                CborValue::Text("documents".to_owned()),
                CborValue::Array(documents),
            ),
            (
                CborValue::Text("status".to_owned()),
                CborValue::Integer(self.status_override.unwrap_or(0).into()),
            ),
        ];
        if self.add_document_errors {
            // A `documentErrors` map naming a DIFFERENT docType the device could NOT return (ErrorCode
            // 0 = "data not returned", ISO/IEC 18013-5 §8.3). It is informational and must NOT fail the
            // valid returned mDL.
            response_entries.push((
                CborValue::Text("documentErrors".to_owned()),
                CborValue::Array(vec![CborValue::Map(vec![(
                    CborValue::Text("org.iso.23220.photoid.1".to_owned()),
                    CborValue::Integer(0.into()),
                )])]),
            ));
        }
        if self.omit_status {
            response_entries.retain(|(k, _)| k.as_text() != Some("status"));
        }
        if self.omit_device_response_version {
            response_entries.retain(|(k, _)| k.as_text() != Some("version"));
        }
        encode(&CborValue::Map(response_entries))
    }
}

/// Mint a fresh, fully-VALID single document (signed by the same trusted DS + holder) that discloses
/// exactly one element `identifier → value`, and return its `Document` CBOR value. Used to append a
/// genuine second document whose claim collides with the first — the cross-document shadowing probe.
fn build_single_valid_document(identifier: &'static str, value: CborValue) -> CborValue {
    // Re-use the full minting path for a one-element document, then lift out `documents[0]`.
    let response = MdocBuilder::new()
        .elements(vec![Element {
            digest_id: 0,
            identifier,
            value,
        }])
        .build();
    first_document_of_response(&response)
}

/// Mint a fresh, fully-VALID single document (same trusted DS + holder) disclosing one element
/// `identifier → value` under `namespace` (a DIFFERENT namespace than the primary document). Used by
/// the multi-namespace probe: the same `elementIdentifier` in two namespaces is a DISTINCT attribute,
/// so the merged response stays VALID and both values are surfaced under their own namespaces. Lifts
/// out `documents[0]`.
fn build_single_valid_document_in_namespace(
    namespace: &'static str,
    identifier: &'static str,
    value: CborValue,
) -> CborValue {
    let response = MdocBuilder::new()
        .namespace(namespace)
        .elements(vec![Element {
            digest_id: 0,
            identifier,
            value,
        }])
        .build();
    first_document_of_response(&response)
}

/// Mint a fresh, issuer-VALID single document (same trusted DS) disclosing one DISTINCT element,
/// signed over `transcript` but with a WRONG-KEY `DeviceSignature` (a non-holder key) — so its issuer
/// bar passes but its holder binding fails on the WRONG KEY (a transcript-INDEPENDENT fault), for the
/// multi-document `HolderBinding`-not-`Replay` probe. Lifts out `documents[0]`.
fn build_single_wrong_key_document(
    identifier: &'static str,
    value: CborValue,
    transcript: Vec<u8>,
) -> CborValue {
    let response = MdocBuilder::new()
        .elements(vec![Element {
            digest_id: 0,
            identifier,
            value,
        }])
        .session_transcript(transcript)
        .corrupt_device_signature()
        .build();
    first_document_of_response(&response)
}

/// Mint a fresh, fully-VALID single document (same trusted DS + holder) issued in its own
/// `(signed = validFrom = signed_at, validUntil = valid_until)` window, disclosing one DISTINCT
/// (non-colliding) element so it merges cleanly with the primary document's attributes. Used to
/// append a second VALID document at a chosen issuance time — the qualified-status fold probe.
fn build_single_valid_document_issued_at(signed_at: &str, valid_until: &str) -> CborValue {
    let response = MdocBuilder::new()
        .elements(vec![Element {
            digest_id: 0,
            identifier: "document_number",
            value: CborValue::Text("D-2027".to_owned()),
        }])
        // A conformant QEAA document: carry the ETSI `category` type indication so the qualified gate
        // reads THIS document's PRO-4.12.4-03 precondition (else it would fail closed to Indeterminate
        // and the fold could not narrow to NotQualified at the post-withdrawal relevant time).
        .qeaa_category()
        .signed(signed_at)
        .validity(signed_at, valid_until)
        .build();
    first_document_of_response(&response)
}

/// Mint a fresh, fully-VALID single document signed by the FOREIGN/untrusted `wrong-issuer` DS (via
/// [`MdocBuilder::use_wrong_issuer`]) in its own `(signed = validFrom = signed_at, validUntil)` window,
/// disclosing one DISTINCT (non-colliding) element. Used to append a second document whose issuer
/// chains to a DIFFERENT (foreign) anchor — the multi-document qualified-status provenance probe. Its
/// IssuerAuth verifies only when the always-on bar also trusts `wrong-issuer`; its issuer is absent
/// from the qualified national TL → Indeterminate. Lifts out `documents[0]`.
fn build_single_wrong_issuer_document_issued_at(signed_at: &str, valid_until: &str) -> CborValue {
    let response = MdocBuilder::new()
        .elements(vec![Element {
            digest_id: 0,
            identifier: "passport_number",
            value: CborValue::Text("P-FOREIGN".to_owned()),
        }])
        .use_wrong_issuer()
        .signed(signed_at)
        .validity(signed_at, valid_until)
        .build();
    first_document_of_response(&response)
}

/// Decode a freshly-minted `DeviceResponse` and lift out its `documents[0]` `Document` CBOR value —
/// the shared body of the single-document re-mint helpers above.
fn first_document_of_response(response: &[u8]) -> CborValue {
    let root = decode(response);
    let CborValue::Map(entries) = &root else {
        panic!("DeviceResponse is a CBOR map")
    };
    let documents = entries
        .iter()
        .find_map(|(k, v)| (k.as_text() == Some("documents")).then_some(v))
        .expect("documents present");
    let CborValue::Array(docs) = documents else {
        panic!("documents is a CBOR array")
    };
    docs.first().expect("one document minted").clone()
}

/// Clone a built `Document` and corrupt its IssuerAuth signature byte, producing a forged document
/// whose issuer signature must fail verification (the multi-document false-accept probe).
fn forge_document_with_broken_issuer_auth(document: &CborValue) -> CborValue {
    let CborValue::Map(entries) = document else {
        panic!("document is a CBOR map")
    };
    let forged = entries
        .iter()
        .map(|(k, v)| {
            if k.as_text() == Some("issuerSigned") {
                (k.clone(), corrupt_issuer_auth_in_issuer_signed(v))
            } else {
                (k.clone(), v.clone())
            }
        })
        .collect();
    CborValue::Map(forged)
}

/// Within an `issuerSigned` map, re-encode the `issuerAuth` COSE_Sign1 with a flipped signature byte.
fn corrupt_issuer_auth_in_issuer_signed(issuer_signed: &CborValue) -> CborValue {
    let CborValue::Map(entries) = issuer_signed else {
        panic!("issuerSigned is a CBOR map")
    };
    let forged = entries
        .iter()
        .map(|(k, v)| {
            if k.as_text() == Some("issuerAuth") {
                let mut sign1 =
                    coset::CoseSign1::from_slice(&encode(v)).expect("decode IssuerAuth");
                if let Some(byte) = sign1.signature.first_mut() {
                    *byte ^= 0xff;
                }
                (
                    k.clone(),
                    decode(&sign1.to_vec().expect("encode IssuerAuth")),
                )
            } else {
                (k.clone(), v.clone())
            }
        })
        .collect();
    CborValue::Map(forged)
}

/// Remove a text-keyed entry from a CBOR map value — the omit-field negative cases (absent MSO
/// `version`) strip one mandatory key after the well-formed structure is built.
fn strip_map_key(value: CborValue, key: &str) -> CborValue {
    match value {
        CborValue::Map(entries) => CborValue::Map(
            entries
                .into_iter()
                .filter(|(k, _)| k.as_text() != Some(key))
                .collect(),
        ),
        other => other,
    }
}

/// Encode a `ciborium` value to CBOR bytes.
fn encode(value: &CborValue) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).expect("encode CBOR");
    buf
}

/// Decode CBOR bytes to a `ciborium` value.
fn decode(bytes: &[u8]) -> CborValue {
    ciborium::from_reader(bytes).expect("decode CBOR")
}

/// ES256-sign `tbs`, returning the raw fixed-width `r‖s` signature (the COSE form).
fn es256_sign(key: &SigningKey, tbs: &[u8]) -> Vec<u8> {
    let sig: Signature = key.sign(tbs);
    sig.to_bytes().to_vec()
}

/// Build a COSE_Key (EC2 / P-256) CBOR map from raw 32-byte X and Y coordinates.
fn cose_ec2_key(x: &[u8], y: &[u8]) -> CborValue {
    CborValue::Map(vec![
        (CborValue::Integer(1.into()), CborValue::Integer(2.into())), // kty = EC2
        (
            CborValue::Integer((-1).into()),
            CborValue::Integer(1.into()),
        ), // crv = P-256
        (
            CborValue::Integer((-2).into()),
            CborValue::Bytes(x.to_vec()),
        ), // x
        (
            CborValue::Integer((-3).into()),
            CborValue::Bytes(y.to_vec()),
        ), // y
    ])
}
