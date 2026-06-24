//! RFC 3161 timestamping for PAdES B-T.
//!
//! Builds a `TimeStampReq` over `sha256(signature value)` and extracts the `TimeStampToken` from
//! the TSA's `TimeStampResp`. The token is embedded into the CMS as the `signature-time-stamp`
//! unsigned attribute (see [`crate::crypto::cms::embed_timestamp`]). Cleverbase's CSC signing API
//! exposes no timestamp endpoint, so the host points this at a configured RFC 3161 TSA.

use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::asn1::{Any, Null, OctetString};
use der::oid::ObjectIdentifier;
use der::{Decode, Encode, Sequence};
use x509_cert::spki::AlgorithmIdentifierOwned;

use crate::crypto::SHA256_OID as ID_SHA256;

/// Errors from RFC 3161 handling.
#[derive(Debug, thiserror::Error)]
pub enum TimestampError {
    /// A DER encode/decode error.
    #[error("DER error: {0}")]
    Der(#[from] der::Error),
    /// The TSA did not grant a timestamp (non-granted status or no token in the response).
    #[error("timestamp request was not granted (no token in response)")]
    NotGranted,
    /// The configured TSA policy OID was not a valid object identifier.
    #[error("invalid TSA policy OID: {0}")]
    InvalidPolicyOid(String),
}

/// `MessageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }`
#[derive(Sequence)]
struct MessageImprint {
    hash_algorithm: AlgorithmIdentifierOwned,
    hashed_message: OctetString,
}

/// `TimeStampReq` (subset: version, messageImprint, reqPolicy OPTIONAL, certReq).
#[derive(Sequence)]
struct TimeStampReq {
    version: u8,
    message_imprint: MessageImprint,
    #[asn1(optional = "true")]
    req_policy: Option<ObjectIdentifier>,
    cert_req: bool,
}

/// `PKIStatusInfo ::= SEQUENCE { status PKIStatus, statusString PKIFreeText OPTIONAL,
/// failInfo PKIFailureInfo OPTIONAL }`. We only need `status`; the optional fields are absorbed.
#[derive(Sequence)]
struct PkiStatusInfo {
    status: u32,
    #[asn1(optional = "true")]
    status_string: Option<Any>,
    #[asn1(optional = "true")]
    fail_info: Option<Any>,
}

/// `TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken TimeStampToken OPTIONAL }`.
#[derive(Sequence)]
struct TimeStampResp {
    status: PkiStatusInfo,
    #[asn1(optional = "true")]
    token: Option<ContentInfo>,
}

/// Build an RFC 3161 `TimeStampReq` over `sha256(signature value)` with `certReq = true`, optionally
/// constraining the TSA to a specific policy OID.
pub fn build_request(
    signature_sha256: &[u8],
    policy_oid: Option<&str>,
) -> Result<Vec<u8>, TimestampError> {
    let req_policy = match policy_oid {
        Some(oid) => Some(
            oid.parse::<ObjectIdentifier>()
                .map_err(|_| TimestampError::InvalidPolicyOid(oid.to_string()))?,
        ),
        None => None,
    };
    let req = TimeStampReq {
        version: 1,
        message_imprint: MessageImprint {
            hash_algorithm: AlgorithmIdentifierOwned {
                oid: ID_SHA256,
                parameters: Some(Any::from_der(&Null.to_der()?)?),
            },
            hashed_message: OctetString::new(signature_sha256.to_vec())?,
        },
        req_policy,
        cert_req: true,
    };
    Ok(req.to_der()?)
}

/// Extract the `TimeStampToken` (a CMS `ContentInfo`, DER) from a `TimeStampResp`.
pub fn parse_response(resp_der: &[u8]) -> Result<Vec<u8>, TimestampError> {
    let resp = TimeStampResp::from_der(resp_der)?;
    // PKIStatus: 0 = granted, 1 = grantedWithMods; anything else is not a usable timestamp.
    if resp.status.status > 1 {
        return Err(TimestampError::NotGranted);
    }
    let token = resp.token.ok_or(TimestampError::NotGranted)?;
    Ok(token.to_der()?)
}

/// Parse the TSA's `genTime` (Unix seconds) from a `TimeStampToken` (CMS `ContentInfo`, DER).
/// Returns `None` if the token cannot be parsed.
pub fn parse_gen_time(token_der: &[u8]) -> Option<i64> {
    let ci = ContentInfo::from_der(token_der).ok()?;
    let sd = SignedData::from_der(&ci.content.to_der().ok()?).ok()?;
    // eContent is an OCTET STRING wrapping the TSTInfo DER.
    let econtent = sd.encap_content_info.econtent?;
    let tstinfo = OctetString::from_der(&econtent.to_der().ok()?).ok()?;
    // Descend into the TSTInfo SEQUENCE and take its first GeneralizedTime field (= genTime).
    let content = sequence_content(tstinfo.as_bytes())?;
    let gt_tlv = first_tlv_with_tag(content, 0x18)?;
    parse_generalized_time_secs(gt_tlv)
}

/// Parse a DER `GeneralizedTime` TLV (`YYYYMMDDHHMMSS[.fff]Z`, always UTC in RFC 3161) to Unix
/// seconds. Unlike `der::GeneralizedTime`, this tolerates the fractional seconds that real
/// qualified TSAs commonly emit (the fraction is ignored — evidence records whole seconds).
fn parse_generalized_time_secs(tlv: &[u8]) -> Option<i64> {
    let (content_len, len_bytes) = read_der_len(tlv.get(1..)?)?;
    let body = tlv.get(1 + len_bytes..1 + len_bytes + content_len)?;
    let s = core::str::from_utf8(body).ok()?;
    let digits = s.as_bytes().get(..14)?;
    if !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    // RFC 3161 TSTInfo `genTime` is `YYYYMMDDHHMMSS`, optionally `.<frac>`, and is ALWAYS terminated
    // by `Z` (UTC). Reject any other suffix — trailing junk, a numeric offset like `+01:00`, or a
    // missing `Z` — so a malformed TSA token makes the caller fall back rather than accept a wrong
    // timestamp. (A fractional part, if present, is intentionally not carried into whole seconds.)
    match body.get(14..) {
        Some(b"Z") => {}
        Some([b'.', frac @ .., b'Z']) if !frac.is_empty() && frac.iter().all(u8::is_ascii_digit) => {}
        _ => return None,
    }
    // Parse a 2/4-digit field by byte range; `.get` (not `[..]`) keeps this off the string-slice
    // panic path. The all-ASCII-digit check above guarantees each sub-slice parses.
    let n = |a: usize, b: usize| s.get(a..b).and_then(|t| t.parse::<i64>().ok());
    let (year, month, day) = (n(0, 4)?, n(4, 6)?, n(6, 8)?);
    let (hour, min, sec) = (n(8, 10)?, n(10, 12)?, n(12, 14)?);
    if !(1..=12).contains(&month) {
        return None;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    // Days in each month (1-based), selected without array indexing so there is no panic path.
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            if leap {
                29
            } else {
                28
            }
        }
    };
    // Reject impossible dates/times (e.g. Feb 31, hour 25) rather than silently normalizing them.
    if day < 1 || day > days_in_month || hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    Some(crate::util::days_from_civil(year, month, day) * 86400 + hour * 3600 + min * 60 + sec)
}

/// Parse the `messageImprint.hashedMessage` (the hash the TSA actually timestamped) from a
/// `TimeStampToken`, so the caller can confirm the token is bound to the value it submitted.
/// Returns `None` if the token cannot be parsed.
pub fn parse_message_imprint(token_der: &[u8]) -> Option<Vec<u8>> {
    let ci = ContentInfo::from_der(token_der).ok()?;
    let sd = SignedData::from_der(&ci.content.to_der().ok()?).ok()?;
    let econtent = sd.encap_content_info.econtent?;
    let tstinfo = OctetString::from_der(&econtent.to_der().ok()?).ok()?;
    let content = sequence_content(tstinfo.as_bytes())?;
    // messageImprint is the first SEQUENCE field of TSTInfo; its hashedMessage is the OCTET STRING.
    let mi = first_tlv_with_tag(content, 0x30)?;
    let mi_content = sequence_content(mi)?;
    let hashed = first_tlv_with_tag(mi_content, 0x04)?;
    let (len, hdr) = read_der_len(hashed.get(1..)?)?;
    Some(hashed.get(1 + hdr..1 + hdr + len)?.to_vec())
}

/// Read a DER length at the start of `b`; returns `(content_length, length_field_byte_count)`.
fn read_der_len(b: &[u8]) -> Option<(usize, usize)> {
    let first = *b.first()?;
    if first < 0x80 {
        Some((first as usize, 1))
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for k in 0..n {
            len = (len << 8) | *b.get(1 + k)? as usize;
        }
        Some((len, 1 + n))
    }
}

/// Given a DER SEQUENCE TLV, return the slice of its content bytes.
fn sequence_content(der: &[u8]) -> Option<&[u8]> {
    if *der.first()? != 0x30 {
        return None;
    }
    let (content_len, len_bytes) = read_der_len(der.get(1..)?)?;
    der.get(1 + len_bytes..1 + len_bytes + content_len)
}

/// Return the first top-level TLV in `der` whose tag byte equals `tag`, as a full TLV slice.
fn first_tlv_with_tag(der: &[u8], tag: u8) -> Option<&[u8]> {
    let mut i = 0;
    while i < der.len() {
        let t = *der.get(i)?;
        let (content_len, len_bytes) = read_der_len(der.get(i + 1..)?)?;
        let total = 1 + len_bytes + content_len;
        if i + total > der.len() {
            return None;
        }
        if t == tag {
            return der.get(i..i + total);
        }
        i += total;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sha256;

    #[test]
    fn request_is_wellformed_der() {
        let imprint = sha256(b"a signature value");
        let der = build_request(&imprint, None).unwrap();
        // SEQUENCE
        assert_eq!(der[0], 0x30);
        // round-trips back to the same structure (version + imprint + certReq).
        let back = TimeStampReq::from_der(&der).unwrap();
        assert_eq!(back.version, 1);
        assert!(back.cert_req);
        assert!(back.req_policy.is_none());
        assert_eq!(back.message_imprint.hashed_message.as_bytes(), &imprint);
    }

    #[test]
    fn request_carries_policy_oid() {
        let imprint = sha256(b"x");
        let der = build_request(&imprint, Some("1.3.6.1.4.1.99999.1.1")).unwrap();
        let back = TimeStampReq::from_der(&der).unwrap();
        assert_eq!(
            back.req_policy.unwrap().to_string(),
            "1.3.6.1.4.1.99999.1.1"
        );
        assert!(back.cert_req);
        // An invalid policy OID is rejected, not silently dropped.
        assert!(build_request(&imprint, Some("not-an-oid")).is_err());
    }

    #[test]
    fn generalized_time_parses_with_and_without_fraction() {
        let mk = |s: &str| {
            let mut v = vec![0x18u8, s.len() as u8];
            v.extend_from_slice(s.as_bytes());
            v
        };
        let plain = parse_generalized_time_secs(&mk("20260622120000Z")).unwrap();
        let frac = parse_generalized_time_secs(&mk("20260622120000.123Z")).unwrap();
        assert_eq!(
            plain, frac,
            "fractional seconds must be ignored, not rejected"
        );
        // 2026-06-22 12:00:00 UTC.
        assert_eq!(plain, 1_782_129_600);
        // Garbage and impossible dates/times are rejected (None), not panicked or normalized.
        assert!(parse_generalized_time_secs(&mk("not-a-time!!!!Z")).is_none());
        assert!(parse_generalized_time_secs(&mk("20260231120000Z")).is_none()); // Feb 31
        assert!(parse_generalized_time_secs(&mk("20260622256100Z")).is_none()); // hour 25, min 61
        assert!(parse_generalized_time_secs(&mk("20260229120000Z")).is_none()); // 2026 not a leap year
        assert!(parse_generalized_time_secs(&mk("20240229120000Z")).is_some()); // 2024 IS a leap year
        assert!(parse_generalized_time_secs(&mk("20261301120000Z")).is_none()); // month 13
        // Malformed suffixes must be rejected (RFC 3161 genTime is UTC, terminated by `Z`), so a bad
        // TSA token falls back to the host clock instead of yielding a wrong gen_time.
        assert!(parse_generalized_time_secs(&mk("20260622120000")).is_none()); // missing Z
        assert!(parse_generalized_time_secs(&mk("20260622120000junk")).is_none()); // trailing junk
        assert!(parse_generalized_time_secs(&mk("20260622120000.123+01:00")).is_none()); // offset, no Z
        assert!(parse_generalized_time_secs(&mk("20260622120000.Z")).is_none()); // empty fraction
    }

    #[test]
    fn parse_response_rejects_non_granted_status() {
        // Hand-built TimeStampResp: SEQUENCE { PKIStatusInfo SEQUENCE { INTEGER 2 (rejection) } }.
        let resp = [0x30u8, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02];
        assert!(matches!(
            parse_response(&resp),
            Err(TimestampError::NotGranted)
        ));
    }

    #[test]
    fn token_parsers_reject_garbage() {
        // Malformed token bytes must yield None (exercising the DER-walk None paths), never panic.
        assert_eq!(parse_gen_time(b"not a token"), None);
        assert_eq!(parse_message_imprint(b"\x30\x03garbage"), None);
        assert_eq!(parse_gen_time(&[0x30, 0x80]), None); // indefinite-length form rejected
    }
}
