//! Small dependency-free helpers: hex, standard base64, percent-encoding, and civil-date math.
//!
//! Kept local (rather than pulling extra crates) so the sans-IO core stays lean and WASM-friendly.

/// Civil date `(year, month, day)` from days since the Unix epoch (Howard Hinnant's algorithm).
/// Single source for the proleptic-Gregorian conversion (visible-appearance date + TSA genTime).
pub fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Days since the Unix epoch for a proleptic-Gregorian date — the inverse of [`civil_from_days`].
pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = y - i64::from(m <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Map a nibble to its lowercase hex ASCII char by arithmetic (no table indexing, no `unwrap`):
/// `0..=9` → `'0'..='9'`, `10..=15` → `'a'..='f'`. Infallible — the low nibble is always 0–15.
/// Single source for nibble→hex, shared by `to_hex`/`percent_encode` and the PAdES `/Contents`
/// hex writer (Constitution Principle III/VIII).
pub(crate) const fn hex_digit(nibble: u8) -> char {
    let n = nibble & 0x0f;
    (if n < 10 { b'0' + n } else { b'a' + n - 10 }) as char
}

/// Lowercase hex encoding.
pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(hex_digit(b >> 4));
        s.push(hex_digit(b & 0x0f));
    }
    s
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Map a 6-bit value to its standard-base64 ASCII char. Uses `.get` (not `[]`) so there is no
/// panicking index; the `& 63` mask keeps the lookup in range, and the unreachable fallback (`'='`,
/// never produced for a real sextet) keeps the function total without an `unwrap`.
fn b64_char(sextet: u32) -> char {
    B64.get((sextet & 63) as usize).map_or('=', |&b| b as char)
}

/// Standard (padded) base64 encoding.
pub fn base64_std(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        // `chunks(3)` never yields an empty chunk, so `first()` is Some; default the absent
        // tail bytes to 0 (the standard base64 padding rule) without indexing.
        let b0 = chunk.first().copied().unwrap_or(0);
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        out.push(b64_char(n >> 18));
        out.push(b64_char(n >> 12));
        out.push(if chunk.len() > 1 {
            b64_char(n >> 6)
        } else {
            '='
        });
        out.push(if chunk.len() > 2 { b64_char(n) } else { '=' });
    }
    out
}

/// RFC 3986 unreserved-only percent-encoding (safe for query parameters).
pub fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push(hex_digit(b >> 4).to_ascii_uppercase());
                out.push(hex_digit(b & 0x0f).to_ascii_uppercase());
            }
        }
    }
    out
}

/// URL-safe base64 without padding (RFC 4648 §5) — used for the CSC credential-authorization hash.
pub fn base64url_nopad(input: &[u8]) -> String {
    base64_std(input)
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_")
}

/// Decode standard base64 (tolerates padding and embedded whitespace).
pub fn base64_decode(input: &str) -> Result<Vec<u8>, &'static str> {
    fn val(c: u8) -> Result<u8, &'static str> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err("invalid base64 character"),
        }
    }
    // Accumulate decoded sextets in four named slots (no array indexing → no panicking `[]`).
    let (mut q0, mut q1, mut q2, mut q3) = (0u8, 0u8, 0u8, 0u8);
    let mut n = 0u8;
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    for &b in input.as_bytes() {
        // Skip padding and any ASCII whitespace (space, tab, CR, LF, form feed, vertical tab).
        if b == b'=' || b.is_ascii_whitespace() {
            continue;
        }
        let v = val(b)?;
        match n {
            0 => q0 = v,
            1 => q1 = v,
            2 => q2 = v,
            _ => q3 = v,
        }
        n += 1;
        if n == 4 {
            out.push((q0 << 2) | (q1 >> 4));
            out.push((q1 << 4) | (q2 >> 2));
            out.push((q2 << 6) | q3);
            n = 0;
        }
    }
    match n {
        0 => {}
        2 => out.push((q0 << 2) | (q1 >> 4)),
        3 => {
            out.push((q0 << 2) | (q1 >> 4));
            out.push((q1 << 4) | (q2 >> 2));
        }
        _ => return Err("invalid base64 length"),
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_decode_roundtrips() {
        for v in [
            &b""[..],
            b"f",
            b"fo",
            b"foo",
            b"foob",
            b"Aladdin:open sesame",
        ] {
            assert_eq!(base64_decode(&base64_std(v)).unwrap(), v);
        }
        assert!(base64_decode("@@@@").is_err());
        // Embedded whitespace (tabs/newlines/spaces) is tolerated, as documented.
        assert_eq!(base64_decode("Zm9v\tZg ==\n").unwrap(), b"foof");
    }

    #[test]
    fn base64url_has_no_padding_or_specials() {
        let u = base64url_nopad(&[0xfb, 0xff, 0xbf]);
        assert!(!u.contains('='));
        assert!(!u.contains('+'));
        assert!(!u.contains('/'));
    }

    #[test]
    fn hex_roundtrip_known() {
        assert_eq!(to_hex(&[0x00, 0x0f, 0xff, 0xa5]), "000fffa5");
    }

    #[test]
    fn base64_known_vectors() {
        assert_eq!(base64_std(b""), "");
        assert_eq!(base64_std(b"f"), "Zg==");
        assert_eq!(base64_std(b"fo"), "Zm8=");
        assert_eq!(base64_std(b"foo"), "Zm9v");
        assert_eq!(base64_std(b"foob"), "Zm9vYg==");
        assert_eq!(
            base64_std(b"Aladdin:open sesame"),
            "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        );
    }

    #[test]
    fn percent_encode_reserved() {
        assert_eq!(percent_encode("a b/c?d=e&f"), "a%20b%2Fc%3Fd%3De%26f");
        assert_eq!(percent_encode("safe-_.~"), "safe-_.~");
    }

    #[test]
    fn civil_date_inverse_property() {
        // `days_from_civil` is documented as the inverse of `civil_from_days`; verify the round-trip
        // across the epoch, negative days, and era boundaries (±146_097 = the 400-year cycle).
        for days in [-146_097, -1000, -1, 0, 1, 1000, 19_000, 146_097, 200_000] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days, "inverse failed at {days}");
        }
    }
}
