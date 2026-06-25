//! One authoritative RFC 3339 / ISO 8601 **UTC** timestamp parser for the whole verifier (DRY —
//! Constitution Principle III).
//!
//! Both the mdoc MSO `validityInfo` (`validFrom`/`validUntil`/`signed`) and the trust-list
//! timestamps (TS 119 612 `NextUpdate`, qualified-status effective `startingTime`) need the same
//! grammar: the `YYYY-MM-DDThh:mm:ssZ` UTC form, with optional fractional seconds. They previously
//! carried two independent copies, both of which validated the day only as `1..=31` for *every*
//! month — so `2023-02-31`, `2023-04-31`, and `2023-02-29` (non-leap) parsed to a **wrong instant**
//! (`civil_to_unix` silently rolls an over-long day forward into the next month). For a validity
//! window / stale-list boundary that is a security defect (a tampered or malformed instant is
//! accepted instead of failing closed).
//!
//! This single parser is **correct** (day-of-month is validated against the month and leap year)
//! and **fails closed** (returns `None` on any deviation), so a malformed timestamp can never parse
//! to a wrong instant.
//!
//! No date crate: the civil-date math is the public-domain `days_from_civil` algorithm (Howard
//! Hinnant) — the same self-contained algorithm `chrono`/`time` use — keeping the verifier
//! pure-Rust / WASM-able with no extra dependency.

/// Parse an RFC 3339 / ISO 8601 **UTC** timestamp (`YYYY-MM-DDThh:mm:ssZ`, with optional fractional
/// seconds) to Unix seconds.
///
/// Only the `Z` (UTC) form is accepted — both the ISO/IEC 18013-5 `tdate` fields and the TS 119 612
/// trust-list timestamps are UTC; an offset / local time is rejected. The day-of-month is validated
/// against the month **and leap year** (Feb 28/29; the 30-day months Apr/Jun/Sep/Nov), so an
/// out-of-range day fails closed (`None`) rather than rolling forward to a wrong instant.
///
/// Returns `None` on any deviation (wrong separators, out-of-range field, non-numeric component,
/// trailing garbage, missing `Z`), so a malformed timestamp fails closed.
pub(crate) fn parse_rfc3339_utc(s: &str) -> Option<i64> {
    let s = s.strip_suffix('Z')?;
    let (date, time) = s.split_once('T')?;

    // Date: exactly three '-'-separated numeric segments.
    let mut date_parts = date.split('-');
    let year: i64 = date_parts.next()?.parse().ok()?;
    let month: i64 = parse_fixed_width(date_parts.next()?, 2)?;
    let day: i64 = parse_fixed_width(date_parts.next()?, 2)?;
    if date_parts.next().is_some() {
        return None;
    }

    // Time: exactly three ':'-separated segments; the seconds segment may carry an optional `.fff`
    // fractional part (truncated — sub-second precision is irrelevant to a window/boundary check).
    let mut time_parts = time.split(':');
    let hour: i64 = parse_fixed_width(time_parts.next()?, 2)?;
    let minute: i64 = parse_fixed_width(time_parts.next()?, 2)?;
    let seconds_field = time_parts.next()?;
    if time_parts.next().is_some() {
        return None;
    }
    let second = parse_seconds_field(seconds_field)?;

    // Field-range validation. The day is checked against the month + leap year (the bug fix); the
    // year is unconstrained (proleptic Gregorian). A leap second (`60`) is tolerated.
    if !(1..=12).contains(&month)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return None;
    }
    if !(1..=days_in_month(year, month)?).contains(&day) {
        return None;
    }

    Some(civil_to_unix(year, month, day, hour, minute, second))
}

/// Parse a fixed-width, all-ASCII-digit field (e.g. a two-digit month/day/hour) to `i64`.
///
/// Enforcing the exact width rejects shapes that `str::parse` would otherwise accept — a leading
/// `+`/`-` sign, surrounding whitespace, or a single-digit field — so the grammar stays strict.
fn parse_fixed_width(field: &str, width: usize) -> Option<i64> {
    if field.len() != width || !field.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    field.parse().ok()
}

/// Parse the seconds field, which is two digits with an optional `.fff…` fractional part. The
/// integer seconds are returned; the fractional part is validated (digits only) but truncated.
fn parse_seconds_field(field: &str) -> Option<i64> {
    let (whole, fraction) = field
        .split_once('.')
        .map_or((field, None), |(w, f)| (w, Some(f)));
    if let Some(fraction) = fraction {
        // A `.` must be followed by at least one digit, and only digits.
        if fraction.is_empty() || !fraction.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
    }
    parse_fixed_width(whole, 2)
}

/// The number of days in `month` (1..=12) of `year`, honouring the Gregorian leap-year rule. Returns
/// `None` for a month outside `1..=12` (caller validates the range, but this keeps the helper total).
fn days_in_month(year: i64, month: i64) -> Option<i64> {
    Some(match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => return None,
    })
}

/// The proleptic-Gregorian leap-year rule: divisible by 4, except centuries unless divisible by 400
/// (so 2000 is a leap year, 1900 is not).
fn is_leap_year(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

/// Convert a UTC civil date-time to Unix seconds using Howard Hinnant's `days_from_civil` algorithm
/// (public-domain; the same algorithm `chrono`/`time` use). Avoids a date dependency for the
/// timestamp parses the verifier needs.
///
/// Callers MUST validate the field ranges first ([`parse_rfc3339_utc`] does); a `day` beyond the
/// month would otherwise roll forward into the next month.
fn civil_to_unix(year: i64, month: i64, day: i64, hour: i64, minute: i64, second: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    let days = era * 146_097 + doe - 719_468;
    days * 86_400 + hour * 3_600 + minute * 60 + second
}

#[cfg(test)]
mod tests {
    use super::{civil_to_unix, days_in_month, is_leap_year, parse_rfc3339_utc};

    #[test]
    fn days_in_month_is_total_over_every_month_and_returns_none_out_of_range() {
        // The parser validates the month range first, but `days_in_month` stays total: an
        // out-of-range month yields `None` rather than a wrong day count (the defensive arm).
        assert_eq!(days_in_month(2023, 0), None);
        assert_eq!(days_in_month(2023, 13), None);
        // The in-range lengths (31 / 30 / 28 / 29-leap) are exercised end-to-end via the parser.
        assert_eq!(days_in_month(2023, 1), Some(31));
        assert_eq!(days_in_month(2023, 4), Some(30));
        assert_eq!(days_in_month(2023, 2), Some(28));
        assert_eq!(days_in_month(2024, 2), Some(29));
    }

    #[test]
    fn parses_known_epochs() {
        assert_eq!(parse_rfc3339_utc("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339_utc("2000-01-01T00:00:00Z"), Some(946_684_800));
        assert_eq!(
            parse_rfc3339_utc("2023-01-01T00:00:00Z"),
            Some(1_672_531_200)
        );
        assert_eq!(
            parse_rfc3339_utc("2021-11-14T22:13:20Z"),
            Some(1_636_928_000)
        );
    }

    #[test]
    fn tolerates_fractional_seconds_truncating_them() {
        // Fractional seconds are valid RFC 3339; they are accepted and truncated (the window/boundary
        // checks are second-granular).
        assert_eq!(
            parse_rfc3339_utc("2023-01-01T00:00:00.123Z"),
            Some(1_672_531_200)
        );
        assert_eq!(
            parse_rfc3339_utc("2023-01-01T00:00:00.000000001Z"),
            Some(1_672_531_200)
        );
        // A trailing `.` with no fractional digits is malformed → fail closed.
        assert_eq!(parse_rfc3339_utc("2023-01-01T00:00:00.Z"), None);
        // Non-digit fractional → fail closed.
        assert_eq!(parse_rfc3339_utc("2023-01-01T00:00:00.12aZ"), None);
    }

    #[test]
    fn tolerates_a_leap_second() {
        // Second 60 (a leap second) is tolerated by the range check.
        assert_eq!(
            parse_rfc3339_utc("2016-12-31T23:59:60Z"),
            Some(1_483_228_800)
        );
    }

    #[test]
    fn rejects_non_utc_and_wrong_separators() {
        assert_eq!(parse_rfc3339_utc("2023-01-01"), None); // no time
        assert_eq!(parse_rfc3339_utc("2023-01-01T00:00:00"), None); // no 'Z'
        assert_eq!(parse_rfc3339_utc("2023-01-01T00:00:00+01:00"), None); // offset, not 'Z'
        assert_eq!(parse_rfc3339_utc("2021-11-14 22:13:20Z"), None); // space, not 'T'
        assert_eq!(parse_rfc3339_utc("2023/01/01T00:00:00Z"), None); // wrong date sep
        assert_eq!(parse_rfc3339_utc("2023-01/01T00:00:00Z"), None); // mixed date sep
        assert_eq!(parse_rfc3339_utc("2023-01-01T00-00:00Z"), None); // wrong time sep
        assert_eq!(parse_rfc3339_utc("2023-01-01T00:00-00Z"), None); // wrong time sep
        assert_eq!(parse_rfc3339_utc("2021-11-14-01T00:00:00Z"), None); // 4 date segments
        assert_eq!(parse_rfc3339_utc("2021-11-14T00:00:00:00Z"), None); // 4 time segments
    }

    #[test]
    fn rejects_out_of_range_fields() {
        assert_eq!(parse_rfc3339_utc("2023-13-01T00:00:00Z"), None); // month 13
        assert_eq!(parse_rfc3339_utc("2023-00-14T00:00:00Z"), None); // month 0
        assert_eq!(parse_rfc3339_utc("2023-01-00T00:00:00Z"), None); // day 0
        assert_eq!(parse_rfc3339_utc("2023-01-32T00:00:00Z"), None); // day 32
        assert_eq!(parse_rfc3339_utc("2023-01-01T24:00:00Z"), None); // hour 24
        assert_eq!(parse_rfc3339_utc("2023-01-01T00:60:00Z"), None); // minute 60
        assert_eq!(parse_rfc3339_utc("2023-01-01T00:00:99Z"), None); // second 99
    }

    #[test]
    fn rejects_non_numeric_or_misshaped_components() {
        assert_eq!(parse_rfc3339_utc("xxxx-11-14T00:00:00Z"), None); // non-numeric year
        assert_eq!(parse_rfc3339_utc("2023-1-01T00:00:00Z"), None); // 1-digit month
        assert_eq!(parse_rfc3339_utc("2023-01-1T00:00:00Z"), None); // 1-digit day
        assert_eq!(parse_rfc3339_utc("2023-01-01T0:00:00Z"), None); // 1-digit hour
        assert_eq!(parse_rfc3339_utc("2023-01-01T+0:00:00Z"), None); // signed hour
        assert_eq!(parse_rfc3339_utc("2023-01-01T00:00:+0Z"), None); // signed second
    }

    #[test]
    fn rejects_invalid_day_of_month_that_used_to_roll_forward() {
        // The defect being fixed: these all have day <= 31 but exceed the *month's* length, so the
        // old `1..=31` check accepted them and `civil_to_unix` silently rolled them into the next
        // month — a WRONG instant. They must now fail closed.
        assert_eq!(parse_rfc3339_utc("2023-02-31T00:00:00Z"), None); // Feb 31
        assert_eq!(parse_rfc3339_utc("2023-02-30T00:00:00Z"), None); // Feb 30
        assert_eq!(parse_rfc3339_utc("2023-02-29T00:00:00Z"), None); // Feb 29, non-leap
        assert_eq!(parse_rfc3339_utc("2023-04-31T00:00:00Z"), None); // Apr 31 (30-day month)
        assert_eq!(parse_rfc3339_utc("2023-06-31T00:00:00Z"), None); // Jun 31
        assert_eq!(parse_rfc3339_utc("2023-09-31T00:00:00Z"), None); // Sep 31
        assert_eq!(parse_rfc3339_utc("2023-11-31T00:00:00Z"), None); // Nov 31
    }

    #[test]
    fn accepts_valid_day_of_month_including_leap_day() {
        // Feb 29 in a leap year is the real instant (no rollover).
        assert_eq!(
            parse_rfc3339_utc("2020-02-29T00:00:00Z"),
            Some(1_582_934_400)
        );
        // The day-before of a 31-day and a 30-day month, valid.
        assert_eq!(
            parse_rfc3339_utc("2023-01-31T00:00:00Z"),
            Some(1_675_123_200)
        );
        assert_eq!(
            parse_rfc3339_utc("2023-04-30T00:00:00Z"),
            Some(1_682_812_800)
        );
        // Feb 28 in a non-leap year, valid.
        assert_eq!(
            parse_rfc3339_utc("2023-02-28T00:00:00Z"),
            Some(1_677_542_400)
        );
    }

    #[test]
    fn leap_year_rule_handles_century_boundaries() {
        // 2000 is a leap year (divisible by 400) → Feb 29 valid.
        assert!(is_leap_year(2000));
        assert_eq!(parse_rfc3339_utc("2000-02-29T00:00:00Z"), Some(951_782_400));
        // 1900 is NOT a leap year (century, not divisible by 400) → Feb 29 rejected.
        assert!(!is_leap_year(1900));
        assert_eq!(parse_rfc3339_utc("1900-02-29T00:00:00Z"), None);
        // 2100 is likewise not a leap year.
        assert!(!is_leap_year(2100));
        assert_eq!(parse_rfc3339_utc("2100-02-29T00:00:00Z"), None);
        // 2024 is an ordinary (÷4) leap year.
        assert!(is_leap_year(2024));
    }

    #[test]
    fn civil_to_unix_handles_pre_epoch_and_leap_years() {
        // One day before the epoch (exercises the negative-year / month<=2 branch).
        assert_eq!(civil_to_unix(1969, 12, 31, 0, 0, 0), -86_400);
        // A leap day (month <= 2 branch).
        assert_eq!(civil_to_unix(2020, 2, 29, 0, 0, 0), 1_582_934_400);
    }
}
