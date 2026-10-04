//! h1v2: a second blind held-out set of everyday integer, byte-slice and
//! small-struct idioms. See `idioms.md` for the idiom list.
#![forbid(unsafe_code)]

/// Parses an ASCII decimal string into a `u32`.
///
/// Returns `None` for empty input, any non-digit byte, or a value that does
/// not fit in a `u32`.
pub fn parse_u32(s: &[u8]) -> Option<u32> {
    if s.is_empty() {
        return None;
    }
    let mut value: u32 = 0;
    for &b in s {
        if !b.is_ascii_digit() {
            return None;
        }
        let digit = (b - b'0') as u32;
        value = value.checked_mul(10)?.checked_add(digit)?;
    }
    Some(value)
}

/// Encodes bytes as lowercase hexadecimal, two characters per byte.
pub fn hex_encode_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Decodes a hexadecimal string (either case) into bytes.
///
/// Returns `None` if the length is odd or any character is not a hex digit.
pub fn hex_decode(s: &[u8]) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.chunks(2) {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

/// Computes the Adler-32 checksum of `data`.
pub fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + byte as u32) % MOD;
        b = (b + a) % MOD;
    }
    (b << 16) | a
}

/// Computes the Fletcher-16 checksum of `data`.
pub fn fletcher16(data: &[u8]) -> u16 {
    let mut sum1: u16 = 0;
    let mut sum2: u16 = 0;
    for &byte in data {
        sum1 = (sum1 + byte as u16) % 255;
        sum2 = (sum2 + sum1) % 255;
    }
    (sum2 << 8) | sum1
}

/// Returns true if `digits` is a non-empty ASCII digit string that passes the
/// Luhn check (as used for card numbers).
pub fn luhn_valid(digits: &[u8]) -> bool {
    if digits.is_empty() {
        return false;
    }
    let mut sum: u32 = 0;
    let mut double = false;
    for &c in digits.iter().rev() {
        if !c.is_ascii_digit() {
            return false;
        }
        let mut d = (c - b'0') as u32;
        if double {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        double = !double;
    }
    sum % 10 == 0
}

/// A point on the integer grid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Point {
    pub x: i32,
    pub y: i32,
}

/// Returns the Manhattan (taxicab) distance between two points.
pub fn manhattan(a: Point, b: Point) -> u32 {
    a.x.abs_diff(b.x) + a.y.abs_diff(b.y)
}

/// An axis-aligned rectangle covering `[x0, x1) x [y0, y1)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rect {
    pub x0: i32,
    pub y0: i32,
    pub x1: i32,
    pub y1: i32,
}

/// Returns the area of the overlap of two rectangles, or 0 if they are
/// disjoint or only touch along an edge.
pub fn rect_intersection_area(a: Rect, b: Rect) -> u64 {
    let left = a.x0.max(b.x0);
    let right = a.x1.min(b.x1);
    let bottom = a.y0.max(b.y0);
    let top = a.y1.min(b.y1);
    if left >= right || bottom >= top {
        return 0;
    }
    (right - left) as u64 * (top - bottom) as u64
}

/// Returns twice the signed area of a simple polygon given its vertices in
/// order (shoelace formula). Counter-clockwise polygons give a positive value.
/// Fewer than three vertices give 0.
pub fn polygon_twice_area(points: &[Point]) -> i64 {
    let n = points.len();
    if n < 3 {
        return 0;
    }
    let mut sum: i64 = 0;
    for i in 0..n {
        let p = points[i];
        let q = points[(i + 1) % n];
        sum += p.x as i64 * q.y as i64 - q.x as i64 * p.y as i64;
    }
    sum
}

/// Returns true if `year` is a leap year in the proleptic Gregorian calendar.
pub fn is_leap_year(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Returns the number of days in `month` (1 to 12) of `year`.
///
/// Panics if `month` is outside 1..=12.
pub fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => panic!("invalid month {month}"),
    }
}

/// Returns the day of the week for a Gregorian date, with 0 = Sunday through
/// 6 = Saturday (Sakamoto's method). `month` is 1 to 12; `year` must be at
/// least 1.
pub fn day_of_week(year: u32, month: u32, day: u32) -> u32 {
    const OFFSETS: [u32; 12] = [0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4];
    let y = if month < 3 { year - 1 } else { year };
    (y + y / 4 - y / 100 + y / 400 + OFFSETS[(month - 1) as usize] + day) % 7
}

/// Returns the 1-based ordinal day of the year for a Gregorian date.
pub fn day_of_year(year: u32, month: u32, day: u32) -> u32 {
    let mut total = day;
    let mut m = 1;
    while m < month {
        total += days_in_month(year, m);
        m += 1;
    }
    total
}

/// Splits a duration in seconds into (hours, minutes, seconds).
pub fn seconds_to_hms(total: u64) -> (u64, u8, u8) {
    let hours = total / 3600;
    let minutes = (total % 3600) / 60;
    let seconds = total % 60;
    (hours, minutes as u8, seconds as u8)
}

/// Counts unordered pairs of half-open intervals `[start, end)` that overlap.
/// Intervals that only touch at an endpoint do not overlap.
pub fn count_overlapping_pairs(intervals: &[(u32, u32)]) -> usize {
    let mut count = 0;
    for i in 0..intervals.len() {
        for j in (i + 1)..intervals.len() {
            let (s1, e1) = intervals[i];
            let (s2, e2) = intervals[j];
            if s1 < e2 && s2 < e1 {
                count += 1;
            }
        }
    }
    count
}

/// Counts bytes into 16 buckets keyed by their high nibble.
pub fn high_nibble_histogram(data: &[u8]) -> [u32; 16] {
    let mut buckets = [0u32; 16];
    for &b in data {
        buckets[(b >> 4) as usize] += 1;
    }
    buckets
}

/// Returns the index of the first maximum element, or `None` if empty.
pub fn argmax(values: &[i32]) -> Option<usize> {
    if values.is_empty() {
        return None;
    }
    let mut best = 0;
    for i in 1..values.len() {
        if values[i] > values[best] {
            best = i;
        }
    }
    Some(best)
}

/// Returns `(min, max)` of the slice in a single pass, or `None` if empty.
pub fn min_max(values: &[u16]) -> Option<(u16, u16)> {
    let (&first, rest) = values.split_first()?;
    let mut lo = first;
    let mut hi = first;
    for &v in rest {
        if v < lo {
            lo = v;
        }
        if v > hi {
            hi = v;
        }
    }
    Some((lo, hi))
}

/// Returns the prefix sums of `values`: element `i` of the result is the sum
/// of `values[..i]`, so the result has `values.len() + 1` entries.
pub fn prefix_sums(values: &[u32]) -> Vec<u64> {
    let mut out = Vec::with_capacity(values.len() + 1);
    let mut running: u64 = 0;
    out.push(running);
    for &v in values {
        running += v as u64;
        out.push(running);
    }
    out
}

/// Returns the sum of `values[lo..hi]` using a table built by `prefix_sums`.
///
/// Panics if `hi` is out of range for the table or `lo > hi`.
pub fn range_sum(prefix: &[u64], lo: usize, hi: usize) -> u64 {
    assert!(lo <= hi, "empty range must have lo <= hi");
    prefix[hi] - prefix[lo]
}

/// Returns true if two distinct positions of the ascending slice sum to
/// `target` (two-pointer scan).
pub fn has_pair_with_sum(sorted: &[i32], target: i64) -> bool {
    if sorted.len() < 2 {
        return false;
    }
    let mut i = 0;
    let mut j = sorted.len() - 1;
    while i < j {
        let sum = sorted[i] as i64 + sorted[j] as i64;
        if sum == target {
            return true;
        } else if sum < target {
            i += 1;
        } else {
            j -= 1;
        }
    }
    false
}

/// Removes consecutive duplicates from an ascending slice in place, moving the
/// unique values to the front. Returns the number of unique values.
pub fn dedup_sorted(values: &mut [u32]) -> usize {
    if values.is_empty() {
        return 0;
    }
    let mut write = 1;
    for read in 1..values.len() {
        if values[read] != values[write - 1] {
            values[write] = values[read];
            write += 1;
        }
    }
    write
}

/// Returns the first index in the ascending slice whose value is not less than
/// `key`, or `sorted.len()` if every value is less.
pub fn lower_bound(sorted: &[u32], key: u32) -> usize {
    let mut lo = 0;
    let mut hi = sorted.len();
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if sorted[mid] < key {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo
}

/// An 8-bit-per-channel colour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rgb {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

/// Packs a colour into RGB565 (5 bits red, 6 green, 5 blue), truncating the
/// low bits of each channel.
pub fn rgb565_pack(c: Rgb) -> u16 {
    ((c.r as u16 >> 3) << 11) | ((c.g as u16 >> 2) << 5) | (c.b as u16 >> 3)
}

/// Unpacks RGB565 into 8-bit channels, replicating the high bits into the low
/// bits so full-scale fields map to 255.
pub fn rgb565_unpack(v: u16) -> Rgb {
    let r5 = ((v >> 11) & 0x1f) as u8;
    let g6 = ((v >> 5) & 0x3f) as u8;
    let b5 = (v & 0x1f) as u8;
    Rgb {
        r: (r5 << 3) | (r5 >> 2),
        g: (g6 << 2) | (g6 >> 4),
        b: (b5 << 3) | (b5 >> 2),
    }
}

/// Returns the greatest common divisor (Euclid's algorithm). `gcd(0, 0) = 0`.
pub fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = a % b;
        a = b;
        b = t;
    }
    a
}

/// Returns the least common multiple; 0 if either argument is 0.
///
/// Panics on overflow in debug builds.
pub fn lcm(a: u64, b: u64) -> u64 {
    if a == 0 || b == 0 {
        return 0;
    }
    a / gcd(a, b) * b
}

/// Returns the largest sum of a non-empty contiguous subarray (Kadane), or
/// `None` if the slice is empty.
pub fn max_subarray_sum(values: &[i32]) -> Option<i64> {
    let (&first, rest) = values.split_first()?;
    let mut best = first as i64;
    let mut current = first as i64;
    for &v in rest {
        let v = v as i64;
        current = if current > 0 { current + v } else { v };
        if current > best {
            best = current;
        }
    }
    Some(best)
}

/// Returns true if every `(`, `[` and `{` in `s` is closed by the matching
/// bracket in the right order. Other bytes are ignored.
pub fn brackets_balanced(s: &[u8]) -> bool {
    let mut stack: Vec<u8> = Vec::new();
    for &c in s {
        match c {
            b'(' | b'[' | b'{' => stack.push(c),
            b')' | b']' | b'}' => {
                let open = match c {
                    b')' => b'(',
                    b']' => b'[',
                    _ => b'{',
                };
                if stack.pop() != Some(open) {
                    return false;
                }
            }
            _ => {}
        }
    }
    stack.is_empty()
}

/// Counts pairs `i < j` with `values[i] > values[j]` (naive quadratic scan).
pub fn count_inversions(values: &[i32]) -> u64 {
    let mut count = 0;
    for i in 0..values.len() {
        for j in (i + 1)..values.len() {
            if values[i] > values[j] {
                count += 1;
            }
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(x: i32, y: i32) -> Point {
        Point { x, y }
    }

    #[test]
    fn parse_u32_cases() {
        assert_eq!(parse_u32(b"0"), Some(0));
        assert_eq!(parse_u32(b"007"), Some(7));
        assert_eq!(parse_u32(b"4294967295"), Some(u32::MAX));
        assert_eq!(parse_u32(b"4294967296"), None);
        assert_eq!(parse_u32(b""), None);
        assert_eq!(parse_u32(b"12a"), None);
        assert_eq!(parse_u32(b"-1"), None);
    }

    #[test]
    fn hex_round_trip() {
        assert_eq!(hex_encode_lower(&[]), "");
        assert_eq!(hex_encode_lower(&[0x00, 0xab, 0x0f, 0xff]), "00ab0fff");
        assert_eq!(hex_decode(b"00AB0fFf"), Some(vec![0x00, 0xab, 0x0f, 0xff]));
        assert_eq!(hex_decode(b""), Some(vec![]));
        assert_eq!(hex_decode(b"abc"), None);
        assert_eq!(hex_decode(b"0g"), None);
    }

    #[test]
    fn adler32_cases() {
        assert_eq!(adler32(b""), 1);
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
        // "a": a = 1 + 97 = 98, b = 98.
        assert_eq!(adler32(b"a"), (98 << 16) | 98);
    }

    #[test]
    fn fletcher16_cases() {
        assert_eq!(fletcher16(b""), 0);
        assert_eq!(fletcher16(b"abcde"), 0xC8F0);
        assert_eq!(fletcher16(b"abcdef"), 0x2057);
        assert_eq!(fletcher16(b"abcdefgh"), 0x0627);
    }

    #[test]
    fn luhn_cases() {
        assert!(luhn_valid(b"79927398713"));
        assert!(!luhn_valid(b"79927398710"));
        assert!(luhn_valid(b"0"));
        assert!(luhn_valid(b"18"));
        assert!(!luhn_valid(b""));
        assert!(!luhn_valid(b"7992 7398 713"));
    }

    #[test]
    fn manhattan_cases() {
        assert_eq!(manhattan(p(0, 0), p(3, 4)), 7);
        assert_eq!(manhattan(p(-2, 5), p(3, -1)), 11);
        assert_eq!(manhattan(p(i32::MIN, 0), p(i32::MAX, 0)), u32::MAX);
    }

    #[test]
    fn rect_intersection_cases() {
        let a = Rect { x0: 0, y0: 0, x1: 4, y1: 3 };
        let b = Rect { x0: 2, y0: 1, x1: 6, y1: 5 };
        assert_eq!(rect_intersection_area(a, b), 4);
        let touching = Rect { x0: 4, y0: 0, x1: 8, y1: 3 };
        assert_eq!(rect_intersection_area(a, touching), 0);
        let inside = Rect { x0: 1, y0: 1, x1: 2, y1: 2 };
        assert_eq!(rect_intersection_area(a, inside), 1);
        let far = Rect { x0: -10, y0: -10, x1: -5, y1: -5 };
        assert_eq!(rect_intersection_area(a, far), 0);
    }

    #[test]
    fn polygon_area_cases() {
        let square = [p(0, 0), p(4, 0), p(4, 3), p(0, 3)];
        assert_eq!(polygon_twice_area(&square), 24);
        let clockwise = [p(0, 0), p(0, 3), p(4, 3), p(4, 0)];
        assert_eq!(polygon_twice_area(&clockwise), -24);
        let triangle = [p(0, 0), p(5, 0), p(0, 5)];
        assert_eq!(polygon_twice_area(&triangle), 25);
        assert_eq!(polygon_twice_area(&[p(1, 1), p(2, 2)]), 0);
    }

    #[test]
    fn calendar_cases() {
        assert!(is_leap_year(2024));
        assert!(!is_leap_year(2026));
        assert!(!is_leap_year(1900));
        assert!(is_leap_year(2000));
        assert_eq!(days_in_month(2024, 2), 29);
        assert_eq!(days_in_month(2023, 2), 28);
        assert_eq!(days_in_month(2026, 9), 30);
        assert_eq!(days_in_month(2026, 12), 31);
    }

    #[test]
    #[should_panic]
    fn days_in_month_rejects_month_13() {
        days_in_month(2026, 13);
    }

    #[test]
    fn day_of_week_cases() {
        assert_eq!(day_of_week(2026, 10, 2), 5); // Friday
        assert_eq!(day_of_week(2000, 1, 1), 6); // Saturday
        assert_eq!(day_of_week(1970, 1, 1), 4); // Thursday
        assert_eq!(day_of_week(2024, 2, 29), 4); // Thursday
    }

    #[test]
    fn day_of_year_cases() {
        assert_eq!(day_of_year(2026, 1, 1), 1);
        assert_eq!(day_of_year(2023, 3, 1), 60);
        assert_eq!(day_of_year(2024, 3, 1), 61);
        assert_eq!(day_of_year(2024, 12, 31), 366);
    }

    #[test]
    fn hms_cases() {
        assert_eq!(seconds_to_hms(0), (0, 0, 0));
        assert_eq!(seconds_to_hms(59), (0, 0, 59));
        assert_eq!(seconds_to_hms(3661), (1, 1, 1));
        assert_eq!(seconds_to_hms(86399), (23, 59, 59));
        assert_eq!(seconds_to_hms(90000), (25, 0, 0));
    }

    #[test]
    fn overlapping_pairs_cases() {
        assert_eq!(count_overlapping_pairs(&[]), 0);
        assert_eq!(count_overlapping_pairs(&[(0, 10), (10, 20)]), 0);
        assert_eq!(count_overlapping_pairs(&[(0, 10), (5, 15), (12, 20)]), 2);
        assert_eq!(count_overlapping_pairs(&[(0, 100), (1, 2), (3, 4), (5, 6)]), 3);
    }

    #[test]
    fn histogram_cases() {
        let h = high_nibble_histogram(&[0x00, 0x0f, 0x10, 0xff, 0xf0, 0x7a]);
        let mut expected = [0u32; 16];
        expected[0] = 2;
        expected[1] = 1;
        expected[7] = 1;
        expected[15] = 2;
        assert_eq!(h, expected);
        assert_eq!(high_nibble_histogram(&[]), [0; 16]);
    }

    #[test]
    fn argmax_cases() {
        assert_eq!(argmax(&[]), None);
        assert_eq!(argmax(&[-5]), Some(0));
        assert_eq!(argmax(&[1, 9, 3, 9, 2]), Some(1));
        assert_eq!(argmax(&[-3, -1, -2]), Some(1));
    }

    #[test]
    fn min_max_cases() {
        assert_eq!(min_max(&[]), None);
        assert_eq!(min_max(&[7]), Some((7, 7)));
        assert_eq!(min_max(&[5, 2, 9, 2, 65535, 0]), Some((0, 65535)));
    }

    #[test]
    fn prefix_and_range_sum() {
        let pre = prefix_sums(&[3, 1, 4, 1, 5]);
        assert_eq!(pre, vec![0, 3, 4, 8, 9, 14]);
        assert_eq!(range_sum(&pre, 0, 5), 14);
        assert_eq!(range_sum(&pre, 1, 3), 5);
        assert_eq!(range_sum(&pre, 2, 2), 0);
        let big = prefix_sums(&[u32::MAX, u32::MAX]);
        assert_eq!(big[2], 2 * u32::MAX as u64);
    }

    #[test]
    #[should_panic]
    fn range_sum_out_of_bounds_panics() {
        let pre = prefix_sums(&[1, 2]);
        range_sum(&pre, 0, 3);
    }

    #[test]
    fn pair_sum_cases() {
        assert!(has_pair_with_sum(&[1, 2, 4, 7, 11], 15));
        assert!(!has_pair_with_sum(&[1, 2, 4, 7, 11], 10));
        assert!(!has_pair_with_sum(&[5], 10));
        assert!(has_pair_with_sum(&[5, 5], 10));
        assert!(has_pair_with_sum(&[i32::MIN, 0, i32::MAX], -1));
    }

    #[test]
    fn dedup_cases() {
        let mut v = [1, 1, 2, 3, 3, 3, 7];
        let n = dedup_sorted(&mut v);
        assert_eq!(n, 4);
        assert_eq!(&v[..n], &[1, 2, 3, 7]);
        let mut empty: [u32; 0] = [];
        assert_eq!(dedup_sorted(&mut empty), 0);
        let mut same = [4, 4, 4];
        assert_eq!(dedup_sorted(&mut same), 1);
    }

    #[test]
    fn lower_bound_cases() {
        let v = [1, 3, 3, 5, 8];
        assert_eq!(lower_bound(&v, 0), 0);
        assert_eq!(lower_bound(&v, 3), 1);
        assert_eq!(lower_bound(&v, 4), 3);
        assert_eq!(lower_bound(&v, 8), 4);
        assert_eq!(lower_bound(&v, 9), 5);
        assert_eq!(lower_bound(&[], 1), 0);
    }

    #[test]
    fn rgb565_cases() {
        assert_eq!(rgb565_pack(Rgb { r: 255, g: 255, b: 255 }), 0xFFFF);
        assert_eq!(rgb565_pack(Rgb { r: 255, g: 0, b: 0 }), 0xF800);
        assert_eq!(rgb565_pack(Rgb { r: 0, g: 255, b: 0 }), 0x07E0);
        assert_eq!(rgb565_pack(Rgb { r: 0, g: 0, b: 255 }), 0x001F);
        assert_eq!(rgb565_unpack(0xFFFF), Rgb { r: 255, g: 255, b: 255 });
        assert_eq!(rgb565_unpack(0x0000), Rgb { r: 0, g: 0, b: 0 });
        // r5 = 16 -> 128 | 4 = 132; g6 = 32 -> 128 | 2 = 130; b5 = 16 -> 132.
        assert_eq!(rgb565_unpack(0x8410), Rgb { r: 132, g: 130, b: 132 });
    }

    #[test]
    fn gcd_lcm_cases() {
        assert_eq!(gcd(0, 0), 0);
        assert_eq!(gcd(0, 9), 9);
        assert_eq!(gcd(48, 18), 6);
        assert_eq!(gcd(17, 5), 1);
        assert_eq!(lcm(4, 6), 12);
        assert_eq!(lcm(0, 6), 0);
        assert_eq!(lcm(21, 6), 42);
    }

    #[test]
    fn max_subarray_cases() {
        assert_eq!(max_subarray_sum(&[]), None);
        assert_eq!(max_subarray_sum(&[-2, 1, -3, 4, -1, 2, 1, -5, 4]), Some(6));
        assert_eq!(max_subarray_sum(&[-3, -1, -2]), Some(-1));
        assert_eq!(
            max_subarray_sum(&[i32::MAX, i32::MAX]),
            Some(2 * i32::MAX as i64)
        );
    }

    #[test]
    fn brackets_cases() {
        assert!(brackets_balanced(b""));
        assert!(brackets_balanced(b"fn f() { a[0] }"));
        assert!(!brackets_balanced(b"(]"));
        assert!(!brackets_balanced(b"(("));
        assert!(!brackets_balanced(b"())"));
        assert!(brackets_balanced(b"{[()()]}"));
    }

    #[test]
    fn inversion_cases() {
        assert_eq!(count_inversions(&[]), 0);
        assert_eq!(count_inversions(&[1, 2, 3]), 0);
        assert_eq!(count_inversions(&[3, 2, 1]), 3);
        assert_eq!(count_inversions(&[2, 4, 1, 3, 5]), 3);
    }
}
