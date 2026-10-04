//! One out-of-line entry per held-out function, the same text in every
//! subject: the bench loop calls these (one call per invocation in every
//! subject), and `samecode.py` compares them across subjects, following
//! calls into the subject's own crate. `checked_sum`'s error is mapped to
//! its index so that every subject returns the same type.

use crate::{h1, h2};

#[inline(never)]
pub fn decimal_digits(n: u64) -> u32 {
    h1::decimal_digits(n)
}
#[inline(never)]
pub fn base32_encoded_len(n: usize, padded: bool) -> usize {
    h1::base32_encoded_len(n, padded)
}
#[inline(never)]
pub fn base64_encoded_len(n: usize, padded: bool) -> usize {
    h1::base64_encoded_len(n, padded)
}
#[inline(never)]
pub fn reverse_bits(x: u32) -> u32 {
    h1::reverse_bits(x)
}
#[inline(never)]
pub fn gray_encode(n: u32) -> u32 {
    h1::gray_encode(n)
}
#[inline(never)]
pub fn gray_decode(g: u32) -> u32 {
    h1::gray_decode(g)
}
#[inline(never)]
pub fn next_power_of_two(n: u32) -> Option<u32> {
    h1::next_power_of_two(n)
}
#[inline(never)]
pub fn isqrt(n: u64) -> u64 {
    h1::isqrt(n)
}
#[inline(never)]
pub fn fenwick_prefix_sum(tree: &[u64], count: u32) -> u64 {
    h1::fenwick_prefix_sum(tree, count)
}
#[inline(never)]
pub fn buddy_order(size: usize, min_block: usize) -> u32 {
    h1::buddy_order(size, min_block)
}
#[inline(never)]
pub fn binomial_meld_carries(a: u64, b: u64) -> u32 {
    h1::binomial_meld_carries(a, b)
}
#[inline(never)]
pub fn hamming_distance(a: &[u8], b: &[u8]) -> Option<u32> {
    h1::hamming_distance(a, b)
}
#[inline(never)]
pub fn run_count(data: &[u8]) -> usize {
    h1::run_count(data)
}
#[inline(never)]
pub fn first_newline(data: &[u8]) -> Option<usize> {
    h1::first_newline(data)
}
#[inline(never)]
pub fn first_printable(data: &[u8]) -> Option<usize> {
    h1::first_printable(data)
}
#[inline(never)]
pub fn checked_sum(values: &[u32]) -> Result<u32, usize> {
    h1::checked_sum(values).map_err(|o| o.at)
}
#[inline(never)]
pub fn ring_index(head: usize, offset: usize, capacity: usize) -> usize {
    h1::ring_index(head, offset, capacity)
}
#[inline(never)]
pub fn align_up(x: u64, align: u64) -> u64 {
    h1::align_up(x, align)
}
#[inline(never)]
pub fn ceil_div(a: u32, b: u32) -> u32 {
    h1::ceil_div(a, b)
}
#[inline(never)]
pub fn crc8(data: &[u8]) -> u8 {
    h1::crc8(data)
}
#[inline(never)]
pub fn parity(x: u32) -> bool {
    h1::parity(x)
}
#[inline(never)]
pub fn trailing_ones(x: u32) -> u32 {
    h1::trailing_ones(x)
}
#[inline(never)]
pub fn byte_swap(x: u32) -> u32 {
    h1::byte_swap(x)
}
#[inline(never)]
pub fn nibble_popcount(n: u8) -> u8 {
    h1::nibble_popcount(n)
}
#[inline(never)]
pub fn matrix_sum_4x8(m: &[[u8; 8]; 4]) -> u32 {
    h1::matrix_sum_4x8(m)
}
#[inline(never)]
pub fn seed16_rounds20(key: &[u8; 16]) -> u32 {
    h1::seed16_rounds20(key)
}
#[inline(never)]
pub fn count_words(text: &[u8]) -> usize {
    h1::count_words(text)
}
#[inline(never)]
pub fn scale_sample(sample: i16, gain: i32, offset: i32) -> i16 {
    h1::scale_sample(sample, gain, offset)
}
#[inline(never)]
pub fn remaining_budget(budget: u32, costs: &[u32], cap: u32) -> u32 {
    h1::remaining_budget(budget, costs, cap)
}
#[inline(never)]
pub fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    h1::read_u32_le(data, offset)
}
#[inline(never)]
pub fn mix64(word: u64) -> u64 {
    h2::mix64(word)
}

// ---- held-out v2's H1 (`h1v2`): `v2_<fn>`, the same text in every subject.
// The subjects' own struct types (`Point`, `Rect`, `Rgb`) are built from and
// mapped to tuples here, so every subject takes and returns the same types;
// `dedup_sorted`, which sorts in place, works on a copy in a fixed buffer.

use crate::h1v2;

#[inline(never)]
pub fn v2_parse_u32(s: &[u8]) -> Option<u32> {
    h1v2::parse_u32(s)
}
#[inline(never)]
pub fn v2_hex_encode_lower(bytes: &[u8]) -> String {
    h1v2::hex_encode_lower(bytes)
}
#[inline(never)]
pub fn v2_hex_decode(s: &[u8]) -> Option<Vec<u8>> {
    h1v2::hex_decode(s)
}
#[inline(never)]
pub fn v2_adler32(data: &[u8]) -> u32 {
    h1v2::adler32(data)
}
#[inline(never)]
pub fn v2_fletcher16(data: &[u8]) -> u16 {
    h1v2::fletcher16(data)
}
#[inline(never)]
pub fn v2_luhn_valid(digits: &[u8]) -> bool {
    h1v2::luhn_valid(digits)
}
#[inline(never)]
pub fn v2_manhattan(a: (i32, i32), b: (i32, i32)) -> u32 {
    h1v2::manhattan(h1v2::Point { x: a.0, y: a.1 }, h1v2::Point { x: b.0, y: b.1 })
}
#[inline(never)]
pub fn v2_rect_intersection_area(a: (i32, i32, i32, i32), b: (i32, i32, i32, i32)) -> u64 {
    h1v2::rect_intersection_area(h1v2::Rect { x0: a.0, y0: a.1, x1: a.2, y1: a.3 }, h1v2::Rect { x0: b.0, y0: b.1, x1: b.2, y1: b.3 })
}
#[inline(never)]
pub fn v2_polygon_twice_area(points: &[(i32, i32)]) -> i64 {
    let mut buf = [h1v2::Point { x: 0, y: 0 }; 32];
    let n = points.len().min(32);
    for (d, s) in buf.iter_mut().zip(points) {
        *d = h1v2::Point { x: s.0, y: s.1 };
    }
    h1v2::polygon_twice_area(&buf[..n])
}
#[inline(never)]
pub fn v2_is_leap_year(year: u32) -> bool {
    h1v2::is_leap_year(year)
}
#[inline(never)]
pub fn v2_days_in_month(year: u32, month: u32) -> u32 {
    h1v2::days_in_month(year, month)
}
#[inline(never)]
pub fn v2_day_of_week(year: u32, month: u32, day: u32) -> u32 {
    h1v2::day_of_week(year, month, day)
}
#[inline(never)]
pub fn v2_day_of_year(year: u32, month: u32, day: u32) -> u32 {
    h1v2::day_of_year(year, month, day)
}
#[inline(never)]
pub fn v2_seconds_to_hms(total: u64) -> (u64, u8, u8) {
    h1v2::seconds_to_hms(total)
}
#[inline(never)]
pub fn v2_count_overlapping_pairs(intervals: &[(u32, u32)]) -> usize {
    h1v2::count_overlapping_pairs(intervals)
}
#[inline(never)]
pub fn v2_high_nibble_histogram(data: &[u8]) -> [u32; 16] {
    h1v2::high_nibble_histogram(data)
}
#[inline(never)]
pub fn v2_argmax(values: &[i32]) -> Option<usize> {
    h1v2::argmax(values)
}
#[inline(never)]
pub fn v2_min_max(values: &[u16]) -> Option<(u16, u16)> {
    h1v2::min_max(values)
}
#[inline(never)]
pub fn v2_prefix_sums(values: &[u32]) -> Vec<u64> {
    h1v2::prefix_sums(values)
}
#[inline(never)]
pub fn v2_range_sum(prefix: &[u64], lo: usize, hi: usize) -> u64 {
    h1v2::range_sum(prefix, lo, hi)
}
#[inline(never)]
pub fn v2_has_pair_with_sum(sorted: &[i32], target: i64) -> bool {
    h1v2::has_pair_with_sum(sorted, target)
}
#[inline(never)]
pub fn v2_dedup_sorted(values: &[u32]) -> (usize, [u32; 32]) {
    let mut buf = [0u32; 32];
    let n = values.len().min(32);
    buf[..n].copy_from_slice(&values[..n]);
    let k = h1v2::dedup_sorted(&mut buf[..n]);
    (k, buf)
}
#[inline(never)]
pub fn v2_lower_bound(sorted: &[u32], key: u32) -> usize {
    h1v2::lower_bound(sorted, key)
}
#[inline(never)]
pub fn v2_rgb565_pack(c: (u8, u8, u8)) -> u16 {
    h1v2::rgb565_pack(h1v2::Rgb { r: c.0, g: c.1, b: c.2 })
}
#[inline(never)]
pub fn v2_rgb565_unpack(v: u16) -> (u8, u8, u8) {
    let c = h1v2::rgb565_unpack(v);
    (c.r, c.g, c.b)
}
#[inline(never)]
pub fn v2_gcd(a: u64, b: u64) -> u64 {
    h1v2::gcd(a, b)
}
#[inline(never)]
pub fn v2_lcm(a: u64, b: u64) -> u64 {
    h1v2::lcm(a, b)
}
#[inline(never)]
pub fn v2_max_subarray_sum(values: &[i32]) -> Option<i64> {
    h1v2::max_subarray_sum(values)
}
#[inline(never)]
pub fn v2_brackets_balanced(s: &[u8]) -> bool {
    h1v2::brackets_balanced(s)
}
#[inline(never)]
pub fn v2_count_inversions(values: &[i32]) -> u64 {
    h1v2::count_inversions(values)
}
