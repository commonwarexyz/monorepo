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
