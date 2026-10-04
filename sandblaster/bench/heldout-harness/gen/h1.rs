//! Held-out benchmark set h1.
//!
//! Small, ordinary integer and byte-slice helpers of the kind found in
//! everyday systems code. Written plainly, without regard to any optimizer.

#![forbid(unsafe_code)]

/// Number of decimal digits needed to print `n` (`0` has one digit).
pub fn decimal_digits(mut n: u64) -> u32 {
    let mut digits = 1;
    while n >= 10 {
        n /= 10;
        digits += 1;
    }
    digits
}

/// Length of the base-32 (RFC 4648) encoding of `n` input bytes.
///
/// With `padded`, output is rounded up to a multiple of 8 characters.
pub fn base32_encoded_len(n: usize, padded: bool) -> usize {
    if padded {
        n.div_ceil(5) * 8
    } else {
        (n * 8).div_ceil(5)
    }
}

/// Length of the base-64 (RFC 4648) encoding of `n` input bytes.
///
/// With `padded`, output is rounded up to a multiple of 4 characters.
pub fn base64_encoded_len(n: usize, padded: bool) -> usize {
    if padded {
        n.div_ceil(3) * 4
    } else {
        let full = (n / 3) * 4;
        match n % 3 {
            0 => full,
            1 => full + 2,
            _ => full + 3,
        }
    }
}

/// Reverses the order of the bits in `x`, one bit at a time.
pub fn reverse_bits(mut x: u32) -> u32 {
    let mut out = 0u32;
    for _ in 0..32 {
        out = (out << 1) | (x & 1);
        x >>= 1;
    }
    out
}

/// Converts a binary number to its reflected Gray code.
pub fn gray_encode(n: u32) -> u32 {
    n ^ (n >> 1)
}

/// Converts a reflected Gray code back to the binary number.
pub fn gray_decode(mut g: u32) -> u32 {
    let mut n = 0;
    while g != 0 {
        n ^= g;
        g >>= 1;
    }
    n
}

/// Smallest power of two that is `>= n`, or `None` if it does not fit in a
/// `u32`. `0` rounds up to `1`.
pub fn next_power_of_two(n: u32) -> Option<u32> {
    __sandblaster_opt_next_power_of_two(n)
}

/// Integer square root (floor) of `n`, found by bisection.
pub fn isqrt(n: u64) -> u64 {
    // Invariant: lo * lo <= n < (hi + 1) * (hi + 1).
    let mut lo: u64 = 0;
    let mut hi: u64 = n.min(u32::MAX as u64);
    while lo < hi {
        let mid = lo + (hi - lo + 1) / 2;
        if mid * mid <= n {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    lo
}

/// Prefix sum of the first `count` elements stored in a 1-based Fenwick
/// (binary indexed) tree. `tree[0]` is unused.
pub fn fenwick_prefix_sum(tree: &[u64], count: u32) -> u64 {
    let mut sum = 0;
    let mut i = count;
    while i > 0 {
        sum += tree[i as usize];
        i &= i - 1;
    }
    sum
}

/// Buddy-allocator order for a request of `size` bytes: the smallest `k`
/// such that `min_block << k >= size`. `min_block` must be nonzero.
pub fn buddy_order(size: usize, min_block: usize) -> u32 {
    let mut order = 0;
    let mut block = min_block;
    while block < size {
        block <<= 1;
        order += 1;
    }
    order
}

/// Number of carries (tree links) performed when melding two binomial heaps
/// holding `a` and `b` elements, i.e. carries in the binary sum `a + b`.
pub fn binomial_meld_carries(mut a: u64, mut b: u64) -> u32 {
    let mut carry = 0u64;
    let mut carries = 0;
    while a != 0 || b != 0 || carry != 0 {
        let s = (a & 1) + (b & 1) + carry;
        carry = s >> 1;
        if carry != 0 {
            carries += 1;
        }
        a >>= 1;
        b >>= 1;
    }
    carries
}

/// Number of differing bits between two equal-length byte slices, or `None`
/// if the lengths differ.
pub fn hamming_distance(a: &[u8], b: &[u8]) -> Option<u32> {
    if a.len() != b.len() {
        return None;
    }
    Some(a.iter().zip(b).map(|(x, y)| (x ^ y).count_ones()).sum())
}

/// Number of maximal runs of equal bytes in `data`.
pub fn run_count(data: &[u8]) -> usize {
    let mut runs = 0;
    let mut prev: Option<u8> = None;
    for &b in data {
        if prev != Some(b) {
            runs += 1;
            prev = Some(b);
        }
    }
    runs
}

/// Index of the first `\n` in `data`.
pub fn first_newline(data: &[u8]) -> Option<usize> {
    data.iter().position(|&b| b == b'\n')
}

/// Index of the first byte that is not an ASCII control character below
/// space (i.e. the first byte `>= 0x20`).
pub fn first_printable(data: &[u8]) -> Option<usize> {
    for (i, &b) in data.iter().enumerate() {
        if b >= 0x20 {
            return Some(i);
        }
    }
    None
}

/// Error returned by [`checked_sum`] when the total exceeds `u32::MAX`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Overflow {
    /// Index of the element whose addition overflowed.
    pub at: usize,
}

/// Sum of `values`, or an error naming the element that overflowed.
pub fn checked_sum(values: &[u32]) -> Result<u32, Overflow> {
    let mut total: u32 = 0;
    for (i, &v) in values.iter().enumerate() {
        total = total.checked_add(v).ok_or(Overflow { at: i })?;
    }
    Ok(total)
}

/// Physical slot for logical position `offset` past `head` in a ring buffer
/// of `capacity` slots. `head` must be `< capacity`.
pub fn ring_index(head: usize, offset: usize, capacity: usize) -> usize {
    let idx = head + offset % capacity;
    if idx >= capacity {
        idx - capacity
    } else {
        idx
    }
}

/// Rounds `x` up to a multiple of `align`, which must be a power of two.
pub fn align_up(x: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two());
    (x + align - 1) & !(align - 1)
}

/// Ceiling of `a / b` for nonzero `b`.
pub fn ceil_div(a: u32, b: u32) -> u32 {
    let q = a / b;
    if a % b != 0 {
        q + 1
    } else {
        q
    }
}

/// CRC-8 (polynomial 0x07, init 0, no reflection, no final xor), computed
/// bit by bit.
pub fn crc8(data: &[u8]) -> u8 {
    let mut crc: u8 = 0;
    for &byte in data {
        crc ^= byte;
        for _ in 0..8 {
            if crc & 0x80 != 0 {
                crc = (crc << 1) ^ 0x07;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// `true` if `x` has an odd number of set bits.
pub fn parity(mut x: u32) -> bool {
    let mut odd = false;
    while x != 0 {
        odd = !odd;
        x &= x - 1;
    }
    odd
}

/// Number of consecutive one bits starting at the least significant bit.
pub fn trailing_ones(mut x: u32) -> u32 {
    let mut n = 0;
    while x & 1 == 1 {
        n += 1;
        x >>= 1;
    }
    n
}

/// Reverses the byte order of `x` using a loop over its bytes.
pub fn byte_swap(x: u32) -> u32 {
    let mut out = 0u32;
    for i in 0..4 {
        let byte = (x >> (8 * i)) & 0xff;
        out |= byte << (8 * (3 - i));
    }
    out
}

/// Number of set bits in a nibble, via a small lookup table built on the
/// spot. Only the low four bits of `n` are used.
pub fn nibble_popcount(n: u8) -> u8 {
    let mut table = [0u8; 16];
    for i in 1..16 {
        table[i] = table[i >> 1] + (i as u8 & 1);
    }
    table[(n & 0x0f) as usize]
}

/// Sum of every entry of a 4 x 8 byte matrix.
pub fn matrix_sum_4x8(m: &[[u8; 8]; 4]) -> u32 {
    let mut sum = 0u32;
    for row in 0..4 {
        for col in 0..8 {
            sum += m[row][col] as u32;
        }
    }
    sum
}

/// Seeds a xorshift32 generator from 16 bytes, then runs it for 20 rounds
/// and returns the final state.
pub fn seed16_rounds20(key: &[u8; 16]) -> u32 {
    let mut state: u32 = 0x9e37_79b9;
    for i in 0..16 {
        state = state.rotate_left(5) ^ key[i] as u32;
    }
    if state == 0 {
        state = 1;
    }
    for _ in 0..20 {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
    }
    state
}

/// Number of whitespace-separated words in `text` (ASCII whitespace).
pub fn count_words(text: &[u8]) -> usize {
    #[derive(PartialEq)]
    enum State {
        Space,
        Word,
    }
    let mut state = State::Space;
    let mut words = 0;
    for &b in text {
        let is_space = matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c);
        state = match (state, is_space) {
            (State::Space, false) => {
                words += 1;
                State::Word
            }
            (_, true) => State::Space,
            (State::Word, false) => State::Word,
        };
    }
    words
}

/// Applies `gain` (in 1/256 units) and `offset` to an audio sample, then
/// clamps the result into the `i16` range.
pub fn scale_sample(sample: i16, gain: i32, offset: i32) -> i16 {
    let scaled = (sample as i32).saturating_mul(gain) >> 8;
    let shifted = scaled.saturating_add(offset);
    shifted.clamp(i16::MIN as i32, i16::MAX as i32) as i16
}

/// Budget left after paying each cost in turn, never going below zero, and
/// capped at `cap`.
pub fn remaining_budget(budget: u32, costs: &[u32], cap: u32) -> u32 {
    let mut left = budget;
    for &c in costs {
        left = left.saturating_sub(c);
    }
    left.min(cap)
}

/// Reads a little-endian `u32` at `offset`, or `None` if out of bounds.
pub fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    __sandblaster_opt_read_u32_le(data, offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decimal_digits() {
        assert_eq!(decimal_digits(0), 1);
        assert_eq!(decimal_digits(9), 1);
        assert_eq!(decimal_digits(10), 2);
        assert_eq!(decimal_digits(999), 3);
        assert_eq!(decimal_digits(1000), 4);
        assert_eq!(decimal_digits(u64::MAX), 20);
    }

    #[test]
    fn test_base32_encoded_len() {
        assert_eq!(base32_encoded_len(0, true), 0);
        assert_eq!(base32_encoded_len(1, true), 8);
        assert_eq!(base32_encoded_len(5, true), 8);
        assert_eq!(base32_encoded_len(6, true), 16);
        assert_eq!(base32_encoded_len(1, false), 2);
        assert_eq!(base32_encoded_len(2, false), 4);
        assert_eq!(base32_encoded_len(5, false), 8);
    }

    #[test]
    fn test_base64_encoded_len() {
        assert_eq!(base64_encoded_len(0, true), 0);
        assert_eq!(base64_encoded_len(1, true), 4);
        assert_eq!(base64_encoded_len(3, true), 4);
        assert_eq!(base64_encoded_len(4, true), 8);
        assert_eq!(base64_encoded_len(1, false), 2);
        assert_eq!(base64_encoded_len(2, false), 3);
        assert_eq!(base64_encoded_len(3, false), 4);
    }

    #[test]
    fn test_reverse_bits() {
        assert_eq!(reverse_bits(0), 0);
        assert_eq!(reverse_bits(1), 0x8000_0000);
        assert_eq!(reverse_bits(0x0000_00f0), 0x0f00_0000);
        assert_eq!(reverse_bits(0x1234_5678), 0x1e6a_2c48);
    }

    #[test]
    fn test_gray() {
        assert_eq!(gray_encode(0), 0);
        assert_eq!(gray_encode(1), 1);
        assert_eq!(gray_encode(2), 3);
        assert_eq!(gray_encode(3), 2);
        assert_eq!(gray_encode(4), 6);
        assert_eq!(gray_decode(6), 4);
        assert_eq!(gray_decode(2), 3);
        assert_eq!(gray_decode(gray_encode(0xdead_beef)), 0xdead_beef);
    }

    #[test]
    fn test_next_power_of_two() {
        assert_eq!(next_power_of_two(0), Some(1));
        assert_eq!(next_power_of_two(1), Some(1));
        assert_eq!(next_power_of_two(3), Some(4));
        assert_eq!(next_power_of_two(64), Some(64));
        assert_eq!(next_power_of_two(65), Some(128));
        assert_eq!(next_power_of_two(1 << 31), Some(1 << 31));
        assert_eq!(next_power_of_two((1 << 31) + 1), None);
    }

    #[test]
    fn test_isqrt() {
        assert_eq!(isqrt(0), 0);
        assert_eq!(isqrt(1), 1);
        assert_eq!(isqrt(15), 3);
        assert_eq!(isqrt(16), 4);
        assert_eq!(isqrt(1_000_000), 1000);
        assert_eq!(isqrt(u64::MAX), 4_294_967_295);
    }

    #[test]
    fn test_fenwick_prefix_sum() {
        // Built from values [1, 2, 3, 4, 5, 6, 7, 8] (1-based).
        let tree = [0, 1, 3, 3, 10, 5, 11, 7, 36];
        assert_eq!(fenwick_prefix_sum(&tree, 0), 0);
        assert_eq!(fenwick_prefix_sum(&tree, 1), 1);
        assert_eq!(fenwick_prefix_sum(&tree, 3), 6);
        assert_eq!(fenwick_prefix_sum(&tree, 5), 15);
        assert_eq!(fenwick_prefix_sum(&tree, 7), 28);
        assert_eq!(fenwick_prefix_sum(&tree, 8), 36);
    }

    #[test]
    fn test_buddy_order() {
        assert_eq!(buddy_order(0, 4096), 0);
        assert_eq!(buddy_order(4096, 4096), 0);
        assert_eq!(buddy_order(4097, 4096), 1);
        assert_eq!(buddy_order(16384, 4096), 2);
        assert_eq!(buddy_order(16385, 4096), 3);
    }

    #[test]
    fn test_binomial_meld_carries() {
        assert_eq!(binomial_meld_carries(0, 0), 0);
        assert_eq!(binomial_meld_carries(1, 1), 1);
        assert_eq!(binomial_meld_carries(7, 1), 3);
        assert_eq!(binomial_meld_carries(5, 2), 0);
        assert_eq!(binomial_meld_carries(0b1011, 0b0111), 4);
    }

    #[test]
    fn test_hamming_distance() {
        assert_eq!(hamming_distance(b"", b""), Some(0));
        assert_eq!(hamming_distance(&[0xff], &[0x00]), Some(8));
        assert_eq!(hamming_distance(b"karolin", b"kathrin"), Some(9));
        assert_eq!(hamming_distance(b"ab", b"abc"), None);
    }

    #[test]
    fn test_run_count() {
        assert_eq!(run_count(b""), 0);
        assert_eq!(run_count(b"a"), 1);
        assert_eq!(run_count(b"aaab"), 2);
        assert_eq!(run_count(b"aabbaa"), 3);
        assert_eq!(run_count(b"abcd"), 4);
    }

    #[test]
    fn test_first_newline() {
        assert_eq!(first_newline(b""), None);
        assert_eq!(first_newline(b"abc"), None);
        assert_eq!(first_newline(b"\n"), Some(0));
        assert_eq!(first_newline(b"ab\ncd\n"), Some(2));
    }

    #[test]
    fn test_first_printable() {
        assert_eq!(first_printable(b""), None);
        assert_eq!(first_printable(&[0x00, 0x1f, 0x09]), None);
        assert_eq!(first_printable(b" x"), Some(0));
        assert_eq!(first_printable(&[0x01, 0x02, b'A']), Some(2));
        assert_eq!(first_printable(&[0x1f, 0x80]), Some(1));
    }

    #[test]
    fn test_checked_sum() {
        assert_eq!(checked_sum(&[]), Ok(0));
        assert_eq!(checked_sum(&[1, 2, 3]), Ok(6));
        assert_eq!(checked_sum(&[u32::MAX, 0]), Ok(u32::MAX));
        assert_eq!(checked_sum(&[u32::MAX, 0, 1, 5]), Err(Overflow { at: 2 }));
    }

    #[test]
    fn test_ring_index() {
        assert_eq!(ring_index(0, 0, 8), 0);
        assert_eq!(ring_index(5, 2, 8), 7);
        assert_eq!(ring_index(5, 3, 8), 0);
        assert_eq!(ring_index(7, 17, 8), 0);
        assert_eq!(ring_index(2, 5, 5), 2);
    }

    #[test]
    fn test_align_up() {
        assert_eq!(align_up(0, 8), 0);
        assert_eq!(align_up(1, 8), 8);
        assert_eq!(align_up(8, 8), 8);
        assert_eq!(align_up(4097, 4096), 8192);
        assert_eq!(align_up(13, 1), 13);
    }

    #[test]
    fn test_ceil_div() {
        assert_eq!(ceil_div(0, 3), 0);
        assert_eq!(ceil_div(1, 3), 1);
        assert_eq!(ceil_div(3, 3), 1);
        assert_eq!(ceil_div(10, 3), 4);
        assert_eq!(ceil_div(u32::MAX, 2), 1 << 31);
    }

    #[test]
    fn test_crc8() {
        assert_eq!(crc8(b""), 0x00);
        assert_eq!(crc8(&[0x01]), 0x07);
        assert_eq!(crc8(&[0x80]), 0x89);
        // Standard CRC-8 check value.
        assert_eq!(crc8(b"123456789"), 0xf4);
    }

    #[test]
    fn test_parity() {
        assert!(!parity(0));
        assert!(parity(1));
        assert!(!parity(3));
        assert!(parity(7));
        assert!(!parity(u32::MAX));
    }

    #[test]
    fn test_trailing_ones() {
        assert_eq!(trailing_ones(0), 0);
        assert_eq!(trailing_ones(1), 1);
        assert_eq!(trailing_ones(0b1011), 2);
        assert_eq!(trailing_ones(0b0111), 3);
        assert_eq!(trailing_ones(u32::MAX), 32);
    }

    #[test]
    fn test_byte_swap() {
        assert_eq!(byte_swap(0), 0);
        assert_eq!(byte_swap(0x1234_5678), 0x7856_3412);
        assert_eq!(byte_swap(0x0000_00ff), 0xff00_0000);
    }

    #[test]
    fn test_nibble_popcount() {
        assert_eq!(nibble_popcount(0), 0);
        assert_eq!(nibble_popcount(1), 1);
        assert_eq!(nibble_popcount(6), 2);
        assert_eq!(nibble_popcount(7), 3);
        assert_eq!(nibble_popcount(15), 4);
        assert_eq!(nibble_popcount(0xf0), 0);
    }

    #[test]
    fn test_matrix_sum_4x8() {
        assert_eq!(matrix_sum_4x8(&[[0; 8]; 4]), 0);
        assert_eq!(matrix_sum_4x8(&[[1; 8]; 4]), 32);
        assert_eq!(matrix_sum_4x8(&[[255; 8]; 4]), 8160);
        let mut m = [[0u8; 8]; 4];
        m[3][7] = 9;
        m[0][0] = 1;
        assert_eq!(matrix_sum_4x8(&m), 10);
    }

    #[test]
    fn test_seed16_rounds20() {
        // Expected values computed independently (Python model of the same
        // recurrence).
        let zero = [0u8; 16];
        let ramp: [u8; 16] = core::array::from_fn(|i| i as u8);
        assert_eq!(seed16_rounds20(&zero), 0x8aec_1156);
        assert_eq!(seed16_rounds20(&ramp), 0x63a3_8c44);
    }

    #[test]
    fn test_count_words() {
        assert_eq!(count_words(b""), 0);
        assert_eq!(count_words(b"   "), 0);
        assert_eq!(count_words(b"hello"), 1);
        assert_eq!(count_words(b"  hello   world "), 2);
        assert_eq!(count_words(b"a\tb\nc\r\nd"), 4);
    }

    #[test]
    fn test_scale_sample() {
        assert_eq!(scale_sample(100, 256, 0), 100);
        assert_eq!(scale_sample(100, 512, 0), 200);
        assert_eq!(scale_sample(100, 128, 5), 55);
        assert_eq!(scale_sample(30000, 512, 0), i16::MAX);
        assert_eq!(scale_sample(-30000, 512, 0), i16::MIN);
        assert_eq!(scale_sample(i16::MAX, i32::MAX, i32::MAX), i16::MAX);
    }

    #[test]
    fn test_remaining_budget() {
        assert_eq!(remaining_budget(100, &[], 1000), 100);
        assert_eq!(remaining_budget(100, &[30, 20], 1000), 50);
        assert_eq!(remaining_budget(100, &[30, 200, 5], 1000), 0);
        assert_eq!(remaining_budget(100, &[10], 40), 40);
    }

    #[test]
    fn test_read_u32_le() {
        let data = [0x78, 0x56, 0x34, 0x12, 0xff];
        assert_eq!(read_u32_le(&data, 0), Some(0x1234_5678));
        assert_eq!(read_u32_le(&data, 1), Some(0xff12_3456));
        assert_eq!(read_u32_le(&data, 2), None);
        assert_eq!(read_u32_le(&data, usize::MAX), None);
        assert_eq!(read_u32_le(&[], 0), None);
    }
}

// sandblaster: the optimizer's replacements of the functions above whose bodies call them, lowered to
// Rust and checked by the lifted round trip (DESIGN.md §2.1).

#[inline(always)]
#[allow(non_snake_case, unused_parens, unused_mut, unused_variables, unused_braces, clippy::all)]
fn __sandblaster_opt_next_power_of_two(l0_n: u32) -> Option<u32> {
    if l0_n <= 1u32 {
        Some(1u32)
    } else {
        let l15_s15: u32 = l0_n - 1u32;
        let l16_s16: u32 = l15_s15 >> 1u32;
        let l17_s17: u32 = l15_s15 | l16_s16;
        let l18_s18: u32 = l17_s17 >> 2u32;
        let l19_s19: u32 = l17_s17 | l18_s18;
        let l20_s20: u32 = l19_s19 >> 4u32;
        let l21_s21: u32 = l19_s19 | l20_s20;
        let l22_s22: u32 = l21_s21 >> 8u32;
        let l23_s23: u32 = l21_s21 | l22_s22;
        let l24_s24: u32 = l23_s23 >> 16u32;
        let l25_s25: u32 = l23_s23 | l24_s24;
        match l25_s25.checked_add(1u32) {
            None => {
                None
            },
            Some(l14_value_14) => {
                Some(l25_s25 + 1u32)
            },
        }
    }
}

#[inline(always)]
#[allow(non_snake_case, unused_parens, unused_mut, unused_variables, unused_braces, clippy::all)]
fn __sandblaster_opt_read_u32_le(l0_data: &[u8], l1_offset: usize) -> Option<u32> {
    match l1_offset.checked_add(4usize) {
        None => {
            None
        },
        Some(l10_value_10) => {
            let l11_s11: usize = l1_offset + 4usize;
            if l1_offset <= l11_s11 {
                if l11_s11 <= l0_data.len() {
                    let l12_s12: &[u8] = &l0_data[l1_offset..];
                    let l13_s13: &[u8] = &l12_s12[..(l11_s11 - l1_offset)];
                    Some(u32::from_le_bytes([l13_s13[0usize], l13_s13[1usize], l13_s13[2usize], l13_s13[3usize]]))
                } else {
                    None
                }
            } else {
                None
            }
        },
    }
}
