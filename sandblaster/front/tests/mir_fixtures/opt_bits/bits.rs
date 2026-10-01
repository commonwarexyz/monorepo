//! Bit counting, written the obvious way.

/// Set bits of `n` above position `k`.
pub fn rank_above(n: u64, k: u32) -> u32 {
    let mut c: u32 = 0;
    for i in 0..64u32 {
        if i > k && (n >> i) & 1 == 1 {
            c = c.wrapping_add(1);
        }
    }
    c
}

/// Set bits of `x`, one bit per iteration.
pub fn popcount_loop(x: u64) -> u32 {
    let mut c: u32 = 0;
    for i in 0..64u32 {
        c = c.wrapping_add(((x >> i) & 1) as u32);
    }
    c
}

/// Already as cheap as it gets.
pub fn low_byte(x: u64) -> u8 {
    x as u8
}
