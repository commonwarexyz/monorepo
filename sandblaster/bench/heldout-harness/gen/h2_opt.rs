// copied verbatim from the lowered copy of utils/src/rng.rs by items.py (only `#[stability(..)]` dropped)
/// Applies a SplitMix64-style finalizer to a deterministic input word.
///
/// This is useful for cheaply decorrelating derived deterministic seeds while
/// preserving reproducibility.
#[inline]
pub const fn mix64(mut word: u64) -> u64 {
    word ^= word >> 30;
    word = word.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    word ^= word >> 27;
    word = word.wrapping_mul(0x94d0_49bb_1331_11eb);
    word ^ (word >> 31)
}
