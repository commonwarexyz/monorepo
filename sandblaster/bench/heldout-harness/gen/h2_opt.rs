// copied verbatim from the lowered copy of utils/src/rng.rs by items.py (only `#[stability(..)]` dropped)
/// Applies a SplitMix64-style finalizer to a deterministic input word.
///
/// This is useful for cheaply decorrelating derived deterministic seeds while
/// preserving reproducibility.
#[inline]
pub const fn mix64(word: u64) -> u64 {
    __sandblaster_opt_mix64(word)
}

#[inline(always)]
#[allow(non_snake_case, unused_parens, unused_mut, unused_variables, unused_braces, clippy::all)]
const fn __sandblaster_opt_mix64(mut l0_word: u64) -> u64 {
    let l8_s8: u64 = (l0_word ^ (l0_word >> 30u32)).wrapping_mul(13787848793156543929u64);
    let l9_s9: u64 = (l8_s8 ^ (l8_s8 >> 27u32)).wrapping_mul(10723151780598845931u64);
    l9_s9 ^ (l9_s9 >> 31u32)
}
