//! The general corpus as emitted at plan O1 (the frozen `../baselines/o1-gen.rs`: checked
//! operators, so `a * b` keeps rustc's overflow check under `overflow-checks = true`), behind
//! exactly the probes of `cgen`: the "O1 emission" subject of every program in the harness's
//! same-binary timings (current emission vs O1 emission vs ideal), and of `opt-corpus e0`.
include!(concat!(env!("OUT_DIR"), "/gen.rs"));

#[allow(unsafe_code)]
pub mod probe {
    pub use crate::Block;
    #[inline(never)] pub fn bit_length(x: u64) -> u32 { crate::bit_length(x) }
    #[inline(never)] pub fn floor_pow2(x: u64) -> u64 { crate::floor_pow2(x) }
    #[inline(never)] pub fn popcount_loop(x: u64) -> u32 { crate::popcount_loop(x) }
    #[inline(never)] pub fn find_block(n: u64, i: u64) -> Option<Block> { crate::find_block(n, i) }
    #[inline(never)] pub fn leb128(xs: &[u8]) -> Option<(u64, &[u8])> { crate::leb128(xs) }
    #[inline(never)] pub fn header4(xs: &[u8]) -> Option<u64> { crate::header4(xs) }
    #[inline(never)] pub fn varint_len(x: u64) -> u32 { crate::varint_len(x) }
    #[inline(never)] pub fn concat_fold(a: &[u64], m: u64, b: &[u64]) -> Option<u64> { crate::concat_fold(a, m, b) }
    #[inline(never)] pub fn prefix_query(xs: &[u32; 64], k: usize) -> u64 { crate::prefix_query(xs, k) }
    #[inline(never)] pub fn min_max(xs: &[u32]) -> (u32, u32) { crate::min_max(xs) }
    #[inline(never)] pub fn sum_small(xs: &[u32]) -> Option<u64> { crate::sum_small(xs) }
    #[inline(never)] pub fn trailing_zeros_loop(x: u64) -> u32 { crate::trailing_zeros_loop(x) }
    #[inline(never)] pub fn first_small(xs: &[u8]) -> Option<u64> { crate::first_small(xs) }
    #[inline(never)] pub fn rank_above(n: u64, k: u32) -> u32 { crate::rank_above(n, k) }
    #[inline(never)] pub fn series(n: u32) -> u64 { crate::series(n) }
    #[inline(never)] pub fn tree_root(h: u32, xs: &[u64]) -> Option<u64> { crate::p15_tree_dfs::tree_root(h, xs) }
    #[inline(never)] pub fn batch_roots(l: &[u64; 8], i: &[u64; 8], s: &[[u64; 20]; 8]) -> [u64; 8] { crate::p16_batch_paths::batch_roots(l, i, s) }
    #[inline(never)] pub fn gf16_mul_block(c: u16, b: &[u8; 64]) -> [u8; 64] { crate::p17_gf16_mul::gf16_mul_block(c, b) }
    #[inline(never)] pub fn mul_carry(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] { crate::p18_carry_chain::mul_carry(a, b) }
    /// P18's precondition-bounded kernel, called directly: rustc cannot see the bounds, so
    /// under `overflow-checks = true` every checked operation keeps its check.
    ///
    /// # Safety
    /// Every limb of `a` and `b` is < 2^28 (the harness passes masked limbs).
    #[inline(never)] pub unsafe fn mul_carry_limbs(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
        // SAFETY: the caller's precondition is the function's
        unsafe { crate::__sandblaster::p18_carry_chain::mul_carry_limbs(a, b) }
    }
    #[inline(never)] pub fn line_mul(a: &[u64; 3], c: u64) -> [u64; 3] { crate::p20_sparse_mul::line_mul(a, c) }
}
