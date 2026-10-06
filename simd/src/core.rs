//! Vector instruction profiles and operation execution.

/// Common vector instructions and execution of operations through a backend token.
///
/// Instructions may be implemented with native SIMD or scalar emulation. [`Self::execute`]
/// selects this backend's operation path without repeating runtime backend selection.
///
/// Each implementation chooses its vector representations and independent nonzero
/// [`Self::U8_LANES`], [`Self::U32_LANES`], and [`Self::U64_LANES`] counts.
/// Algorithms must use the corresponding count rather than assume a particular width
/// or a relationship between lane types.
///
/// # Instruction notation
///
/// - `r` is the result; `v[i]` is lane `i`, with lane zero loaded/stored first.
/// - `L` is the result vector's lane count (the input vector's for stores).
///   Lane equations hold for `0 <= i < L` unless specified.
/// - Lanes are unsigned integers; arithmetic in equations is over mathematical integers.
///   `mod` gives the nonnegative remainder; `mod 2^w` truncates to `w` bits.
///   `/` denotes floor division on nonnegative integers.
/// - `&`, `|`, `^`, and `!` are bitwise operations; `!` complements within the lane width.
///   `>>` is a zero-filling shift; `<<` is an integer left shift before truncation.
/// - `bit(x, j) = (x >> j) & 1`; `rotr_w(x, n)` rotates a `w`-bit lane right by `n`.
/// - `v[start..end]` is a half-open lane range; `[a, b]` concatenates lane sequences.
/// - `P(x) = sum_j bit(x, j) * X^j`, over all bits of `x`, is a polynomial over GF(2).
///
/// Memory instructions specify **Alignment** in bytes and **Reads** or **Writes** in
/// elements. Alignment is the element type's alignment, with no additional vector
/// alignment required. Unlisted input elements are ignored; unlisted output elements
/// are unchanged. **Immediate** gives the valid range for a compile-time operand when
/// invalid values may be rejected during compilation; otherwise invalid arguments
/// have the documented panic behavior. Register-only instructions impose no memory
/// alignment requirement. These conventions also apply to the derived profiles.
///
/// Methods take an execution token by value so generic algorithms can use static
/// dispatch with a backend-specific vector representation.
///
/// # Examples
///
/// ```
/// use commonware_simd::Simd;
///
/// fn add<S: Simd>(simd: S, a: &[u64], b: &[u64], output: &mut [u64]) {
///     let sum = simd.u64_add(simd.u64_load(a), simd.u64_load(b));
///     simd.u64_store(sum, output);
/// }
/// ```
pub trait Simd: Copy {
    /// Four unsigned 32-bit lanes, independent of [`Self::U32_LANES`].
    type U32x4: Copy;

    /// `r[i] = input[i]`.
    ///
    /// - **Alignment:** `align_of::<u32>()`.
    /// - **Reads:** `input[0..4]`.
    ///
    /// # Panics
    ///
    /// Panics if `input.len() < 4`.
    fn u32x4_load(self, input: &[u32]) -> Self::U32x4;

    /// `output[i] = value[i]`.
    ///
    /// - **Alignment:** `align_of::<u32>()`.
    /// - **Writes:** `output[0..4]`.
    ///
    /// # Panics
    ///
    /// Panics before writing if `output.len() < 4`.
    fn u32x4_store(self, value: Self::U32x4, output: &mut [u32]);

    /// `r[i] = (a[i] + b[i]) mod 2^32`.
    fn u32x4_add(self, a: Self::U32x4, b: Self::U32x4) -> Self::U32x4;

    /// `r[i] = value[(MASK >> (2*i)) & 3]`.
    ///
    /// - **Immediate:** `0 <= MASK < 256`; invalid values may be rejected at compile time or panic.
    fn u32x4_shuffle<const MASK: i32>(self, value: Self::U32x4) -> Self::U32x4;

    /// Loads four big-endian words: `r[i] = sum_{j=0..3} input[4*i+j] * 2^(8*(3-j))`.
    ///
    /// - **Alignment:** `align_of::<u8>()`.
    /// - **Reads:** `input[0..16]`.
    ///
    /// # Panics
    ///
    /// Panics if `input.len() < 16`.
    fn u32x4_load_be(self, input: &[u8]) -> Self::U32x4;

    /// Loads two big-endian words; `r[2] = r[3] = 0`.
    ///
    /// - **Alignment:** `align_of::<u8>()`.
    /// - **Reads:** `input[0..8]`.
    ///
    /// # Panics
    ///
    /// Panics if `input.len() < 8`.
    fn u32x4_load_be2(self, input: &[u8]) -> Self::U32x4;

    /// Stores four big-endian words: `output[4*i+j] = (value[i] >> (8*(3-j))) mod 256`.
    ///
    /// - **Alignment:** `align_of::<u8>()`.
    /// - **Writes:** `output[0..16]`.
    ///
    /// # Panics
    ///
    /// Panics before writing if `output.len() < 16`.
    fn u32x4_store_be(self, value: Self::U32x4, output: &mut [u8]);

    /// `r[i] = [a, b][N+i]` for `0 <= i < 4`.
    ///
    /// - **Immediate:** `0 <= N <= 4`; invalid values may be rejected at compile time or panic.
    fn u32x4_align<const N: i32>(self, a: Self::U32x4, b: Self::U32x4) -> Self::U32x4;

    /// `r[i] = b[i]` if `bit(MASK, i) = 1`, otherwise `r[i] = a[i]`.
    ///
    /// - **Immediate:** `0 <= MASK < 16`; invalid values may be rejected at compile time or panic.
    fn u32x4_blend<const MASK: i32>(self, a: Self::U32x4, b: Self::U32x4) -> Self::U32x4;

    /// Vector of [`Self::U8_LANES`] unsigned 8-bit lanes.
    type U8: Copy;

    /// Number of lanes in [`Self::U8`]. Must be positive.
    const U8_LANES: usize;

    /// Vector of [`Self::U32_LANES`] unsigned 32-bit lanes.
    type U32: Copy;

    /// Number of lanes in [`Self::U32`]. Must be positive.
    const U32_LANES: usize;

    /// Vector of [`Self::U64_LANES`] unsigned 64-bit lanes.
    type U64: Copy;

    /// Number of lanes in [`Self::U64`]. Must be positive.
    const U64_LANES: usize;

    /// `r[i] = input[i]`.
    ///
    /// - **Alignment:** `align_of::<u8>()`.
    /// - **Reads:** `input[0..Self::U8_LANES]`.
    ///
    /// # Panics
    ///
    /// Panics if `input.len() < Self::U8_LANES`.
    fn u8_load(self, input: &[u8]) -> Self::U8;

    /// `output[i] = value[i]`.
    ///
    /// - **Alignment:** `align_of::<u8>()`.
    /// - **Writes:** `output[0..Self::U8_LANES]`.
    ///
    /// # Panics
    ///
    /// Panics before writing if `output.len() < Self::U8_LANES`.
    fn u8_store(self, value: Self::U8, output: &mut [u8]);

    /// `r[i] = value`.
    fn u8_splat(self, value: u8) -> Self::U8;

    /// `r[i] = a[i] ^ b[i]`.
    fn u8_xor(self, a: Self::U8, b: Self::U8) -> Self::U8;

    /// `r[i] = input[i]` if `i < input.len()`, otherwise `r[i] = 0`.
    ///
    /// - **Alignment:** `align_of::<u8>()`.
    /// - **Reads:** `input[0..input.len()]`; empty input is allowed.
    ///
    /// # Panics
    ///
    /// Panics if `input.len() > Self::U8_LANES`.
    fn u8_load_partial(self, input: &[u8]) -> Self::U8;

    /// `output[i] = value[i]` for `0 <= i < output.len()`.
    ///
    /// - **Alignment:** `align_of::<u8>()`.
    /// - **Writes:** `output[0..output.len()]`; empty output is allowed.
    ///
    /// # Panics
    ///
    /// Panics before writing if `output.len() > Self::U8_LANES`.
    fn u8_store_partial(self, value: Self::U8, output: &mut [u8]);

    /// `r[i] = a[i] & b[i]`.
    fn u8_and(self, a: Self::U8, b: Self::U8) -> Self::U8;

    /// `r[i] = (value[i] << N) mod 2^8`.
    ///
    /// # Panics
    ///
    /// Panics if `N >= 8`.
    fn u8_shl<const N: u32>(self, value: Self::U8) -> Self::U8;

    /// `r[i] = value[i] >> N`.
    ///
    /// # Panics
    ///
    /// Panics if `N >= 8`.
    fn u8_shr<const N: u32>(self, value: Self::U8) -> Self::U8;

    /// `r = value[0] ^ ... ^ value[Self::U8_LANES - 1]`.
    fn u8_xor_fold(self, value: Self::U8) -> u8;

    /// `r[i] = input[i]`.
    ///
    /// - **Alignment:** `align_of::<u32>()`.
    /// - **Reads:** `input[0..Self::U32_LANES]`.
    ///
    /// # Panics
    ///
    /// Panics if `input.len() < Self::U32_LANES`.
    fn u32_load(self, input: &[u32]) -> Self::U32;

    /// `output[i] = value[i]`.
    ///
    /// - **Alignment:** `align_of::<u32>()`.
    /// - **Writes:** `output[0..Self::U32_LANES]`.
    ///
    /// # Panics
    ///
    /// Panics before writing if `output.len() < Self::U32_LANES`.
    fn u32_store(self, value: Self::U32, output: &mut [u32]);

    /// `r[i] = value`.
    fn u32_splat(self, value: u32) -> Self::U32;

    /// `r[i] = a[i] ^ b[i]`.
    fn u32_xor(self, a: Self::U32, b: Self::U32) -> Self::U32;

    /// `r[i] = (a[i] + b[i]) mod 2^32`.
    fn u32_add(self, a: Self::U32, b: Self::U32) -> Self::U32;

    /// `r[i] = rotr_32(value[i], N)`.
    ///
    /// # Panics
    ///
    /// Panics if `N >= 32`.
    fn u32_rotate_right<const N: u32>(self, value: Self::U32) -> Self::U32;

    /// `r[i] = (a[i] - b[i]) mod 2^32`.
    fn u32_sub(self, a: Self::U32, b: Self::U32) -> Self::U32;

    /// `r[i] = a[i] & b[i]`.
    fn u32_and(self, a: Self::U32, b: Self::U32) -> Self::U32;

    /// `r[i] = a[i] | b[i]`.
    fn u32_or(self, a: Self::U32, b: Self::U32) -> Self::U32;

    /// `r[i] = (value[i] << N) mod 2^32`.
    ///
    /// # Panics
    ///
    /// Panics if `N >= 32`.
    fn u32_shl<const N: u32>(self, value: Self::U32) -> Self::U32;

    /// `r[i] = value[i] >> N`.
    ///
    /// # Panics
    ///
    /// Panics if `N >= 32`.
    fn u32_shr<const N: u32>(self, value: Self::U32) -> Self::U32;

    /// `r[i] = (mask[i] & a[i]) | (!mask[i] & b[i])` (bitwise selection).
    fn u32_select(self, mask: Self::U32, a: Self::U32, b: Self::U32) -> Self::U32;

    /// `r[i] = value[indices[i]]`.
    ///
    /// - **Alignment:** `align_of::<usize>()` for `indices`.
    /// - **Reads:** `indices[0..Self::U32_LANES]`.
    ///
    /// # Panics
    ///
    /// Panics if `indices.len() < Self::U32_LANES` or any read index is `>= Self::U32_LANES`.
    fn u32_permute(self, value: Self::U32, indices: &[usize]) -> Self::U32;

    /// `r[i] = [a, b][indices[i]]`.
    ///
    /// - **Alignment:** `align_of::<usize>()` for `indices`.
    /// - **Reads:** `indices[0..Self::U32_LANES]`.
    ///
    /// # Panics
    ///
    /// Panics if `indices.len() < Self::U32_LANES` or any read index is `>= 2 * Self::U32_LANES`.
    fn u32_permute2(self, a: Self::U32, b: Self::U32, indices: &[usize]) -> Self::U32;

    /// `r[i] = input[i]`.
    ///
    /// - **Alignment:** `align_of::<u64>()`.
    /// - **Reads:** `input[0..Self::U64_LANES]`.
    ///
    /// # Panics
    ///
    /// Panics if `input.len() < Self::U64_LANES`.
    fn u64_load(self, input: &[u64]) -> Self::U64;

    /// `output[i] = value[i]`.
    ///
    /// - **Alignment:** `align_of::<u64>()`.
    /// - **Writes:** `output[0..Self::U64_LANES]`.
    ///
    /// # Panics
    ///
    /// Panics before writing if `output.len() < Self::U64_LANES`.
    fn u64_store(self, value: Self::U64, output: &mut [u64]);

    /// `r[i] = value`.
    fn u64_splat(self, value: u64) -> Self::U64;

    /// `r[i] = (a[i] + b[i]) mod 2^64`.
    fn u64_add(self, a: Self::U64, b: Self::U64) -> Self::U64;

    /// `r[i] = (value[i] << N) mod 2^64`.
    ///
    /// # Panics
    ///
    /// Panics if `N >= 64`.
    fn u64_shl<const N: u32>(self, value: Self::U64) -> Self::U64;

    /// `r[i] = value[i] >> N`.
    ///
    /// # Panics
    ///
    /// Panics if `N >= 64`.
    fn u64_shr<const N: u32>(self, value: Self::U64) -> Self::U64;

    /// `r[i] = a[i] & b[i]`.
    fn u64_and(self, a: Self::U64, b: Self::U64) -> Self::U64;

    /// `r[i] = a[i] | b[i]`.
    fn u64_or(self, a: Self::U64, b: Self::U64) -> Self::U64;

    /// `r[i] = (a[i] - b[i]) mod 2^64`.
    fn u64_sub(self, a: Self::U64, b: Self::U64) -> Self::U64;

    /// `r[i] = a[i] ^ b[i]`.
    fn u64_xor(self, a: Self::U64, b: Self::U64) -> Self::U64;

    /// `r[i] = (mask[i] & a[i]) | (!mask[i] & b[i])` (bitwise selection).
    fn u64_select(self, mask: Self::U64, a: Self::U64, b: Self::U64) -> Self::U64;

    /// `r = value[N]`.
    ///
    /// # Panics
    ///
    /// Panics if `N >= Self::U64_LANES`.
    fn u64_extract<const N: usize>(self, value: Self::U64) -> u64;

    /// `r[N] = lane`; `r[i] = value[i]` for `i != N`.
    ///
    /// # Panics
    ///
    /// Panics if `N >= Self::U64_LANES`.
    fn u64_insert<const N: usize>(self, value: Self::U64, lane: u64) -> Self::U64;

    /// Executes an operation using this backend's algorithm path.
    ///
    /// Scalar backends invoke [`Operation::portable`], Ice Lake backends invoke
    /// [`Operation::ice_lake`], Armv9 backends invoke [`Operation::arm_v9`], and NEON
    /// backends invoke [`Operation::neon`]. Native implementations establish the required
    /// target-feature scope. Emulated implementations require no corresponding hardware
    /// features.
    ///
    /// Enter a whole SIMD kernel with `simd.execute(#[inline(always)] |simd| ...)`.
    /// A kernel is a substantial SIMD computation that keeps intermediates in registers.
    /// The closure body and hot shared SIMD helpers must inline into the target-feature scope;
    /// annotate both with `#[inline(always)]`. Receiving a token alone does not give an
    /// ordinary function those features. Scalar helpers and independently scoped kernels
    /// may remain calls.
    ///
    /// # Examples
    ///
    /// An ordinary generic function can execute a child operation without implementing
    /// [`Operation`] itself:
    ///
    /// ```
    /// use commonware_simd::{Operation, Simd};
    ///
    /// fn composed<S: Simd, O: Operation<S>>(simd: S, child: O) -> O::Output {
    ///     simd.execute(child)
    /// }
    /// ```
    fn execute<O: Operation<Self>>(self, operation: O) -> O::Output;
}

/// Ice Lake instruction profile implemented by native and emulated backend tokens.
///
/// This profile models 512-bit vectors with 64 unsigned byte lanes, 16 unsigned
/// 32-bit lanes, and eight unsigned 64-bit lanes. Native implementations require
/// AVX-512F, AVX-512BW, GFNI, AVX-512 IFMA, SHA, SSSE3, and SSE4.1.
/// The name identifies an instruction bundle, not a required CPU vendor or model.
///
/// Instruction contracts use the [notation defined by `Simd`](Simd#instruction-notation).
pub trait IceLake: Simd {
    /// `r[i] = sum_{j=0..3} input[4*i+j] * 2^(8*(3-j))` for `0 <= i < 16`.
    ///
    /// - **Alignment:** `align_of::<u8>()`.
    /// - **Reads:** `input[0..64]`.
    ///
    /// # Panics
    ///
    /// Panics if `input.len() < 64`.
    fn u32_load_be(self, input: &[u8]) -> Self::U32;

    /// Two SHA-256 rounds (SHA256RNDS2), with all additions modulo `2^32`.
    ///
    /// ```text
    /// (H, G, D, C) = a[0..4]; (F, E, B, A) = b[0..4]
    /// for t = 0, 1:
    ///     T1 = H + (rotr_32(E, 6) ^ rotr_32(E, 11) ^ rotr_32(E, 25))
    ///            + ((E & F) ^ (!E & G)) + k[t]
    ///     T2 = (rotr_32(A, 2) ^ rotr_32(A, 13) ^ rotr_32(A, 22))
    ///            + ((A & B) ^ (A & C) ^ (B & C))
    ///     (A, B, C, D, E, F, G, H) = (T1 + T2, A, B, C, D + T1, E, F, G)
    /// r = [F, E, B, A]
    /// ```
    ///
    /// Assignments update the state simultaneously. `k[2..4]` is ignored.
    fn sha256_rounds2(self, a: Self::U32x4, b: Self::U32x4, k: Self::U32x4) -> Self::U32x4;

    /// `r[i] = (a[i] + sigma0([a[1], a[2], a[3], b[0]][i])) mod 2^32`,
    /// where `sigma0(x) = rotr_32(x, 7) ^ rotr_32(x, 18) ^ (x >> 3)` (SHA256MSG1).
    fn sha256_msg1(self, a: Self::U32x4, b: Self::U32x4) -> Self::U32x4;

    /// `r[i] = (a[i] + sigma1(b[i+2])) mod 2^32` for `i < 2`;
    /// `r[i] = (a[i] + sigma1(r[i-2])) mod 2^32` for `2 <= i < 4`,
    /// where `sigma1(x) = rotr_32(x, 17) ^ rotr_32(x, 19) ^ (x >> 10)` (SHA256MSG2).
    fn sha256_msg2(self, a: Self::U32x4, b: Self::U32x4) -> Self::U32x4;

    /// `bit(r[i], j) = bit(MASK, 4*bit(a[i], j) + 2*bit(b[i], j) + bit(c[i], j))`
    /// for `0 <= j < 32` (VPTERNLOGD).
    ///
    /// - **Immediate:** `0 <= MASK < 256`; invalid values may be rejected at compile time or panic.
    fn u32_ternary<const MASK: i32>(self, a: Self::U32, b: Self::U32, c: Self::U32) -> Self::U32;

    /// `r[i] = 0` if `indices[i] & 0x80 != 0`; otherwise
    /// `r[i] = value[16*(i / 16) + (indices[i] & 15)]` (VPSHUFB).
    fn u8_shuffle128(self, value: Self::U8, indices: Self::U8) -> Self::U8;

    /// Let `g = i / 4`, `j = i mod 4`, `q = (MASK >> (2*g)) & 3`.
    /// `r[i] = a[4*q+j]` if `g < 2`, otherwise `r[i] = b[4*q+j]` (VSHUFI32X4).
    ///
    /// - **Immediate:** `0 <= MASK < 256`; invalid values may be rejected at compile time or panic.
    fn u32_shuffle_groups<const MASK: i32>(self, a: Self::U32, b: Self::U32) -> Self::U32;

    /// `r[4*g..4*g+4] = [a[4*g+2], a[4*g+3], b[4*g+2], b[4*g+3]]` for `0 <= g < 4`.
    fn u32_unpackhi64(self, a: Self::U32, b: Self::U32) -> Self::U32;

    /// `P(r[i]) = (P(a[i]) * P(b[i])) mod (X^8 + X^4 + X^3 + X + 1)`
    /// in `GF(2)[X]` (AES modulus `0x11b`).
    fn u8_gf_mul(self, a: Self::U8, b: Self::U8) -> Self::U8;

    /// Let `p = (a[i] mod 2^52) * (b[i] mod 2^52)`.
    /// `r[i] = (acc[i] + (p mod 2^52)) mod 2^64`.
    fn u64_madd52lo(self, acc: Self::U64, a: Self::U64, b: Self::U64) -> Self::U64;

    /// Let `p = (a[i] mod 2^52) * (b[i] mod 2^52)`.
    /// `r[i] = (acc[i] + (floor(p / 2^52))) mod 2^64`.
    fn u64_madd52hi(self, acc: Self::U64, a: Self::U64, b: Self::U64) -> Self::U64;

    /// `r[4*g+j] = value[4*g + ((MASK >> (2*j)) & 3)]`
    /// for `0 <= g < 4`, `0 <= j < 4`.
    ///
    /// - **Immediate:** `0 <= MASK < 256`; invalid values may be rejected at compile time or panic.
    fn u32_shuffle128<const MASK: i32>(self, value: Self::U32) -> Self::U32;

    /// Let `q = (MASK >> (2*j)) & 3`.
    /// `r[4*g+j] = a[4*g+q]` if `j < 2`, otherwise `r[4*g+j] = b[4*g+q]`,
    /// for `0 <= g < 4`, `0 <= j < 4`.
    ///
    /// - **Immediate:** `0 <= MASK < 256`; invalid values may be rejected at compile time or panic.
    fn u32_shuffle2_128<const MASK: i32>(self, a: Self::U32, b: Self::U32) -> Self::U32;

    /// `r[i] = b[i]` if `bit(MASK, i mod 4) = 1`, otherwise `r[i] = a[i]`.
    ///
    /// # Panics
    ///
    /// Panics unless `0 <= MASK < 16`.
    fn u32_blend128<const MASK: i32>(self, a: Self::U32, b: Self::U32) -> Self::U32;

    /// `r[4*g..4*g+4] = [a[4*g], b[4*g], a[4*g+1], b[4*g+1]]` for `0 <= g < 4`.
    fn u32_unpacklo32(self, a: Self::U32, b: Self::U32) -> Self::U32;

    /// `r[4*g..4*g+4] = [a[4*g+2], b[4*g+2], a[4*g+3], b[4*g+3]]` for `0 <= g < 4`.
    fn u32_unpackhi32(self, a: Self::U32, b: Self::U32) -> Self::U32;

    /// `r[4*g..4*g+4] = [a[4*g], a[4*g+1], b[4*g], b[4*g+1]]` for `0 <= g < 4`.
    fn u32_unpacklo64(self, a: Self::U32, b: Self::U32) -> Self::U32;
}

/// Armv9-A with SVE2 instruction profile implemented by native and emulated backend tokens.
///
/// Requires NEON, SHA2, SVE, and SVE2 explicitly; an Armv9 architecture label
/// alone does not establish their availability. Logical vectors retain NEON's 128-bit
/// shape. Native providers use the low 128 bits of SVE registers, independently of
/// the thread's full SVE vector length. Optional SVE2 extensions require separate checks.
///
/// Instruction contracts use the [notation defined by `Simd`](Simd#instruction-notation).
pub trait ArmV9: Neon {
    /// `r[i] = rotr_32(a[i] ^ b[i], N)` (SVE2 XAR).
    ///
    /// # Panics
    ///
    /// Panics if `N >= 32`.
    fn u32_xor_rotate_right<const N: u32>(self, a: Self::U32, b: Self::U32) -> Self::U32;
}

/// AArch64 NEON with SHA2 instruction profile implemented by native and emulated backend tokens.
///
/// Requires NEON and SHA2. This profile models 128-bit vectors with 16 unsigned byte
/// lanes, four unsigned 32-bit lanes, and two unsigned 64-bit lanes. SHA states use
/// `[A, B, C, D]` and `[E, F, G, H]` lane order. Its narrowing and widening primitives
/// use a separate half-width vector with two unsigned 32-bit lanes.
///
/// Instruction contracts use the [notation defined by `Simd`](Simd#instruction-notation).
pub trait Neon: Simd {
    /// Four SHA-256 rounds, returning `[A, B, C, D]` (SHA256H).
    ///
    /// For each `wk[t]`, compute `T1 = H + Sigma1(E) + Ch(E,F,G) + wk[t]` and
    /// `T2 = Sigma0(A) + Maj(A,B,C)`, then simultaneously update
    /// `(A,B,C,D,E,F,G,H) = (T1+T2,A,B,C,D+T1,E,F,G)` modulo `2^32`.
    /// `Sigma0(x) = rotr_32(x,2) ^ rotr_32(x,13) ^ rotr_32(x,22)`,
    /// `Sigma1(x) = rotr_32(x,6) ^ rotr_32(x,11) ^ rotr_32(x,25)`,
    /// `Ch(x,y,z) = (x & y) ^ (!x & z)`, and
    /// `Maj(x,y,z) = (x & y) ^ (x & z) ^ (y & z)`.
    fn sha256_h(self, abcd: Self::U32x4, efgh: Self::U32x4, wk: Self::U32x4) -> Self::U32x4;

    /// The same four rounds as [`Self::sha256_h`], returning `[E, F, G, H]` (SHA256H2).
    /// Both state arguments contain the state before these rounds.
    fn sha256_h2(self, efgh: Self::U32x4, abcd: Self::U32x4, wk: Self::U32x4) -> Self::U32x4;

    /// `r[i] = (a[i] + sigma0([a[1],a[2],a[3],b[0]][i])) mod 2^32` (SHA256SU0).
    /// `sigma0(x) = rotr_32(x,7) ^ rotr_32(x,18) ^ (x >> 3)`.
    fn sha256_su0(self, a: Self::U32x4, b: Self::U32x4) -> Self::U32x4;

    /// Let `t[i] = a[i] + [b[1],b[2],b[3],c[0]][i]` modulo `2^32`.
    /// `r[i] = t[i] + sigma1(c[i+2])` for `i < 2`, and
    /// `r[i] = t[i] + sigma1(r[i-2])` for `i >= 2`, modulo `2^32` (SHA256SU1).
    /// `sigma1(x) = rotr_32(x,17) ^ rotr_32(x,19) ^ (x >> 10)`.
    fn sha256_su1(self, a: Self::U32x4, b: Self::U32x4, c: Self::U32x4) -> Self::U32x4;

    /// Eight unsigned 16-bit lanes corresponding to one half of a byte vector.
    type U16: Copy;

    /// `r[i] = table[indices[i]]` if `indices[i] < 16`, otherwise `r[i] = 0`.
    fn u8_table_lookup(self, table: Self::U8, indices: Self::U8) -> Self::U8;

    /// `P(r[i]) = P(a[i]) * P(b[i])` in `GF(2)[X]`,
    /// for `0 <= i < 8`; the 16-bit polynomial product is unreduced.
    fn u8_clmul_lo(self, a: Self::U8, b: Self::U8) -> Self::U16;

    /// `P(r[i]) = P(a[i+8]) * P(b[i+8])` in `GF(2)[X]`,
    /// for `0 <= i < 8`; the 16-bit polynomial product is unreduced.
    fn u8_clmul_hi(self, a: Self::U8, b: Self::U8) -> Self::U16;

    /// `r[i] = a[i] ^ b[i]`.
    fn u16_xor(self, a: Self::U16, b: Self::U16) -> Self::U16;

    /// `r[i] = (value[i] << N) mod 2^16`.
    ///
    /// # Panics
    ///
    /// Panics if `N >= 16`.
    fn u16_shl<const N: u32>(self, value: Self::U16) -> Self::U16;

    /// `r[i] = value[i] >> N`.
    ///
    /// # Panics
    ///
    /// Panics if `N >= 16`.
    fn u16_shr<const N: u32>(self, value: Self::U16) -> Self::U16;

    /// `r[i] = low[i] mod 2^8` for `i < 8`;
    /// `r[i] = high[i-8] mod 2^8` for `8 <= i < 16`.
    fn u16_narrow_pair(self, low: Self::U16, high: Self::U16) -> Self::U8;

    /// Vector of [`Simd::U64_LANES`] unsigned 32-bit lanes, in matching lane order.
    /// This is half the width of the common [`Simd::U32`] vector.
    type U32Half: Copy;

    /// `r[i] = value[i] mod 2^32` for `0 <= i < 2`.
    fn u64_narrow(self, value: Self::U64) -> Self::U32Half;

    /// `r[i] = value` for `0 <= i < 2`.
    fn u32_half_splat(self, value: u32) -> Self::U32Half;

    /// `r[i] = (a[i] + b[i]) mod 2^32` for `0 <= i < 2`.
    fn u32_half_add(self, a: Self::U32Half, b: Self::U32Half) -> Self::U32Half;

    /// `r[i] = (value[i] << N) mod 2^32` for `0 <= i < 2`.
    ///
    /// # Panics
    ///
    /// Panics if `N >= 32`.
    fn u32_half_shl<const N: u32>(self, value: Self::U32Half) -> Self::U32Half;

    /// `r[i] = a[i] * b[i]` (full unsigned 64-bit product), for `0 <= i < 2`.
    fn u32_widen_mul(self, a: Self::U32Half, b: Self::U32Half) -> Self::U64;

    /// `r[i] = (acc[i] + a[i] * b[i]) mod 2^64` for `0 <= i < 2`.
    fn u32_widen_madd(self, acc: Self::U64, a: Self::U32Half, b: Self::U32Half) -> Self::U64;
}

/// Equivalent algorithm paths selected by a concrete backend token.
///
/// The portable path is required. Accelerated paths default to it while preserving
/// the supplied token, so child operations can still select specialized paths.
/// Operations may capture owned inputs, borrowed mutable buffers, or registers of `S`.
/// Their outputs can also depend on `S`, including its register types.
///
/// Closures implementing `FnMut(S) -> R` are operations with output `R` and are invoked
/// once per execution. They may own inputs and borrow mutable state; closures that only
/// implement `FnOnce` are excluded. Use `simd.execute(#[inline(always)] |simd| ...)`
/// to enter a whole kernel: a substantial SIMD computation that keeps intermediates in
/// registers. Ordinary generic functions can compose leaves and return results directly.
/// The closure body and hot shared SIMD helpers must inline
/// into the kernel's target-feature scope, so annotate both with `#[inline(always)]`.
/// Inlining the closure adapter alone does not force the body to inline. Passing a token to an
/// ordinary function alone does not establish that scope. Scalar helpers and other
/// independently scoped kernels may remain calls.
///
/// # Examples
///
/// Instruction leaves define local operation types for their equivalent paths. Ordinary
/// generic functions compose them and return results directly:
///
/// ```
/// use commonware_simd::{IceLake, Operation, Simd};
///
/// fn foo<S: Simd>(value: S::U32) -> impl Operation<S, Output = S::U32> {
///     struct Foo<S: Simd>(S::U32);
///     impl<S: Simd> Operation<S> for Foo<S> {
///         type Output = S::U32;
///
///         fn portable(self, simd: S) -> S::U32 {
///             simd.u32_xor(self.0, simd.u32_splat(1))
///         }
///
///         fn ice_lake(self, simd: S) -> S::U32
///         where
///             S: IceLake,
///         {
///             simd.u32_ternary::<0x96>(self.0, simd.u32_splat(1), simd.u32_splat(0))
///         }
///     }
///     Foo::<S>(value)
/// }
///
/// #[inline(always)]
/// fn compose<S: Simd>(simd: S, value: S::U32) -> S::U32 {
///     let value = simd.execute(foo::<S>(value));
///     simd.u32_add(value, simd.u32_splat(1))
/// }
///
/// fn kernel<S: Simd>(simd: S, input: u32) -> S::U32 {
///     simd.execute(#[inline(always)] |simd: S| compose(simd, simd.u32_splat(input)))
/// }
/// ```
///
/// Register-capturing operations cannot execute on a different backend:
///
/// ```compile_fail
/// use commonware_simd::{IceLake, Operation, Simd, emulated::{EmulatedIceLake, EmulatedNeon}};
///
/// fn foo<S: Simd>(value: S::U32) -> impl Operation<S, Output = S::U32> {
///     struct Foo<S: Simd>(S::U32);
///     impl<S: Simd> Operation<S> for Foo<S> {
///         type Output = S::U32;
///
///         fn portable(self, simd: S) -> S::U32 {
///             simd.u32_xor(self.0, simd.u32_splat(1))
///         }
///
///         fn ice_lake(self, simd: S) -> S::U32
///         where
///             S: IceLake,
///         {
///             simd.u32_ternary::<0x96>(self.0, simd.u32_splat(1), simd.u32_splat(0))
///         }
///     }
///     Foo::<S>(value)
/// }
///
/// let value = EmulatedIceLake.u32_splat(1);
/// EmulatedNeon.execute(foo::<EmulatedIceLake>(value));
/// ```
pub trait Operation<S: Simd>: Sized {
    /// Result of every algorithm path for this backend.
    ///
    /// May contain backend-specific registers. Runtime dispatch and consistency checks
    /// require a common output type across the backends they execute.
    type Output;

    /// Executes using only common vector instructions and child operations.
    fn portable(self, simd: S) -> Self::Output;

    /// Executes the Ice Lake algorithm, defaulting to the portable algorithm.
    #[inline(always)]
    fn ice_lake(self, simd: S) -> Self::Output
    where
        S: IceLake,
    {
        self.portable(simd)
    }

    /// Executes the Armv9 with SVE2 algorithm, defaulting to the portable algorithm.
    #[inline(always)]
    fn arm_v9(self, simd: S) -> Self::Output
    where
        S: ArmV9,
    {
        self.portable(simd)
    }

    /// Executes the NEON algorithm, defaulting to the portable algorithm.
    #[inline(always)]
    fn neon(self, simd: S) -> Self::Output
    where
        S: Neon,
    {
        self.portable(simd)
    }
}

impl<S: Simd, R, F: FnMut(S) -> R> Operation<S> for F {
    type Output = R;

    #[inline(always)]
    fn portable(mut self, simd: S) -> R {
        self(simd)
    }
}
