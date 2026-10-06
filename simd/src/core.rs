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
/// All arithmetic and bitwise operations act independently on corresponding lanes.
/// Lane zero corresponds to the first element loaded or stored.
///
/// Methods take an execution token by value so generic algorithms can use static
/// dispatch with a backend-specific vector representation.
///
/// # Examples
///
/// ```
/// use commonware_simd::Simd;
///
/// fn add<S: Simd>(s: S, a: &[u64], b: &[u64], output: &mut [u64]) {
///     let sum = s.u64_add(s.u64_load(a), s.u64_load(b));
///     s.u64_store(sum, output);
/// }
/// ```
pub trait Simd: Copy {
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

    /// Number of lanes in [`Self::U64`]. Must be greater than zero.
    const U64_LANES: usize;

    /// Loads the first [`Self::U8_LANES`] elements in order. Requires only `u8` alignment.
    /// Remaining elements are ignored.
    ///
    /// # Panics
    ///
    /// Panics if the input has too few elements.
    fn u8_load(self, input: &[u8]) -> Self::U8;

    /// Stores lanes into the first [`Self::U8_LANES`] elements in order.
    /// Requires only `u8` alignment; remaining elements are unchanged.
    ///
    /// # Panics
    ///
    /// Panics before writing if the output has too few elements.
    fn u8_store(self, value: Self::U8, output: &mut [u8]);

    /// Broadcasts `value` to every lane.
    fn u8_splat(self, value: u8) -> Self::U8;

    /// Computes bitwise XOR of corresponding lanes.
    fn u8_xor(self, a: Self::U8, b: Self::U8) -> Self::U8;

    /// Loads a prefix into the first lanes, filling remaining lanes with zero.
    /// Empty prefixes are allowed. Panics if `input.len() > Self::U8_LANES`.
    fn u8_load_partial(self, input: &[u8]) -> Self::U8;

    /// Stores the first `output.len()` lanes, including an empty prefix.
    /// Panics before writing if `output.len() > Self::U8_LANES`.
    fn u8_store_partial(self, value: Self::U8, output: &mut [u8]);

    /// Computes bitwise AND of corresponding lanes.
    fn u8_and(self, a: Self::U8, b: Self::U8) -> Self::U8;

    /// Shifts each byte lane left by `N`, truncating to eight bits.
    /// Panics if `N >= 8`.
    fn u8_shl<const N: u32>(self, value: Self::U8) -> Self::U8;

    /// Shifts each byte lane right by `N`, filling with zero.
    /// Panics if `N >= 8`.
    fn u8_shr<const N: u32>(self, value: Self::U8) -> Self::U8;

    /// XORs every byte lane into one byte.
    fn u8_xor_fold(self, value: Self::U8) -> u8;

    /// Loads the first [`Self::U32_LANES`] elements in order. Requires only `u32` alignment.
    /// Remaining elements are ignored.
    ///
    /// # Panics
    ///
    /// Panics if the input has too few elements.
    fn u32_load(self, input: &[u32]) -> Self::U32;

    /// Stores lanes into the first [`Self::U32_LANES`] elements in order.
    /// Requires only `u32` alignment; remaining elements are unchanged.
    ///
    /// # Panics
    ///
    /// Panics before writing if the output has too few elements.
    fn u32_store(self, value: Self::U32, output: &mut [u32]);

    /// Broadcasts `value` to every lane.
    fn u32_splat(self, value: u32) -> Self::U32;

    /// Computes bitwise XOR of corresponding lanes.
    fn u32_xor(self, a: Self::U32, b: Self::U32) -> Self::U32;

    /// Adds corresponding lanes, wrapping modulo `2^32`.
    fn u32_add(self, a: Self::U32, b: Self::U32) -> Self::U32;

    /// Rotates each lane right by `N` bits.
    ///
    /// # Panics
    ///
    /// Panics if `N >= 32`.
    fn u32_rotate_right<const N: u32>(self, value: Self::U32) -> Self::U32;

    /// Subtracts corresponding lanes, wrapping modulo `2^32`.
    fn u32_sub(self, a: Self::U32, b: Self::U32) -> Self::U32;

    /// Computes bitwise AND of corresponding lanes.
    fn u32_and(self, a: Self::U32, b: Self::U32) -> Self::U32;

    /// Computes bitwise OR of corresponding lanes.
    fn u32_or(self, a: Self::U32, b: Self::U32) -> Self::U32;

    /// Shifts lanes left by `N`, truncating to 32 bits. Panics if `N >= 32`.
    fn u32_shl<const N: u32>(self, value: Self::U32) -> Self::U32;

    /// Shifts lanes right by `N`, filling with zero. Panics if `N >= 32`.
    fn u32_shr<const N: u32>(self, value: Self::U32) -> Self::U32;

    /// Selects individual bits: `(mask & a) | (!mask & b)`.
    /// Arbitrary partial masks are supported, not just whole-lane masks.
    fn u32_select(self, mask: Self::U32, a: Self::U32, b: Self::U32) -> Self::U32;

    /// Permutes lanes across the entire vector: output lane `i` is `value[indices[i]]`.
    /// Reads the first `Self::U32_LANES` indices and ignores any remainder.
    /// Panics if there are too few indices or an active index is outside the vector.
    fn u32_permute(self, value: Self::U32, indices: &[usize]) -> Self::U32;

    /// Permutes across concatenated vectors `[a, b]`, using the same index contract
    /// as [`Self::u32_permute`] with indices below `2 * Self::U32_LANES`.
    fn u32_permute2(self, a: Self::U32, b: Self::U32, indices: &[usize]) -> Self::U32;

    /// Loads the first [`Self::U64_LANES`] elements in order.
    ///
    /// No alignment beyond that of `u64` is required. Remaining elements are ignored.
    ///
    /// # Panics
    ///
    /// Panics if `input` has fewer than [`Self::U64_LANES`] elements.
    fn u64_load(self, input: &[u64]) -> Self::U64;

    /// Stores lanes in order into the first [`Self::U64_LANES`] elements.
    ///
    /// No alignment beyond that of `u64` is required. Remaining elements are unchanged.
    ///
    /// # Panics
    ///
    /// Panics before writing if `output` has fewer than [`Self::U64_LANES`] elements.
    fn u64_store(self, value: Self::U64, output: &mut [u64]);

    /// Broadcasts `value` to every lane. Use zero to construct a zero vector.
    fn u64_splat(self, value: u64) -> Self::U64;

    /// Adds corresponding lanes, wrapping modulo `2^64`.
    fn u64_add(self, a: Self::U64, b: Self::U64) -> Self::U64;

    /// Shifts each lane left by `N` bits, filling vacated bits with zero.
    ///
    /// # Panics
    ///
    /// Panics if `N >= 64`.
    fn u64_shl<const N: u32>(self, value: Self::U64) -> Self::U64;

    /// Shifts each lane right by `N` bits, filling vacated bits with zero.
    ///
    /// # Panics
    ///
    /// Panics if `N >= 64`.
    fn u64_shr<const N: u32>(self, value: Self::U64) -> Self::U64;

    /// Computes bitwise AND of corresponding lanes.
    fn u64_and(self, a: Self::U64, b: Self::U64) -> Self::U64;

    /// Computes bitwise OR of corresponding lanes.
    fn u64_or(self, a: Self::U64, b: Self::U64) -> Self::U64;

    /// Subtracts corresponding lanes, wrapping modulo `2^64`.
    fn u64_sub(self, a: Self::U64, b: Self::U64) -> Self::U64;

    /// Computes bitwise XOR of corresponding lanes.
    fn u64_xor(self, a: Self::U64, b: Self::U64) -> Self::U64;

    /// Selects individual bits: `(mask & a) | (!mask & b)`.
    fn u64_select(self, mask: Self::U64, a: Self::U64, b: Self::U64) -> Self::U64;

    /// Returns lane `N`. Panics if `N >= Self::U64_LANES`.
    fn u64_extract<const N: usize>(self, value: Self::U64) -> u64;

    /// Replaces lane `N`, preserving every other lane.
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
    /// # Examples
    ///
    /// An ordinary generic function can execute a child operation without implementing
    /// [`Operation`] itself:
    ///
    /// ```
    /// use commonware_simd::{Operation, Simd};
    ///
    /// fn composed<S: Simd, O: Operation>(s: S, child: O) -> O::Output {
    ///     s.execute(child)
    /// }
    /// ```
    fn execute<O: Operation>(self, operation: O) -> O::Output;
}

/// Ice Lake instruction profile implemented by native and emulated backend tokens.
///
/// This profile models 512-bit vectors with 64 unsigned byte lanes, 16 unsigned
/// 32-bit lanes, and eight unsigned 64-bit lanes. Native implementations require
/// AVX-512F, AVX-512BW, GFNI, AVX-512 IFMA, and SHA.
/// The name identifies an instruction bundle, not a required CPU vendor or model.
pub trait IceLake: Simd {
    /// Four unsigned 32-bit lanes for 128-bit SHA instructions.
    type U32x4: Copy;

    /// Loads the first four elements in order, requiring only `u32` alignment.
    /// Ignores remaining elements. Panics if the input has fewer than four elements.
    fn u32x4_load(self, input: &[u32]) -> Self::U32x4;

    /// Stores four lanes in order, requiring only `u32` alignment.
    /// Leaves remaining elements unchanged. Panics before writing if output is too short.
    fn u32x4_store(self, value: Self::U32x4, output: &mut [u32]);

    /// Adds corresponding lanes, wrapping modulo `2^32`.
    fn u32x4_add(self, a: Self::U32x4, b: Self::U32x4) -> Self::U32x4;

    /// Selects each output lane with successive two-bit fields of `MASK`.
    /// Requires `0 <= MASK < 256`; invalid constants may be rejected at compile time
    /// or panic when emulated.
    fn u32x4_shuffle<const MASK: i32>(self, value: Self::U32x4) -> Self::U32x4;

    /// Performs Intel SHA256RNDS2: two SHA-256 rounds with `a = [H,G,D,C]`,
    /// `b = [F,E,B,A]`, and message-plus-constant sums in `k[0]` and `k[1]`.
    /// Returns updated `[F,E,B,A]`; ignores the upper two lanes of `k`.
    fn sha256_rounds2(self, a: Self::U32x4, b: Self::U32x4, k: Self::U32x4) -> Self::U32x4;

    /// Performs Intel SHA256MSG1: returns `a[i] + sigma0(next[i])` modulo `2^32`,
    /// where `next = [a[1],a[2],a[3],b[0]]` and
    /// `sigma0(x) = rotr7(x) ^ rotr18(x) ^ (x >> 3)`.
    fn sha256_msg1(self, a: Self::U32x4, b: Self::U32x4) -> Self::U32x4;

    /// Performs Intel SHA256MSG2: sets `r[0..2] = a[0..2] + sigma1(b[2..4])`,
    /// then `r[2..4] = a[2..4] + sigma1(r[0..2])`, all modulo `2^32`.
    /// Here `sigma1(x) = rotr17(x) ^ rotr19(x) ^ (x >> 10)`.
    fn sha256_msg2(self, a: Self::U32x4, b: Self::U32x4) -> Self::U32x4;

    /// Applies a three-input bit truth table, selecting bit `4*a + 2*b + c`
    /// of `MASK` for each corresponding input bit (Intel VPTERNLOGD).
    /// Requires `0 <= MASK < 256`; invalid constants may be rejected at compile time
    /// or panic when emulated.
    fn u32_ternary<const MASK: i32>(self, a: Self::U32, b: Self::U32, c: Self::U32) -> Self::U32;

    /// Shuffles bytes independently within each 128-bit group (Intel VPSHUFB).
    /// An index with bit 7 set produces zero; otherwise its low four bits select
    /// a byte in the corresponding group, ignoring bits 4 through 6.
    fn u8_shuffle128(self, value: Self::U8, indices: Self::U8) -> Self::U8;

    /// Selects four 128-bit groups (Intel VSHUFI32X4). Successive two-bit fields
    /// of `MASK` select any source group: output groups 0/1 use `a` and
    /// output groups 2/3 use `b`.
    /// Requires `0 <= MASK < 256`; invalid constants may be rejected at compile time
    /// or panic when emulated.
    fn u32_shuffle_groups<const MASK: i32>(self, a: Self::U32, b: Self::U32) -> Self::U32;

    /// Interleaves each 128-bit group's high 64-bit halves: `[a2,a3,b2,b3]`.
    fn u32_unpackhi64(self, a: Self::U32, b: Self::U32) -> Self::U32;

    /// Multiplies corresponding byte lanes in GF(256) with AES modulus `0x11b`.
    fn u8_gf_mul(self, a: Self::U8, b: Self::U8) -> Self::U8;

    /// Multiplies the low 52 bits of each source lane and adds the low 52 product bits
    /// into the full accumulator lane, wrapping modulo `2^64`.
    fn u64_madd52lo(self, acc: Self::U64, a: Self::U64, b: Self::U64) -> Self::U64;

    /// Multiplies the low 52 bits of each source lane and adds product bits 52..104
    /// into the full accumulator lane, wrapping modulo `2^64`.
    fn u64_madd52hi(self, acc: Self::U64, a: Self::U64, b: Self::U64) -> Self::U64;

    /// Shuffles four u32 lanes independently within every 128-bit group.
    /// Two bits of `MASK` select each output lane, starting with its low bits.
    /// Requires `0 <= MASK < 256`; invalid constants may be rejected at compile time
    /// or panic when emulated.
    fn u32_shuffle128<const MASK: i32>(self, value: Self::U32) -> Self::U32;

    /// Within each 128-bit group, selects output lanes 0/1 from `a` and 2/3 from `b`.
    /// The four two-bit selectors in `MASK` select the corresponding source lane.
    /// Requires `0 <= MASK < 256`; invalid constants may be rejected at compile time
    /// or panic when emulated.
    fn u32_shuffle2_128<const MASK: i32>(self, a: Self::U32, b: Self::U32) -> Self::U32;

    /// Within every four-lane group, selects `b` where the corresponding bit of
    /// `MASK` is set and `a` otherwise. Panics unless `0 <= MASK < 16`.
    fn u32_blend128<const MASK: i32>(self, a: Self::U32, b: Self::U32) -> Self::U32;

    /// Interleaves each group's low two u32 lanes: `[a0, b0, a1, b1]`.
    fn u32_unpacklo32(self, a: Self::U32, b: Self::U32) -> Self::U32;

    /// Interleaves each group's high two u32 lanes: `[a2, b2, a3, b3]`.
    fn u32_unpackhi32(self, a: Self::U32, b: Self::U32) -> Self::U32;

    /// Interleaves each group's low 64-bit halves: `[a0, a1, b0, b1]`.
    fn u32_unpacklo64(self, a: Self::U32, b: Self::U32) -> Self::U32;
}

/// Armv9-A with SVE2 instruction profile implemented by native and emulated backend tokens.
///
/// Requires baseline NEON plus SVE and SVE2 explicitly; an Armv9 architecture label
/// alone does not establish their availability. Logical vectors retain NEON's 128-bit
/// shape. Native providers use the low 128 bits of SVE registers, independently of
/// the thread's full SVE vector length. Optional SVE2 extensions require separate checks.
pub trait ArmV9: Neon {
    /// XORs corresponding lanes and rotates each result right by `N` bits.
    /// Models SVE2 XAR on u32 lanes. Panics if `N >= 32`.
    fn u32_xor_rotate_right<const N: u32>(self, a: Self::U32, b: Self::U32) -> Self::U32;
}

/// AArch64 NEON instruction profile implemented by native and emulated backend tokens.
///
/// This profile models 128-bit vectors with 16 unsigned byte lanes, four unsigned
/// 32-bit lanes, and two unsigned 64-bit lanes. Its narrowing and widening primitives
/// use a separate half-width vector with two unsigned 32-bit lanes.
pub trait Neon: Simd {
    /// Eight unsigned 16-bit lanes corresponding to one half of a byte vector.
    type U16: Copy;

    /// Looks up each index in the 16-byte table; indices >= 16 produce zero.
    fn u8_table_lookup(self, table: Self::U8, indices: Self::U8) -> Self::U8;

    /// Carryless polynomial multiplication of the low eight byte lanes, unreduced.
    fn u8_clmul_lo(self, a: Self::U8, b: Self::U8) -> Self::U16;

    /// Carryless polynomial multiplication of the high eight byte lanes, unreduced.
    fn u8_clmul_hi(self, a: Self::U8, b: Self::U8) -> Self::U16;

    /// Computes bitwise XOR of corresponding 16-bit lanes.
    fn u16_xor(self, a: Self::U16, b: Self::U16) -> Self::U16;

    /// Shifts lanes left by `N`, truncating to 16 bits. Panics if `N >= 16`.
    fn u16_shl<const N: u32>(self, value: Self::U16) -> Self::U16;

    /// Shifts lanes right by `N`, filling with zero. Panics if `N >= 16`.
    fn u16_shr<const N: u32>(self, value: Self::U16) -> Self::U16;

    /// Truncates low/high half-vectors to bytes and concatenates them in lane order.
    fn u16_narrow_pair(self, low: Self::U16, high: Self::U16) -> Self::U8;
    /// Vector of [`Self::U64_LANES`] unsigned 32-bit lanes, in matching lane order.
    /// This is half the width of the common [`Self::U32`] vector.
    type U32Half: Copy;

    /// Truncates each 64-bit lane to its low 32 bits.
    fn u64_narrow(self, value: Self::U64) -> Self::U32Half;

    /// Broadcasts `value` to every half-vector lane.
    fn u32_half_splat(self, value: u32) -> Self::U32Half;

    /// Adds corresponding half-vector lanes, wrapping modulo `2^32`.
    fn u32_half_add(self, a: Self::U32Half, b: Self::U32Half) -> Self::U32Half;

    /// Shifts each half-vector lane left by `N` bits, filling vacated bits with zero.
    ///
    /// # Panics
    ///
    /// Panics if `N >= 32`.
    fn u32_half_shl<const N: u32>(self, value: Self::U32Half) -> Self::U32Half;

    /// Multiplies corresponding unsigned 32-bit lanes into full 64-bit products.
    fn u32_widen_mul(self, a: Self::U32Half, b: Self::U32Half) -> Self::U64;

    /// Adds full unsigned widening products to wrapping 64-bit accumulators.
    fn u32_widen_madd(self, acc: Self::U64, a: Self::U32Half, b: Self::U32Half) -> Self::U64;
}

/// Equivalent algorithm paths selected by a concrete backend token.
///
/// The portable path is required. Accelerated paths default to it while preserving
/// the supplied token, so child operations can still select specialized paths.
/// Operations may capture owned inputs or borrowed mutable buffers.
///
/// # Examples
///
/// A parent can implement only the portable path and call an ordinary generic function
/// that executes a child. The child uses the original backend's operation path:
///
/// ```
/// use commonware_simd::{Operation, Simd};
///
/// fn composed<S: Simd, O: Operation>(s: S, child: O) -> O::Output {
///     s.execute(child)
/// }
///
/// struct Parent<O>(O);
///
/// impl<O: Operation> Operation for Parent<O> {
///     type Output = O::Output;
///
///     fn portable<S: Simd>(self, s: S) -> Self::Output {
///         composed(s, self.0)
///     }
/// }
/// ```
pub trait Operation: Sized {
    /// Result shared by all algorithm paths.
    ///
    /// Backend-specific vectors normally remain inside generic functions; operation
    /// boundaries exchange buffers or scalar results.
    type Output;

    /// Executes using only common vector instructions and child operations.
    fn portable<S: Simd>(self, s: S) -> Self::Output;

    /// Executes the Ice Lake algorithm, defaulting to the portable algorithm.
    fn ice_lake<S: IceLake>(self, s: S) -> Self::Output {
        self.portable(s)
    }

    /// Executes the Armv9 with SVE2 algorithm, defaulting to the portable algorithm.
    fn arm_v9<S: ArmV9>(self, s: S) -> Self::Output {
        self.portable(s)
    }

    /// Executes the NEON algorithm, defaulting to the portable algorithm.
    fn neon<S: Neon>(self, s: S) -> Self::Output {
        self.portable(s)
    }
}
