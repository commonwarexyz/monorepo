//! Platform-independent vector operations.

/// Platform-independent operations on vectors of unsigned 64-bit lanes.
///
/// Each implementation chooses its vector representation and a nonzero lane count.
/// Algorithms must use [`Self::U64_LANES`] rather than assume a particular width.
/// All arithmetic and bitwise operations act independently on corresponding lanes.
/// Lane zero corresponds to the first element loaded or stored.
///
/// Methods take an execution token by value so generic algorithms can use static
/// dispatch with a backend-specific vector representation.
///
/// # Examples
///
/// ```
/// use commonware_simd::Portable;
///
/// fn add<S: Portable>(s: S, a: &[u64], b: &[u64], output: &mut [u64]) {
///     let sum = s.u64_add(s.u64_load(a), s.u64_load(b));
///     s.u64_store(sum, output);
/// }
/// ```
pub trait Portable: Copy {
    /// Vector of [`Self::U64_LANES`] unsigned 64-bit lanes.
    type U64: Copy;

    /// Number of lanes in [`Self::U64`]. Must be greater than zero.
    const U64_LANES: usize;

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
}
