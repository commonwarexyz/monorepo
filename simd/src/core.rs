//! Vector instruction profiles and operation execution.

/// Common vector instructions and execution of operations through a backend token.
///
/// Instructions may be implemented with native SIMD or scalar emulation. [`Self::execute`]
/// selects this backend's operation path without repeating runtime backend selection.
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
/// use commonware_simd::Simd;
///
/// fn add<S: Simd>(s: S, a: &[u64], b: &[u64], output: &mut [u64]) {
///     let sum = s.u64_add(s.u64_load(a), s.u64_load(b));
///     s.u64_store(sum, output);
/// }
/// ```
pub trait Simd: Copy {
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
/// This profile models 512-bit vectors with eight unsigned 64-bit lanes. Native
/// implementations require AVX-512F, GFNI, and AVX-512 IFMA. Additional instruction
/// methods and their feature requirements will be defined as kernels are integrated.
/// The name identifies an instruction bundle, not a required CPU vendor or model.
pub trait IceLake: Simd {}

/// Armv9-A with SVE2 instruction profile implemented by native and emulated backend tokens.
///
/// Native implementations require SVE and SVE2 explicitly; an Armv9 architecture label
/// alone does not establish their availability. Optional SVE2 extensions and vector-length
/// handling will be defined as kernels are integrated. This profile does not imply a
/// fixed vector width or a particular CPU model.
pub trait ArmV9: Simd {}

/// AArch64 NEON instruction profile implemented by native and emulated backend tokens.
///
/// This profile models 128-bit vectors with two unsigned 64-bit lanes. Additional
/// instruction methods will be defined as kernels are integrated.
pub trait Neon: Simd {}

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
