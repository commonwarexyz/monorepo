//! Basic operations on bytes.
//!
//! This exists to abstract over the SIMD operations and intrinsics that vary by
//! backend. The operations are at the GF(2^8) level, and so for the 16 bit
//! version of ocelot, need to be combined. This is perhaps less optimal than
//! having a kernel for the exact field you need, but should not cost too much,
//! in exchange for having code reuse between the two field sizes.
//!
//! # Backends
//!
//! Each backend lives in its own submodule, and [`with_kernel`] selects the
//! best one available on the current CPU:
//!
//! - AVX-512: 64 bytes at a time on x86-64 CPUs with AVX-512F and GFNI.
//! - [`portable`]: scalar operations on 16 bytes at a time, with no platform
//!   requirements. This is the fallback when nothing better is available, and
//!   the reference other backends are tested against.

#[cfg(target_arch = "x86_64")]
mod avx512;
pub mod portable;
#[cfg(test)]
mod tests;

/// A computation which can run over an arbitrary [`Kernel`].
///
/// [`with_kernel`] hands its caller a kernel whose concrete type is only known
/// at runtime, so the computation must be generic over kernels. Plain closures
/// can't have generic call methods, so we use a trait instead: implement it on
/// a struct capturing the computation's inputs, and return its results from
/// [`Self::call`].
pub trait WithKernel {
    /// The result of the computation.
    type Output;

    /// Run the computation with a concrete kernel.
    fn call<K: Kernel>(self, kernel: K) -> Self::Output;
}

/// Run a computation with the best [`Kernel`] this CPU supports.
///
/// This is the only way to gain access to a kernel, so that accelerated
/// kernels are only constructed where their instructions are available.
pub fn with_kernel<F: WithKernel>(f: F) -> F::Output {
    #[cfg(target_arch = "x86_64")]
    if let Some(kernel) = avx512::Avx512::new() {
        // SAFETY: constructing `kernel` checked every feature enabled by its call method.
        return unsafe { kernel.call(f) };
    }
    f.call(portable::Portable)
}

pub trait Kernel: Copy + Default + Send + Sync + 'static {
    /// Run a computation with this kernel's target features enabled.
    #[inline]
    fn run<F: WithKernel>(self, f: F) -> F::Output {
        f.call(self)
    }

    /// The type we use to hold several bytes.
    type Vector: Copy + Send + Sync;

    /// The number of bytes in each [`Self::Vector`].
    ///
    /// Operations are performed in parallel on each lane.
    const LANES: usize;

    /// Minimum number of lanes accepted by the partial load/store operations.
    ///
    /// This must be positive and divide [`Self::LANES`].
    const PARTIAL_GRANULARITY: usize = Self::LANES;

    /// Whether to fuse GF(2^8) butterfly updates into one byte loop.
    const FUSED_BUTTERFLY: bool = false;

    /// A representation of a constant value used in each lane.
    ///
    /// This can just be [`Self::Vector`], if there's no advantage in a particular
    /// kernel to knowing this. In general, this can be helpful, so we make the
    /// distinction.
    type Constant: Copy;

    /// Take a single value, and prepare it as a constant in each lane.
    fn splat(self, x: u8) -> Self::Constant;

    /// Load a vector from exactly [`Self::LANES`] bytes.
    ///
    /// # Panics
    ///
    /// If `bytes.len() != Self::LANES`.
    fn load(self, bytes: &[u8]) -> Self::Vector;

    /// Load a non-empty prefix of a vector, setting inactive lanes to zero.
    ///
    /// `bytes.len()` must not exceed [`Self::LANES`] and must be a multiple of
    /// [`Self::PARTIAL_GRANULARITY`].
    #[inline]
    fn load_partial(self, bytes: &[u8]) -> Self::Vector {
        self.load(bytes)
    }

    /// Store a vector into exactly [`Self::LANES`] bytes.
    ///
    /// # Panics
    ///
    /// If `out.len() != Self::LANES`.
    fn store(self, a: Self::Vector, out: &mut [u8]);

    /// Store a non-empty prefix of a vector without writing inactive lanes.
    ///
    /// `out.len()` must not exceed [`Self::LANES`] and must be a multiple of
    /// [`Self::PARTIAL_GRANULARITY`].
    #[inline]
    fn store_partial(self, a: Self::Vector, out: &mut [u8]) {
        self.store(a, out);
    }

    /// Compute the xor operation a ^ b, in each lane.
    ///
    /// This is also, conveniently, addition in GF(2^8).
    fn xor(self, a: Self::Vector, b: Self::Vector) -> Self::Vector;

    /// Xor all of the bytes in this vector together.
    fn xor_fold(self, a: Self::Vector) -> u8;

    /// Perform a GF(2^8) multiplication in each lane.
    ///
    /// This is modulo the AES polynomial of 0x11b.
    fn gf8_mul_vec(self, a: Self::Vector, b: Self::Vector) -> Self::Vector;

    /// Perform a GF(2^8) multiplication by a constant in each lane.
    fn gf8_mul_constant(self, a: Self::Vector, b: Self::Constant) -> Self::Vector;
}
