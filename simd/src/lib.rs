//! Abstract over SIMD operations.
//!
//! # Design
//!
//! The proposed design separates instruction semantics, algorithm implementations, and
//! execution. [`Simd`] defines the common instruction and execution interface, and
//! [`Operation`] defines equivalent algorithm paths. The concrete backends, accelerated
//! instructions, and dispatch signatures below remain a prototype.
//!
//! ## Instruction profiles
//!
//! Operations expose a fixed set of algorithm paths: portable, Ice Lake, Armv9, and NEON.
//! Each path is generic over a trait describing the instructions it may use. `Simd` provides
//! the common vector instructions and execution of child operations. Accelerated profiles extend
//! `Simd` and target the following deployment platforms:
//!
//! - `IceLake`: 512-bit AVX-512F and AVX-512BW operations, GFNI byte arithmetic, and AVX-512
//!   IFMA's 52-bit multiply-accumulates, and SHA-NI on separate 128-bit vectors. This is a crate-defined bundle; AVX-512F alone does not imply GFNI,
//!   IFMA, or SHA support. Any additional AVX-512 subsets required by modeled operations must also
//!   be documented and checked.
//! - `ArmV9`: Baseline NEON plus SVE and SVE2 explicitly required. Logical vectors have
//!   128 bits; native instructions use the low 128 bits of SVE registers. Optional SVE2
//!   extensions must be documented and checked separately.
//! - `Neon`: Baseline AArch64 NEON operations on 128-bit vectors.
//!
//! Profiles describe checked instruction bundles, not required CPU models or vendors. A backend
//! can implement a profile whenever it satisfies that contract. CPU generations do not imply
//! monotonically increasing feature support. AVX2 is not an initial accelerated target.
//!
//! Algorithms specialize when additional instructions change their strategy. Different vector
//! widths alone do not require a separate algorithm: common instruction loops remain generic
//! over `Simd`. NEON operations can use the portable default until a distinct strategy is needed.
//!
//! The accelerated profiles have native and bit-exact emulated implementations. Emulation preserves
//! lane widths, wrapping arithmetic, truncation, shuffle domains, masks, and memory-access behavior.
//! Algorithms can use different vector widths and instruction schedules for different profiles.
//! The emulator allows every profile to run on any host.
//!
//! ## Concrete backends
//!
//! [`emulated`] provides array-backed `EmulatedScalar`, `EmulatedIceLake`, `EmulatedArmV9`, and
//! `EmulatedNeon` execution tokens.
//! [`native`] provides checked NEON and Armv9 tokens on AArch64 and an Ice Lake token on x86-64.
//! With the default `std` feature, construction detects CPU support at runtime. Without `std`,
//! construction requires the instruction bundle to be enabled at compile time.
//! Each token implements its instruction profile, so a generic profile algorithm can run
//! with either a native or an emulated provider.
//! Vector and mask representations are associated types of the instruction traits. Native and
//! emulated backends can use different representations while preserving the same lane semantics.
//! Ice Lake uses eight `u64` lanes; NEON uses two. [`emulated::EmulatedArmV9`] uses two lanes,
//! matching Graviton4's 128-bit SVE vectors. Native Armv9 uses the same logical width at every
//! supported SVE vector length. Emulators preserve the modeled widths on any host, so tests
//! exercise each profile's vector boundaries and tail handling.
//!
//! `EmulatedScalar` implements the common vector operations through `Simd`. It may use
//! compiler vectorization or scalar lanes; portability does not promise that every
//! operation maps to one hardware instruction, even for small vectors. The architecture emulators
//! instead model the exact instructions and vector shapes used by the accelerated algorithms.
//! Comparing algorithms and checking native instructions against their emulators are distinct tests.
//!
//! Concrete types keep backend selection explicit. The operation's profile methods describe
//! instruction requirements, not concrete execution providers. A new provider of an existing
//! profile can execute existing algorithms without consumer changes. Adding an algorithm profile
//! is an explicit change to the common operation interface.
//!
//! ## Execution and composition
//!
//! A concrete backend token implements `Simd` and its accelerated instruction profiles, if any.
//! `Simd` supplies both common vector instructions and `execute`; no separate executor trait is
//! required. Native tokens have private construction and are obtained only after establishing
//! the required CPU features. Their execution methods invoke the corresponding operation path
//! through crate-owned target-feature wrappers. Scalar and emulated tokens invoke their paths
//! without requiring those hardware features.
//!
//! Computations that expose alternative algorithm paths implement `Operation`, capturing their
//! arguments and defining an output type for each backend. The portable implementation is required.
//! Ice Lake, Armv9, and NEON methods have portable defaults, so an operation only overrides
//! the paths it specializes. Each specialized algorithm is generic over its instruction profile and shared
//! between native and emulated providers.
//!
//! ### Kernels
//!
//! A kernel is a substantial SIMD computation whose hot instructions should be optimized
//! together, keeping intermediate values in registers where possible. Enter a kernel through
//! `simd.execute(#[inline(always)] |simd| ...)`. Functions and closures implementing
//! `FnMut(S) -> R` implement [`Operation`] through the portable path and are invoked once.
//! They preserve the selected backend so instruction leaves can still specialize.
//!
//! The token proves CPU support and preserves register types; it does not give ordinary
//! functions the backend's compiler target features. The closure body and small shared SIMD
//! helpers must inline into the native execution wrapper to share its feature context. Use
//! `#[inline(always)]` on the closure and hot generic helpers intended to join that context.
//! A reusable kernel can return `impl Operation<S>` containing the annotated closure,
//! allowing callers to write `simd.execute(kernel::<S>(arguments))`. The constructor
//! only captures arguments and need not inline. Its computation and hot helpers still
//! need to join the execution wrapper's feature context.
//!
//! Inlining the adapter does not force a large closure body to inline. A substantial helper
//! can instead establish its own execution boundary and remain a separate call. Scalar helpers
//! need neither. Inlining is a compiler hint, so verify important kernels with release assembly
//! and benchmarks rather than assuming every call or register spill disappears.
//!
//! ```rust,ignore
//! pub trait Simd: Copy {
//!     type U64: Copy;
//!     const U64_LANES: usize;
//!
//!     fn u64_load(self, input: &[u64]) -> Self::U64;
//!     fn u64_store(self, value: Self::U64, output: &mut [u64]);
//!     fn u64_splat(self, value: u64) -> Self::U64;
//!     fn u64_add(self, a: Self::U64, b: Self::U64) -> Self::U64;
//!
//!     fn execute<O: Operation<Self>>(self, operation: O) -> O::Output;
//! }
//!
//! pub trait IceLake: Simd {
//!     // AVX-512, GFNI, IFMA, and SHA-NI profile instructions.
//! }
//!
//! pub trait ArmV9: Neon {
//!     // SVE2 profile instructions.
//! }
//!
//! pub trait Neon: Simd {
//!     // NEON profile instructions.
//! }
//!
//! pub trait Operation<S: Simd>: Sized {
//!     type Output;
//!
//!     fn portable(self, simd: S) -> Self::Output;
//!
//!     fn ice_lake(self, simd: S) -> Self::Output where S: IceLake {
//!         self.portable(simd)
//!     }
//!
//!     fn arm_v9(self, simd: S) -> Self::Output where S: ArmV9 {
//!         self.portable(simd)
//!     }
//!
//!     fn neon(self, simd: S) -> Self::Output where S: Neon {
//!         self.portable(simd)
//!     }
//! }
//! ```
//!
//! The mutual references between `Simd` and `Operation` constrain methods; they do not form
//! circular supertrait bounds. Each concrete token implements `execute` by calling its chosen
//! operation entry point. The accelerated defaults call `portable` with that same token.
//!
//! Taking the operation by value permits owned inputs and borrowed mutable buffers without
//! allocating. Instruction leaves keep their operation type private inside an opaque constructor.
//! Ordinary generic functions compose those leaves and return results directly:
//!
//! ```
//! use commonware_simd::{IceLake, Operation, Simd};
//!
//! fn foo<S: Simd>(value: S::U32) -> impl Operation<S, Output = S::U32> {
//!     struct Foo<S: Simd>(S::U32);
//!     impl<S: Simd> Operation<S> for Foo<S> {
//!         type Output = S::U32;
//!
//!         fn portable(self, simd: S) -> S::U32 {
//!             simd.u32_xor(self.0, simd.u32_splat(1))
//!         }
//!
//!         fn ice_lake(self, simd: S) -> S::U32
//!         where
//!             S: IceLake,
//!         {
//!             simd.u32_ternary::<0x96>(self.0, simd.u32_splat(1), simd.u32_splat(0))
//!         }
//!     }
//!     Foo::<S>(value)
//! }
//!
//! fn compose<S: Simd>(simd: S, value: S::U32) -> S::U32 {
//!     let value = simd.execute(foo::<S>(value));
//!     simd.u32_add(value, simd.u32_splat(1))
//! }
//! ```
//!
//! `Simd::execute` selects a path statically for its concrete token: `EmulatedScalar` invokes
//! `portable`, both Ice Lake tokens invoke `ice_lake`, both Armv9 tokens invoke `arm_v9`, and
//! both NEON tokens invoke `neon`. Generic functions can use common instructions directly
//! without implementing `Operation`.
//!
//! `Operation<S>` can capture and return backend-specific registers such as `S::U32`.
//! Generic composition keeps those registers tied to the executing token. Runtime dispatch
//! and consistency checks require a common output across their enumerated backends; normalize
//! registers to buffers or scalar results at that outer boundary.
//!
//! Runtime dispatch and consistency checks need a universal operation type with a common
//! output. An explicit outer operation can implement `portable`, call the shared composition
//! function, and normalize its result. Its default accelerated methods preserve the supplied
//! token, so specialized children still take that token's accelerated path. The portable entry
//! point constrains the instructions used directly; it does not force children to use their
//! portable paths. Ordinary shared composition needs no parent operation.
//!
//! [`dispatch()`] selects a supported native backend, or `EmulatedScalar` at the outer boundary
//! and executes the root operation. The concrete token threads through the tree. Child calls to
//! `execute` repeat neither feature detection nor runtime backend selection and use static dispatch.
//! Passing a runtime enum through the tree and matching it at every child would lose this property.
//!
//! ```rust,ignore
//! // root constructs the universal operation that normalizes the composition result.
//! let output = simd::dispatch(root(input));
//! ```
//!
//! Native implementations of `execute` establish the target-feature scope for operations,
//! including when re-entering from surrounding code that has been outlined. This re-entry does
//! not repeat CPU detection. Ordinary functions receiving a token do not inherit target features;
//! native instruction helpers must remain sound independently of inlining. Small components
//! should inline within the feature scope, but Rust does not guarantee inlining, so representative
//! cross-crate compositions need emitted-code and performance checks.
//! Composing buffer operations also does not automatically fuse their loops; vector-level
//! components can be combined inside a shared loop to avoid intermediate memory passes.
//!
//! ### Bulk loops and shared algorithms
//!
//! Shared loops can remain ordinary generic functions receiving the existing token and executing
//! instruction leaves. When a bulk loop needs a feature scope around the whole computation,
//! an explicit operation can serve as a manual execution adapter: its `portable` method calls
//! the shared loop, and the caller enters through `simd.execute(...)`. This adapter has a distinct
//! feature-scope purpose; ordinary composition does not need it. Pass the existing token rather
//! than dispatching again, including from outlined functions or worker callbacks.
//!
//! Shared defaults and helpers containing vector arithmetic must inline into the native execution
//! entry to avoid a feature-gated call per vector. Start with `#[inline]`, and use
//! `#[inline(always)]` where emitted code shows it is needed. Neither hint guarantees inlining.
//! Native primitive bodies must also be available to the downstream optimizer. Inspect realistic
//! cross-crate kernels without LTO and with multiple codegen units for calls inside hot loops and
//! unnecessary vector spills; a call once per bulk operation can be acceptable.
//!
//! ## Consistency testing
//!
//! [`check_consistent`] takes an operation factory and compares scalar execution
//! with every emulated profile. It exercises `execute`,
//! including specialized children and portable defaults throughout composed operations:
//!
//! ```rust,ignore
//! // Each root owns independent state and returns a common output type.
//! simd::check_consistent(|| root(&input));
//! ```
//!
//! The factory constructs independent operations with identical initial state for each execution.
//! It avoids requiring operations with mutable references to be cloneable. The helper compares
//! observable results: return values, errors, and modified buffers, including partial writes on
//! failure. Tests of borrowed buffers need an adapter that owns each execution's state and returns
//! a snapshot for comparison. Merely comparing a return value would miss divergent buffer writes.
//! The comparison may use semantic equality when valid representations differ, such as canonical
//! field equality. Backend vector representations do not need to be comparable across backends.
//! A portable-only leaf runs the same algorithm at different widths. An outer normalization
//! operation can call shared composition that exercises specialized children. Testing these
//! compositions is therefore useful in addition to testing leaves.
//!
//! Consumers can exercise different algorithm strategies through the consistency helper.
//! Emulator-specific unit tests live in each backend's module and run on every host, including
//! checks against independent mathematical oracles.
//!
//! Instruction fuzz plans enter through [`dispatch()`] on each target platform and compare the
//! selected native backend directly with its matching emulator, using identical inputs for both
//! executions. Include boundary
//! values for carries, truncation, shuffles, masks, and partial memory operations.
//! This separates instruction correctness from consumer algorithm
//! correctness, provided both executions use the same generic algorithm and all hardware-specific
//! behavior goes through the modeled interface. A few native integration tests remain useful for
//! dispatch, feature scopes, memory layout, and compiler behavior. Consumer-specific assembly or
//! native-only algorithms need their own validation.
//! The goal is to keep the hardware test matrix in this crate; consumers can validate their
//! generic algorithms through emulation.
//!
//! ## Future work
//!
//! 1. Extend instruction coverage as real kernels require it, starting with erasure-coding,
//!    curve-arithmetic, and hashing operations.
//! 2. Validate every native profile on matching hardware. Armv9 currently exposes fixed 128-bit
//!    logical vectors rather than a scalable SVE vector interface.
//! 3. Migrate consumers to opaque operation constructors and shared generic algorithms.
//!    Preserve generic composition with specialized children under portable parent defaults.
//! 4. Use [`check_consistent`] in shared fuzz plans when specific instructions enable
//!    meaningful alternative strategies, including observable mutable state. Keep hardware
//!    primitive validation separate and verify that native tests execute the selected path.
//! 5. Integrate a real composed kernel and verify nested and cross-crate code generation and
//!    performance. Use the results to refine the API before expanding instruction coverage.
//! 6. Explore narrower capability declarations within the fixed profiles after the prototype.
//!    Helper bounds can restrict instruction use, but changing an operation method's requirements
//!    needs an explicit interface design. Do not assume Rust can enumerate trait implementations
//!    or automatically select an optional specialization. Keep profile selection explicit.
//! 7. Explore symbolic or concolic execution after the emulation prototype. These require
//!    modeled inputs, arithmetic, memory, and branches; a dispatcher alone cannot observe ordinary
//!    Rust execution. A broader algorithm-testing framework is a subsequent target.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
extern crate std;

// Consumer primitive inventory.
// Ocelot reference: PR #4823, commit b6b08b0f7aa59805a38a12e98108010f993a7877:
// https://github.com/commonwarexyz/monorepo/blob/b6b08b0f7aa59805a38a12e98108010f993a7877/coding/src/ocelot/kernel/avx512.rs
// Curve references: cryptography/curve25519/src/curve/{avx512,neon}.rs.
// A dash means the operation is unused by that kernel, not unsupported by the architecture.
//
// | Operation | Ocelot AVX-512 | curve25519 AVX-512 | curve25519 NEON |
// | --- | --- | --- | --- |
// | Full unaligned load/store | 64 byte lanes | 8 u64 lanes | 2 u64 lanes |
// | Zero-filled partial load / partial store | Masked epi32 memory operations; 4-byte prefix granularity | - | - |
// | Zero and scalar broadcast | Repeated byte constants | Zero and repeated u64 constants | Zero and repeated u64 constants |
// | Bitwise XOR | Field addition and accumulation | - | - |
// | Horizontal byte XOR | Checksum reduction; currently store then fold | - | - |
// | Bitwise AND | - | Limb masks | Limb and digit masks |
// | Bitwise OR | - | - | Recombine reduced digits |
// | Wrapping u64 add/subtract | - | Field arithmetic and carries | Field arithmetic and carries |
// | Immediate logical u64 shifts | - | Carries, scaling, product reconstruction | Carries, digit splitting, scaling |
// | Wrapping u32 addition and immediate left shift | - | - | Scale multiplication digits |
// | GF(256) byte multiplication | gf2p8mul_epi8; vector and broadcast-constant operands | - | - |
// | IFMA52 low/high multiply-accumulate | - | madd52lo_epu64, madd52hi_epu64 | - |
// | Truncating u64 -> u32 narrowing | - | - | vmovn_u64; also shift-then-narrow |
// | Unsigned widening u32 * u32 -> u64 | - | - | vmull_u32; scalar-constant variant |
// | Widening multiply-accumulate into u64 | - | - | vmlal_u32 |
// | Selection | - | Whole-u64-lane mask blend | Bitwise select, currently whole-lane masks |
// | Lane insertion/extraction | - | - | Pack/unpack two field elements at boundaries |
//
// Ocelot uses the AES polynomial basis (modulus 0x11b), matching GFNI multiplication directly.
// Its GF16 algorithms compose GF8 multiplication and XOR over two byte planes; they do not
// require integer widening or GFNI affine transforms. The current PR has portable and AVX-512
// kernels only. An Ocelot NEON instruction schedule remains to be chosen.
//
// IFMA multiplies the low 52 bits of each source, selects the low or high 52-bit product half,
// and adds into the full wrapping u64 accumulator. NEON widening consumes two u32 lanes and
// produces two u64 lanes; narrowing truncates rather than saturating. Model lane-mask blending
// separately from bitwise selection with arbitrary partial masks.
//
// Ocelot currently requires AVX-512F + GFNI, and curve25519 requires AVX-512F + IFMA. Ocelot's
// dword-masked memory operations avoid requiring AVX-512BW. Check any additional feature
// requirements when introducing new instructions. Field reduction, GF16 multiplication,
// butterflies, and curve formulas remain algorithms built from these primitives. Scaling by
// 19 can use shifts and additions, with native code generation checked against existing kernels.

commonware_macros::stability_scope!(ALPHA {
    #[cfg(test)]
    mod operation_tests;
    mod consistency;
    pub use consistency::check_consistent;
    mod core;
    pub use core::{ArmV9, IceLake, Neon, Operation, Simd};
    mod dispatch;
    pub use dispatch::dispatch;
    pub mod emulated;
    pub mod native;
    #[cfg(any(test, feature = "fuzz"))]
    pub mod fuzz;
});
