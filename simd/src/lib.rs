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
//! - `IceLake`: 512-bit AVX-512F operations, GFNI byte arithmetic, and AVX-512 IFMA's 52-bit
//!   multiply-accumulates. This is a crate-defined bundle; AVX-512F alone does not imply GFNI
//!   or IFMA support. Any additional AVX-512 subsets required by modeled operations must also
//!   be documented and checked.
//! - `ArmV9`: Armv9-A with SVE and SVE2 explicitly required. Optional SVE2 extensions must
//!   be documented and checked separately. The profile does not imply a fixed vector width.
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
//! `native::NativeNeon` provides native NEON execution on AArch64 after checking CPU support.
//! Native providers remain proposed for Ice Lake and Armv9.
//! Each token implements its instruction profile, so a generic profile algorithm can run
//! with either a native or an emulated provider.
//! Vector and mask representations are associated types of the instruction traits. Native and
//! emulated backends can use different representations while preserving the same lane semantics.
//! Ice Lake uses eight `u64` lanes; NEON uses two. [`emulated::EmulatedArmV9`] uses two lanes,
//! matching Graviton4's 128-bit SVE vectors. Native SVE vector-length
//! handling remains to be defined. Emulators preserve the modeled widths on any host, so tests
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
//! arguments and defining a common output type. The portable implementation is required.
//! Ice Lake, Armv9, and NEON methods have portable defaults, so an operation only overrides
//! the paths it specializes. Each specialized algorithm is generic over its instruction profile and shared
//! between native and emulated providers.
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
//!     fn execute<O: Operation>(self, operation: O) -> O::Output;
//! }
//!
//! pub trait IceLake: Simd {
//!     // AVX-512, GFNI, and IFMA profile instructions.
//! }
//!
//! pub trait ArmV9: Simd {
//!     // SVE2 profile instructions.
//! }
//!
//! pub trait Neon: Simd {
//!     // NEON profile instructions.
//! }
//!
//! pub trait Operation: Sized {
//!     type Output;
//!
//!     fn portable<S: Simd>(self, s: S) -> Self::Output;
//!
//!     fn ice_lake<S: IceLake>(self, s: S) -> Self::Output {
//!         self.portable(s)
//!     }
//!
//!     fn arm_v9<S: ArmV9>(self, s: S) -> Self::Output {
//!         self.portable(s)
//!     }
//!
//!     fn neon<S: Neon>(self, s: S) -> Self::Output {
//!         self.portable(s)
//!     }
//! }
//! ```
//!
//! The mutual references between `Simd` and `Operation` constrain methods; they do not form
//! circular supertrait bounds. Each concrete token implements `execute` by calling its chosen
//! operation entry point. The accelerated defaults call `portable` with that same token.
//!
//! Taking the operation by value permits owned inputs and borrowed mutable buffers without
//! allocating. A module can keep its operation type private and expose an opaque constructor:
//!
//! ```rust,ignore
//! pub fn foo(input: &[u8]) -> impl Operation<Output = Output> + '_ {
//!     Foo { input }
//! }
//! ```
//!
//! `Simd::execute` selects a path statically for its concrete token: `EmulatedScalar` invokes
//! `portable`, both Ice Lake tokens invoke `ice_lake`, both Armv9 tokens invoke `arm_v9`, and
//! both NEON tokens invoke `neon`. Generic functions can use common instructions directly
//! without implementing `Operation`:
//!
//! ```rust,ignore
//! fn double<S: Simd>(s: S, input: &[u64], output: &mut [u64]) {
//!     let value = s.u64_load(input);
//!     s.u64_store(s.u64_add(value, value), output);
//! }
//! ```
//!
//! Ordinary functions bounded only by `Simd` can also execute specialized child operations:
//!
//! ```rust,ignore
//! fn composed<S: Simd>(s: S, input: &[u8]) -> Output {
//!     let intermediate = s.execute(foo(input));
//!     s.execute(bar(intermediate))
//! }
//! ```
//!
//! Operation boundaries normally exchange buffers or scalar results. `Operation::Output` must
//! be common to all profiles; backend-specific vectors instead compose inside generic functions.
//!
//! A parent operation can implement only `portable` and call such a composition function. Its
//! default accelerated methods preserve the supplied token, so specialized children still take
//! that token's accelerated path. The portable entry point constrains the instructions used by
//! the parent; it does not force child operations to use their portable paths. Leaf operations
//! without specializations use their portable defaults. This requires neither trait-implementation
//! discovery nor overlapping fallback implementations.
//!
//! [`dispatch()`] selects native NEON when supported, or `EmulatedScalar` at the outer boundary
//! and executes the root operation. The concrete token threads through the tree. Child calls to
//! `execute` repeat neither feature detection nor runtime backend selection and use static dispatch.
//! Passing a runtime enum through the tree and matching it at every child would lose this property.
//!
//! ```rust,ignore
//! let output = simd::dispatch(foo(input));
//! ```
//!
//! The crate should encapsulate the backend adapters and target-feature wrappers used by
//! Curve25519's `WithBackend` and Ocelot's `WithKernel` patterns. Consumers implement algorithms,
//! without repeating that plumbing or requiring macros to generate it. Generic callback traits
//! or concrete closures can bridge the outer dispatch boundary; ordinary closures cannot have
//! call methods generic over backend types.
//!
//! Native implementations of `execute` establish the target-feature scope around bulk
//! computations, including when re-entering from surrounding code that has been outlined.
//! This re-entry does not repeat CPU detection. Holding a token does not propagate compiler
//! target features to arbitrary callees;
//! native instruction helpers must remain sound independently of inlining. Small components
//! should inline within the feature scope, but Rust does not guarantee inlining, so representative
//! cross-crate compositions need emitted-code and performance checks.
//! Composing buffer operations also does not automatically fuse their loops; vector-level
//! components can be combined inside a shared loop to avoid intermediate memory passes.
//!
//! ## Consistency testing
//!
//! [`check_consistent`] takes an operation factory and compares scalar execution
//! with every emulated profile. It exercises `execute`,
//! including specialized children and portable defaults throughout composed operations:
//!
//! ```rust,ignore
//! simd::check_consistent(|| foo(&input));
//! ```
//!
//! The factory constructs independent operations with identical initial state for each execution.
//! It avoids requiring operations with mutable references to be cloneable. The helper compares
//! observable results: return values, errors, and modified buffers, including partial writes on
//! failure. Tests of borrowed buffers need an adapter that owns each execution's state and returns
//! a snapshot for comparison. Merely comparing a return value would miss divergent buffer writes.
//! The comparison may use semantic equality when valid representations differ, such as canonical
//! field equality. Backend vector representations do not need to be comparable across backends.
//! A portable-only leaf runs the same algorithm at different widths, while a parent with only portable
//! orchestration can still exercise different specialized children. Testing composed operations
//! is therefore useful in addition to testing leaves.
//!
//! Once specific profile instructions are available, simple operations such as a hash can
//! exercise different strategies through the consistency helper. Shared fuzz plans should
//! generate inputs once for all executions and include boundary values for carries,
//! truncation, shuffles, masks, and partial memory operations. Agreement between
//! implementations does not replace an independent mathematical oracle.
//!
//! Native instruction tests belong in this crate and compare each hardware primitive with its
//! emulator on supported hosts. This separates instruction correctness from consumer algorithm
//! correctness, provided both executions use the same generic algorithm and all hardware-specific
//! behavior goes through the modeled interface. A few native integration tests remain useful for
//! dispatch, feature scopes, memory layout, and compiler behavior. Consumer-specific assembly or
//! native-only algorithms need their own validation.
//!
//! ## Future work
//!
//! 1. Define instructions for the `IceLake`, `ArmV9`, and `Neon` profiles and precise primitive
//!    semantics, starting with operations needed by existing erasure-coding or curve-arithmetic
//!    kernels. Extend [`Simd`]'s common instructions as needed.
//! 2. Extend native backends and instruction-level hardware tests beyond NEON. Define native SVE
//!    vector-length handling for `ArmV9` and extend emulation as profile instructions are added.
//! 3. Add opaque operation constructors for real kernels and extend native dispatch as backends land.
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

// TODO: Use this primitive inventory when implementing the instruction traits and emulators.
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
    mod consistency;
    pub use consistency::check_consistent;
    mod core;
    pub use core::{ArmV9, IceLake, Neon, Operation, Simd};
    pub mod dispatch;
    pub use dispatch::dispatch;
    pub mod emulated;
    pub mod native;
    #[cfg(any(test, feature = "fuzz"))]
    pub mod fuzz;
});
