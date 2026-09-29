//! Abstract over SIMD operations.
//!
//! # Design
//!
//! The proposed design separates instruction semantics, algorithm implementations, and
//! execution. The crate currently contains no implementation; the names and signatures below
//! are sketches for a prototype.
//!
//! ## Instruction profiles
//!
//! Operations expose a fixed set of algorithm paths: portable, AVX-512, and NEON. Each path is
//! generic over a trait describing the instructions it may use. `Simd` provides the portable
//! baseline; the accelerated profiles extend it and target the following deployment platforms:
//!
//! - `Avx512`: 512-bit AVX-512F operations, GFNI byte arithmetic, and AVX-512 IFMA's 52-bit
//!   multiply-accumulates. This is a crate-defined bundle; AVX-512F alone does not imply GFNI
//!   or IFMA support. Any additional AVX-512 subsets required by modeled operations must also
//!   be documented and checked.
//! - `Neon`: AArch64 NEON operations.
//!
//! GFNI and IFMA can remain separate instruction capabilities composed into `Avx512`. Profiles
//! describe explicit feature sets rather than a hierarchy of CPU generations, whose supported
//! instructions need not increase monotonically. AVX2 is not an initial accelerated target.
//!
//! The accelerated profiles have native and bit-exact emulated implementations. Emulation preserves
//! lane widths, wrapping arithmetic, truncation, shuffle domains, masks, and memory-access behavior.
//! Algorithms can use different vector widths and instruction schedules for different profiles.
//! The emulator allows every profile to run on any host.
//!
//! ## Concrete backends
//!
//! The prototype uses concrete backend types: `Portable`, `NativeAvx512`, `EmulatedAvx512`,
//! `NativeNeon`, and `EmulatedNeon`. Each type acts as an execution token and implements its
//! instruction capabilities. `Avx512` and `Neon` are capability traits; `NativeAvx512` and
//! `EmulatedAvx512` both implement `Avx512`, so a generic AVX-512 algorithm can run with either.
//! Vector and mask representations are associated types of the instruction traits. Native and
//! emulated backends can use different representations while preserving the same lane semantics.
//!
//! `Portable` exposes platform-independent vector operations through `Simd`. Its implementation
//! may use compiler vectorization or scalar lanes; portability does not promise that every
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
//! A concrete backend token implements `Executor` and its instruction traits. `Simd` extends
//! `Executor`; `Avx512` and `Neon` extend `Simd`. Native tokens have private construction and are
//! obtained only after establishing the required CPU features. Their execution methods invoke
//! the corresponding operation path through crate-owned target-feature wrappers. Portable and
//! emulated tokens invoke their paths without requiring those hardware features.
//!
//! Computations implement one `Operation` trait, capturing their arguments and defining a common
//! output type. The portable implementation is required. AVX-512 and NEON methods have portable
//! defaults, so an operation only overrides the paths it specializes. Each specialized algorithm
//! is generic over its instruction profile and shared between native and emulated providers.
//!
//! ```rust,ignore
//! pub trait Operation: Sized {
//!     type Output;
//!
//!     fn portable<S: Simd>(self, s: S) -> Self::Output;
//!
//!     fn avx512<S: Avx512>(self, s: S) -> Self::Output {
//!         self.portable(s)
//!     }
//!
//!     fn neon<S: Neon>(self, s: S) -> Self::Output {
//!         self.portable(s)
//!     }
//! }
//!
//! pub trait Executor: Copy + Sized {
//!     fn execute<O: Operation>(self, operation: O) -> O::Output;
//! }
//! ```
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
//! `Executor::execute` selects a path statically for its concrete token: `Portable` invokes
//! `portable`, both AVX-512 tokens invoke `avx512`, and both NEON tokens invoke `neon`. Generic
//! composition only needs `Simd`, which provides instruction access and execution of child operations:
//!
//! ```rust,ignore
//! fn composed<S: Simd>(s: S, input: &[u8]) -> Output {
//!     let intermediate = s.execute(foo(input));
//!     s.execute(bar(intermediate))
//! }
//! ```
//!
//! A parent operation can implement only `portable` and call such a composition function. Its
//! default accelerated methods preserve the supplied token, so specialized children still take
//! that token's accelerated path. The portable entry point constrains the instructions used by
//! the parent; it does not force child operations to use their portable paths. Leaf operations
//! without specializations use their portable defaults. This requires neither trait-implementation
//! discovery nor overlapping fallback implementations.
//!
//! A crate-owned dispatcher selects an available native token or `Portable` at the outer boundary
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
//! Executors establish the target-feature scope around bulk computations, including when
//! re-entering from surrounding code that has been outlined. This re-entry does not repeat CPU
//! detection. Holding a token does not propagate compiler target features to arbitrary callees;
//! native instruction helpers must remain sound independently of inlining. Small components
//! should inline within the feature scope, but Rust does not guarantee inlining, so representative
//! cross-crate compositions need emitted-code and performance checks.
//! Composing buffer operations also does not automatically fuse their loops; vector-level
//! components can be combined inside a shared loop to avoid intermediate memory passes.
//!
//! ## Consistency testing
//!
//! A differential helper takes an operation factory and compares execution through `Portable`,
//! `EmulatedAvx512`, and `EmulatedNeon` without requiring native hardware. It exercises the same
//! execution entry points as production, including specialized children and portable defaults
//! throughout composed operations:
//!
//! ```rust,ignore
//! simd::test::check_consistent(|| foo(&input));
//! ```
//!
//! The factory constructs independent operations with identical initial state for each execution.
//! It avoids requiring operations with mutable references to be cloneable. The helper compares
//! observable results: return values, errors, and modified buffers, including partial writes on
//! failure. Tests of borrowed buffers need an adapter that owns each execution's state and returns
//! a snapshot for comparison. Merely comparing a return value would miss divergent buffer writes.
//! The comparison may use semantic equality when valid representations differ, such as canonical
//! field equality. Backend vector representations do not need to be comparable across backends.
//! A portable-only leaf may run the same algorithm three times, while a parent with only portable
//! orchestration can still exercise different specialized children. Testing composed operations
//! is therefore useful in addition to testing leaves.
//!
//! A fuzz harness generates inputs and calls this helper. Tests should include boundary values
//! for carries, truncation, shuffles, masks, and partial memory operations. Agreement between
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
//! 1. Define the `Avx512` (including GFNI and IFMA) and `Neon` profiles and precise primitive
//!    semantics, starting with operations needed by existing erasure-coding or curve-arithmetic
//!    kernels. Retain `Simd` as the portable fallback and consistency reference.
//! 2. Implement the concrete `Portable`, `NativeAvx512`, `EmulatedAvx512`, `NativeNeon`, and
//!    `EmulatedNeon` backends, with associated vector types and instruction-level hardware tests.
//! 3. Prototype the fixed-profile `Operation` methods and defaults, `Executor`, and the instruction
//!    hierarchy `Simd: Executor`, `Avx512: Simd`, and `Neon: Simd`. Add opaque operation constructors
//!    and a crate-owned outer dispatcher. Validate generic composition with specialized leaves
//!    under a parent that only implements portable orchestration, without consumer-side macros.
//! 4. Add the fixed-profile consistency helper and differential fuzz coverage for both leaves and
//!    composed operations, including observable mutable state. Keep hardware primitive validation
//!    separate and verify that native tests actually execute the selected hardware path.
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
