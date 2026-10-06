# commonware-simd

[![Crates.io](https://img.shields.io/crates/v/commonware-simd.svg)](https://crates.io/crates/commonware-simd)
[![Docs.rs](https://docs.rs/commonware-simd/badge.svg)](https://docs.rs/commonware-simd)

Abstract over SIMD operations.

## Backends

Native and array-backed emulated providers implement the same instruction contracts:

| Provider | Byte/u32/u64 lanes | Required instructions |
| --- | --- | --- |
| Scalar | 1/1/1 | None |
| NEON | 16/4/2 | Baseline AArch64 NEON |
| Armv9 | 16/4/2 | NEON, SVE, and SVE2; fixed 128-bit logical vectors |
| Ice Lake | 64/16/8 | AVX-512F, AVX-512BW, GFNI, AVX-512IFMA, and SHA-NI |

Ice Lake also provides a separate four-lane `u32` vector for SHA-256 rounds
and message scheduling.

The default `std` feature enables runtime detection. Without `std`, native
providers require the instruction bundle to be enabled at compile time.
Dispatch selects a supported native provider or falls back to scalar.

## Operations

`Operation<S>` ties captured registers and outputs to the executing backend.
Instruction leaves define their equivalent portable and specialized paths in a
local struct and implementation inside the constructor. Ordinary generic
functions compose those leaves and return results directly:

```rust
use commonware_simd::{IceLake, Operation, Simd};

fn foo<S: Simd>(value: S::U32) -> impl Operation<S, Output = S::U32> {
    struct Foo<S: Simd>(S::U32);
    impl<S: Simd> Operation<S> for Foo<S> {
        type Output = S::U32;

        fn portable(self, simd: S) -> S::U32 {
            simd.u32_xor(self.0, simd.u32_splat(1))
        }

        fn ice_lake(self, simd: S) -> S::U32
        where
            S: IceLake,
        {
            simd.u32_ternary::<0x96>(self.0, simd.u32_splat(1), simd.u32_splat(0))
        }
    }
    Foo::<S>(value)
}

#[inline(always)]
fn compose<S: Simd>(simd: S, value: S::U32) -> S::U32 {
    let value = simd.execute(foo::<S>(value));
    simd.u32_add(value, simd.u32_splat(1))
}

fn kernel<S: Simd>(simd: S, input: u32) -> S::U32 {
    simd.execute(#[inline(always)] |simd: S| compose(simd, simd.u32_splat(input)))
}
```

Enter a whole kernel through `simd.execute(#[inline(always)] |simd| ...)`. A kernel
is a substantial SIMD computation that keeps intermediates in registers.
Closures implement `Operation<S>` through `FnMut(S) -> R` and are invoked once
per execution. They can own and mutate inputs, borrow mutable buffers, and return
backend registers; closures that only implement `FnOnce` are excluded. Child
leaves still select the specialized path for the same backend.

Native execution establishes the backend's target-feature scope. The closure body
and hot shared SIMD helpers must inline into that scope; use `#[inline(always)]`
on both. Inlining the closure adapter alone does not force the body to inline.
Ordinary result-returning generic glue can compose leaves, but receiving the token
alone does not give a function its target features. Scalar helpers and other
independently scoped kernels may remain calls.

For a reusable kernel, return `impl Operation<S>` and keep its computation in an
annotated closure. This makes the execution boundary explicit at the call site:

```rust
use commonware_simd::{Operation, Simd};

fn add<S: Simd>(left: S::U32, right: S::U32) -> impl Operation<S, Output = S::U32> {
    #[inline(always)]
    move |simd: S| simd.u32_add(left, right)
}

fn caller<S: Simd>(simd: S, left: S::U32, right: S::U32) -> S::U32 {
    simd.execute(add::<S>(left, right))
}
```

The constructor only captures arguments and need not inline. The closure and any
hot helpers it calls still need to inline into the execution wrapper. Returning
an operation does not by itself make an outlined helper inherit target features.

`dispatch` and `check_consistent` require a universal
operation with the same output type across the backends they execute. At that
outer boundary, an explicit operation can call the shared composition function
and normalize registers to scalars or buffers. A typed closure implements
`Operation` for one backend; universal dispatch requires one value implementing
it for several backends. Use a local operation struct for that outer adapter,
then execute the typed closure kernel with its supplied `simd` token.

## Testing

Shared fuzz plans enter through `dispatch` to check composition and compare the
selected native backend directly with its matching emulator on real hardware. Run
the fuzzer on each target platform to validate that platform's compiled instructions.
Emulator-specific unit
tests live in that backend's module and run independently of CPU support.
Operation variants can be compared separately with `check_consistent`.

Hardware coverage belongs in this crate so consumers using the modeled interface
can check their algorithms with emulation rather than repeat the hardware matrix.

Run `just test -p commonware-simd` for unit tests and bounded fuzz checks. The
`simd/fuzz` target uses the same plans for continuous fuzzing.

## Status

Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.
