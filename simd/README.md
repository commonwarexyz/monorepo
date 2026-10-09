# commonware-simd

[![Crates.io](https://img.shields.io/crates/v/commonware-simd.svg)](https://crates.io/crates/commonware-simd)
[![Docs.rs](https://docs.rs/commonware-simd/badge.svg)](https://docs.rs/commonware-simd)

Abstract over SIMD operations.

In order to perform more operations per second, modern CPUs come equipped with
large SIMD (Single Instruction, Multiple Data) units; as the name suggests,
these units can operate on multiple units of data at a time, allowing for
higher throughput.

This crate makes it easy to write algorithms which take advantage of this extra
processing power.
Not only does it provide an abstraction for a subset of operations common to
most platforms, it also provides abstractions over operations only available
on specific platforms, and a means of composing these operations.
This lets you compose portable code and platform-specific code together,
letting you write performant and readable algorithms.

## Backends

This crate does not aim to implement every SIMD instruction that exists.
We focus on instructions that are useful in the rest of the codebase.
In particular, we don't imagine that floating-point instructions will be useful.

We also don't try to track every possible subset or iteration of particular
instruction sets.
For example, on x86, various iterations of SIMD exist---SSE2, AVX, AVX-512---
and some specialized instructions like GFNI, SHA-NI, etc. may not be available.
Rather than trying to target all the possible combinations of these, we instead
have a few "frontier" targets, which are platforms that are both widely available,
and have all the gadgets you might want to use.
We also support NEON for platforms such as Apple silicon that lack SVE2.

These platforms are:

- **Ice Lake**: x86-64 with AVX-512F, AVX-512BW, GFNI, AVX-512IFMA, SHA-NI,
  SSSE3, and SSE4.1.
- **NEON**: AArch64 with NEON and SHA2.
- **Armv9**: AArch64 with NEON, SHA2, SVE, and SVE2.

Being on this list means that we expose instructions beyond those which are supported
on every platform.
Algorithms can reasonably be expected to be optimized against these platforms,
and make use of these instructions.

It is nevertheless possible to benefit from SIMD-accelerated algorithms on
other platforms, without modifying those algorithms or this crate.
By implementing the portable subset for your backend of choice, you can benefit
from the cross-platform subset of SIMD, which is substantial!
This does not require modifying the crate at all, or any algorithms written
using the crate!
The only downside is that algorithms may not be aware of particular instructions
they could be using on your platform.

## Usage

Algorithms are written against the `Simd` trait, which defines vector types and
operations on them. The associated type `Simd::U64` holds multiple `u64` values,
referred to as "lanes", and operations usually affect each lane independently.

For example, addition wraps independently in each lane:

```rust
use commonware_simd::Simd;

#[inline(always)]
fn add<S: Simd>(simd: S, a: S::U64, b: S::U64) -> S::U64 {
    simd.u64_add(a, b)
}
```

The number of lanes varies by backend. Loads and stores use slices containing
at least `S::U64_LANES` elements; any extra elements are ignored. Process full
vectors and handle the remaining elements separately:

```rust
use commonware_simd::Simd;

#[inline(always)]
fn add_slices<S: Simd>(simd: S, a: &[u64], b: &[u64], output: &mut [u64]) {
    assert_eq!(a.len(), b.len());
    assert_eq!(a.len(), output.len());
    let full = a.len() / S::U64_LANES * S::U64_LANES;
    for i in (0..full).step_by(S::U64_LANES) {
        let sum = simd.u64_add(simd.u64_load(&a[i..]), simd.u64_load(&b[i..]));
        simd.u64_store(sum, &mut output[i..]);
    }
    for i in full..a.len() {
        output[i] = a[i].wrapping_add(b[i]);
    }
}
```

Slices need only their element type's alignment, not vector alignment. Aligning
buffers to vector boundaries can help performance, but is not required for correctness.
Use the lane count for each element type independently; backends need not use the
same vector width for `u8`, `u32`, and `u64`.

Functions that are generic over `Simd` compose naturally. The backend token is
copied into each helper:

```rust
use commonware_simd::Simd;

#[inline(always)]
fn add<S: Simd>(simd: S, a: S::U64, b: S::U64) -> S::U64 {
    simd.u64_add(a, b)
}

#[inline(always)]
fn add_three<S: Simd>(simd: S, a: S::U64, b: S::U64, c: S::U64) -> S::U64 {
    add(simd, add(simd, a, b), c)
}
```

### Operations

An `Operation` can define equivalent algorithms for different backends. Implement
`portable` using the common instructions, then optionally override `ice_lake`, `neon`, or
`arm_v9` to use that profile's extra instructions. Each specialized path defaults
to `portable` and must produce the same result.

Our addition example needs only common instructions. A function returning
`impl Operation<S>` can capture vector values such as `S::U64`:

```rust
use commonware_simd::{Operation, Simd};

fn add<S: Simd>(a: S::U64, b: S::U64) -> impl Operation<S, Output = S::U64> {
    #[inline(always)]
    move |simd: S| simd.u64_add(a, b)
}

fn kernel<S: Simd>(simd: S, a: S::U64, b: S::U64) -> S::U64 {
    simd.execute(add::<S>(a, b))
}
```

`Simd::execute` keeps the supplied backend when executing a child operation.
Vector types such as `S::U64` depend on the backend and cannot be passed to
another backend.

At the outer boundary, `dispatch` selects a native backend supported by the host,
falling back to scalar emulation.
The default `std` feature enables runtime CPU feature detection. Without `std`,
native backends require their features to be enabled at compile time.

Dispatch requires one operation that implements every candidate backend with a
common output type. Use a struct for this adapter, and return ordinary Rust
values such as `u64` or a buffer, rather than backend-specific vector types:

```rust
use commonware_simd::{Operation, Simd, dispatch};

struct Add(u64, u64);

impl<S: Simd> Operation<S> for Add {
    type Output = u64;

    fn portable(self, simd: S) -> u64 {
        simd.execute(#[inline(always)] |simd: S| {
            let sum = simd.u64_add(simd.u64_splat(self.0), simd.u64_splat(self.1));
            simd.u64_extract::<0>(sum)
        })
    }
}

assert_eq!(dispatch(Add(u64::MAX, 1)), 0);
```

Closures implementing `FnMut(S) -> R` also implement `Operation<S>`. They can
borrow mutable buffers and are called once per execution. A closure with a typed
backend parameter is useful inside a generic function:

```rust
use commonware_simd::Simd;

fn add_scalar<S: Simd>(simd: S, a: u64, b: u64) -> u64 {
    simd.execute(#[inline(always)] |simd: S| {
        let sum = simd.u64_add(simd.u64_splat(a), simd.u64_splat(b));
        simd.u64_extract::<0>(sum)
    })
}
```

Such a closure implements `Operation` for that particular backend; use the struct
adapter above when runtime dispatch requires several backend implementations.
Closures that only implement `FnOnce` are not supported.

### Testing

When testing an operation, check both that it agrees across backends and that it
matches an independent reference implementation.

Use `check_consistent` in a fuzz test to compare all emulated backends. Using the
`Add` operation above:

```rust
# use commonware_simd::{Operation, Simd};
# struct Add(u64, u64);
# impl<S: Simd> Operation<S> for Add {
#     type Output = u64;
#     fn portable(self, simd: S) -> u64 {
#         simd.execute(#[inline(always)] |simd: S| {
#             let sum = simd.u64_add(simd.u64_splat(self.0), simd.u64_splat(self.1));
#             simd.u64_extract::<0>(sum)
#         })
#     }
# }
use commonware_invariants::minifuzz;
use commonware_simd::check_consistent;

minifuzz::test(|u| {
    let a: u64 = u.arbitrary()?;
    let b: u64 = u.arbitrary()?;
    check_consistent(|| Add(a, b));
    Ok(())
});
```

The factory must create equivalent inputs each time, including fresh mutable
buffers. Include observable buffer changes in the output so they are compared.
These checks exercise different lane counts and specialized algorithm paths;
agreement alone does not prove that the algorithm is correct.

Use `test_dispatch` to compare the portable scalar result against a reference:

```rust
# use commonware_simd::{Operation, Simd};
# struct Add(u64, u64);
# impl<S: Simd> Operation<S> for Add {
#     type Output = u64;
#     fn portable(self, simd: S) -> u64 {
#         simd.execute(#[inline(always)] |simd: S| {
#             let sum = simd.u64_add(simd.u64_splat(self.0), simd.u64_splat(self.1));
#             simd.u64_extract::<0>(sum)
#         })
#     }
# }
use commonware_simd::test_dispatch;

for (a, b) in [(0, 0), (1, 2), (u64::MAX, 1), (u64::MAX, u64::MAX)] {
    assert_eq!(test_dispatch(Add(a, b)), a.wrapping_add(b));
}
```

`test_dispatch` always uses scalar emulation, so consumer test results are
consistent across platforms. Pair it with `check_consistent` even when an
operation uses only common instructions, to cover different vector sizes.
Emulation checks algorithm behavior; this crate's native tests and fuzz targets
check instruction implementations on supported hardware.

### Performance Footguns

Enter a whole SIMD kernel through `simd.execute(#[inline(always)] |simd| ...)`.
You can also define an `#[inline(always)]` function returning `impl Operation<S>`
and pass its result to `simd.execute`. Annotate the returned operation's body with
`#[inline(always)]` as well, as in the `add` example above.
Native execution establishes the required CPU target features at this boundary.
Passing a backend token to an ordinary helper does not give that helper the same
target features.

Annotate the closure body and hot shared SIMD helpers with `#[inline(always)]`
so they inline into that scope. Scalar helpers and independently scoped kernels
can remain function calls.

Pass vector values such as `S::U64` directly between helpers, as in `add_three`.
Avoid storing an intermediate vector to a slice just to load it again in the
next helper. Extract individual lanes or store the final vector when you need
ordinary Rust values or buffer output.

Reuse the backend token for child operations. Call `dispatch` once for the
whole computation, rather than inside a loop, to avoid repeated CPU detection.

## Status

Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.
