---
title: "Many Too Many"
description: "Taming SIMD backends with a new crate."
date: "October 15th, 2026"
published-time: "2026-10-15T00:00:00Z"
modified-time: "2026-10-15T00:00:00Z"
author: "Lucas Meier"
author_twitter: "https://x.com/cronokirby"
url: "https://commonware.xyz/blogs/many-too-many"
image: "https://commonware.xyz/imgs/many-too-many.png"
---

To get the most performance out of modern CPUs, you need to use their SIMD instructions.
CPU designers have realized that while they can't make the CPU run more instructions
per second, they can just have those instructions process more data at the same time.
If your code looks like doing the same thing on a lot of data, you can use these
instructions to speed up your code by 2, 4, or even 8 times!

We've taken advantage of these specialized instructions in several of our performance-sensitive
crates. For example, our [curve25519 crate](https://github.com/commonwarexyz/monorepo/tree/main/cryptography/curve25519) uses SIMD instructions to verify
a batch of signatures as fast as possible, we take advantage of these instructions
to accelerate SHA-256 and BLAKE3 hashing of multiple messages, and we use
them to accelerate Reed-Solomon coding, among other possibilities.

Unfortunately, SIMD remains a bit of a dusty corner of Rust. One nice thing about
this language is that we can write normal, readable code, and get something pretty
fast. Sometimes it will even generate SIMD for us, but really only in the simplest
of cases. The path offered to you on stable Rust to access SIMD instructions is
a bit crummy: you can either use unsafe intrinsic functions, or write assembly
yourself. [Only recently](https://blog.rust-lang.org/2025/08/07/Rust-1.89.0/) did Rust add AVX-512 intrinsics, the state of the art on x86-64, whereas
Arm [doesn't even have SVE2 intrinsics yet](https://github.com/rust-lang/rust/issues/145052), so you're stuck with assembly to get
state of the art performance there.

While there are crates that provide abstractions to make writing SIMD easier,
including [a prototype](https://doc.rust-lang.org/nightly/std/simd/index.html) in the nightly Rust standard library, we weren't satisfied
with any of them,
so our approach to using SIMD has involved writing assembly or intrinsics for each
platform we cared about.
In some cases, we literally had to write large routines for each platform,
while in other cases, we used a trick inspired from the [`fearless_simd`](https://docs.rs/fearless_simd) crate,
wherein we defined a trait with a few critical operations that benefited from using
SIMD, allowing the rest of the higher level code to remain generic.
Even so, we were having to choose between the best performance, and more readable
and reusable code, and needing to spend a lot of CI time running tests for many
crates across many different platforms, because of all these different code paths.

We were not happy with this situation, and so decided to take our own stab
at implementing SIMD abstractions. We're quite happy with it, and here are some
reasons why:

- SIMD code no longer needs to involve intrinsics or assembly.
- SIMD code can use platform-specific instructions.
- This allows matching or exceeding the performance of our hand-written kernels.
- Code outside of our SIMD crate does not need to be tested on different platforms,
despite being able to specialize to each of the platforms. Your MacBook can test
that your algorithm works on your AVX-512 accelerated server, and vice versa.

If these points are exciting to you, have a look at the [`commonware-simd`](https://github.com/commonwarexyz/monorepo/pull/5204) crate,
it's pretty small, well documented, and your agent can probably give you a nice
interactive explanation. For the remaining readers, let's walk through how
our crate tackles the pain points of writing SIMD in comparison to other crates.

# Sharing code

Most SIMD code looks like scalar code, just operating over a vector of things
at once, rather than each item one-by-one.

The simplest way to try and take advantage of SIMD is to just write scalar
code, and hope for the best.
Through LLVM, Rust has a decent auto-vectorizer, and for simple loops,
it can actually transform them into SIMD code.

<style>
  .mtm-loop-autovec {
    aspect-ratio: 1024 / 290;
    margin: 28px 0 6px;
  }

  .mtm-loop-spill {
    aspect-ratio: 1024 / 310;
    margin: 28px 0 6px;
  }

  .mtm-loop-compose {
    aspect-ratio: 1024 / 372;
    margin: 28px 0 6px;
  }

  .mtm-loop-tree {
    aspect-ratio: 1024 / 340;
    margin: 28px 0 6px;
  }

  .mtm-loop-soup {
    aspect-ratio: 1024 / 240;
    margin: 28px 0 6px;
  }
</style>
<noscript>
  <style>
    .mtm-loop {
      aspect-ratio: auto;
      border-left: 2px solid #d9251c;
      color: gray;
      margin: 28px 0 6px;
      padding-left: 12px;
    }
  </style>
</noscript>
<div id="mtm-fig-autovec" class="mtm-loop mtm-loop-autovec" role="img" aria-label="Two rows of sixteen numbered cells represent the same loop, out[i] = a[i] + b[i], compiled two ways. In the top row, labeled Scalar loop, a cursor moves across one cell at a time and fills each cell red, so the instruction counter beside it climbs from 0 to 16. In the bottom row, labeled Auto-vectorized with four lanes, a cursor four cells wide fills four cells blue with each instruction on the same clock, so the row finishes after only 4 instructions and then waits while the scalar row keeps going. When both rows are full, the counters read 16 and 4, showing that the vectorized loop needs four times fewer instructions when LLVM manages to vectorize it.">
  <noscript>This figure animates the same 16-element loop processed one element per instruction, taking 16 instructions, and four elements per instruction, taking 4.</noscript>
</div>
<script type="module" src="many-too-many.js"></script>

::: {.image-caption}
Figure 1: The same loop, run one element per instruction and four elements per instruction. The vectorized version needs four times fewer instructions, when LLVM manages to produce it.
:::

The problem with this is that it's unreliable. It works ok for simple loops,
but you get no guarantee, and it doesn't scale well beyond that.

For anything else, you need to invoke intrinsics, or assembly, and a variety
of approaches have sprung up.

The first problem that pops up is how to represent SIMD vectors. Different
platforms have different vector sizes. In normal Rust, a `u64` is a `u64`,
regardless of if you're compiling to x86-64 or Arm. But now a vector of `u64` might
mean 2 of these on Arm's NEON instruction set, 4 on x86's AVX, or even 8 on AVX-512.

One approach is to define types for each possible vector width, and then to write
code against them. If you use the largest width, operations may require multiple
instructions on certain platforms, but this is, hopefully, not a huge performance
hindrance. Some crates using this include [`wide`](https://docs.rs/wide), and the [`std::simd`](https://doc.rust-lang.org/nightly/std/simd/index.html) prototype
on nightly, which give you types like `u64x4` or `Simd<u64, 4>` whose width is
fixed regardless of what platform you compile for. Our curve25519 crate uses
this approach actually: the operations each platform need to implement are designed
to always take in 8 field or group elements at once, matching the size that AVX-512
can support.

The downside, which we can see through this example, is that things might perform
best on a particular platform, and that you might have to spill items onto
the stack. In other words, because you have a platform-independent Rust type representing
your vector, the generated code might involve a lot of glue moving things from CPU
registers holding SIMD vectors to Rust types on the stack.

<div id="mtm-fig-spill" class="mtm-loop mtm-loop-spill" role="img" aria-label="Two Rust values, a and b, each an array of eight 64-bit integers, sit side by side in a stack panel at the top. Below them is a panel of eight 128-bit registers, v0 through v7, each holding two lanes and each placed directly under the pair of stack elements it receives. For the line a = a + b, the four pairs of a drop one at a time into v0 to v3 and the four pairs of b drop into v4 to v7. Then each pair of registers flashes red under an add label, which is the only useful work. Then the four result pairs rise back into a on the stack. The registers are cleared, and the whole cycle repeats for the next line, a = a ^ b, with an xor. A counter in the bottom right tracks glue instructions against work instructions and ends at 24 glue to 8 work. The closing message says that most instructions just move data.">
  <noscript>This figure animates a u64x8 value on the stack being loaded into 128-bit registers two lanes at a time, operated on, and stored back, for each of two operations. Most of the instructions move data rather than compute.</noscript>
</div>

::: {.image-caption}
Figure 2: When a fixed-width `u64x8` value lives on the stack and the hardware registers hold only two lanes, each operation becomes a series of loads and stores around a few useful instructions.
:::

To get around this,
you often need to make sure that the operation that gets dispatched to different
platform-specific operations has a lot of work to do, to amortize this overhead.
This means wrapping more code than you might ideally want in platform-specific
code, increasing duplication. It also makes code less composable. Because of this
overhead, you can't write a bit of SIMD code for operation A, a bit of SIMD code
for operation B, and then compose them together: you need to fuse the two to be
able to keep things in registers.
Contrast this with normal Rust, where you can freely move things into small
sub-functions for readability, while being pretty confident that the compiler
can figure out how to inline functions, and keep values in registers for
the best performance across a big operation.

<div id="mtm-fig-compose" class="mtm-loop mtm-loop-compose" role="img" aria-label="Two pipelines compared on the same clock. In the top one, labeled composed across a platform boundary, a value leaves the registers, passes through operation A, is stored down to a stack box, loaded back up, passes through operation B, and only then returns to the registers; the store and load detour is drawn as a long dashed path. In the bottom one, labeled inlined, the value goes straight from A to B and back to the registers, arriving in little more than half the time. A time bar beside each title shows the difference.">
  <noscript>This figure animates a value passing through operations A and B. Composed across a platform boundary, it is stored to the stack and loaded again between them. Inlined, it goes straight from A to B in a register.</noscript>
</div>

::: {.image-caption}
Figure 3: Composing two operations across a platform boundary round-trips the intermediate value through the stack. Inlined, it never leaves a register.
:::

# Not that kind of token

When writing assembly, you might think that it's a matter of slapping
a `#[cfg]` on a particular piece of code, and writing one version for each
architecture. Unfortunately, SIMD throws another curveball at us, in that
the instructions available to us depend on the particular CPU, not just the
architecture. You thus need *runtime* feature detection
to know what instructions are available.

If you omit this check, you get a panic, which is not what we want.
Instead, we'd like to fall back to a different version of the code if an
instruction is missing.
We also want to minimize the number of checks we need, to avoid querying
the CPU repeatedly in a hot loop.

An approach to solve this is to tie SIMD operations to a token.

Here's what that looks like with our crate:

```rust
use commonware_simd::Simd;

#[inline(always)]
fn mix<S: Simd>(simd: S, a: S::U64, b: S::U64, c: S::U64) -> S::U64 {
    simd.u64_add(simd.u64_xor(a, b), c)
}

// Assumes the slices have a length which is a multiple of S::U64_LANES.
#[inline(always)]
fn mix_slices<S: Simd>(simd: S, a: &[u64], b: &[u64], c: &[u64], out: &mut [u64]) {
    for i in (0..out.len()).step_by(S::U64_LANES) {
        let a = simd.u64_load(&a[i..]);
        let b = simd.u64_load(&b[i..]);
        let c = simd.u64_load(&c[i..]);
        simd.u64_store(mix(simd, a, b, c), &mut out[i..]);
    }
}
```

`S` is a backend, and `simd` is a token for that backend. `S::U64` is whatever
that backend uses to hold `S::U64_LANES` values of type `u64`: a 128-bit register
holding 2 lanes on Arm, a 512-bit register holding 8 with AVX-512, or a plain
`[u64; 1]` for the scalar fallback. Every instruction is a method on the token,
so there's no way to emit one without having a token in hand, and the token
is what makes this safe.

The native tokens have a private field, so the only way to get one is through
a constructor like `NativeIceLake::new()`, which returns an `Option`. That
constructor runs the CPU feature detection for the whole bundle of instructions
that backend needs, and refuses to hand you a token if any are missing.
If you hold a token, that's proof that the CPU can run every instruction
the backend offers. Inside the crate, each safe method calls an `unsafe`
function annotated with `#[target_feature]`, and the justification for that
`unsafe` block is always the same: the token exists, so the feature does too.

This also solves the "don't check in a hot loop" problem. The check happens
exactly once, when you obtain the token. After that, the token is a zero-sized
`Copy` type, so passing it into every helper costs nothing, and none of those
helpers need to ask the CPU anything. And because the constructor returns
`None` rather than panicking, you can fall back to a different backend when
the fancy one isn't available, which is what `dispatch` does, as we'll see
later.


# The need for specialization

You can get a lot of mileage out of just writing SIMD against a common set
of instructions that are widely available.
One advantage of an abstraction representing some notion of "portable SIMD"
rather than just fallback scalar code is that your algorithm can generalize
to new backends.
One exciting example is WASM, which could benefit from acceleration for free,
without having to expend more effort on our end to support it.

In many cases, we care about going the extra mile to get the best possible
performance on a particular architecture, and we get really excited
to use the fanciest instructions to eke out everything we can.

In that case, you need instructions that might not be available everywhere.

Our approach is to pick a few targets that we care particularly about being
performant, and to model what instructions they have that could be useful
to us.

The alternative would be to track every subset and iteration of every
instruction set: SSE4, AVX2, AVX-512 with or without each of its extensions,
NEON with or without the crypto extensions, and so on. Each combination is
another path to write, test, and benchmark, and most of them aren't ones we'd
ever deploy on. So instead we picked "frontier" targets: platforms that are
widely available, and have all the gadgets we might want. We settled on three:

- **Ice Lake**: x86-64 with AVX-512F, AVX-512BW, GFNI, AVX-512IFMA, and SHA-NI.
  This is the server profile. AVX-512 gives us the widest vectors around,
  and the extensions are each there for a reason: GFNI multiplies bytes in
  GF(2^8) for Reed-Solomon coding, IFMA does 52-bit multiply-adds for the
  field arithmetic in Curve25519, and SHA-NI does what it says on the tin.
  Intel has shipped this bundle since Ice Lake in 2019, and AMD since Zen 4.
- **NEON**: AArch64 with NEON and SHA2. This is every Apple silicon machine,
  which is to say, our laptops, and also older Arm servers like Graviton 2 and 3.
  Vectors are only 128 bits wide, but the SHA2 extension gives us hardware
  SHA-256 rounds, which matters a lot for merkle trees.
- **Armv9**: AArch64 with NEON, SHA2, SVE, and SVE2. This is the newer Arm
  server profile, like Graviton 4. It has everything NEON has, plus SVE2
  instructions like `XAR` (xor then rotate), which is handy for hashing. Apple
  silicon doesn't have SVE2, which is why NEON is its own profile rather than
  the fallback.

Anything that isn't one of these, like an x86-64 machine with only AVX2, gets
the scalar fallback. That's a real cost, which we'll come back to in the
caveats, but it's the right trade for the hardware we actually run on.

The names are a bit of a shorthand. "Ice Lake" means that bundle of instructions,
not that particular CPU: a Zen 4 server has all of them and gets this backend too.

Each profile is a trait extending `Simd`, which adds the instructions we
care about on that platform:

```rust
pub trait IceLake: Simd {
    /// Two SHA-256 rounds (SHA256RNDS2).
    fn sha256_rounds2(self, a: Self::U32x4, b: Self::U32x4, k: Self::U32x4) -> Self::U32x4;

    /// Arbitrary three-input bitwise logic (VPTERNLOGD).
    fn u32_ternary<const MASK: i32>(self, a: Self::U32, b: Self::U32, c: Self::U32) -> Self::U32;

    /// Multiply-add on 52-bit limbs (VPMADD52LUQ).
    fn u64_madd52lo(self, acc: Self::U64, a: Self::U64, b: Self::U64) -> Self::U64;

    // ...
}

pub trait Neon: Simd {
    /// Four SHA-256 rounds (SHA256H).
    fn sha256_h(self, abcd: Self::U32x4, efgh: Self::U32x4, wk: Self::U32x4) -> Self::U32x4;

    // ...
}

pub trait ArmV9: Neon {
    /// Xor, then rotate (SVE2 XAR).
    fn u32_xor_rotate_right<const N: u32>(self, a: Self::U32, b: Self::U32) -> Self::U32;
}
```

The important thing to notice is that these traits add operations, not types.
`u32_ternary` takes and returns `Self::U32`, the exact same register type that
`Simd::u32_xor` uses. (NEON does add a couple of half-width helper types for
its narrowing and widening multiplies, but the registers you pass around
between functions are still the ones `Simd` defines.) A specialized instruction
is just another method on the same token, operating on the same registers,
so a function with `S: IceLake` can mix portable and Ice Lake instructions
freely, without converting anything.

What we don't want is to have to write an entire function over again just
because one small part needs `S: Neon` or `S: IceLake`. What we want
is a way to have a function using `S: Simd` know how to invoke the right specialized
branch as needed, letting us keep the code composable.

We introduce the notion of an `Operation` for this. An `Operation` knows how
to execute itself against each of the privileged targets we have:

```rust
pub trait Operation<S: Simd>: Sized {
    type Output;

    fn portable(self, simd: S) -> Self::Output;

    fn ice_lake(self, simd: S) -> Self::Output
    where
        S: IceLake,
    {
        self.portable(simd)
    }

    fn neon(self, simd: S) -> Self::Output
    where
        S: Neon,
    {
        self.portable(simd)
    }

    fn arm_v9(self, simd: S) -> Self::Output
    where
        S: ArmV9,
    {
        self.neon(simd)
    }
}
```

Only `portable` is required. Each specialized method has a `where` clause
narrowing `S` to the matching profile, which is what lets its body call that
profile's instructions. The defaults chain downwards: Armv9 falls back to
NEON, and everything else falls back to portable, so you only write the paths
that actually have something to gain. And because `S` is a parameter of the
trait rather than the method, an operation can capture registers of type
`S::U32` and return them too.

To write an `Operation`, the idiomatic way is to return an opaque impl:

```rust
use commonware_simd::{ArmV9, IceLake, Operation, Simd};

#[inline(always)]
fn xor_rotate<S: Simd>(a: S::U32, b: S::U32) -> impl Operation<S, Output = S::U32> {
    struct XorRotate<S: Simd>(S::U32, S::U32);

    impl<S: Simd> Operation<S> for XorRotate<S> {
        type Output = S::U32;

        #[inline(always)]
        fn portable(self, simd: S) -> S::U32 {
            simd.u32_rotate_right::<7>(simd.u32_xor(self.0, self.1))
        }

        #[inline(always)]
        fn arm_v9(self, simd: S) -> S::U32
        where
            S: ArmV9,
        {
            // SVE2 has a single instruction for this.
            simd.u32_xor_rotate_right::<7>(self.0, self.1)
        }
    }

    XorRotate::<S>(a, b)
}
```

The struct holds the inputs, which here are registers belonging to `S`, and
the trait impl holds one body per path. Ice Lake and NEON don't appear at all,
and get the portable version through the defaults.

Then, within a normal generic SIMD function, you can call `execute` to invoke
that operation:

```rust
#[inline(always)]
fn step<S: Simd>(simd: S, state: S::U32, key: S::U32) -> S::U32 {
    let mixed = simd.execute(xor_rotate::<S>(state, key));
    simd.u32_add(mixed, simd.u32_splat(0x9e37_79b9))
}
```

`step` only knows that `S: Simd`, and never mentions SVE2. But `execute` is
a method on the token, and each backend's token knows which path is its own:
an Armv9 token runs `arm_v9`, an Ice Lake token runs `ice_lake`, and so on.
Once `step` is monomorphized for a concrete backend, the right branch is
selected at compile time, and the register produced by the leaf flows straight
into the `u32_add` without touching memory.

This lets you freely compose specialized and generic code together, minimizing
code duplication, and maximizing modularity!

<div id="mtm-fig-tree" class="mtm-loop mtm-loop-tree" role="img" aria-label="A call tree for a generic hash function. The root node hash calls three generic nodes named load, compress, and finish, all drawn as black-outlined boxes. Load calls the leaf operation initialize, and compress calls the leaf operations rounds4 and schedule4. Each leaf is split into four colored stripes for its equivalent paths: gray for portable, blue for ice_lake, green for neon, and red for arm_v9, as shown in a legend on the right. At first the label reads S = ?. Then the label becomes S = NativeIceLake, and every leaf shrinks its other stripes away until it is solid blue. The leaves spring back to four colors and the same happens for S = NativeNeon, turning them green, S = NativeArmV9, turning them red, and S = EmulatedScalar, turning them gray. Throughout, the generic nodes and the edges between them never change.">
  <noscript>This figure shows a call tree whose generic nodes stay fixed while each leaf operation, drawn with one stripe per backend path, resolves to a single color as S is set to each backend in turn.</noscript>
</div>

::: {.image-caption}
Figure 4: Generic code is shared across backends, and choosing the backend `S` at compile time resolves every multi-path leaf operation to a single implementation.
:::

How do other libraries handle this? Looking around, we found three patterns.

The first is to put the specialized operation into the shared trait, and make
every backend implement it somehow. [`pulp`](https://docs.rs/pulp)'s `Simd` trait
and [`memchr`](https://github.com/BurntSushi/memchr)'s internal `Vector` trait work this way, and [Highway](https://github.com/google/highway) will emulate
an AES round on targets that lack AES instructions. This works, but only the
library can add a fast path, and every backend has to implement every
operation, even when that means a slow emulation of an instruction that only
makes sense on one platform.

The second is to specialize whole kernels: write one SHA-NI function, one Arm
SHA2 function, and one portable function, then pick between them at dispatch
time. [RustCrypto's `sha2`](https://github.com/RustCrypto/hashes) and [`curve25519-dalek`](https://github.com/dalek-cryptography/curve25519-dalek) do this, and so does `pulp` if
you write against a concrete token like `V4`. This gets you full performance,
at the cost of duplicating everything *around* the specialized instruction,
which is exactly how we ended up with a pile of assembly files.

The third is to downcast inside generic code.
[`fearless_simd`](https://docs.rs/fearless_simd) lets you ask a token for its
level and get a concrete NEON token back, [`archmage`](https://docs.rs/archmage) has a similar conversion,
and Highway does it with `#if HWY_TARGET`. This is the closest to what we do,
but the specialized branch ends up behind a `cfg(target_arch)`, the fallback
is a convention rather than something the type system checks, and the
specialized branch can only run on a machine that has the hardware.

With `Operation`, the specialized paths are methods bounded by a profile trait,
over the same register types: there's no conversion, no `cfg`, the fallback
is type-checked, and, as we'll see next, every path runs under emulation.

# Checking specialized paths

As soon as you introduce different algorithms for different backends, you need
to make sure that they do the same thing regardless of the backend. Previously
our approach involved writing a scalar backend, and then running tests on every
platform to ensure that the native code on that platform matched the scalar backend.

The SIMD crate instead lets you check that your algorithm is correct on *any* platform,
regardless of which platform you run your CI on. It does this by implementing
emulated backends for each privileged target, that can run anywhere.

Alongside `NativeIceLake`, there's `EmulatedIceLake`, which implements the
same `IceLake` trait with plain arrays and ordinary integer arithmetic.
It has the same 16 `u32` lanes, and it runs the same `ice_lake` path of
every operation, so you can run your AVX-512 algorithm, specialized branches
and all, on a MacBook. There's an `EmulatedNeon`, an `EmulatedArmV9`, and an
`EmulatedScalar` with one lane per vector.

`check_consistent` takes a function producing an operation, and runs it on
every emulated backend, asserting that they agree with the scalar result.
Returning to our `xor_rotate` example, here's an operation which mixes a
whole buffer:

```rust
use commonware_simd::{Operation, Simd};

struct Mix {
    state: Vec<u32>,
    key: u32,
}

impl<S: Simd> Operation<S> for Mix {
    type Output = Vec<u32>;

    fn portable(mut self, simd: S) -> Vec<u32> {
        simd.execute(#[inline(always)] |simd: S| {
            let key = simd.u32_splat(self.key);
            // (Handling the remainder is left out for brevity.)
            for chunk in self.state.chunks_exact_mut(S::U32_LANES) {
                let value = step(simd, simd.u32_load(chunk), key);
                simd.u32_store(value, chunk);
            }
        });
        self.state
    }
}
```

Notice that `Mix` only implements `portable`. It doesn't need specialized
paths of its own, because the specialization happens in `xor_rotate`, which
`step` calls. Testing it is a one-liner inside a fuzz loop:

```rust
use commonware_invariants::minifuzz;
use commonware_simd::{check_consistent, test_dispatch};

#[test]
fn mix_is_consistent() {
    minifuzz::test(|u| {
        let state: Vec<u32> = u.arbitrary()?;
        let key: u32 = u.arbitrary()?;
        check_consistent(|| Mix { state: state.clone(), key });
        // reference_mix is a plain scalar implementation.
        assert_eq!(test_dispatch(Mix { state: state.clone(), key }), reference_mix(&state, key));
        Ok(())
    });
}
```

The factory closure is called once per backend, since executing an operation
consumes it. This single test exercises 1-, 4-, and 16-lane versions of the
loop, along with the SVE2 `XAR` branch, none of which require the
corresponding hardware. The second assertion uses `test_dispatch`, which always
runs the scalar backend, to compare against an independent reference. That
matters because agreement between backends only tells you that the paths
match each other, not that any of them are right.

Of course, the emulated backends might be buggy. This is why we fuzz them against
the real platforms. These fuzz tests need to run on each platform we provide,
but only these tests need to do so: other crates that use SIMD can bootstrap
off of these results to just use the emulated backends.

# Dispatch

Through this walkthrough, we've seen how to write and test the consistency of operations,
but not how to actually run them to get a result. That's what `dispatch` is for.
`Mix` from above is already in the right shape, so running it on whatever the
current CPU supports is just:

```rust
use commonware_simd::dispatch;

fn mix(state: Vec<u32>, key: u32) -> Vec<u32> {
    dispatch(Mix { state, key })
}
```

On x86-64, `dispatch` tries `NativeIceLake::new()`. On AArch64, it tries
`NativeArmV9::new()`, then `NativeNeon::new()`. If none of these produce a
token, it falls back to `EmulatedScalar`. Whichever token it gets, it calls
`execute` on it, and from there on the backend is baked into the type `S`,
so every nested `execute`, including the one that picks the `arm_v9` branch
of `xor_rotate`, is resolved at compile time. The feature detection happens
once per call to `dispatch`, so you call it once around the whole computation
rather than inside a loop.

The signature of `dispatch` requires the operation to implement `Operation`
for every candidate backend, all with the same `Output`. This is why `Mix` is a
struct with a blanket `impl<S: Simd>`: a closure can't be generic over `S`.
It's also why `Mix` returns a `Vec<u32>` rather than a register. Different
backends have different register types, so backend-specific values are
normalized at this boundary, and only at this boundary.

There's one more thing `execute` does on a native backend, which deserves
mentioning, since it's the reason for all of the `#[inline(always)]`
annotations. Rust needs a function to be marked with `#[target_feature]` for
LLVM to emit AVX-512 instructions inside of it, and the token on its own
doesn't grant that to functions you write. So the native `execute` is a
trampoline:

```rust
#[inline]
#[target_feature(enable = "avx512f,avx512bw,gfni,avx512ifma,sha")]
unsafe fn execute_ice_lake<O: Operation<Self>>(self, operation: O) -> O::Output {
    operation.ice_lake(self)
}
```

Everything inlined into this function gets compiled with those features
enabled, which is what you want. Anything that *doesn't* get inlined is
compiled without them, and becomes a function call per instruction, which is
very much not what you want. Hence the rule: enter a kernel through
`execute`, and mark the kernel body and its hot helpers `#[inline(always)]`.
A nested `execute` costs nothing, because its trampoline inlines into a caller
that already has the features.

One nice feature of having the `Simd` trait contain generic types is that when
these functions are actually monomorphized into a concrete backend, all the
vector types become intrinsic types corresponding to registers.

Thus, you can write a large kernel composed of small modular parts, but then
still have a coherent soup of registers that LLVM is free to rearrange and optimize
as needed:

<div id="mtm-fig-soup" class="mtm-loop mtm-loop-soup" role="img" aria-label="Four small gray boxes labeled load, rounds4, schedule4, and add_state sit side by side. Each holds a few colored instruction bars: blue for the left message, green for the right message, and gray for a shared constant. Each box also carries the generic vector type S::U32x4. That label fades to __m128i to show monomorphization into Ice Lake registers. The four boxes then slide together, their names fade, and they merge into one wide box titled hash::<NativeIceLake>, noted as one function with every value in a register. The bars still sit in source order, grouped by helper. Finally the bars lift into separate lanes and move sideways. The two gray constants move to the front, and the blue and green bars settle into one row that alternates blue and green. This shows LLVM interleaving the two independent chains.">
  <noscript>This figure shows four small generic helpers monomorphizing to a concrete backend, inlining into one function, and having their instructions interleaved by LLVM.</noscript>
</div>

::: {.image-caption}
Figure 5: Generic helpers written against `S::U32x4` monomorphize to `__m128i`, inline into a single `hash::<NativeIceLake>` function, and become one pool of registers that LLVM reorders to interleave the two independent message chains.
:::

# Example: SHA2

Our first real consumer is SHA-256. We hash a lot of merkle tree nodes, and
to do that quickly we had hand-written assembly for interleaving two
independent compressions on both x86-64 (SHA-NI) and AArch64 (SHA2), plus a
16-lane AVX-512 kernel for hashing batches of equal-length messages.
[The migration to `commonware-simd`](https://github.com/commonwarexyz/monorepo/pull/5203)
replaces all of that with one generic implementation.

The nicest part is how small the specialized bits become. The entire
platform-specific surface of the pair hashing kernel is two leaves. Here's the
one computing four rounds, for both messages at once:

```rust
fn rounds4<S: Simd>(
    state: State<S>,
    left: S::U32x4,
    right: S::U32x4,
) -> impl Operation<S, Output = State<S>> {
    struct Rounds<S: Simd>(State<S>, S::U32x4, S::U32x4);

    impl<S: Simd> Operation<S> for Rounds<S> {
        type Output = State<S>;

        fn portable(self, simd: S) -> Self::Output {
            // Extract the lanes, and do the rounds in scalar code.
        }

        fn ice_lake(self, simd: S) -> Self::Output
        where
            S: IceLake,
        {
            let (a, b, c, d) = self.0;
            let b = simd.sha256_rounds2(b, a, self.1);
            let d = simd.sha256_rounds2(d, c, self.2);
            let a = simd.sha256_rounds2(a, b, simd.u32x4_shuffle::<0xee>(self.1));
            let c = simd.sha256_rounds2(c, d, simd.u32x4_shuffle::<0xee>(self.2));
            (a, b, c, d)
        }

        fn neon(self, simd: S) -> Self::Output
        where
            S: Neon,
        {
            let (a, b, c, d) = self.0;
            let next_a = simd.sha256_h(a, b, self.1);
            let next_c = simd.sha256_h(c, d, self.2);
            let b = simd.sha256_h2(b, a, self.1);
            let d = simd.sha256_h2(d, c, self.2);
            (next_a, b, next_c, d)
        }
    }

    Rounds::<S>(state, left, right)
}
```

The other leaf is the message schedule, and looks the same. Everything else,
which is to say loading the nodes, padding, the round constants, the
interleaving of the two messages, and the final byte swapping, is written
once, against `S: Simd`.

A subtler win comes from the operations carrying registers of `S`. SHA-NI
wants the hash state in a strange `[F, E, B, A]` lane order, whereas the Arm
instructions and our scalar code want `[A, B, C, D]`. Rather than shuffling
in and out of a canonical order at every leaf, the initialization leaf loads
the state in whichever layout its backend prefers, and that layout then flows
through all 16 round groups untouched, with the conversion happening once at
the very end. The type system makes this safe: an operation holding an
Ice Lake register can't be executed by a NEON token, so the layouts can never
get mixed up.

Finally, the tuning decisions moved into the profiles too. Software SHA always
benefits from filling all 16 lanes of the batch kernel, but on a CPU with SHA-NI
a single message already hashes quickly, so batching only pays off for runs of
at least 7 messages. This used to be a `cfg(target_arch)` plus a runtime check;
now it's an `Operation` returning a `usize`, with an `ice_lake` override:

```rust
struct BatchLanes;

impl<S: Simd> Operation<S> for BatchLanes {
    type Output = usize;

    fn portable(self, _: S) -> usize {
        if S::U32_LANES >= 16 { 16 } else { 1 }
    }

    fn ice_lake(self, _: S) -> usize
    where
        S: IceLake,
    {
        1
    }
}
```

- Before: 14 `.asm` files, `unsafe` wrappers around `asm!`, and `cfg(target_arch)` throughout `sha256/mod.rs` and `simd/mod.rs`.
- After: no `asm` and no `unsafe`. The migration commit deletes 1,381 lines and adds 1,259.
- There are no `cfg(target_arch)` checks left in the SHA-256 code at all. The last one, deciding when to batch, became the `BatchLanes` operation above.

# Caveats

We're happy with the crate, but it's worth being upfront about what you give up.

**We need to have thought of the instruction you want to use.** Consumers
never touch intrinsics, which is what makes their code safe, but it also means
there's no escape hatch. If an algorithm needs an instruction we haven't
modeled, it has to be added to the crate, along with an emulated version and
fuzz coverage against the native one. We think of this as a feature, since it
keeps the set of instructions small and audited, but it does mean that the
crate grows with its consumers, and that you can't just reach for
`_mm512_whatever` in a pinch.

**We target specific platforms.** Three profiles is a deliberately short list.
If you're running on an x86-64 machine with AVX2 but not AVX-512, you get the
scalar fallback, not a 256-bit version of your algorithm. This is the right
trade-off for us, since the servers we care about do have AVX-512, but it's not
the right one for everybody. You can implement `Simd` for a backend of your
own, and get the portable subset of every algorithm for free, but `dispatch`
won't know about it, and neither will the specialized paths.

**You need to be careful to use `execute` or inline.** A token proves the
features exist, but it doesn't turn them on for the functions you write.
Forgetting an `#[inline(always)]` doesn't produce a compile error, or a test
failure. It produces correct code that's slow, and the only way to notice is to
read the assembly. The
[struct target feature pre-RFC](https://internals.rust-lang.org/t/pre-rfc-struct-target-feature/17761)
describes the language feature that would make this go away, by letting the
token itself carry the features into any function that receives it.

**Agreement isn't correctness.** `check_consistent` tells you that every path
computes the same thing, not that the thing is right. Pair it with
`test_dispatch` and an independent reference implementation.

**The guarantee is only as good as the emulators.** Running your specialized
branch under `EmulatedIceLake` proves it correct on real hardware only insofar
as the emulator matches the hardware. We fuzz each native backend against its
emulator on the corresponding platform to keep this honest, but that's a
property of the crate's CI, not a proof.

**A profile says what you can run, not what's fastest.** Knowing that SHA-NI
exists doesn't tell you its throughput relative to the 16-lane software
kernel. The batching threshold in the SHA-256 example is exactly this kind of
decision, and it had to be measured, not derived.

**Code size and compile time grow with one compiled copy per backend.** Every
kernel is monomorphized once for each backend that `dispatch` might select,
plus once more for each emulated backend your tests use.

**Only the common vector types can cross leaf boundaries.** An operation's
`Output` is a single type for all of its paths, so it can only be built from
types that every backend has, like `S::U32`. Profile-only types, such as the
16-bit vectors NEON uses for carry-less multiplication, have to stay inside
one path.

# Conclusion

Very little of this is new on its own. Passing a token into generic code and
re-entering a feature scope through a trampoline comes from [`pulp`](https://docs.rs/pulp) and
[`fearless_simd`](https://docs.rs/fearless_simd), grouping instructions into a few frontier bundles is how [Highway](https://github.com/google/highway)
has always worked, and checking platform implementations against a portable one
is what [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) does in its tests. What we think is new is the combination:
specialized paths as methods on an `Operation` with sensible defaults,
operations which carry a backend's registers, and an emulator for every profile,
so that the whole thing can be tested on any machine.

There's a natural next step for those emulators. Since they're plain integer
code, they're amenable to tools like [Kani](https://github.com/model-checking/kani), or an SMT backend, which would let
us prove that the specialized paths agree with the portable one for *all*
inputs, rather than the ones a fuzzer happened to find.

The crate is ALPHA, and we'd love to hear about what instructions you'd want
to see. [Give it a try](https://github.com/commonwarexyz/monorepo/pull/5204).
