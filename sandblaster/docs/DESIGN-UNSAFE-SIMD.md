# Verifying Commonware's unsafe SIMD as written

*Design record, 2026-10-06. **Decided** by the user the same day ("We
need to support this."): sandblaster verifies Commonware's existing
`unsafe` SIMD as written, through the narrow reading below; it never adds
`unsafe`, and the engines are neither split nor rewritten. The design was
written outside the repository and reviewed adversarially
(`docs/UNSAFE-SIMD-CRITIQUE.md`); the accepted fixes are the
**Amendments** at the end, which govern wherever they conflict with the
text above them. Both files moved here as the design record on
2026-10-06. What is built so far, and where the implementation deviates
from the text, is the **Implementation record** after the amendments.*

Read with: DESIGN.md §1.1 item 8, §2, §9, §16.4, §16.5, §18;
`docs/mir-lift.md` §20 (especially §20.1, §20.4 and §20.9);
`kernel/AUDIT.md` §21; `docs/checked-structuring.md` §2.4 and §4
(assumption A3); the C8 survey (`sandblaster-wt/recovery/prover-simd/SIMD-SURVEY.md`,
outside the repository), whose §5 costed an earlier form of this reading.

Evidence used here: the four engines' sources
(`cryptography/src/reed_solomon/engine/engine_{neon,ssse3,avx2,avx512}.rs`,
`engine_scalar.rs`, `engine.rs`, `tables.rs`, `shards.rs`, `utils.rs`);
rustc's MIR of them from the C8 survey's extractions (outside the
repository: `recovery/prover-simd/mir-survey/rs_neon.sbmir.gz`, aarch64, and
`rs_x86.sbmir.gz`, `x86_64-apple-darwin`); stdarch's source in the pinned
toolchain `nightly-2026-06-21`; the target models in
`sandblaster/targets/core/*.core`. No cargo build was run.

---------------------------------------------------------------------------

## 0. The decision and what it changes

The user's decision, 2026-10-06: **"We need to support this."** Commonware's
Reed–Solomon SIMD engines load and store through raw pointers inside
`unsafe`. Sandblaster will verify that code as written.

* **No unsafe is added and no code changes.** Sandblaster never adds
  `unsafe` to shipped code. It verifies the `unsafe` already there.
  Decision (9) (split each engine into safe vector arithmetic and
  unverified load/store wrappers) is withdrawn: nothing has to be split.
* **Decision (1) is amended.** DESIGN.md §2 and §16.5 say: no
  proof-justified `unsafe`, no memory model for raw pointers, "now or
  later". That stays true for everything except four kinds of unsafe
  operation, read narrowly and each with proven obligations:
  1. raw pointers formed from references to slices, arrays and integers;
  2. pointer offsets;
  3. vector loads and stores through those pointers;
  4. calls into `#[target_feature]` code.

  The obligations are that every access is in bounds, aligned wherever
  the intrinsic requires it, and that the CPU feature is available.
  Every other unsafe operation stays refused (§1.10).
* **The blanket refusal goes.** Since C1, the lift refuses any body that
  contains `unsafe`, "whatever L would read of it" (`docs/mir-lift.md`
  §20). That syntactic refusal is replaced by the narrow reading below.

**What a green build adds.** On its domain, a verified function that uses
the admitted operations has no undefined behaviour:

* every pointer access stays inside the object the pointer was formed
  from;
* no other reference touches that object while the pointer is in use;
* every instruction runs on a CPU that has its feature.

This needs no new kind of theorem. L reads each failure as `Stuck`, and
the existing theorems (E2 `L::thm::f`, E3 `L::pthm::f`) already exclude
`Stuck` on the domain.

**What the four engines contain.** Measured on rustc's MIR of the
engines' own functions:

| | NEON | SSSE3, AVX2, AVX-512 | total |
| --- | ---: | ---: | ---: |
| pointer loads (`vld1q_u8`, `_mm*_loadu_*`) | 28 | 59 | 87 |
| pointer stores (`vst1q_u8`, `_mm*_storeu_*`) | 20 | 43 | 63 |
| pointer formations (`as_mut_ptr`, `ptr::from_ref`) | 13 | 39 | 52 |
| offsets (`add`) | 30 | 40 | 70 |
| pointer casts (`cast`) | 8 | 39 | 47 |
| any other unsafe operation | 0 | 0 | 0 |

The "other" row was checked against every callee and every cast in the
engines' MIR. There is no `get_unchecked`, no `ptr::read`, no transmute,
no raw dereference, no union, no inline assembly and no FFI. Besides
pointers, the engines' `unsafe` exists only for calls into
`#[target_feature]` code, which rustc forces (C8 survey §2).

**The main choices this design makes.** Each could be decided
differently.

* **Aliasing.** It is a trusted static check of each pointer's window
  (§2.6), rather than tracking pointer validity in L's state. L's state
  and the walker stay as they are.
* **Pointer bounds.** They are those of the reference the pointer was
  formed from, which is stricter than Rust's allocation bounds (§2.3).
* **CPU features.** Statically enabled features count. Needs are
  inferred inside the module, and a host-callable function declares its
  needs as a host obligation (§4). On aarch64 the engines need nothing.
  On x86, detection stays in host code until a second level verifies it.
* **Laws.** The scalar engine is the reference, first with the two
  tables' documented relation as a hypothesis. Verifying `tables.rs`
  removes the hypothesis later (§5.1).
* **Prerequisites.** The non-pointer gaps (`u128`, `&mut` slices, the
  crate's own types) are prerequisites, counted separately (§1.9, §6).

---------------------------------------------------------------------------

## 1. The admitted subset

### 1.1 Where the reading applies

* **Only to crate code read from MIR.** That means the lifted module's
  functions and the crate functions they call (`shards.rs`, `utils.rs`,
  `tables.rs`). Pointers in **library MIR** (core, std, third-party
  crates) keep today's treatment: L does not model them, and only the
  existing models reach them, by exact path (the slice iterators). This is
  what stops the reading from admitting library internals, such as the
  pointer arithmetic inside `get_unchecked` or `IterMut::next`.
* **The library pointer helpers are leaves.** The helpers the engines call
  are read by their exact path in both readings, and never followed into
  their MIR (§1.3, §1.4). Their bodies are one MIR statement each:
  `&raw mut (*_1)` then `PtrToPtr` for `as_mut_ptr`; `&raw const (*_1)`
  for `from_ref`; `PtrToPtr` for `cast`; `Offset(_1, _2)` for `add`.

### 1.2 Pointer types

* **Admitted.** Thin `*const T` and `*mut T` whose pointee `T` is plain:
  * `u8`, `u16`, `u32`, `u64`, `usize`, `u128`;
  * a `core::arch` vector type (`__m128i`, `__m256i`, `__m512i`,
    `uint8x16_t`, …);
  * `[T; N]` of a plain `T`.
* **mirx change.** mirx prints these as `(ptr const T)` and `(ptr mut T)`.
  Today it prints `(unsupported "type RawPtr(..)")`.
* **Refused.** Pointers to `bool`, `char`, signed integers, structs,
  enums, references, pointers or anything holding them. Fat pointers
  (`*mut [T]`) appear only inside the helpers' bodies; if MIR inlining
  brings them into crate code, they read like thin pointers (§2.1 carries
  the size anyway).

### 1.3 Formations

A **formation** creates a pointer from a reference. Its **base** is the
referent of that reference, after looking through one `unsize` cast
(`&mut [u8; 64]` → `&mut [u8]`). The base is never the whole
allocation: under Stacked Borrows a pointer formed from a reference may
only access that reference's range.

| Rust | MIR in the engines | base | kind | where |
| --- | --- | --- | --- | --- |
| `chunk.as_mut_ptr()`, `chunk: &mut [u8; 64]` | `_15 = move _13 as &mut [u8] (unsize)`; `_14 = <[u8]>::as_mut_ptr(move _15)` | `[u8; 64]` (64 bytes) | mutable | every engine's `mul_*`, `fftb_*`, `ifftb_*` (28 sites) |
| `x.as_mut_ptr()`, `x: &mut [u8; 64]` parameter | the same | `[u8; 64]` | mutable | `fftb_128`, `ifftb_128`, … |
| `core::ptr::from_ref::<u128>(&lut.lo[i])`, `lut: &Multiply128lutT` | `_9 = &((*_3).0: [u128; 4])[_10]`; `_8 = std::ptr::from_ref::<u128>(move _9)` | `u128` (16 bytes) | shared | NEON and SSSE3 `mul_128`, AVX2 `LutAvx2::from` (24 sites) |
| `a.as_ptr()`, `a: &[T; N]` or `&[T]` | `unsize`; `<[T]>::as_ptr` | `[T; N]` or `[T]` | shared | fixture `sd_neon_ptr`; `utils::formal_derivative_16_avx512` |
| `core::ptr::from_mut(r)` | `std::ptr::from_mut::<T>` | `T` | mutable | none yet |
| `&raw const place`, `&raw mut place` (MIR `AddressOf`) | not in the engines' own MIR | the place | shared, mutable | admitted so that MIR inlining of the helpers does not change the reading |

The **kind** is fixed at formation and kept in the pointer's value:
`as_ptr`, `from_ref` and `&raw const` give shared pointers; `as_mut_ptr`,
`from_mut` and `&raw mut` of a `&mut` or a local give mutable ones. A
store through a shared pointer is undefined behaviour in Rust, even after
`cast_mut()`.

### 1.4 Derivations

* **Offsets.** `<*const T>::add(k)` and `<*mut T>::add(k)` add
  `k · size_of::<T>()` bytes. `sub(k)` and `offset(k: isize)` are
  admitted on the same terms. MIR shows `add` as a call by exact path
  (`std::ptr::mut_ptr::<impl *mut u8>::add`), or as an `Offset` binop
  when inlined; both read the same.
  * NEON steps `*mut u8` by `16 * k`.
  * SSSE3 steps `*mut __m128i` by `1..3` (16 bytes each).
  * AVX2 steps `*mut __m256i` by `1` (32 bytes).
* **Casts.** `cast::<U>()`, `cast_mut()`, `cast_const()` and MIR
  `PtrToPtr` casts between thin pointers keep the value and change only
  the static pointee type. An example is the `*mut u8 → *const u8` cast
  rustc inserts before every `vld1q_u8`. The kind does not change.
* **Copies.** A `copy` or `move` of a pointer local is the same pointer.

### 1.5 Loads and stores

The trusted table of admitted pointer intrinsics. Each row names a
validated model that already exists. The AVX ones are validated but not
yet loaded for elaboration, which is C8's second slice.

| intrinsic | bytes | the model's memory type | needed by | alignment rustc requires |
| --- | ---: | --- | --- | --- |
| `vld1q_u8`, `vst1q_u8` | 16 | `Array U8 16` | NEON | none: stdarch is `read_unaligned`/`write_unaligned` on aarch64 |
| `vld1q_u64`, `vst1q_u64` | 16 | `Array U64 2` (little-endian words) | curve25519 NEON (later) | none, as above |
| `vld1q_u32`, `vst1q_u32` | 16 | `Array U32 4` | none yet | none |
| `_mm_loadu_si128`, `_mm_storeu_si128` | 16 | `Array U8 16` | SSSE3, AVX2 tables | none: `copy_nonoverlapping` of bytes, `write_unaligned` |
| `_mm256_loadu_si256`, `_mm256_storeu_si256` | 32 | `Array U8 32` | AVX2 | none |
| `_mm512_loadu_si512`, `_mm512_storeu_si512` | 64 | `Array U8 64` | AVX-512, `utils::formal_derivative_16_avx512` | none |

* **No alignment obligations today.** Every admitted intrinsic is
  unaligned, so none of the four engines has one. This was checked in
  stdarch's source at the pinned nightly.
* **Aligned forms stay refused.** `_mm_load_si128` is `*mem_addr`, an
  aligned dereference; it and the other aligned forms have no model and
  are refused until a target needs one. §2.5 gives the rule they would
  follow.

### 1.6 Calls into `#[target_feature]` code

Two shapes occur in the engines.

* **Calls into a feature function from code without the feature.**
  * `<Neon as Engine>::mul` calls `unsafe fn mul_neon`
    (`#[target_feature(enable = "neon")]`).
  * `<Avx512 as Engine>::fft` calls `unsafe fn fft_private`
    (`#[target_feature(enable = "avx512f,gfni")]`).
* **Value intrinsics in `#[inline(always)]` helpers without the
  feature.** The helpers wrap them in `unsafe` (C8 survey §2):
  * the value intrinsics of each `mul_128` (19 in NEON's, 21 in SSSE3's);
  * AVX-512's `unsafe fn multiply_512` and `muladd_512`;
  * `LutGfni::from` and `LutAvx2::from`.

Both read as ordinary calls and model applications. Their obligation, that
the features are available, is discharged statically (§4).

### 1.7 `unsafe fn` and `unsafe` blocks

* **Accepted in lifted files.** Neither has a run-time meaning.
* **Safety comments are not trusted.** Rustdoc comments such as "The CPU
  must support NEON" are neither trusted nor used: the reading checks
  the actual conditions.
* **S drops the marker.** The structured reading gives an `unsafe fn` an
  ordinary signature, since the subset has no `unsafe`.
* **Still refused.** `unsafe impl` and `unsafe trait` (as today).
* **Ghost code.** The DSL root's `#![forbid(unsafe_code)]` stays: it
  covers the ghost files (laws, proofs) and the dialect. It no longer
  covers in-place files whose bodies are read from MIR.

### 1.8 Transmutes

* **Not needed.** The engines' MIR has no transmute: its casts are
  `PtrToPtr`, `int-to-int` and `unsize` only.
* **Refused when written by the crate** (§1.11, item 2). L keeps reading
  its modeled `[u8; n] ↔ uN` transmutes wherever they appear, as today:
  core's `from_le_bytes`/`to_le_bytes` use them, and rustc's MIR
  optimizations may introduce such casts in safe code too.
* **Easy to admit later.** The byte views of §2.2 make a transmute
  between plain types of equal size a one-line reading
  (`of_bytes_U(bytes_T(x))`), when a target needs it.

### 1.9 What else the engines need (not unsafe)

These are reader and model gaps of the C8 survey (B3, B4). They do not
depend on pointers, but the engines cannot be verified without them.

| need | which functions | where it lands |
| --- | --- | --- |
| `u128` as a value type in both readings, with its byte view | everything that touches `Multiply128lutT` (`mul_128`, `muladd_128`, `fftb_*`, `ifftb_*`, `mul_*`, `LutAvx2::from`) | C4 (`u128` as two `u64`). Only the representation and byte view are needed here; no arithmetic |
| the crate's own types outside the module: `Multiply128lutT`, `MultiplyGfni`, `ShardsRefMut` | all of the above; the transforms | lift: module types of the extraction |
| codes into slices (`follow`/`update` of a `[T]`, not only `[T; N]`) | any element code of `&mut [[u8; 64]]` | L, `follow` |
| the `IterMut` model: `iter_mut`, `next` yielding element codes | `mul_neon`, `mul_ssse3`, `mul_avx2`, `mul_private` | a model leaf in both readings, like `slice::Iter` |
| `Zip` of `IterMut`s, nested three deep in AVX-512 | the partial butterflies; AVX-512's fused two-layer butterfly | a model leaf |
| subslice codes (a range projection) for `split_at_mut`, `IndexMut` by ranges, `dist2_mut`, `dist4_mut` | the transforms | L: a `PRange` step; S: subslice states written back |
| `utils::xor`, `utils::xor_within` | the transforms' `GF_MODULUS` branches | reader |
| models: `_mm_set1_epi8`, `_mm_srli_epi64` | SSSE3 | targets (validate under Rosetta 2 here) |
| models: `_mm256_set1_epi8`, `_mm256_broadcastsi128_si256`; the AVX models loaded | AVX2 | targets, C8 second slice |
| models: `_mm512_inserti64x4`, `_mm512_castsi256_si512`; AVX-512 loaded | AVX-512 | targets (AVX-512 host) |
| the reader's "discriminant value 15 used as data" in AVX2 `mul_256`: the `i8` argument `15` of `_mm256_set1_epi8(0x0f)` | AVX2 | `read.rs` bug |

Not needed for `mul`, `fft` and `ifft`:

* the constructors (`LazyLock`, cpufeatures' atomics), §4;
* `eval_poly` (loops in library code, `fwht`);
* `DefaultEngine`, which dispatches through `Box<dyn Engine>`.

### 1.10 What stays refused

Every unsafe operation not listed above. That includes:

* dereferencing a raw pointer as a place (`*p`, `&*p`, `(*p).f`);
* `ptr::read`, `ptr::write`, `read_unaligned`, `write_unaligned`, `copy`,
  `copy_nonoverlapping`, `swap`, `replace` called by crate code;
* `slice::from_raw_parts(_mut)`, `get_unchecked(_mut)`, `*_unchecked`
  arithmetic, `split_at_unchecked`, `as_chunks_unchecked`,
  `hint::assert_unchecked`, `unreachable_unchecked`;
* `transmute`, `transmute_copy`, `MaybeUninit::assume_init*`,
  `mem::zeroed`;
* union field reads, `static mut`, `extern` (FFI) calls, inline assembly;
* pointer-integer casts (`as usize`, `addr`, `expose_provenance`,
  `with_addr`), pointer comparisons, `offset_from`, `align_offset`,
  `wrapping_*` and `byte_*` arithmetic, null pointers;
* pointers that escape (§2.6, W1):
  * stored into memory (a field, an array element, through a reference);
  * returned or passed to any call other than an admitted helper or
    intrinsic;
  * captured by a closure;
  * kept alive across a new formation from the same reference;
* raw pointers as parameters or fields of crate functions and types;
* aligned, masked, gather, scatter, non-temporal and interleaving
  (`vld2`..`vld4`) loads and stores, `lddqu`, prefetches;
* `#[target_feature]` calls whose features are not established (§4);
* runtime feature detection inside a verified function (until §4.5's
  second level);
* SHA-256 x16's `[*const u8; 16]` table handed to assembly.

### 1.11 Gaps the blanket refusal hides today

Lifting the syntactic refusal exposes three places where today's L or
parse would read source-level unsafe code without noticing it. Each is
closed as part of this change, with a negative twin. Items 1 and 3 matter
for soundness; item 2 is policy only.

1. **Unions are parsed as structs (soundness).** `ir.rs` sets `is_enum`
   from `(kind enum)` and otherwise reads an ADT as a struct; it ignores
   the aggregate's `(union-field f)`. Building a union is safe Rust, and
   reading its fields needs `unsafe`, so a union field read would be read
   as a struct field: a wrong value. Fix: the trusted parse refuses
   `(kind union)`.
2. **A crate's own `transmute` (policy).** L's reading of its modeled
   transmutes is exact, so reading a user's `transmute::<[u8; 4], u32>`
   gives the right value. It is still outside the decision. L cannot tell
   a user's transmute from one rustc's optimizations introduce, so L
   keeps its reading. Fix: the build-failing diagnostic pass (§6.3, risk
   12) names a `transmute` written in the crate's source and refuses it.
3. **Calls to library `unsafe fn`s (soundness).** L follows library MIR.
   Some library preconditions are not visible in that MIR, and violating
   them is still undefined behaviour. For example,
   `NonZero::new_unchecked(0)` skips its check (L reads
   `RuntimeChecks(ub)` as `false`) and builds a value whose niche is
   invalid, which is immediate undefined behaviour, yet L would read it
   as a value. Fix: mirx records each instance's `unsafe`; L refuses a
   call from crate MIR to a library `unsafe fn` outside the admitted
   list. The crate's own `unsafe fn`s are read normally: their bodies go
   through the same reading.

Raw dereferences, `static mut`, assembly and FFI are already stuck in L
today (not modeled, or no MIR).

---------------------------------------------------------------------------

## 2. The memory model in L (trusted)

### 2.1 Pointer values

One inductive in `literal.core`, parameterized by the instance's root
type `R` (`L::<f>::Root`):

```text
mir::Ptr(R) :=
  | PMut(code : Tuple2(R, List(mir::Proj)), off : Usize, size : Usize)
  | PShr(bytes : List(U8), off : Usize)
```

* **`PMut`: a mutable formation.**
  * `code` is the existing reference code of the base (root and path,
    §20.4 "Places and references").
  * `off` is the byte offset.
  * `size` is the base's size in bytes, fixed at formation. A slice's
    length cannot change.
* **`PShr`: a shared formation.**
  * `bytes` is the base's byte view taken at formation: a snapshot, just
    as L already reads `&T` as the value of its referent.
  * `off` is the byte offset; the size is `len bytes`.
* **The element type is static:** the MIR type of the pointer local.
  `add` scales by it, and the intrinsic's memory type sets how many bytes
  a load reads.
* **The base type is static per family.** A family has one formation
  (§2.6), so every load and store site knows the base type it goes back
  through.
* **Pointers never leave their frame** (W1), so `R` is always the
  instance's own root type.

### 2.2 Byte views

For each base type `B`, the generator emits:

* `bytes_B : B -> List(U8)`, a list of `size_of::<B>()` bytes;
* `of_bytes_B : List(U8) -> Option(B)`, which is `None` unless the length
  is right.

| `B` | `bytes_B(x)` |
| --- | --- |
| `u8` | `[x]` |
| `u16`, `u32`, `u64`, `usize` | little-endian bytes (the transmute reading's, §20.4) |
| `u128` (C4: `lo`, `hi` words) | `le(lo) ++ le(hi)` |
| `[u8; N]` | the array's own list (no conversion, so terms stay small) |
| `[T; N]`, `[T]` | the elements' views concatenated, element 0 first |
| a vector type | the bytes of its model representation, lane 0 first, lanes little-endian |

Every byte string of the right length is a value of each of these types.
They have no padding, no niches and no pointers. So a store can never
produce an invalid value, and loads never read uninitialized or pointer
bytes. Targets are little-endian only (A8); mirx records the endianness
and a big-endian extraction is refused.

Examples:

* a chunk `[u8; 64]` is 64 bytes;
* a shard `[[u8; 64]]` of `n` chunks is `64n` bytes, where byte `j` is
  byte `j % 64` of chunk `j / 64`;
* a table row `u128` `v` is 16 bytes, where byte `k` is
  `(v >> 8k) & 0xff`. That is `to_ne_bytes` on these targets, which is
  what `tables::Multiply128lutT` documents.

### 2.3 Formation, offsets and casts

| MIR | L |
| --- | --- |
| mutable formation from a `&mut` held as code `q`, base type `B` | `PMut(q, 0, size)`. `size` is `size_of::<B>()`, or for a slice base its length (read through `q`) times the element size |
| shared formation from `&T`, whose L value is the snapshot `v` | `PShr(bytes_T(v), 0)` |
| `&raw mut place` / `&raw const place` | the same, with the place's code or value |
| `add(p, k)` on `*T`, `t = size_of::<T>()` | `off' = off + k·t`; **stuck** unless `off' ≤ size`, with no overflow (Int arithmetic) |
| `sub(p, k)`, `offset(p, k)` | `off' = off − k·t` (signed for `offset`); **stuck** unless `0 ≤ off' ≤ size` |
| `cast`, `cast_mut`, `cast_const`, `PtrToPtr` | the same value |

The `add` rule is stricter than Rust's. Rust allows any offset inside the
whole allocation, but L allows offsets only inside the base (one past the
end included). Being stricter makes L stuck in some defined programs,
never give a value in an undefined one.

### 2.4 Loads and stores

A **load** of `n` bytes through `p` at an admitted intrinsic `I`:

* `PMut(q, off, size)`:
  1. `v = deref__B(s, q)`, the existing read through a code;
  2. `bs = mem::read(bytes_B(v), off, n)`, **stuck** unless
     `off + n ≤ len`;
  3. the result is `I`'s model applied to `bs` in the model's memory
     type: `Array U8 16` as is, `Array U64 2` packed little-endian.
* `PShr(bytes, off)`: the same from `bytes`.

A **store** of the vector `x` through `p` at intrinsic `I`:

* `PMut(q, off, size)`:
  1. `w = I's model(x)`, the bytes the store writes;
  2. `v = deref__B(s, q)`;
  3. `bs' = mem::write(bytes_B(v), off, bytes(w))`, **stuck** unless in
     bounds;
  4. `v' = of_bytes_B(bs')`;
  5. `write__B(s, q, v')`, the existing write back through a code.
* `PShr(..)`: **stuck**. A write through a pointer formed from a shared
  reference is undefined behaviour.

A `&mut` parameter's referent is a cell during the call and is written
back at return (state passing, §20.4). So a store into `x[i]` through a
pointer inside `fftb_128` is visible to the caller exactly as a write
through `&mut x[i]` is.

### 2.5 Stuck, never a value

Each of these reads as `Stuck`, so a function that reaches one on some
input of its domain has no theorem:

* an offset outside `0..=size`;
* an access with `off + n > size`;
* a store through a shared pointer;
* a pointer slot that is `None` (uninitialized or moved out);
* an aligned access whose alignment cannot be shown.

The last rule applies only to aligned forms, which are not admitted
today. When one is, its access needs alignment `a`, and `a` must divide
both `align_of::<B>()` and `off`. A reference is aligned to its referent
type, so these two facts give an aligned address. Anything else is stuck,
even where the actual address happens to be aligned.

**Obligations come for free.** The theorem `L::thm::f` says the run
returns `Ret`; `L::pthm::f` says it returns `Panic`. Either rules out
`Stuck`, so a proven theorem shows that every `add`, load and store on
every path the domain reaches was in bounds. No new statement and no new
proof rule are needed, and the kernel checks the arithmetic like any
other.

### 2.6 Aliasing: the window rule

**The problem.**

* L reads a mutable pointer through its code, so it sees the **current**
  value of the base.
* L reads a shared pointer from a **snapshot**.
* Both readings equal Rust's only if nothing else touches the base while
  the pointer is in use. Otherwise Rust's aliasing rules make the access
  undefined behaviour, and L must not give a value there.

**Example.** A store through `p = chunk.as_mut_ptr()`, then a read of
`chunk[0]`, then another store through `p`. This is undefined under Tree
Borrows: the read freezes the reborrow, and the second write through it
is then undefined. Yet L would happily compute a value.

**The design.** A trusted static check on crate MIR, in a new file
`mir/window.rs`. A formation whose family fails it is read as `Stuck`.

**Definitions.** A *point* is one MIR statement or terminator.

* **Formation `F`:** a call of an admitted formation helper, or an
  `AddressOf`.
* **Source `σ`:** the reference `F` takes, looking through one unsize
  temporary, or the local whose address it takes.
* **Family `Φ(F)`:** the local that `F` assigns, closed under the
  derivations of §1.4 (`copy`, `move`, `cast`, `PtrToPtr`, `add`, `sub`,
  `offset`).
* **Ancestors `A(F)`:** `σ` plus every local that can reach the base's
  memory and whose value flows into `σ`, computed flow-insensitively over
  the whole body:
  * through `copy`, `move`, `&`, `&mut`, `unsize`, field and downcast
    projections;
  * through the root local of any place read, when that place is not
    behind a dereference (the base lives in a local);
  * through the reference-carrying arguments of a call that returns a
    reference.

  "Can reach memory" means the local's type holds a reference, a raw
  pointer or a lifetime (`IterMut<'_, T>`), or the local is the base
  itself. Index operands (`[_10]`) are not ancestors: they select an
  element, they do not reach memory.

  For example, in `mul_neon`, `A` is `{_13 chunk, _10, _11, _9 iter, _7,
  _8, _2 x}`.
* **Uses `U(F)`:** the points that read a member of `Φ(F)`.
* **Window `W(F)`:** the points `p ≠ F` with a path `F → p` and a path
  `p → u ∈ U(F)`, neither passing through `F`.

**Rules.** A formation is read only if its family meets all of these:

* **W0, one family at a time.** No member of `Φ(F)` is live just before
  `F`. Liveness is standard backward liveness on MIR locals. This
  refuses a pointer kept across a new formation from the same place,
  for example `q = p; p = a.as_mut_ptr(); store(q)`.
* **W1, no escape.** Every read of a member is one of:
  * a derivation into a member;
  * the pointer argument of an admitted load or store;
  * a `StorageDead`.

  A member belongs to one family only, so a pointer local assigned from
  two different formations is refused.
* **W2, mutable families: exclusive window.** No point in `W(F)`
  mentions a local in `A(F)`. That covers a read, write, borrow, move,
  drop, `StorageDead` or call argument. When the base is a local, the
  local itself counts.
* **W3, shared families: no write in the window.** No point in `W(F)`:
  * assigns to a local in `A(F)`, with or without projections;
  * takes `&mut` or `&raw mut` of a place based on one;
  * uses a `&mut`-typed local of `A(F)` (which could write, or hand on
    the right to write).

  Reads through shared references are allowed.
* **W4, stores only through mutable formations.** L enforces this
  dynamically (`PShr` stores are stuck); W4 reports it early by name.

**Why this is exact.** In a window that passes W2, every access to the
base goes through one tag:

* Under **Stacked Borrows** the family's raw tag sits above the
  reborrow, and no access through any other tag happens before the last
  use.
* Under **Tree Borrows** raw pointers carry the reborrow's tag, and no
  foreign access reaches it in the window.

So no access in the window is undefined, and the base's memory holds
exactly what L's code holds. W3 gives the same for a shared family: no
write to the base happens in its window, so the snapshot equals memory at
every use, and the shared tag is never invalidated.

The rules target what both aliasing models allow. Rust has not fixed one
model, and a rule that only one of them allows could become undefined
later.

**What the borrow checker adds.** Is there another reference that could
reach the base without being an ancestor? There are two cases.

* *Created after `F`.* It must be derived from an ancestor, and that
  derivation is a mention inside `W(F)`, refused by W2.
* *Created before `F` and used after it.* If it overlaps the base, its
  loan is still live when `F` uses `σ`. rustc's borrow checker rejects
  that unless it is an ancestor.

Two `&mut` parameters, such as `fftb_128`'s `x` and `y`, never alias:
the caller's borrows guarantee it, and host undefined behaviour is §1.1
item 7's assumption.

**Accepted shapes, measured on the engines' MIR.**

* **`mul_neon`.** `F` is block 7's `as_mut_ptr` call. Its window runs to
  block 28's last store. In that window the code mentions:
  * the family (`_14` and its casts and offsets);
  * vectors;
  * the `16 * k` temporaries;
  * `_4 = lut`, a shared reference unrelated to the chunk;
  * the calls to `mul_128`, which take vectors and `lut`.

  None of these is in `A`. Block 4's `next` is outside the window: from
  it, every path to a use passes `F` again.
* **`fftb_128` and `ifftb_128`.** Two mutable families, from `x` and
  from `y`, interleave loads and stores. Each one's ancestors are its own
  parameter and the unsize temporary. `y`'s formation lies in `x`'s
  window, but `y` is not an ancestor of `x`.
* **AVX-512's fused two-layer butterfly.** Four families come from four
  chunks of four `IterMut`s, zipped three deep. The chunks are taken
  apart before the first formation, and no window mentions the zip
  iterator.
* **`mul_128`'s eight table loads.** Shared families from
  `&(*lut).lo[i]`. The ancestors are `lut` and its source; nothing writes
  them.
* **`formal_derivative_16_avx512`** (utils.rs, later).
  * 16 shared families, from `Index::index(&block, i)[chunk]`.
  * 15 mutable families, from `IndexMut::index_mut(&mut block, i)[chunk]`.

  Each pointer is formed and used within one expression, so each window
  holds only its own derivation and access.

**Refused shapes** (fixture twins, §7):

* the reference read or written between a store and a load through its
  pointer;
* two formations from one `&mut` with interleaved uses;
* a base local written, or borrowed `&mut`, in a shared family's window;
* a pointer stored into an array, returned, or passed to a crate
  function.

**Considered and rejected: tracking validity in L's state.** L's state
would carry a version per root, and every access other than through a
pointer would bump it. That changes every place access of every function
with pointers. It adds version obligations to the walker. It still needs
W1's escape rules. The static rule leaves L's state and the walker as
they are, and refuses instead of tracking.

**Trust.** The window check is trusted, like `literal::must_panic`'s
allow-lists. A bug in it could let L give a value where Rust has
undefined behaviour. §6 lists its tests: one twin per rule, and a Miri
cross-check under both aliasing models.

### 2.7 Assumption A3, restated

`docs/checked-structuring.md` §4, A3 currently reads: "State passing of
`&mut` referents, write-back at return, and snapshots for shared
references are exact for borrow-checked MIR of the subset: no interior
mutability, no raw pointers, no `unsafe`."

It becomes:

> …are exact for borrow-checked MIR of the subset with no interior
> mutability, and with raw pointers only in families that pass the window
> rule (§20.10), formed and used in crate code. Inside a family's window,
> its base is reached only through the family. A mutable pointer reads
> and writes the base's current value through its code; a shared pointer
> reads a snapshot that equals memory at every use.

---------------------------------------------------------------------------

## 3. The structured reading S and the walker (untrusted)

### 3.1 How S models a family

S has no pointer values. It reads a family as three things:

* a **base**: S's lvalue for a mutable source (`x`, or `x[i]` for an
  `IterMut` element), or S's value for a shared source (`lut.lo[0]`);
* an **offset**: a `usize` expression;
* a **kind**.

The constructs then read as follows:

* **Offsets** become arithmetic on the offset: `off + k * size_of::<T>()`.
  S's own obligation is `off' <= size_of::<B>()`, the same fact that
  decides L's test.
* **A load** becomes the intrinsic's model applied to
  `__lift_mem::read::<B, N>(base, off)`. Its obligation is
  `off + N <= size_of::<B>()`.
* **A store** becomes the assignment
  `base = __lift_mem::write::<B, N>(base, off, <store model>(v));`. It is
  an ordinary assignment to a `&mut` state, so the existing write-back
  carries it out of the function.

**Shared definitions.** `__lift_mem::read`, `write` and the per-type
byte views are the **same kernel definitions** L uses (`literal.core`).
Both sides therefore elaborate to the same terms, and S adds no trust.
S's call of a load model goes through a small lift-prelude wrapper that
takes the bytes; it does not need a new surface entry in
`intrinsics.rs`, so no lock's `builtins` line changes.

**Feature rule.** S's feature check for functions read from MIR follows
§4, not the dialect's rule.

### 3.2 `mul_neon` in S (sketch)

```rust
fn mul_neon(self_: Neon, x: Seq<[u8; 64]>, log_m: u16) -> Seq<[u8; 64]> {
    let lut = self_.mul128[log_m as usize];
    let mut x = x;
    let mut i = 0usize;
    while i < x.len() {                                  // IterMut, by index
        // family of x_ptr: base x[i] (mutable), offset 0
        let x0_lo = vld1q_u8_mem(__lift_mem::read::<[u8; 64], 16>(x[i], 0));
        let x1_lo = vld1q_u8_mem(__lift_mem::read::<[u8; 64], 16>(x[i], 16));
        let x0_hi = vld1q_u8_mem(__lift_mem::read::<[u8; 64], 16>(x[i], 32));
        let x1_hi = vld1q_u8_mem(__lift_mem::read::<[u8; 64], 16>(x[i], 48));
        let (p0_lo, p0_hi) = Neon::mul_128(x0_lo, x0_hi, lut);
        let (p1_lo, p1_hi) = Neon::mul_128(x1_lo, x1_hi, lut);
        x[i] = __lift_mem::write::<[u8; 64], 16>(x[i], 0, vst1q_u8_mem(p0_lo));
        x[i] = __lift_mem::write::<[u8; 64], 16>(x[i], 16, vst1q_u8_mem(p1_lo));
        x[i] = __lift_mem::write::<[u8; 64], 16>(x[i], 32, vst1q_u8_mem(p0_hi));
        x[i] = __lift_mem::write::<[u8; 64], 16>(x[i], 48, vst1q_u8_mem(p1_hi));
        i += 1;
    }
    x
}
```

`mul_128`'s table loads read the same way:

```rust
let t0_lo = vld1q_u8_mem(__lift_mem::read::<u128, 16>(lut.lo[0], 0));
```

That term is `lut.lo[0]`'s 16 little-endian bytes.

### 3.3 The walker

The walker needs very little that is new:

* **Same terms on both sides.** Pointer values in L's slots are built by
  L's own steps from concrete codes and literal offsets, so the walker
  evaluates them. A load becomes `model(mem::read(bytes_B(v), off, n))`
  on both sides, with `v` the symbolic referent the walker already
  tracks for the code. The byte-view functions must stay folded on both
  sides, as neutral heads, the same way model applications do today.
* **L's new bound tests are decided** by evaluation when the offsets are
  literals, which they are throughout the four engines (`16 * k`, `1..3`
  on 16-byte elements). Otherwise linear arithmetic on S's obligations
  decides them.
* **Stores** are `write__B` through a code, which the walker already
  relates to S's assignment of the `&mut` state.

Estimate: 1–2 days inside the S work.

### 3.4 Proof automation the laws need

All of it is untrusted and kernel-checked. Gaps go into the prover, never
into reshaping the code (principle 1).

* **In-bounds arithmetic.** Constants in the engines; `linarith`
  elsewhere. For a pointer advanced in a loop, the offset is a loop
  variable of S, and its invariant is an ordinary loop attachment.
* **Byte-view lemmas** for the library (`front/stdlib`), proven once:
  * `read(a, o, n)[k] == a[o + k]` for byte arrays;
  * `write(a, o, c)[j] == if o <= j < o + n { c[j - o] } else { a[j] }`;
  * `read(write(a, o, c), o, n) == c`, and disjoint reads and writes
    commute;
  * for `u128`: `bytes(v)[k] == ((v >> 8k) & 0xff) as u8`;
  * for `[[u8; 64]]`: byte `j` is `x[j / 64][j % 64]`;
  * for `vld1q_u64`'s memory type: word `e` is `from_le_bytes` of bytes
    `8e..8e+8`.
* **Lanes.** The lane-split closer of C8's second slice turns a vector
  equation into 16 lane equations. NEON TBL lanes close by `bv()` today;
  a PSHUFB lane needs the closer, or 256 cases per lane without it.
* **Chunks.** The loop over `iter_mut` gets the invariant "chunks before
  `i` are transformed, the rest unchanged", using the existing loop
  machinery.

---------------------------------------------------------------------------

## 4. Target features

### 4.1 The condition

Two rules, one about safety and one about meaning:

* **The safety rule.** Calling a `#[target_feature]` function, or a
  value intrinsic, from code that is not compiled with its features is
  allowed only in `unsafe`. Rust 1.86 and later: statically enabled
  features do not count for this rule.
* **The undefined-behaviour rule.** That call is undefined behaviour if
  and only if the CPU running it lacks a feature.

The reading follows the second rule, which is the real one.

### 4.2 Static features

* **Recorded.** mirx records the target's statically enabled features
  and its endianness, as
  `(target-static-features "neon" "aes" ..)` and `(endian little)`. They
  come from the session's `cfg(target_feature)` set, which includes
  `-C target-cpu` and `-C target-feature`.
* **Checked against the build.** The build compares that list with
  `CARGO_CFG_TARGET_FEATURE`, which Cargo passes to build scripts. A
  mismatch is refused, because the MIR depends on the set: cpufeatures
  folds a statically enabled feature to `true`.
* **Why they count.** A binary assumes its target's static features
  everywhere; rustc emits those instructions anywhere it likes. A CPU
  without them cannot run the binary at all. Counting static features is
  therefore rustc's own contract, not a new assumption.
* **Facts measured in the survey's MIR:**
  * NEON is static on every aarch64 target. `has_neon::init_get` returns
    the constant `(InitToken, true)`.
  * SSSE3 is static on `x86_64-apple-darwin` (`has_ssse3::init_get` is
    constant `true`), but not on `x86_64-unknown-linux-gnu`.
  * AVX2 and AVX-512F with GFNI are run-time detections on both targets:
    `cpuid`, `xgetbv` and an atomic cache.

### 4.3 Needs, inferred

Every function `f` read from MIR gets a feature set `needs(f)`, computed
as a fixpoint over the extraction's call graph. It is what `f`'s body
requires beyond its own `#[target_feature]` set and the static set:

```text
needs(f) = closure( ⋃ { features(i) : intrinsic calls i in f }
                  ∪ ⋃ { tf(g) ∪ needs(g) : calls of crate functions g in f } )
           − closure( tf(f) ∪ static )
```

`closure` is rustc's implication closure (`target::feature_closure`).
`tf(f)` is `f`'s declared `#[target_feature]`.

* **Inside the module, nothing is written by hand.** For example:
  * `mul_128` needs `{neon}` minus static, which on aarch64 is `{}`;
  * AVX-512's `multiply_512` needs `{avx512f, gfni}`, which its caller
    `mul_private` covers;
  * `<Neon as Engine>::mul` needs `{}` on aarch64.
* **Calls need no run-time test.** L reads calls into feature code as
  ordinary calls. By construction, every call chain from a host-callable
  function either meets a `#[target_feature]` function whose own entry
  was checked, or carries the need up to the boundary.

### 4.4 The boundary: `requires_features(..)`

A host-callable function whose `needs` are not empty must declare them in
its laws attachment:

```rust
#[lift_attach(<crate::reed_solomon::engine::Avx2 as crate::reed_solomon::engine::Engine>::mul)]
fn avx2_mul_contract() {
    requires_features("avx2");
}
```

* **Checked.** The gate's trusted check refuses the function unless
  `closure(declared) ⊇ needs(f)`.
* **Locked.** The clause is on the review surface: the lock holds it and
  the spec sheet prints it.
* **A host obligation.** The record lists it, like any `requires`: "call
  only on a CPU with AVX2".

This extends the assumption DESIGN.md §1.1 item 7 already makes ("host
code calls a `#[target_feature]` function only on a CPU with those
features") to functions that declare `requires_features`.

What each engine needs at the boundary:

* **NEON on aarch64:** nothing.
* **SSSE3 on `x86_64-apple-darwin`:** nothing.
* **SSSE3 on `x86_64-unknown-linux-gnu`, and AVX2, AVX-512 on both
  targets:** `requires_features` on their `Engine` methods.

### 4.5 How run-time detection discharges it

**aarch64.** `cpu_features::neon()` is not a run-time detection. NEON is
static, cpufeatures' `new!` folds the call to `true`, and L reads that
constant. The `assert!` in `Neon::new()` and `eval_poly` therefore never
fires. Nothing about NEON is trusted beyond the static feature record.

**x86, first level** (this design's version 1). The detection stays in
unverified host code:

* `Avx2::new()` asserts `cpu_features::avx2()`.
* `Avx2`'s fields are private, and `engine_avx2.rs` builds an `Avx2`
  nowhere else. So the only way to obtain one is `new()`, `Default` or
  copying an existing one.
* So every `Avx2` value implies AVX2, and the host meets the
  `requires_features("avx2")` obligation of `<Avx2 as Engine>::mul`. This
  is the argument Commonware's own `SAFETY` comments make ("Constructors
  and runtime dispatch ensure the SIMD feature is available").
* The record states the obligation and that justification. The
  constructors stay host code anyway, because they also build `LazyLock`
  tables.

**x86, second level** (later, when a verified function needs detection
inside it: `DefaultEngine`, `formal_derivative`, the constructors).

* **Per-answer readings.** mirx records each detection call with its
  features:
  * cpufeatures' `new!`-generated `get`, recognized by its macro
    expansion and literal feature list;
  * std's `is_*_feature_detected!`, as a `std_detect` leaf with its
    feature constant.

  A function that reaches `k` detected feature sets is read in both
  readings once per answer, `2^k` times. Each answer is constant for the
  run. "Yes" adds the features to the static set for that reading. Each
  reading gets its own theorem. This is the plan `docs/mir-lift.md` §20.9
  already sketches ("an unknown boolean, fixed for the run").
* **Feature tokens.** A type declared in the laws as
  `#[feature_token("avx2")]` must satisfy two conditions:
  * its fields are private;
  * every construction site in the module is reachable only in "yes"
    readings. In "no" readings the constructor panics first, and its
    panic theorem proves it.

  Functions that take the token then get its features without a host
  obligation. This verifies the argument the first level leaves to the
  host.

Cost: about 100–150 trusted lines and 4–6 agent-days. It is not needed
for the `mul`, `fft` and `ifft` laws.

### 4.6 What is trusted

* **The static feature record** matches the build. It is checked against
  `CARGO_CFG_TARGET_FEATURE`. The trust is that the binary only runs on
  CPUs of its target, which is rustc's contract.
* **The needs fixpoint and the boundary check:** about 50–80 lines.
* **At the first level, the host obligations themselves.** For the x86
  engines, that is the constructor argument above.
* **At the second level, that detection is correct and constant.** A
  "yes" from cpufeatures or `std_detect` means the CPU executes the
  features and the operating system has enabled their state; the answer
  does not change within a process. Both crates cache their answer.

---------------------------------------------------------------------------

## 5. Laws for the engines

### 5.1 The reference and the layers

* **The reference.** The scalar engine is the reference (DESIGN.md
  "References and implementation equals reference": a SIMD engine is
  proven equal to the scalar engine beside it).
* **What the review surface holds.** Laws are only about host-callable
  functions (`Engine::mul`, `fft`, `ifft`). Summaries of internal
  functions (`mul_128` per lane, `fftb_128` per chunk) go in `PROOF.rs`
  and are not reviewed.

The laws come in three layers:

1. **Per engine, against the engine's own table.** `Neon::mul` multiplies
   every element by `mul_elem` of its `Multiply128lutT` row; `Scalar::mul`
   by its `Mul16` row.
2. **Engine against engine, with the table relation as a hypothesis.**
   Neon equals Scalar whenever Neon's 128-bit row is the byte split of
   Scalar's 16-bit row. That is the layout `tables::Multiply128lutT`
   documents, and the crate's test `mul128_byte_layout` checks it
   exhaustively.
3. **"On every input".** This drops the hypothesis by verifying
   `tables.rs`'s `initialize_mul128` and `initialize_mul16`, and by
   reading `LazyLock` through a host model ("dereferencing gives the
   initializer's value"). It is a separate target (§7, step 12).

Field access from the laws to the engines' private tables (`n.mul128`)
needs C7's views on lifted types. Until then, layer 2 is stated over the
tables the constructors read (`tables::get_mul128()`,
`tables::get_mul16()`).

### 5.2 Draft `LAWS.rs` (NEON)

```rust
//! Reed–Solomon's NEON engine computes what the scalar engine computes.
use sandblaster::prelude::*;
use crate::reed_solomon::engine::{Engine, GfElement, Neon, Scalar, ShardsRefMut};
use crate::reed_solomon::engine::tables::Multiply128lutT;

/// Byte `k` of a 128-bit table row, little-endian (`to_ne_bytes` on these targets).
#[spec]
#[example(row_byte(0x0102u128, 0u8) == 2u8)]
#[example(row_byte(0x0102u128, 1u8) == 1u8)]
pub fn row_byte(t: u128, k: u8) -> u8 { (t >> (8u32 * (k as u32))) as u8 }

/// One field element times the multiplier of `lut`, from its four nibbles. The element
/// has low byte `lo` and high byte `hi`; the result is the product's (low, high) bytes.
#[spec]
pub fn mul_elem(lut: Multiply128lutT, lo: u8, hi: u8) -> (u8, u8) {
    let (n0, n1, n2, n3) = (lo & 15u8, lo >> 4u32, hi & 15u8, hi >> 4u32);
    (row_byte(lut.lo[0], n0) ^ row_byte(lut.lo[1], n1) ^ row_byte(lut.lo[2], n2) ^ row_byte(lut.lo[3], n3),
     row_byte(lut.hi[0], n0) ^ row_byte(lut.hi[1], n1) ^ row_byte(lut.hi[2], n2) ^ row_byte(lut.hi[3], n3))
}

/// The same element times Scalar's 16-bit row (`Mul16`, entry `[log_m]`).
#[spec]
pub fn mul_elem16(lut16: [[u16; 16]; 4], lo: u8, hi: u8) -> (u8, u8) {
    let p = lut16[0][(lo & 15u8) as usize] ^ lut16[1][(lo >> 4u32) as usize]
          ^ lut16[2][(hi & 15u8) as usize] ^ lut16[3][(hi >> 4u32) as usize];
    (p as u8, (p >> 8u32) as u8)
}

/// `lut` is the byte split of `lut16`: byte `x` of `lo[i]` and `hi[i]` is the low and high
/// byte of `lut16[i][x]` (the layout `tables::Multiply128lutT` documents).
#[spec]
pub fn is_split_of(lut: Multiply128lutT, lut16: [[u16; 16]; 4]) -> Prop {
    forall(|i: usize, x: u8| (i < 4 && x < 16u8) implies
        (row_byte(lut.lo[i], x) == lut16[i][x as usize] as u8
         && row_byte(lut.hi[i], x) == (lut16[i][x as usize] >> 8u32) as u8))
}

/// A chunk multiplied element by element. Element `i < 32` keeps its low byte at `i`
/// and its high byte at `32 + i` (Engine::mul's layout).
#[spec]
pub fn mul_chunk(lut: Multiply128lutT, c: [u8; 64]) -> [u8; 64] { /* 32 elements, each `mul_elem` */ }

/// Layer 1: Neon's mul multiplies every element of every chunk by its table row.
#[law]
fn neon_mul_multiplies_each_element(n: Neon, x: Seq<[u8; 64]>, log_m: GfElement) {
    ensures({ let mut a = x; n.mul(&mut a, log_m); a }
         == x.map(|c: [u8; 64]| mul_chunk(n.mul128[log_m as usize], c)));
}

/// Layer 2: Neon's mul equals Scalar's mul on every input, when Neon's table rows are
/// the byte split of Scalar's.
#[law]
fn neon_mul_is_scalar_mul(n: Neon, s: Scalar, x: Seq<[u8; 64]>, log_m: GfElement) {
    requires(is_split_of(n.mul128[log_m as usize], s.mul16[log_m as usize]));
    ensures({ let mut a = x; n.mul(&mut a, log_m); a }
         == { let mut b = x; s.mul(&mut b, log_m); b });
}

/// The transforms: the same block transform as Scalar, shard for shard, including the
/// shards `Engine::fft` leaves unspecified (both engines run the same butterflies).
#[law]
fn neon_fft_is_scalar_fft(n: Neon, s: Scalar, d: Shards, pos: usize, size: usize,
                          truncated_size: usize, skew_delta: usize) {
    requires(same_tables(n, s));   // every row split, and the same skew table
    ensures({ let mut a = d; n.fft(&mut a, pos, size, truncated_size, skew_delta); a }
         == { let mut b = d; s.fft(&mut b, pos, size, truncated_size, skew_delta); b });
}

#[law]
fn neon_ifft_is_scalar_ifft(n: Neon, s: Scalar, d: Shards, pos: usize, size: usize,
                            truncated_size: usize, skew_delta: usize) {
    requires(same_tables(n, s));
    ensures({ let mut a = d; n.ifft(&mut a, pos, size, truncated_size, skew_delta); a }
         == { let mut b = d; s.ifft(&mut b, pos, size, truncated_size, skew_delta); b });
}

/// What `Engine::fft` documents under "Panics", for every engine.
#[spec]
pub fn transform_ok(len: usize, pos: usize, size: usize, truncated_size: usize,
                    skew_delta: usize) -> bool {
    size.is_power_of_two() && size <= 65536usize && truncated_size <= size
        && pos <= len && size <= len - pos && (size == 1usize || skew_delta <= 65536usize - size)
}

#[lift_attach(<crate::reed_solomon::engine::Neon as crate::reed_solomon::engine::Engine>::fft)]
fn neon_fft_contract() {
    panics_when(!transform_ok(data.len(), pos, size, truncated_size, skew_delta));
}
// … the same contract for `ifft`, and for Scalar's `fft` and `ifft`.
```

* **Shard state.** `Shards` and `d` stand for the lifted state of
  `ShardsRefMut`: shard count, chunks per shard, and the chunks.
* **`ifft`'s precondition** ("input shards in
  `data[pos + truncated_size..pos + size]` must be zero") is not needed
  for equivalence: both engines compute the same on every input.
* **A stronger later law.** A characterization of Scalar's transform
  (the additive FFT over the Cantor basis) is a later, stronger law;
  Neon inherits it through the equivalence.
* **The x86 engines' laws** are the same with `Ssse3`, `Avx2` and
  `Avx512`. Avx512 uses its GFNI table (`MulGfni`, its documented 8×8
  bit matrices) in place of `Multiply128lutT`, so its layer-2 hypothesis
  relates `MulGfni` to `Mul16`. That is the crate's
  `mul_gfni_matrix_semantics` test, as a predicate.

### 5.3 The memory-safety statement

The record prints this per verified function, generated from the
reading's counts. It is a consequence of the theorem, not an extra one.
For example:

> `<Neon as Engine>::mul`: on every input, the MIR returns the value its
> laws give and has no undefined behaviour. Per chunk, its 4 loads and 4
> stores each touch 16 bytes inside that chunk's 64. They go through a
> pointer formed from the chunk's `&mut`, and nothing else touches the
> chunk while that pointer is in use. Each of its 8 table loads reads the
> 16 bytes of one `u128` table entry behind a shared reference. Every
> NEON instruction runs with NEON available, which is static for
> `aarch64-apple-darwin`.

For `fft` and `ifft` the statement also says when the function panics:
the panic contract, which is `validate_transform`'s condition.

### 5.4 Proof route and expected size

* **`mul_128` per lane** (PROOF.rs summary):
  * the 8 table loads become `row_byte`s, by the `u128` byte-view lemma;
  * each TBL lane closes by `bv()`;
  * the lane-split closer joins the lanes.

  Expected: 30–60 proof lines for its 33 code lines.
* **`mul_neon`.**
  * Loop invariant over `IterMut`.
  * Per chunk, the byte-view lemmas show that the first `mul_128` call
    sees elements 0–15 (bytes 0–15 low, 32–47 high) and the second
    elements 16–31 (bytes 16–31 low, 48–63 high).
  * The four stores put each product byte back at its element's
    positions.

  Expected: 40–80 lines.
* **Layer 2.** Both engines are proven equal to `x.map(mul_chunk ..)`, an
  intermediate closed form (DESIGN.md §16.1 e). No coupled loops are
  needed, even though Neon does 16 elements per call and Scalar does one.
* **`fft` and `ifft`.** The two `fft_private`s have the same loops; only
  the partial butterfly differs. A per-chunk lemma covers that:
  `fftb_128(x, y)` is `(x ^ y·m, y ^ x ^ y·m)`, which is Scalar's
  `mul_add` then `xor`. Then either lockstep for lifted functions (C3)
  or a shared characterization of the butterfly schedule.
* **Stop rule.** DESIGN.md §18's stop rules apply: more than 20 proof
  lines per code line, or more than two agent-weeks for the first
  target, is reported to the user.

---------------------------------------------------------------------------

## 6. The trusted delta, effort and risks

### 6.1 Trusted lines (estimate, code lines)

| part | file | lines |
| --- | --- | ---: |
| printer: `(ptr const/mut T)` types; static features and endianness; each instance's `unsafe`; the pointer helpers as leaves by exact path; `AddressOf`, `Offset` and `PtrToPtr` printed structurally | `mirx` | 60–90 |
| parse: the above; refuse `(kind union)` | `mir/ir.rs` | 30–45 |
| library: `mir::Ptr`; `mem::read` and `mem::write` with their bounds; little-endian packing of words and `u128`; `array_of_list` for the models' memory types | `mir/literal.core` | 50–80 |
| generator: pointer slots; formations; offsets and casts; load and store arms with write-back; byte views per base type; the scope rule (crate MIR only); refusal of calls from crate MIR to library `unsafe fn`s outside the admitted list | `mir/literal.rs` | 160–230 |
| the window rule (families, liveness, ancestors, windows, W0–W4) | `mir/window.rs` (new) | 120–180 |
| the pointer intrinsic table; static features in the feature rule | `mir/arch.rs` | 40–60 |
| features: the needs fixpoint; the boundary check against `requires_features`; the static-feature load check; lift glue for the clause and the record | `mir/mod.rs`, `mir/gate.rs`, lift | 50–80 |
| the blanket refusal removed; an untrusted, build-failing diagnostic pass checks each source `unsafe` block against the admitted operations (it also refuses a crate's own `transmute`, §1.11 item 2) | `lift.rs` | −10 to +10 |
| **total** | | **about 510–775** (central estimate 640) |

* **Size relative to item 8.** This is 10–15% on top of DESIGN.md §1.1
  item 8's 5.01k lines. For comparison, C8's first slice was planned at
  150–300 and came in at about 335.
* **Why more than the C8 survey's estimate.** The survey's §5 estimated
  330–510. This design adds:
  * the window rule's precision (ancestors and liveness, so that
    `fftb_128` and the fused AVX-512 butterfly are accepted);
  * the feature needs inference;
  * the closures of §1.11.
* **Possible trims for a first version.** About 30–40 lines: the
  `AddressOf`, `Offset`, `sub` and `offset` forms, which the engines do
  not use.

**Not counted here** (other capabilities, also needed by the engines):

* `u128` as a value type (C4; +40–60 for what the engines need);
* the `IterMut` and `Zip` models (+60–100 in L);
* subslice codes (+60–100);
* the second level of §4.5 (+100–150).

**Untrusted:** S +150–250 lines; walker +50–100; tests.

### 6.2 Effort (agent-days)

| step | work | agent-days |
| --- | --- | ---: |
| 0 | normative text: `docs/mir-lift.md` §20.10, DESIGN.md and AUDIT.md edits (§8) | 1–2 |
| 1 | fixtures: positive crates, twins, extraction (NEON native, x86 for `x86_64-apple-darwin`), Miri variants | 2–3 |
| 2 | `mirx` and the parse | 1–2 |
| 3 | L: pointer values, byte views, formations, offsets, loads and stores; the §1.11 closures; `tests/literal.rs` against rustc with twins; fault injection | 4–7 |
| 4 | the window rule, with one twin per rule | 2–4 |
| 5 | features: static record and check; needs inference; `requires_features`; record text | 1–3 |
| 6 | S, the walker, conformance of the fixtures (NEON natively) | 3–5 |
| | **the reading, steps 0–6** | **14–26** |
| 7 | NEON `mul`: `u128` (C4 slice); `Multiply128lutT` and `Neon` as types; the `IterMut` model; laws and proofs for `mul_128`, `muladd_128`, `fftb_128`, `ifftb_128`, `mul_neon`, `<Neon as Engine>::mul` | 8–13 |
| 8 | NEON `fft`, `ifft`: `Zip`; subslice codes; `ShardsRefMut`; `dist2_mut`, `dist4_mut`, `split_at_mut`; `utils::xor`; loops; C3 or a characterization; panic contracts | 10–18 |
| 9 | SSSE3: two models (validated under Rosetta 2 here); PSHUFB lanes; the same pointer shapes on 16-byte elements | 4–7 |
| 10 | AVX2: AVX models loaded (a lock change); two models; an x86 host for evidence and conformance | 4–8 |
| 11 | AVX-512: GFNI laws over 8×8 bit matrices; three models; an AVX-512 host | 8–15 |
| 12 | optional: second-level features (§4.5); `tables.rs` initializers for "on every input" | 6–12 |
| 13 | independent review of the window rule and of L's pointer constructs, once the artifact has its shape | 2–3 |

Totals:

* the reading: 14–26;
* NEON complete (`mul`, `fft`, `ifft`): 32–57;
* all four engines: 48–87;
* plus step 13's review (2–3), and step 12 if wanted.

The first target, `<Neon as Engine>::mul`, is step 7: 8–13 days after
the reading. That is at the edge of DESIGN.md §18's stop rule (two
agent-weeks for the first target); going over it is reported to the
user.

### 6.3 Risks

1. **The window rule is the main soundness risk.** It is trusted and
   subtle; a bug gives a value where Rust has undefined behaviour.
   *Mitigations:*
   * the rule is conservative: what both Stacked and Tree Borrows allow;
   * one twin per rule;
   * a Miri cross-check. Each positive pointer fixture has a variant that
     uses `ptr::read_unaligned` and `write_unaligned`, which is how
     stdarch implements the admitted intrinsics. It runs under Miri with
     both aliasing models. The aliasing twins must be reported as
     undefined behaviour by at least one model;
   * an independent review at the end (step 13).
2. **Rust's aliasing model is not final.**
   *Mitigations:*
   * the rule targets the intersection of the two models;
   * the Miri cross-check runs again at every toolchain bump, which also
     re-extracts every `.sbmir`.
3. **MIR shape drift.** The helpers could be inlined by a later rustc, or
   `add` could gain a `ub_checks` precondition.
   *Mitigations:*
   * both the leaf form and the inlined constructs read the same;
   * `RuntimeChecks(ub)` is already read as `false`, and the bounds test
     covers what those checks check.
4. **Conformance with 8 MiB tables.** `mul_neon`, `fftb_128` and the
   transforms take `&self`, whose `&'static Mul128` is 8 MiB. Evaluating
   L on that value is heavy.
   *Mitigations:*
   * compare the functions that take a row (`mul_128`, `muladd_128`)
     and the fixtures;
   * give the harness a lazy table input: one concrete row and a shared
     placeholder;
   * respect `memguard`'s cap (resource limits).

   The theorems do not depend on conformance: it tests L's constructs,
   which the fixtures cover.
5. **Proof cost of byte views and lanes.** This depends on the lane-split
   closer (C8 second slice) and the byte-view lemmas.
   *Mitigation:* measure against DESIGN.md §18's stop rule (20:1).
6. **Prerequisites outside this design dominate the transforms.**
   Subslice codes, `IterMut`, `Zip` and `ShardsRefMut` (B3) are a
   schedule risk, not a soundness one.
7. **x86 hardware.**
   * AVX2 and AVX-512 evidence and conformance need x86 hosts (Zen 5).
   * New SSE models validate under Rosetta 2 here.
   * Whether Rosetta 2 executes AVX2 on this macOS has to be checked
     before counting on it.
8. **Feature trust.**
   * The static record is checked against the build.
   * The x86 engines' `Engine` methods carry host obligations until the
     second level exists; the record says so.
9. **Lock churn.**
   * S uses lift-prelude wrappers, so no `builtins` change.
   * Loading the AVX models is a lock change in any case (C8 second
     slice: a header-only re-accept of every lock, and four varint item
     hashes restated).
10. **Scope pressure.** Other `unsafe` will be requested next:
    `get_unchecked`, `from_raw_parts`, pointers passed to helper
    functions. Each needs its own user decision, as the decision says.
11. **Parallel work.** C8's first slice is landing now in the same files
    (`mir/arch.rs`, `read.rs`, `tests/simd.rs`, the `sd_neon*` fixtures).
    Apply this design after it lands. Its test
    `a_load_through_a_raw_pointer_is_refused_and_named` (fixture
    `sd_neon_ptr`) flips: that load becomes an accepted fixture, with the
    twins of §7 refused in its place.
12. **A missed closure.** An unsafe operation that the old syntactic
    refusal hid, and that §1.11 does not list, would be admitted
    silently.
    *Mitigation:* the untrusted diagnostic pass reads the source's
    `unsafe` blocks and must find, for each one, only admitted operations
    in the MIR; any mismatch fails the build with the operation named.

---------------------------------------------------------------------------

## 7. Step plan

Each step ends with its tests green. Following the standing preference,
there are no gates, mutation runs or red teams on intermediate work: the
independent review is step 13, once the artifact has its shape.

**Step 0. Normative text.** Write `docs/mir-lift.md` §20.10 ("Pointers in
crate code") from §1–§4 of this design, and make the DESIGN.md and
AUDIT.md edits of §8.

**Step 1. Fixtures first.** New crates under
`front/tests/mir_fixtures/`, each a minimal copy of one engine shape:

| fixture | shape | verified against |
| --- | --- | --- |
| `sd_ptr_load` (today's `sd_neon_ptr`, now accepted) | `unsafe { vld1q_u8(a.as_ptr()) }`, `a: &[u8; 16]`, in a function without `#[target_feature]` (NEON is static) | the vector's lanes are `a` |
| `sd_ptr_words` | `vld1q_u8(core::ptr::from_ref(t).cast::<u8>())`, `t: &[u64; 2]` (a shared word base, before `u128`); later the same with `t: &u128` | lanes are `t`'s little-endian bytes |
| `sd_ptr_chunk` | `x: &mut [u8; 64]`: 4 loads at `add(16 * k)`, the `sd_neon` nibble multiply, 4 stores; an `#[inline(always)]` helper with intrinsics in `unsafe`, called from a `#[target_feature]` function | per-byte scalar reference |
| `sd_ptr_pair` | `x, y: &mut [u8; 64]`: two mutable families interleaved, `fftb_128`'s shape | the scalar butterfly per byte |
| `sd_ptr_chunks` (with step 7) | `x: &mut [[u8; 64]]` through `iter_mut`, one family per chunk | the chunk law, mapped |
| `sd_x86_ptr` | SSSE3 shape: `as_mut_ptr().cast::<__m128i>()`, `add(1..3)`, `_mm_loadu_si128`/`_mm_storeu_si128`; extracted for `x86_64-apple-darwin` | per-byte reference |

Twins, each refused with its reason named:

* a load past the end (`add(49)` then a 16-byte load);
* `add(65)`;
* a store through `as_ptr().cast_mut()`;
* a pointer returned, stored in an array, or passed to a crate function;
* two formations from one `&mut`, interleaved;
* the reference read inside the window;
* a base local written inside a shared family's window;
* `get_unchecked`, `ptr::read`, `*p`;
* a union field read, `transmute`;
* `_mm_load_si128` (aligned, no model);
* a `#[target_feature(enable = "sha3")]` call from a host-callable
  function without `requires_features`;
* an extraction whose static features differ from the build's.

The Miri variants of risk 1 are run here.

*Exit:*

* the fixtures verify in place with native conformance (NEON);
* the x86 fixture's theorems hold for an x86_64 build;
* every twin is refused with its reason;
* fault injection breaks exactly the right theorem: an offset, a load's
  width, a family's base, a formation's kind.

**Steps 2–6. The reading.** Implement it in order: the printer and parse,
L, the window rule, features, then S and the walker. Each L construct
gets a `tests/literal.rs` case against rustc's semantics, with its
negative twin.

*Exit:* step 1's exit, on the real implementation.

**Step 7. `engine_neon`'s `mul` and its helpers.**

1. `u128` as a value with its byte view (C4 slice).
2. `Multiply128lutT` and `Neon` as types of the extraction.
3. `mul_128` and `muladd_128`: their summaries, the table loads, lanes.
4. `fftb_128` and `ifftb_128`: two mutable families each. They need
   nothing beyond the reading and `u128`.
5. The `IterMut` model, then `mul_neon`.
6. `<Neon as Engine>::mul` with layers 1 and 2 of §5.

*Exit:*

* `<Neon as Engine>::mul` is verified in place;
* the record shows §5.3's statement;
* native conformance on the functions with small inputs.

**Step 8. `fft` and `ifft`.** In order:

1. `Zip` of `IterMut`s;
2. the partial butterflies;
3. subslice codes;
4. `ShardsRefMut` with `dist4_mut`, `dist2_mut`, `split_at_mut` and
   `IndexMut`;
5. `utils::xor` and `xor_within`;
6. the two-layer butterflies;
7. `fft_private` and `ifft_private`, via lockstep (C3) against Scalar's
   or a shared characterization;
8. the panic contracts.

*Exit:* `<Neon as Engine>::{fft, ifft}` are verified against Scalar's,
with matching panic contracts.

**Step 9. SSSE3.**

* Models for `_mm_set1_epi8` and `_mm_srli_epi64`, validated under
  Rosetta 2.
* PSHUFB lanes: the closer, or the 256-case lemma.
* The pointer side is step 7's with 16-byte elements.
* On `x86_64-unknown-linux-gnu`, `requires_features("ssse3")`.
* Conformance under Rosetta 2 if the harness runs there, otherwise on an
  x86 host.

**Step 10. AVX2.**

* The AVX models are loaded: a lock change, done in C8's second slice.
* Models for `_mm256_set1_epi8` and `_mm256_broadcastsi128_si256`.
* `LutAvx2::from`'s eight shared table loads.
* `requires_features("avx2")` on the `Engine` methods.
* An x86 host.

**Step 11. AVX-512.**

* Laws for `_mm512_gf2p8affine_epi64_epi8` over `MulGfni`'s documented
  matrices.
* `LutGfni::from` (value intrinsics only).
* The fused two-layer butterfly's four families.
* `requires_features("avx512f", "gfni")`.
* An AVX-512 host.

**Step 12 (optional).**

* The second feature level, which verifies the constructors' detection
  and removes the x86 host obligations.
* `tables.rs`, which removes layer 2's hypothesis.
* `utils::formal_derivative_16_avx512` (31 families) with its caller's
  detection.
* curve25519's NEON and AVX-512 `load` and `store`.

**Step 13. Independent review** of the window rule, L's pointer
constructs and §1.11. Then the result goes to the user.

---------------------------------------------------------------------------

## 8. Edits the repository's documents need

These were listed here because the design stage did not touch the
worktree. Done on 2026-10-06 (stage "prepare"): DESIGN.md decisions (1)
and (9), §2's policy, the §16 table row, §16.4, §16.5, the roadmap's C10
row and first target, the North star's hardware bullet, §1.1 item 8's
counts; `docs/mir-lift.md` §20.1 (the optimization level and the window
extraction) and §20.4 (unions); `kernel/AUDIT.md` §21.1; the README. The
rest lands with the reading it describes.

* **DESIGN.md:**
  * North star "Honest evidence", the hardware bullet: Commonware's
    engines are verifiable as written; decision (9) is no longer needed.
  * §1.1 item 7: static features; `requires_features` host obligations.
  * §1.1 item 8: new trusted files and lines (`mir/window.rs`).
  * §2 "No unsafe, for good": replace with the narrow reading and its
    four kinds.
  * §16 table row "`unsafe`" and §16.4 "Loads and stores": the narrow
    reading.
  * §16.5 "No unsafe, for good": amended. No new `unsafe`, ever; the
    existing `unsafe` in the admitted subset is verified.
  * §18:
    * decision (1) amended (2026-10-06, "We need to support this");
    * decision (9) withdrawn;
    * the C8 row and the first-target text (no split; the reading's
      steps);
    * a new capability row for this reading, with §6's numbers.
  * "What a green build means": the memory-safety sentence of §0.
* **`docs/mir-lift.md`:**
  * §20 introduction: remove "One look at a body's syntax remains … is
    refused";
  * §20.2 table: the S rows of §3;
  * §20.4 types: pointers in crate MIR;
  * §20.4 statements: the formation, offset and cast rows;
  * §20.4 terminators: load and store rows;
  * §20.9 rule 1: pointer intrinsics read through the table;
  * §20.9 rule 6: static features count; needs;
  * new §20.10, this reading.
* **`docs/checked-structuring.md` §4:** A3 as in §2.7.
* **`kernel/AUDIT.md` §21.1:** new rows (`mir/window.rs`, the deltas of
  §6.1) and an auditor's checklist for each rule W0–W4.
* **`front/tests/simd.rs`:** the pointer test flips (risk 11).
* **SEMANTICS.md §19,** at the next lock acceptance: §20.10 joins it with
  the rest of §20.

---------------------------------------------------------------------------

## Appendix A. `mul_neon` in rustc's MIR (aarch64, abridged)

From `recovery/prover-simd/mir-survey/rs_neon.sbmir.gz`, with locals
abbreviated. These are the constructs §1 admits and §2.6 checks.

```text
(fn ".. engine_neon::Neon::mul_neon"  (target-features "neon") (argc 3)
  (2 (ref mut (slice (array u8 64))))   ; x
  (13 (ref mut (array u8 64)))          ; chunk
  (14 RawPtr(u8, Mut))                  ; x_ptr        → (ptr mut u8)
  (bb 7  _13 = move ((_10 as Some).0)
         _15 = cast unsize (copy _13) (ref mut (slice u8))
         call <[u8]>::as_mut_ptr(move _15) -> _14              ; formation F (mutable, base [u8; 64])
  (bb 9  _17 = cast PtrToPtr (copy _14) *const u8
         call (arch vld1q_u8 (features "neon") unsafe pointer) (move _17) -> _16
  (bb 10 call <*mut u8>::add(copy _14, 16) -> _20                ; off 16, ≤ 64
  (bb 11 _19 = cast PtrToPtr (move _20) *const u8
         call (arch vld1q_u8 ..) (move _19) -> _18               ; read 16..32
  (bb 12 _25 = checked mul (16, 2); assert !overflow
  ...
  (bb 18 call Neon::mul_128(copy _16, copy _21, copy _4) -> _33   ; vectors and lut only
  (bb 20 call (arch vst1q_u8 ..) (copy _14, copy _31)            ; write 0..16
  ...
  (bb 28 call (arch vst1q_u8 ..) (move _45, copy _35) -> goto bb4 ; last use: end of the window
```

`mul_128`'s table loads:

```text
_9 = &((*_3).0: [u128; 4])[_10]                     ; _3: &Multiply128lutT
call std::ptr::from_ref::<u128>(move _9) -> _8      ; formation (shared, base u128)
call <*const u128>::cast::<u8>(move _8) -> _7
call (arch vld1q_u8 ..) (move _7) -> _6             ; read 0..16 of the row
```

On aarch64, `cpu_features::neon()` is
`has_neon::get` → `init_get` → `_1 = const true; _0 = (InitToken, move _1)`.
It is the constant `true`, so `Neon::new()`'s `assert!` is dead code.

## Appendix B. Counts per engine (rustc's MIR of the engines' own functions)

| construct | NEON | x86 (SSSE3, AVX2, AVX-512) |
| --- | ---: | ---: |
| `vld1q_u8` / `_mm_loadu_si128` | 28 | 36 |
| `vst1q_u8` / `_mm_storeu_si128` | 20 | 20 |
| `_mm256_loadu_si256`, `_mm256_storeu_si256` | — | 10, 10 |
| `_mm512_loadu_si512`, `_mm512_storeu_si512` | — | 13, 13 |
| `<[u8]>::as_mut_ptr` | 5 | 23 |
| `ptr::from_ref::<u128>` | 8 | 16 |
| `<*const u128>::cast` | 8 (`u8`) | 16 (`__m128i`) |
| `<*mut u8>::cast` | — | 5 (`__m128i`), 5 (`__m256i`), 13 (`__m512i`) |
| `add` | 30 (`*mut u8`) | 30 (`*mut __m128i`), 10 (`*mut __m256i`) |
| `PtrToPtr` casts | 20 | 43 |
| other casts | `int-to-int` 6, `unsize` 5 | `int-to-int` 24, `unsize` 23 |
| transmutes, raw dereferences, unions, assembly | 0 | 0 |

---------------------------------------------------------------------------

## Amendments (adversarial review, 2026-10-06)

An adversarial soundness review (`docs/UNSAFE-SIMD-CRITIQUE.md`) tried
to find a program in the admitted subset where L gives a value while the
real program has undefined behaviour or a different value. The value model
(byte views, bounds, formation, offsets, loads, stores) held up; the two
critical findings are about the reading's *inputs*. Every accepted fix is
listed here and governs the design above where it conflicts.

* **A-S1 (critical). The window rule must run on MIR that reflects the
  source's aliasing, and the opt level must be pinned.** The extraction
  reads rustc's *optimized* MIR (§20.1), but §2.6's exactness argument and
  §2.7's A3′ are about source-level Stacked/Tree Borrows. `ReferencePropagation`,
  `CopyProp`, `GVN` and `DeadStoreElimination` (all on at the default
  mir-opt-level) can delete the very access W2/W3 rely on — e.g. the read
  of `chunk[0]` that makes §2.6's example refuse — so L could give a value
  for a program that is UB. The shipped `release` build also uses a
  different pipeline than the extraction's `check`. Fix: pin
  `-Zmir-opt-level=0` for pointer-bearing extractions, record it
  (`(mir-opt-level 0)`) and refuse any other level at load (as the target
  and overflow-checks are refused); or extract a second un-optimized MIR
  for the window analysis and require it to name the same function and
  locals. Make the two-model Miri cross-check (risk 1) a **mandatory build
  gate over the real engine functions**, not only the fixtures. Amend §2.7
  A3′ to assume the extracted MIR preserves the source's aliasing
  structure, naming the pin as the mitigation. Risk 3 is extended to cover
  the aliasing analysis, not only the value reading.

* **A-S2 (critical). Fix the union parse now, independently, and
  surgically.** §1.11 item 1's premise is wrong: the blanket `unsafe`
  refusal inspects only crate-body tokens (`first_unsafe`), so a union
  field read inside a *followed library function* is not gated by it and
  can mis-value today. `(kind union)` already appears in the shipped
  `mmr.sbmir` (`LazyLock::Data`) and `verifier.sbmir` (`MaybeUninit`,
  `LazyLock::Data`); nothing is mis-valued only because no `union-field`
  read is currently modeled to a value there. Fix: treat this as a latent
  bug in the current lift, fixed immediately with a negative twin. Prefer
  refusing a `Field`/`SetDiscriminant` access to a union place and a
  `(union-field ..)` aggregate over refusing the `(kind union)` type; if
  only the type refusal is practical, first measure its effect on the
  accepted MMR and verifier locks, and put any reached-but-never-accessed
  union type on an explicit reviewed allow-list rather than parsing it as
  a struct. Add a standing scan of every `.sbmir` for unions.

* **A-S3 (high). Bind the static feature set to the build.** §4.2's check
  against `CARGO_CFG_TARGET_FEATURE` is incomplete: that variable omits
  features implied by `-C target-cpu=native`/`<model>`, and the extraction
  is a separate `cargo check` whose flags are not tied to the verifying
  build's. A mismatch can change which feature detections fold to
  constants, so the theorem describes a different program than ships, with
  only conformance (a test) as backstop. Fix: derive the static record
  from the build's own flags; refuse a non-default `-C target-cpu` (or
  require an explicit, reviewed feature allow-list the record is checked
  against); record and compare `target-cpu`/`target-feature` themselves;
  and state in §1.1 item 7 and risk 8 the assumption that the extraction
  and the build share the target and its feature configuration. Until the
  binding exists, "static features count" is trusted-more-than-stated.

* **A-S4 (high). The mutable-iterator models are TCB, not prerequisites.**
  `IterMut` and `Zip` of `IterMut`s (§1.9) must yield *disjoint,
  non-overlapping element codes* and compose their write-backs; that
  disjointness — which the window rule does **not** supply — is what makes
  `mul_neon`, every `fft_butterfly_partial`, and `formal_derivative`'s
  leaf memory-safe. Fix: promote them to trusted lift surface with their
  own conformance tests, a stated disjointness property, and a negative
  twin (a model yielding overlapping codes must break a theorem), and
  count them in the trusted delta (§6.1) rather than "not counted here."

* **A-S5 (high). Alignment is a per-intrinsic checked obligation, not a
  constant.** §1.5's "none" column is correct at the pinned nightly (all
  six admitted loads/stores are `read_unaligned`/`write_unaligned`/byte
  copies, confirmed in stdarch), but it is a property of the
  *implementation*. Fix: make alignment a per-intrinsic field of the
  trusted table set from each intrinsic's documented contract, keep §2.5's
  alignment-obligation machinery wired even though every current entry
  discharges it with `a = 1`, and tie the unaligned fact to the model's
  validation evidence so a toolchain bump re-checks it.

* **A-S6 (high). Enforce, and explain, the base-type restrictions.** The
  admitted base and pointee types must be checked **transitively
  `UnsafeCell`-free** (so `PShr` snapshots equal memory) and **niche-free**
  in the trusted parse — not merely matched by name, so a later widening to
  structs cannot break the snapshot or the byte-view round trip. Niche-
  freedom is also why a panic *between* a load and a store (a safe
  `self.skew[..]` index in `fft_private`) is unwind-safe: the partially
  written `&mut` referent is still a valid value. §2.5 and §5.3 state this.

* **A-S7 (medium). The library-`unsafe fn` allow-list is exact and
  load-bearing.** It contains `<*T>::add`/`sub`/`offset`, which are
  themselves `unsafe fn`s, so §1.11 item 3's rule has carve-outs that are
  the pointer operations the whole subset rests on. Fix: match the
  allow-list by exact def-path **plus signature**, enumerate it in the
  trusted gate, print it on the record, and give each entry a negative
  twin (a same-named non-pointer `add`, a library `unsafe fn` just off the
  list). The rule's intent is "refuse a callee with an unchecked safety
  precondition"; a *safe* library leaf carrying such a precondition
  (niche constructors via `transmute_unchecked`) must be re-confirmed
  stuck.

* **A-S8 (medium). Name the `&mut` non-aliasing assumption.** The window
  rule does not catch two aliasing `&mut` parameters (`fftb_128`'s `x`,
  `y`); that is A3, assumed, and this design leans on it harder. §5.3's
  per-function statement names each `&mut` parameter's non-aliasing
  precondition as a host obligation wherever a raw pointer is formed from
  it.

* **A-S9 (medium). Admitted load/store models are pure byte
  reinterpretation.** L equates the validated hardware model with the
  byte-level `mem::read`/`mem::write` only because these loads/stores
  reinterpret their `n` bytes with no masking, broadcast, gather or
  conversion (which is also why the stdarch byte-copy implementation and
  the real instruction agree). §1.5 records this as an admission
  condition; the already-refused masked/gather/broadcast forms are the
  boundary.

* **A-process. Trust gates come first.** The two-model Miri cross-check
  over the real engine functions and the independent human review of
  `window.rs` and L's pointer arms land **with** the reading (step 3), not
  at step 13, because the window rule and L's pointer constructs are
  trusted the moment the blanket refusal is lifted. Both re-run at every
  toolchain bump (A-S1, A-S5, A-S9 depend on the pinned MIR shape and
  stdarch).

---------------------------------------------------------------------------

## Implementation record

### Stage "prepare" (2026-10-06)

Notes and measurements: `sandblaster-wt/recovery/unsafe-simd/impl/`
(outside the repository).

**A-S2, unions: fixed in the current lift, surgically.** The parse
(`mir/ir.rs`, `refuse_union_access`, trusted) now records `(kind union)`
(`AdtDef::is_union`; an unknown kind is a parse error) and makes every
access to a union's fields unsupported in both readings: a `Field` or
`Downcast` projection of a place of union type (reads, writes, borrows,
through references or not), a union's aggregate (with or without
`(union-field ..)`), and a constant of union type (rustc's destructuring of
a union constant would list every field at offset 0). L reads each as
stuck, named; S refuses it. A union moved or copied whole is read as
before, and `ModuleNames::transparent_path` never reads a union as the
newtype of its field. The type is not refused, so no allow-list was
needed: in every checked-in extraction the only unions are `MaybeUninit`
and `LazyLock`'s `Data`, reached as field types of other types and never
accessed, and the parse refuses no access in any of them. Measured:
`sandblaster check` on varint, MMR and verifier gives the same obligation
counts (21,253; 4,263; 2,339), the same 63, 69 + 18 and 69 + 13 theorems
and the same lock roots as before. Pinned by `tests/literal.rs`
`a_union_field_is_never_read_and_a_struct_field_is` (L: a struct's field
read is its value, directly and through a followed library function; the
union's aggregate, field reads, a borrowed field, a field write through
`&mut`, a union constant each stuck and named, and the critique's twin, a
crate function without `unsafe` reading a union's field through a
followed library function, stuck on a concrete union value; a union moved
whole read; without the fix the test fails),
`the_parse_refuses_what_it_would_have_guessed` (the kind), `tests/mir.rs`
`a_union_is_never_read_through_its_field_nor_as_its_field` (S, and the
newtype rule) and `every_checked_in_extraction_is_scanned_for_unions` (the
standing scan the critique asks for: it fails on a new union or on any
refused access in a checked-in `.sbmir`).

**A-S1, the optimization level: the second extraction (the amendment's
alternative), because level 0 regresses the readings.** Measured on the
three verified modules, extracted with the stage's mirx at a pinned level
1 and at level 0:

* level 1 reproduces the checked-in extractions byte for byte, but for the
  two new header lines `(mir-opt-level 1)` and `(target ..)`;
* at level 0 (varint 647 blocks against 571, MMR 528 against 500, verifier
  401 against 376), varint keeps its 63 theorems and its lock, but the
  structured reading refuses six MMR functions (`Position::checked_add`
  and `Location::checked_add`: "read of `_0` before it is set";
  `location_to_position`, `is_valid_size`, `chunk_peaks`: a `&str`
  constant dereferenced; `position_to_location`: a zero-sized closure
  value) and, in the verifier, the two `checked_add`s,
  `location_to_position` and `proof.rs`'s `Subtree` code (type errors), so
  the MMR and the verifier would lose their theorems and their accepted
  locks;
* L itself reads the same instances at both levels with unmodeled
  constructs only in the same host codec functions.

So the readings keep level 1, and the window analysis gets its own
unoptimized extraction:

* mirx pins `-Zmir-opt-level` for the extracted crate
  (`SBMIR_MIR_OPT_LEVEL`, `extract.sh --mir-opt-level N`, default 1) and
  records `(mir-opt-level N)`;
* the build refuses a main extraction recorded at another level than
  `mir::MIR_OPT_LEVEL` = 1;
* `#[lift(mir = "m.sbmir", window_mir = "m.window.sbmir")]` declares the
  window extraction, which `mir::load_window` refuses unless it records
  level 0 exactly (`mir::WINDOW_MIR_OPT_LEVEL`) and is the same program
  (below). Nothing reads it yet but the check; the window analysis (§2.6)
  will be its only reader. Since the check compares every header record,
  a window extraction accompanies only a main extraction made by this
  mirx (with its `(target ..)` and `(mir-opt-level 1)` records).

Pinned by `tests/mir.rs`
`the_mir_opt_level_is_the_readings_and_a_window_extraction_is_the_same_program_unoptimized`
(each level, and each correspondence twin: another level or none, another
module, compiler, source set or root set, a function missing or of another
signature) and
`a_window_extraction_is_declared_beside_the_extraction_and_checked`
(through the lift: loaded beside `mir`, refused without `mir`, unreadable,
unrecorded or at level 1). On the real extractions the check accepts each
module's level-0 extraction against its level-1 one and refuses level 1
as a window.

**Deviations, and why.**

1. *"Require it to name the same function and locals"* (A-S1). Locals
   cannot match: level 1's passes merge and drop locals by design (varint's
   functions gain locals and blocks at level 0). The check requires the
   same functions with the same signatures (definition, item, parameter
   and return types, body presence, target features), the same roots and
   the same sources. Relating the window analysis' verdict to the level-1
   MIR that L reads is part of the window stage: a formation is a call of
   an admitted helper with a source position, and the verdict must be
   carried per formation by that position and callee, refusing any
   formation that does not correspond one to one. That rule is trusted
   and gets its own twins there.
2. *A main extraction without the record is accepted* (as level 1). The
   build refuses every recorded level other than 1, but the extractions
   older than the record (the three shipped modules and the toolchain's
   fixtures) carry none, and re-extracting the shipped ones would also add
   the `(target ..)` record, after which a build for another architecture
   (an x86_64 CI host) refuses them. They were made with `cargo check`'s
   default, level 1, and the shipped three were re-extracted at a pinned
   level 1 and compared byte for byte. The window extraction, the one the
   soundness argument needs at level 0, has no such exception, and the
   pointer reading (step 3) should require the record on any extraction
   with pointer code.
3. *The critique's list of level-1 passes.* It names
   `ReferencePropagation`, `GVN` and `DeadStoreElimination` at the default
   level; as far as this stage could tell (rustc's pass list, not checked
   against this nightly's source) those run at level 2, while level 1
   runs, among others, `CopyProp`, `SimplifyLocals`, `RemoveZsts` and
   `LowerSliceLenCalls`. That changes nothing: level 1 still rewrites
   locals and assignments the window rule reads, so the fix stands.

### Stage "unsafe-reading" (2026-10-07)

Notes and logs: `sandblaster-wt/recovery/unsafe-simd/impl/` (outside the
repository). The reading as built is described in `docs/mir-lift.md`
§20.10; the trusted lines are counted in DESIGN.md §1.1 item 8 and
`kernel/AUDIT.md` §21.1.

**Built.** The admitted subset (formations from references, `add`, `sub`,
`offset`, casts, the trusted table of loads and stores with a
per-intrinsic alignment, S5); library `unsafe fn`s matched by exact path
and signature, with mirx recording each function's declared unsafety, so
that an unsafe callee outside the table is refused (S7); the memory model
in L (`PMut`/`PShr` pointers, little-endian byte views of plain types
checked free of `UnsafeCell` and niches, S6; `Stuck` on any access out of
bounds or misused); the structured reading and the walker's support; the
window rule W0–W4 on the unoptimized extraction (S1), with the `&mut`
parameters a family's base reaches named in its verdicts (S8); the
static features bound to the build's, `-C target-cpu` and
`-C target-feature` included (S3); the pure-reinterpretation check of
every admitted row (S9); the `IterMut` model with its disjointness (S4).
The C1 blanket refusal of `unsafe` is replaced by this reading for an
extraction made by the current mirx (`(unsafe-reading 1)`); an older one
keeps the refusal, with "extract it again". The Miri gate
(`front/tests/miri/run.sh`: the fixtures and the twins, and with
`--engines` Commonware's NEON engine through a harness) writes a record
when clean, which `tests/unsafe_simd.rs` checks against the pinned
toolchain and the covered files (deviation 15).

**Measured.**

* The fixture `sd_ptr` (`mul_neon`'s shape: an `unsafe`
  `#[target_feature(enable = "neon")]` function walking
  `x: &mut [[u8; 64]]` with `iter_mut`, loading the four quarters of each
  chunk through `as_mut_ptr().add(16 * k)`, multiplying them by an
  `#[inline(always)]` NEON helper and storing them back; the same on one
  `&mut [u8; 64]`, `fftb_128`'s shape; two pointer families in one
  function; a safe entry point; a load from a shared formation): every
  theorem is proven — `mul_16`, `chunk_mul` (0.2 s walk), `xor_rows`,
  `load_row`, `mul_chunks__loop0` (the `IterMut` loop's lemma: 3.8 s walk,
  0.7 s kernel check, 20,718 nodes), `mul_chunks`, `mul`; the whole module
  in about 45 s of test time under the 6 GiB cap (peak about 0.45 GiB).
  L agrees with rustc on concrete inputs (0, 1 and 2 chunks).
* The twins: each refused, in L (stuck or refused, with the reason) and
  by the lift (named): a load past the end, an offset past one beyond it,
  a store through a shared formation (W4), a pointer returned or stored
  (W1), a pointer dereferenced as a place, the base written or read
  inside the window and two formations from one `&mut` (W2), a load from
  a `bool` table (a niche), a runtime-detected feature with no fact, the
  library `unsafe fn`s `ptr::read`, `get_unchecked` and `byte_add` beside
  the admitted `add` (S7), while a crate function named `add` is read as
  any function. The feature binding refuses another build's static
  features, `-C target-cpu`, `-C target-feature` (in the extraction or
  the build) and a big-endian extraction; without the build's features
  NEON outside a `#[target_feature]` function is refused.
* Fault injection on the literal side: an offset, a load's width, the
  family a load goes through, a formation's kind, and the `IterMut`
  model's disjointness (every code the first element's) each break the
  theorem of the function that holds them.
* The Miri gate (`front/tests/miri/run.sh --engines`, 17 minutes on the
  final sources): the positive fixtures clean under Stacked and Tree
  Borrows (3 tests each); a load past the end, an offset past one beyond,
  a store through a shared formation and a write through the base's
  reference inside the window reported as undefined behaviour by both
  models, two formations by Stacked Borrows; Commonware's NEON engine as
  shipped clean under both models (through `tests/miri/engines`, below:
  `mul` on 1 to 3 chunks with four multipliers, `fft` and `ifft` over 4
  shards of one chunk and 2 shards of two, each against the naive engine;
  so `mul_neon`, `mul_128`, `fftb_128`, `ifftb_128` and both butterfly
  paths). Its record, `tests/miri/GATE.txt`, is checked by
  `tests/unsafe_simd.rs` (deviation 15).
* The admitted rows re-read from the toolchain's stdarch: all 13 are
  unaligned copies of exactly their bytes.
* Codec and storage, on the final sources with the cache off. The
  builds verify in place: varint VERIFIED (21,250 obligations, 21,253
  before: below; 603 definitions kernel-checked; lift conformance passed;
  lock `38c1c9c0` matching); MMR VERIFIED (4,263; 741; lock `d87803e2`);
  the verifier VERIFIED (2,339; 588; lock `a7563685`); every §15 gate
  passing. `sandblaster check` agrees: varint 63 of 63 theorems, MMR 69
  of 69 with 18 panic theorems, the verifier 69 of 69 with 13, with only
  the command line's known emission finding. The theorem gate's time on
  varint was 4.3 s before this stage and 4.5 s after (5.1 s in one run
  beside another job).

**Deviations, and why.**

1. *No `__lift_mem` prelude* (§3.1). The lift prelude is hashed into
   every lifted module's lock, so adding to it would change the accepted
   locks of codec and storage. S instead calls the admitted load and
   store intrinsics themselves, typed from their models (`[u8; n]` to the
   vector, the vector to `[u8; n]`) in lifted code, and in ghost code so
   that laws and proofs can speak of them; and an element of a `&mut [T]`
   parameter, held as the state `&[T]`, is assigned with the
   elaborator's slice update, which is L's write through a code.
2. *The static features are rustc's stable ones.* rustc's session lists
   unstable features too; the build's `CARGO_CFG_TARGET_FEATURE` lists
   only stable ones, and the binding requires equality.
3. *W2 exempts the storage markers of ancestors that are not the base*:
   an `unsize`d reference's temporary dies inside the window in the
   unoptimized MIR without any access.
4. *Verdicts are carried to the level-1 MIR by source span and kind*
   (the helper's definition path, or `&raw mut`/`&raw const`), exactly
   one per formation (the prepare stage's deviation 1 left this rule to
   this stage).
5. *The helpers are followed by mirx but read by their path*: their MIR
   bodies are printed (they are library code rustc lets the extractor
   follow) and never read; L applies the table's meaning.
6. *S reads byte-array bases at constant offsets only.* Every admitted
   base the engines use is a byte chunk at constant offsets; any other is
   refused in S and read in L.
7. *S holds a family's window* (§3.1 sketched the base as an S variable):
   inside a window S keeps the base's bytes as the stores left them (the
   value before the first store, `let c = x[i];`, or a stored byte), so it
   never reads the state back. L does read it back: a store through a
   code into a slice's element leaves the next access reading
   `index(update(l, i, v), i)`, which no evaluation reduces on a symbolic
   slice; the walker rewrites it by `seq::index_update_same` as it
   appears. Without that, the four stores of one chunk nest, and the
   loop's walk ran out of memory.
8. *The walker abstracts large literal sides with sharing.* The kernel's
   abstraction reads a value back as a tree (closures' environments
   substituted at each occurrence); the chunk loop's literal side read
   back to 10^7–10^17 nodes. `Walker::abstract_dag` reads it back
   memoized (a DAG), hash-conses the target with it and abstracts
   syntactic occurrences; values below 2·10^6 tree nodes keep the
   kernel's abstraction. `mem::arr_of_list` binds the list's length before
   its proof, so the proof mentions the number, not the list (the proof
   closures of every loaded vector had copied the list 480 times).
9. *`IterMut` in S* is its index; `next` binds the index and the test, and
   the switch on its result is `if c { iter = i + 1; .. }`: one test, so
   the decrease proof needs no case of its own. A checked operation of two
   unsigned literals that does not overflow is read as its value (`16 *
   3`): this is why varint has 3 fewer overflow obligations (all three
   were closed by evaluation), with its theorems and lock unchanged.
10. *`Zip` is not modeled* (S4 "if the engines need them"): `mul_neon`
    does not use it; the transforms' butterflies do, at the next stage.
11. *Alignment*: every admitted row needs 1 (stdarch's unaligned copies);
    the alignment arm is wired and untested by any row.
12. *The `alias` twin writes the base* (a byte the next store covers): a
    read through the parent leaves a raw pointer usable in both Stacked
    and Tree Borrows, so a reading twin is not undefined behaviour; W2
    refuses both (`alias_read` is kept as the conservative case).
13. *The Miri gate over the real engine* goes through a harness crate,
    `tests/miri/engines`, outside Commonware's sources: cpufeatures'
    Miri support answers `false` for every feature, so `Neon::new()`
    asserts under Miri; the harness patches cpufeatures with a copy whose
    Miri support answers the build's static features. Commonware's own
    `minifuzz_mul` under Miri, without the patch, fails at that assert.
14. *`requires_features`* (§4.4) is not built: NEON needs nothing at the
    boundary, and the x86 engines are not in this stage.
15. *The Miri gate is a recorded run, not a build gate* (A-S1 asks for a
    mandatory build gate over the real engine functions). Miri needs the
    pinned nightly with its own sysroot, and the engine harness takes
    about 10 minutes for its first aliasing model on this host (the
    build, with the codec build script verifying varint, then the
    interpreter building the engines' multiplication tables) and about 6
    for the second, 17 for the whole gate: more than every build of the
    shipped crates can carry. Instead a clean `run.sh --engines` writes
    its record, `tests/miri/GATE.txt` (the toolchain, and the SHA-256 of
    each fixture, harness, the `cpufeatures` patch and `engine_neon.rs`),
    and `tests/unsafe_simd.rs` fails while the record names another
    toolchain or a covered file has changed. A toolchain bump, or a change
    to Commonware's NEON engine, therefore fails the test suite until the
    gate runs again. The record is evidence that the gate ran, not a
    proof: it could be edited by hand, which its history shows.

**Open.**

* The laws of a whole chunk and of the slice
  (`tests/unsafe_simd.rs`, `pending_laws`, run with `--ignored`). One byte
  of `chunk_mul`'s result at a literal index proves (by `bv()` after
  unfolding, or by the quarter lemma and `follows()`), but no general form
  does yet: the 64-byte equation exceeds the automation's read-back bound
  (2·10^6 nodes) or its step budget, a quarter of it too (`bv()` gives an
  `Erased` placeholder), `cases(j, 0..64, { bv(); })` checks the
  `requires` proof `j < 64` at its old type in each case (a prover bug:
  a case's literal is not carried into the hypotheses), and a 64-arm
  `match j` runs out of the 6 GiB cap; the loop's contract over the slice
  exceeds the step budget on the four 64-byte stores. The per-vector law
  (`mul_16` is the scalar reference lane by lane), the row load's law and
  the lemma that a quarter loaded, multiplied and stored is the scalar
  reference are proven; the chunk multiplier's functions are not yet
  determined by the specification (the sections gate names them).
  Next: a case split that requalifies its hypotheses and shares the
  unfolded goal across the cases, and a lane-splitting array closer.
* The engines need C4 first: `mul_128` loads its table rows through
  `u128` bases (`from_ref::<u128>(&lut.lo[0]).cast::<u8>()`), which
  `plain` refuses while L has no 128-bit integers.
* `Zip`, `requires_features` and the x86 engines. The x86 engines' Miri
  gate comes with them: on this aarch64 host it needs Miri to interpret
  an x86_64 target (cross-interpretation), which has not been tried.
* The independent human review of `mir/window.rs` and of L's pointer
  constructs (A-process). It is meant to land with the reading, and an
  agent cannot do it.

### Stage "table-lookup-lanes" (2026-10-07; C8's second slice, first item)

Notes and logs: `sandblaster-wt/recovery/unsafe-simd/impl/tl/` (outside
the repository). Everything this stage built is in the untrusted prover
(`front/src/auto`) and in tests and fixtures: the kernel checks every
proof it produces, and **the trusted delta is zero** (DESIGN.md §1.1 item
8 and `kernel/AUDIT.md` §21.1 are unchanged).

**What was missing** (§3.4 "Lanes"). A table lookup's lane is the model's
dependent `if k < 16 as .h then t[k] else 0` (TBL; PSHUFB's is `if m &
128 != 0 then 0 else t[m & 15]`). Two prover gaps kept such lanes out of
reach:

* *The read-back.* After a lane step inside a lookup (the `vandq_u8` that
  makes its index), the rewritten lane read back with an `Erased`
  placeholder: the arm's index proof, which uses the path equation `h`,
  is carried along the step's equation by the abstraction, and the
  kernel reads a proof closure back by substitution, so the unfolded
  vector came back as an untyped pair. The step was refused, and the
  search ran out of budget.
* *No lane split.* Nothing split a vector equation into its lanes. Lane
  by lane, the search spent about 1.2M steps on one TBL lane and 12.7M on
  one lane of `mul_128`'s shape (each lane step and each decided
  comparison a motive over the lane, type-checked); a whole vector law
  exhausted the 20M budget. The first slice's x86 laws went through a
  lemma of 256 cases per lane.

**Built.**

* The read-back gives a transport's endpoints its type
  (`auto::util::kernel_friendly`), so a lane step inside a lookup is
  taken (a single lane at a literal index now proves by the plain search).
* **The lane closer** (`auto::lanes::lane_split`, tried once per atomic
  target before the simplifier; its module docs). On an equation between
  two vectors of which one is made by the models:
  1. the models of both sides are unfolded at once (each
     `def[intrinsic]` head replaced by its body; `BvRefl` equates the two
     forms), so each side is the vector of its lanes;
  2. an array the sides read that is not a variable (a row `lut.lo[0]`)
     is generalized to one, which the kernel introduces as its lanes
     (§5.9); the statement is annotated as written (`let rows : Π(row..).
     Eq(..) = λ.. ; rows lut.lo[0] ..`), because the kernel would infer it
     with the row's lanes, which no longer convert with `fst(lut.lo[0])`
     once a non-variable is put in;
  3. each lane's reads of vector lanes are abstracted: the sixteen lanes
     of a lane-wise computation are one shape, proven once as a function
     of its inputs and applied to each lane's reads (a shape's proof is
     checked once by the kernel, not sixteen times); a read is matched in
     both its forms, `seq::index T (fst x) k` (a value read back) and
     `array::index T N x k` (the elaborated `x[k]`, which a proof quoted
     by substitution keeps), so no proof is left stating a read the shape
     abstracted;
  4. a shape is decided by a case analysis on its conditions, the
     lookups' index tests: a condition linear arithmetic decides (`(x &
     15) < 16`) is rewritten to its value by a transport, an undecided one
     (bit 7 of a symbolic byte) is split by a match; the condition is
     generalized only where the lane tests it — a match's scrutinee
     becomes the motive variable `z`, and the path equation a dependent
     `if c as .h` is applied to becomes the motive's binder `e : Eq(Bool,
     c, z)` — while the match's own motive and every proof keep `c`, so
     the arm's index proof keeps its type and `z := c, e := refl` gives
     the lane back; the motive is read straight from the lane's terms, with
     no abstraction search (the shape's whole proof is checked once,
     below);
  5. a lane with no condition left closes by conversion, `BvRefl`, or (on
     a quarter of the remaining budget) the search on the lane; each
     shape's proof is checked by the kernel as soon as it is built (a slot
     left ill-typed is first re-proved from the context, `auto::repair`),
     so a shape that does not check leaves the target to the search instead
     of failing the goal's check;
  6. the lanes are joined by one `Cons` congruence each and `array::ext`.

  Untrusted code lines (comments and blank lines not counted):
  `auto/lanes.rs` 96 → 654, `auto/util.rs` +7, `auto/search.rs` +3.

**Measured.**

* `front/tests/hardware.rs` (`table_lookups_are_decided_lane_by_lane`,
  `pshufb_lanes_are_split_on_their_index_bit`): a vector of nibble lookups
  (`vqtbl1q_u8(t, vandq_u8(x, 15))` against the direct reads `t[x & 15]`),
  the same lane at a literal index through the plain search, a lookup in a
  row read from an array of rows, the four lookups and three xors of one
  `mul_128` product vector, PSHUFB against its reference, two PSHUFBs
  xored: proven; the twins (the high nibble from the wrong vector; the
  table and the indices swapped) unproven, with no kernel rejection. The
  closer's search costs about 0.25M steps on a vector of nibble lookups
  (one shape, one decided condition; a 7k-node proof), 0.23M on a PSHUFB
  vector (one split), 0.55M on two PSHUFBs xored and 1.0M on the
  `mul_128` product vector (one shape, four conditions; a 15k-node
  proof, whose check costs the kernel 0.91M; the others 0.04M–1.2M, each
  accepted as built). Before the lane shapes, deciding the sixteen lanes
  one by one cost 3.5M steps of search and 6.9M of the kernel's check for
  that vector (a 110k-node proof); through the plain search one lane
  alone cost 12.7M, and a whole vector more than the goal's 20M.
* `front/tests/simd.rs`: the x86 fixture's three laws are `unfold(f);
  follows();` (its proof file went from 103 to 49 lines: the `lanes`
  helper, the 256-case lemma and its sixteen moves are gone; every gate
  and the three MIR theorems pass as before).
* **The fixture `mir_fixtures/sd_neon_mul128`**: Reed–Solomon's
  `mul_128` and `muladd_128` as `engine_neon.rs` writes them — an
  `#[inline(always)]` helper whose eight table rows are loaded through raw
  pointers formed from shared references (`ptr::from_ref(&lut.lo[i])
  .cast::<u8>()`, `vld1q_u8`), whose value intrinsics are in `unsafe`,
  returning both product vectors — with the rows `[u8; 16]` where the
  engine's are `u128` (deviation 2). Laws: `mul_128_is_the_scalar_reference`
  (every element's low and high product bytes, each the xor of its four
  nibbles' row entries: what the scalar engine computes per element, its
  16-bit rows split into bytes) and `muladd_128_adds_the_product`, each
  proven by `unfold(..); follows();`. Built in place: VERIFIED + LIFTED IN
  PLACE, every gate passing, MIR theorems 2 of 2, lift conformance on 800
  inputs of 2 functions and the literal reading on 128, 0 mismatches. The
  twins `sd_neon_mul128_shift` (the low bytes' high nibble taken with a
  shift by 3) and `sd_neon_mul128_row` (the third and fourth rows of the
  low product bytes swapped) are refused by the same laws and proofs, with
  their MIR theorems proven (the wrong code is read as what it is).
* The unsafe-reading stage's open chunk laws: the four quarter laws of a
  64-byte chunk (`chunk_mul_quarter_q`) now prove with `follows()` in
  place of `bv()` (`tests/unsafe_simd.rs`, `pending_laws`, still
  `--ignored`: the loop's contract and the slice laws remain open).
* Mutants (each run, then reverted): without the transport typing of the
  read-back, the single lane at a literal index is unproven; with the
  dependent match's path equation left as `refl(Bool, c)` instead of the
  motive's binder, the shape's proof is ill-typed (`refl(Bool, c) :
  Eq(Bool, c, c)` where `Eq(Bool, c, z)` is expected), which the
  closer's own check reports (its repair then re-proves the slot from the
  case's equation). The shape check also found that the first lane
  closer left a read in its elaborated form in the reference's bound
  proofs: those proofs had been accepted only after the goal's
  self-check repaired them; matching both forms made them well typed as
  built.
* Codec and storage, on the final sources with the cache off: varint
  VERIFIED (21,250 obligations, 603 definitions kernel-checked, lift
  conformance passed, lock `38c1c9c0` matching), MMR VERIFIED in place
  (4,263; 741; lock `d87803e2`), the verifier VERIFIED in place (2,339;
  588; lock `a7563685`), every §15 gate passing, with the same counts of
  automated and hinted obligations as before this stage. `sandblaster
  check` agrees (63 of 63 theorems; 69 of 69 with 18 panic theorems; 69 of
  69 with 13), with only the command line's known emission finding.
* Suites on the final sources: `simd` 10, `hardware` 10, the prover suites
  (`auto_*`, `prover_*`: 181 tests), `unsafe_simd` 10 (1 ignored),
  `verified_roots` 6, `spec15_law_rules` 25, `theorem_gate` 13, `literal`
  38, `panic_contracts` 14 (2 ignored), `fault_injection` 4 and `mir` 51
  (whose standing scan reads the new extractions) pass.

**Deviations, and why.**

1. *The closer is off where the search does not use `BvRefl` by itself*
   (`AutoConfig::auto_bvrefl` false: the law rules' echo prover and the
   completeness discharges). Its bridges and last steps are `BvRefl`, and
   the echo prover of LR6 (a) is defined without it. With the closer on
   there, the first slice's laws about a single intrinsic
   (`lookup_is_the_scalar_reference`, `lookup_is_pshufb`,
   `lookup_masked_is_the_scalar_reference`) read as echoes of the model
   and failed the gate. As before this stage, a law that restates one
   model's lanes is not counted an echo; the check never unfolded a model
   on symbolic data.
2. *The fixture's rows are byte arrays.* The engine's rows are `u128`,
   which L does not read yet (C4). The formation, the loads, the lookups,
   the order of the xors and the two outputs are the engine's.
3. *Layer 1 only* (§5.1). The law relates `mul_128` to the per-element
   product through its own split rows. Layer 2 (Scalar's 16-bit rows, with
   the byte split as a hypothesis) needs the hypothesis instantiated at
   each element's four nibbles and word algebra over the casts; the
   search does not instantiate it (a probe of the per-element lemma
   stayed unproven), so it is open.
4. *`tests/simd.rs`'s native build passes the static features stable
   rustc gives `aarch64-apple-darwin`* (it passed four): an extraction
   made by the current mirx records them and the build must match
   (A-S3); the first slice's fixtures, extracted before the record, are
   unaffected.

**Open.**

* Layer 2 of the split-table laws (the ∀-hypothesis instantiated per
  nibble).
* The loop's contract and the slice laws of the chunk multiplier (above).
* `u128` table rows (C4), then the engine's `mul_128` itself.

### Stage "neon-mul" (2026-10-07; step 7: `<Neon as Engine>::mul`, layers 1 and 2)

Notes and logs: `sandblaster-wt/recovery/unsafe-simd/impl/nm/` (outside
the repository), with the lock preview and the law diff. The reading's
new constructs are described in `docs/mir-lift.md` §20.4 and §20.10; the
trusted lines are counted in DESIGN.md §1.1 item 8 and `kernel/AUDIT.md`
§21.1.

**Result.** The root `cryptography/sandblaster/rs_engine` lifts in place,
from Commonware's own files and as written, `<Neon as Engine>::mul` with
the `mul_neon`, `mul_128` and `muladd_128` it runs, and `<Scalar as
Engine>::mul`, the reference (the extraction's 5 roots, 26 functions with
the library callees; the engines' transforms, constructors and other
helpers stay host code, listed in `unverified_fns`). Its laws:

1. `neon_mul_multiplies_every_chunk` (layer 1): `{ let mut a = x;
   n.mul(&mut a, log_m); a } == mul_all(n.mul128[log_m as usize], x)`,
   every element of every chunk multiplied through the NEON engine's
   table row;
2. `scalar_mul_multiplies_every_chunk` (layer 1): the same through the
   scalar engine's 16-bit row, `mul_all16(s.mul16[log_m as usize], x)`;
3. `neon_mul_is_scalar_mul` (layer 2): `requires(is_split_of(
   n.mul128[log_m as usize], s.mul16[log_m as usize]))`, `ensures({ let
   mut a = x; n.mul(&mut a, log_m); a } == { let mut b = x; s.mul(&mut
   b, log_m); b })`: the two engines agree on every input when the NEON
   row is the byte split of the scalar row;

and `muladd_128`'s contract (lane by lane, `x ^ y·m`), since it is
lifted too (deviation 1). `sandblaster check`: 331 definitions
kernel-checked, 2,887 obligations proven (2,836 automated, 51 hinted), the
3 laws proven, every §15.8 gate passing but the lock (no `SPEC.lock`: the
preview is in the notes, 52 surface items, root `581461cb`), MIR theorems
5 of 5 (`Neon::mul`, `mul_neon`, `mul_128`, `muladd_128`, `Scalar::mul`)
with 3 loop lemmas, in 108 s (the theorem gate 51 s, most of it
`mul_neon`'s loop lemma). No function has a panic contract: each theorem says
that the MIR returns on every input — never a panic, never stuck.

**The memory-safety statement** (§5.3), from the reading's counts:

> `<Neon as Engine>::mul`: on every input, the MIR returns the value its
> laws give and has no undefined behaviour, and it never panics. It calls
> `mul_neon`, a `#[target_feature(enable = "neon")]` function, with NEON
> static on `aarch64-apple-darwin`. Per chunk, `mul_neon`'s 4 loads and 4
> stores each touch 16 bytes inside that chunk's 64, at offsets 0, 16, 32
> and 48 of one pointer formed from the chunk's `&mut [u8; 64]`
> (`as_mut_ptr`; 6 moves, each inside the chunk), and nothing else
> touches the chunk while that pointer is in use (the window rule, on the
> unoptimized extraction). `mul_neon` forms raw pointers from its `&mut`
> parameter `x`, which aliases no other parameter (A3; `x`'s chunks are
> yielded once each by `iter_mut`). Each of the 8 table loads of a
> `mul_128` call (two calls per chunk) reads the 16 bytes of one `u128`
> table entry (`lut.lo[i]`, `lut.hi[i]`) through a pointer formed from a
> shared reference (`ptr::from_ref(..).cast::<u8>()`), which nothing
> writes in its window. Every NEON instruction it runs (`LD1`, `ST1`,
> `TBL`, `AND`, `USHR`, `EOR`, `DUP`) runs with NEON available.
>
> `Neon::muladd_128`: the same 8 table loads of its `mul_128` call; no
> store. `<Scalar as Engine>::mul`: safe code; on every input it returns
> the value its laws give and never panics (every index — a nibble into a
> 16-entry row, `i < 32` into each half of `split_at_mut(32)` of a 64-byte
> chunk — is in bounds).

**Built.** *Trusted* (each construct with a test and a negative twin;
118 code lines):

* `u128` (C4's slice): held as its two 64-bit words, low word first
  (`Tuple2(U64, U64)` in L, `(u64, u64)` in the subset's names); plain
  for the narrow reading, 16 bytes, its bytes `u128::to_le_bytes`' (the
  low word's eight little-endian bytes, then the high word's), back only
  from exactly sixteen; no operator, cast or constant of it is read
  (`literal.rs` +2, `ptr.rs` +8, `mod.rs` +1).
* `PRange(lo, hi)`, a reference code's step to the elements `lo..hi` of
  an array or a slice: element `i` of it is element `lo + i` of the whole
  (`mir::range_index`: `None` unless `lo <= hi <= len` and `i < hi -
  lo`); the range read whole is a slice (`mir::slice_range`,
  `mir::array_range`) and never written whole (`literal.core` +17, the
  follow and update arms of `literal.rs`).
* `<[T]>::split_at_mut` as a model, by the exact path of its definition:
  a panic where core's panics (`mid > len`), else the codes of the halves
  `PRange(0, mid)` and `PRange(mid, len)`, which never reach one element
  (as `IterMut`'s codes, A-S4).
* `Len(P)` (an array's `N`, a slice place's length through its code), and
  the parse's fusion of rustc's `s.len()` on a `&mut [T]` — `t = &raw
  const (fake) *s; d = PtrMetadata(move t)`, only storage markers
  between — into `d = Len(*s)`; any other fake raw borrow is unsupported.
  The printer prints `RawPtrKind::FakeForPtrMetadata` as `(addr-of fake
  P)` (`ir.rs` +41, `mirx` one line).
* A fix of L's places: the projections after the `Deref` of a `&mut` are
  typed from its referent (from the reference before: `(*r)[i]` of a
  `&mut [T]` was refused, and a place read before reads the same).

*The item skeleton* (TCB item 8's skeleton; about 108 code lines): an
open trait at several verified instances (`instance = "Engine: ..Neon,
Engine: ..Scalar"`), each instance's impl read as its methods, an item
generic over such a trait refused, and so such a trait declared in a
lifted file; element attachments (`#[lift_attach(f, loop_nr = k,
element)]`, with `requires(..)`; `requires(..)` on a loop attachment
refused); an in-place module's `items = ..` keeping the type aliases it
names (`tables::Mul128`, named only by `engine_neon.rs`); a `use
core::{arch::aarch64::*, iter::zip}` group keeping its `core::arch`
leaves; in the loader, a private child module of the host's in-place
file crate-visible in the model (rustc enforces the host's privacy; the
laws name `engine_neon::Neon`) and found where rustc finds it
(`engine.rs`'s children in `engine/`). The front end's constant
evaluation reads a constant of an alias of an unsigned type
(`GfElement = u16`) at the alias's width (+18; the kernel evaluates
constants again).

*Untrusted*:

* S (`mir/read.rs` +666): element functions — a loop's body on one
  element, opaque with the attachment's contract, for an `IterMut` loop
  and for a loop inside another's body that works on one element through
  references into it; a loop inside another loop's body whose attachment
  has a contract read as a *returning helper*, its contract about what it
  returns, and its references into the outer loop's element (`x_lo`,
  `x_hi`) not passed but rebuilt at the header from the state and an
  index parameter (`<elem>_index`), with their `PRange` as literals; a
  `div`/`rem` of two unsigned constants folded (`SHARD_CHUNK_BYTES / 2`);
  `Len` of a slice or array place (a subslice's own length), refused of
  any other place.
* The walker (`simproof.rs` +91, `checked.rs` +82): `while` lemmas over
  rebuilt references and extra parameters; element functions unfolded in
  the walk; under an element read out of a slice, the kernel's array eta
  (§5.9) is undone at every read-back — eta lists and element-by-element
  updates folded back to their array (`auto::util::fold_array_eta_any`,
  `fold_update_lists`), the length proofs of spelled-out lists made
  `refl`, element functions' bodies unfolded through lemmas with their
  array parameters' eta lists folded; a callee's `ensures` fact about a
  `while` loop's call bound again at the loop's continuation; a split's
  test abstracted on the structured side at the split's own type.
* The prover: the lane closer tried again (at most four times) after a
  rewrite of the target when a side is an opaque function's result;
  `seq::update_update_same` and `seq::update_neg` (checked lemmas).
* Lift conformance (a test): an in-place struct's field built as the
  source writes it where the lift reads it otherwise (a `&'static T`, a
  `u128`), and an input of more than 65,536 elements skipped, named.

**Measured.**

* The root: the numbers above. Lift conformance, natively (`sandblaster
  conform`): 800 inputs on `mul_128` and
  `muladd_128` (400 each; the literal reading on 64 of each), 0
  mismatches, in 6.5 minutes (the first build of the harness, a copy of
  the host crate, included). `Neon::mul`, `mul_neon` and `Scalar::mul`
  are skipped, named: their `&self` holds the engine's 65,536-entry
  table (8 MiB; 1.1M and 4.3M scalar elements in the lift's view), beyond
  the check's evaluation budget (the check now skips an input of more
  than 65,536 elements, by name). The loop helpers and element functions
  are compared through their functions, as everywhere. The harness builds
  a `&'static` field as a leaked box of its value and a `u128` from the
  lift's words (`conform::in_place::host_field_value`, untrusted test
  code, with a unit test).
* The Miri gate (`run.sh --engines`, rerun because L's pointer constructs
  changed): clean in 20 minutes:
  the positive fixtures under Stacked and Tree Borrows (3 tests each),
  every undefined-behaviour twin reported (`ub_two_formations` under
  Stacked Borrows only, as before), and Commonware's NEON engine (`mul`,
  `fft`, `ifft`) against its naive engine clean under both (2 tests
  each); the record `GATE.txt` is unchanged (no covered file changed).
* Codec and storage, the cache off: the codec build (358 s) "verified
  module `varint` ... 21250 obligation(s) proven, 603 definition(s)
  kernel-checked; every §15 gate passed; lift conformance passed;
  SPEC.lock: matches (116 item(s), root 38c1c9c0..)"; the storage build
  (1,683 s) "`mmr` verified in place ... 4263 ..., 741 ...; lift
  conformance passed; SPEC.lock: matches (211 item(s), root d87803e2..)"
  and "`verifier` verified in place ... 2339 ..., 588 ...; SPEC.lock:
  matches (272 item(s), root a7563685..)". `sandblaster check` on the
  final sources agrees: varint 63 of 63, the MMR 69 of 69 with 18 panic
  theorems, the verifier 69 of 69 with 13, the same obligation counts and
  locks (the command line's emission finding only).
* Suites on the final sources: `literal` 41, `mir` 51, `unsafe_simd` 11
  (1 ignored), `simd` 10, `hardware` 10, `walker` 4, `theorem_gate` 13,
  `lift_open` 28, `typeck` 27, `panic_contracts` 14 (2 ignored),
  `verified_roots` 7, and the front's unit test of the conformance
  harness's fields; `cargo check --all-targets` of the seven sandblaster
  packages, 0 warnings. Two tests stated the old meaning and were updated:
  `literal`'s `u128` is held as its words (no operator on it read, as
  before), and `mir`'s `Len` is refused of a place that is no slice or
  array (it was refused of every place).
* A regression found and fixed on the way: the walker's abstraction of
  the literal side, tried first with the literal runs kept folded (added
  early for the element functions), lost varint's `read` loop lemma (an
  `absurd` proof holding `Erased`) and four of the verifier's theorems (a
  test inside a run left unabstracted, so a contradictory path was not
  closed). With the read-back folds above it was no longer needed for the
  engines, and it was removed; a bisection by toggles found it.
* Tests, each with negative twins: `tests/literal.rs` (the halves of
  `split_at_mut` with their own lengths; lengths and the fake raw borrow;
  `u128`'s words and bytes), `tests/verified_roots.rs` (the root's front
  end: `Engine` at both engines, both element functions, the rebuilt
  references, the extraction's fake raw borrows read as lengths; twins:
  `Mul128` left out of `items`, `Engine` at the NEON engine alone),
  `tests/lift_open.rs` (an item generic over a trait at several instances
  refused), `tests/unsafe_simd.rs` (element attachments and their three
  refusals), `tests/typeck.rs` (a constant of an alias). Mutant: with the
  old `Deref` typing, the `split_at_mut` test fails (the reading refuses
  `(*r)[i]`).
* Size and effort: `LAWS.rs` 412 lines (315 code; the vocabulary spelled
  out lane by lane and byte by byte), `PROOF.rs` 818 (667 code: 38
  lemmas, 11 spec functions, 8 attachments, 4 proofs) for about 105 lines
  of code (`mul` 5, `mul_neon` 24, `mul_128` 42, `muladd_128` 17,
  `Scalar::mul` 17): 6.4 proof lines per code line, under §5.4's stop
  rule (20). One agent, about eight hours over the stage's sessions.

**Deviations, and why.**

1. *`muladd_128` is lifted and verified* (with its contract) rather than
   left as host code: with `mul_128` its only callee among the engine's
   functions, and `mul_128` then without a host caller, the contract is
   what the transforms (host code) get; `mul_128` needs none.
2. *The scalar engine's `mul` is lifted beside the NEON one*, as layer
   2's reference (§5.1).
3. *`is_split_of` compares bytes*: eight equations `row_bytes(lut.lo[i])
   == lo_bytes(lut16[i])` and `row_bytes(lut.hi[i]) ==
   hi_bytes(lut16[i])`, where §5.2 drafts a ∀ over nibbles, and
   `row_bytes` reads a `u128` row as its sixteen little-endian bytes from
   its (low, high) words (`t.0.to_le_bytes()`, ..): the ghost language
   has no `u128` operators either, and arrays compare whole.
4. *The laws are over the whole slice* (`mul_all`, structural over a
   `Seq` of chunks) where §5.2 drafts `x.map(..)`: the same statement
   without a closure.
5. *Element functions and returning helpers*, beyond §3.2's sketch: the
   scalar engine's inner loop works on one chunk through `split_at_mut`'s
   halves, so it is read as a helper that returns the chunk, rebuilding
   its references into it rather than passing them.
6. *The tables' relation stays a hypothesis*: layer 3 is step 12.
7. *The lock is not accepted*: the stage leaves the preview and the law
   diff for review.

**Open.**

* Prover gaps that lengthen `PROOF.rs` (a gap is to be fixed in the
  prover, not worked around in proofs; the next stage's first item): (a)
  auto does not take a conjunct of an unfolded `bool` spec that compares
  arrays to the arrays' equality (`split_rows` needs `by_unfolding`); (b)
  an equation between two array literals whose elements the facts equate
  one by one needs a `rewrite` per element (`chunk_split`'s 64 lines); (c)
  a law comparing two slices needs the slices' view injectivity as a
  lemma (`same_chunks`); (d) the scalar inner loop's bound is stated as
  two inequalities (`iter_24.end == 32` substituted into the loop's terms
  exhausted the budget); (e) its names are MIR locals (`iter_24`).
* Layer 3 (`tables.rs`'s constructors, `LazyLock`), and `fft`, `ifft`
  (step 8).
* The pending chunk and slice laws of `tests/unsafe_simd.rs` may now be
  in reach with the element functions (not tried).

### Stage "unsafe-simd-review" (2026-10-07; an independent, adversarial review of the four stages above)

Notes, fixtures, probes, logs and two prototype patches:
`sandblaster-wt/recovery/unsafe-simd/impl/rv/` (outside the repository).
This was an agent's review; the independent human review of `mir/window.rs`
and of L's pointer arms (A-process) is still open. Nothing else in the
repository was changed.

**F1 (critical, soundness): the window rule misses a base that lives in a
local of the forming function.** `window::check` makes the base local an
ancestor only for `&raw` of a place without `Deref`. For a formation by a
helper (`as_mut_ptr`, `as_ptr`, `from_mut`, `from_ref`) or by
`&raw mut (*r)`, the ancestor closure adds only locals whose type reaches
memory. A local array, or a by-value array parameter, whose reference the
formation takes is then no ancestor, and W2/W3 never see a direct read,
write or `StorageDead` of it inside the window. §2.6 counts it ("or the
local is the base itself"), and AUDIT.md §21.1's checklist item 6 asks for
"the place it borrows". Six programs get an `Ok` verdict and a value from
L, while Miri reports undefined behaviour in each under both Stacked and
Tree Borrows:

* `as_mut_ptr`, `as_ptr`, `ptr::from_mut` and `&raw mut (*r)` of a local,
  with the local written inside the window;
* a by-value array parameter;
* a store after the local's scope has ended.

End to end, `local_xor` lifts in place with a two-line proof: store `v`,
`a[0] = 5`, then store `v ^ w`, all through a pointer to the local `a`.
Every proof and §15 gate passes, and its MIR theorem is proven.

The shipped module is not affected. Its nine formations take the chunk
reference that `IterMut` yields, and `&(*lut).lo[i]` behind a reference
parameter.

Fix (prototyped in a copy, not applied): when an ancestor is assigned a
borrow of a place without `Deref`, the place's root local becomes a base.
It is then an ancestor whatever its type, and its storage markers count as
uses. With it, all six are refused with W2 or W3. The 52 verdicts of every
checked-in window extraction are unchanged, rs_engine's 9 included.

**F2 (medium): the window extraction's codegen configuration is not
checked.** `load_window` compares only the header records the prepare
stage had. It does not compare the four that the unsafe-reading stage
added: `target-static-features`, `endian`, `target-cpu` and
`target-feature-flags`. A window extraction made with
`RUSTFLAGS=-Ctarget-feature=+sm4` is accepted beside a default main
extraction. A write under `#[cfg(not(target_feature = "sm4"))]` is then in
the body L reads, but not in the one the window rule judged. The verdict is
`Ok` and L gives a value, while the program has `param_write`'s undefined
behaviour. `extract.sh` does not clear `RUSTFLAGS`. Every checked-in pair
has equal records.

Fix (prototyped): compare those four records as well.

**Lower.**

* The front suite is red: `reader_widen`, below.

* AUDIT.md §21.1's checklist item 3 still says "not `u128`".
* `docs/checked-structuring.md` §4 A3 was never restated as §2.7 and A-S1
  ask: it still says "no raw pointers, no `unsafe`".
* The §5.3 memory-safety statement is written by hand, not generated. A
  verified build's record prints only the A3 line.
* The helper allow-list is not printed on the record, as A-S7 asks.
* The alignment arm is untested.
* Conservative refusals: a store through a `split_at_mut` half is stuck in
  L, and an `IterMut` passed through `enumerate`, `zip` or `rev` is
  refused.

**Confirmed on a fresh build.**

* `cargo check --all-targets`: 0 warnings.
* The Miri gate is clean (1,108 s). `GATE.txt` was rewritten identical.
* Natively, `<Neon as Engine>::mul` equals `<Scalar as Engine>::mul` and
  `Naive`, with 0 mismatches:
  * 99,082 random and edge cases;
  * all 65,536 multipliers on a 3-chunk input.
* `is_split_of` holds on every row of the real tables.
* `sandblaster check` of rs_engine: every gate passes except the lock (not
  accepted). That is 331 definitions, 2,887 obligations, 3 laws, and 5 of 5
  MIR theorems.
* Codec and storage tests pass, with varint, MMR and the verifier VERIFIED
  and their locks matching.
* The full front suite, kernel and targets run 80 times: 1,379 tests
  pass and 1 fails. `reader_widen` expects `window` to be unproven, and its
  theorem now proves. The kernel checks that theorem, so this is a sound
  improvement from one of these stages. The expectation is stale; the test
  passed at the merge stage, and none of the four stages ran it.

The laws state the nibble-table lookup of each engine's own row. The gate's
LR6 (b) warns that each one resembles the code. They also state the two
engines' agreement under the documented byte-split relation. They do not
state GF(2^16) multiplication, which rests on the tables (layer 3, open).

**Verdict.**

* Committing: not until F1, F2 and the red suite are fixed. The F1 and F2
  fixes go in with their twins (the review's fixtures, and the F1 programs
  among the Miri gate's twins) and are counted in §1.1 item 8 and AUDIT.md.
* Presenting rs_engine's laws: yes, with the caveats above. F1 and F2 do
  not reach that module.

### Stage "soundness-fixes" (2026-10-07; the review's findings fixed)

Notes, scripts, logs, the patch scripts and the probes:
`sandblaster-wt/recovery/unsafe-simd/impl/soundness-fixes/` (outside the
repository). The trusted lines are counted in DESIGN.md §1.1 item 8 and
`kernel/AUDIT.md` §21.1; the normative text is `docs/mir-lift.md` §20.1 and
§20.10. The independent human review of `mir/window.rs` and of L's pointer
arms (A-process) is still open.

**F1, the window rule's bases (critical), fixed in principle.** Which
places can be a pointer's base, re-derived: a reference points into a
local's own storage only when it was made by borrowing a place that lives
in that local (no `Deref`: the local, a field, an element, a variant's
field); otherwise into memory behind another reference (whose local is an
ancestor by its type), into what a parameter or a call result reaches
(the caller's memory, A3, or memory reached from the call's
reference-carrying arguments, ancestors), or into constant or static
memory (no local holds it; immutable for the admitted types). So the
**bases** of a formation are the root locals of the places that live in
them and are borrowed (`&`, `&mut`, `&raw`) into an ancestor, or by the
`&raw` formation itself, computed flow-insensitively with the ancestors;
every base is an ancestor whatever its type. Every direct use of a base
is a point that mentions it, and each point's uses are classified
(`Use`: read, moved whole, moved out of, written, borrowed mutably, a
storage marker, dropped, an unprinted operation). W2 refuses any use of an
ancestor in the window but the storage marker of an ancestor that is not a
base (a base's storage marker ends its memory). W3 now allows only reads
(a copy, a shared or fake borrow, a length, a discriminant, an index), a
whole move of a shared reference (its value; an owning value moved, a
`Box`, could be freed by its new owner) and a non-base storage marker; an
ancestor of `&mut` type not at all. Two pointers from one base are two
families, the second's borrow a use in the first's window; a reference
made before the formation and used after it is an ancestor or a loan the
borrow checker rejects.

Beyond the prototype (`../rv/f1-window-fix.patch`), which the re-derivation
confirmed for its two constructs (a borrow into an ancestor makes a base;
a base's storage counts), W3 had to refuse more than writes: a base moved
inside a shared window (`moved_into_call` passed the prototype), an
owning value moved (a `Box` the base is reached through), a drop, a move
out of memory behind an ancestor, a borrow of a kind other than
`shared` and `fake` (mutable whatever it is named; the old rule matched
`"mut"` only), and an unprinted rvalue or callee (which mentioned no local
before: an unprinted statement or terminator already mentioned all).

*Twins* (`front/tests/mir_fixtures/sd_ptr_local`, extracted at levels 1
and 0): the review's six programs and 19 siblings — a by-value parameter
written through a mutable pointer, `&raw mut` of a local written, and of a
local whose scope ended, a field of a local struct, a tuple's array, a row
of a local array of rows, a `Box` and a `Vec` owned by a local, a
temporary (shared and mutable), a closure writing the local, two mutable
pointers from one local, a shared then a mutable one, a reborrow moved and
written, a loop and a call writing the local, a pointer formed in a loop's
body and used after it, a non-`Copy` local moved into a call inside a
shared window, a `static mut` — each refused: its window verdict names the
rule (W2 or W3, the local the base lives in), L is stuck there with that
reason (`struct_field` and `moved_into_call` with the module's types
declared, the lifted crate's environment; `boxed` earlier, on the `Box`,
which L does not model), the lift's diagnostic pass names it, and every one with
undefined behaviour is in the Miri gate's twins (23: both models report
each but `local_raw_write`, Stacked Borrows only; `moved_into_call` is
clean under Miri, which reads a moved-from local's bytes, and is refused
conservatively; `static_mut_store` is defined and refused as a cast of a
pointer constant). Positive: a local written only through its pointer, two
shared pointers to one local (both read as rustc computes them), an
immutable static and a promoted constant (their window verdicts pass; L
does not read a constant reference to an array, stuck, named: a
conservative refusal; the lift refuses the `static` item itself), and the
two alignment fixtures below. Before the fix 19 of the 24 twins the window
rule judges passed it; after it, each is refused.

*The checked-in verdicts*: the 52 verdicts of every checked-in window
extraction (rs_engine's 9, `sd_neon_mul128` and its two twins 8 each,
`sd_ptr` 5, `sd_ptr_twins` 14) are byte-identical in full text before and
after (`tests/unsafe_simd.rs` `every_checked_in_window_verdict` prints them;
it asserts rs_engine's nine `Ok`, `mul_neon`'s naming `x`).

**F2, the window extraction's configuration (medium), fail closed.** The
parse keeps every header record (`Sbmir::header`: every top-level record
but the functions and the type definitions); `load_window` requires every
one but `(mir-opt-level ..)` equal to the main extraction's — so a record
the printer adds later is compared without anyone listing it — and every
type definition the two share equal (the text of a type the printer does
not print blanked: rustc's internal ids in it differ between runs). The
specific comparisons it replaces (compiler, crate, module, overflow
checks, target, exclusions, sources, roots, printer) are all header
records. `extract.sh` refuses a non-empty inherited `RUSTFLAGS`,
`CARGO_ENCODED_RUSTFLAGS`, `CARGO_BUILD_RUSTFLAGS` or
`CARGO_TARGET_<triple>_RUSTFLAGS`, and runs Cargo with
`CARGO_ENCODED_RUSTFLAGS` set (empty, or `--rustflags`, an option for
negative twins only), which overrides every other source of rustflags,
Cargo's configuration files included; mirx records them, `(rustflags
"..")`, and `load` refuses a main extraction recording any. The record is
what makes a `--cfg` difference visible: no other record shows it.

*Twins* (`front/tests/mir_fixtures/sd_ptr_cfg`: `param_write`'s shape with
the write compiled out under `-C target-feature=+sm4`, `cfg_alias`, the
review's, and under `--cfg sd_twin`, `cfg_flag_alias`): with the matching
window extraction both formations fail W2; the window extraction made
under `-C target-feature=+sm4` is refused, naming its static features, its
`-C target-feature` and its rustflags; the one made under `--cfg sd_twin`
is refused naming its rustflags, the only record it differs in; each
header record changed alone (rustflags, byte order, target CPU, target
feature flags, printer, overflow checks, exclusions, a note) is refused,
and so is a type definition both share, changed (`sd_ptr_local`'s
`Pair`); a main extraction with rustflags is refused by `load`.

**F10, `reader_widen`.** `window` (`data.get(i..j)`) moves from the
functions read only to those proven: its theorem is kernel-checked and
accepted by the trusted check (`prove_and_check` refuses any theorem the
gate's α-equality refuses), and what it equates is right: L's reading of
it, with core's `get` by a range followed in library MIR, gives rustc's
value on every range of the slices of lengths 0 to 3, out-of-order and
out-of-bounds ones included (`window_reads_as_rustc_computes`, 86 inputs).

**F5, the alignment arm.** A test hook (`literal::test_fault::
set_row_align`, never set by a build, beside the `IterMut` fault) reads
every admitted row as needing a given alignment. With 16: a load from a
base aligned to 16 (`[u128; 2]`, `rows_at`) reads at offsets 0 and 16 and
is stuck at 8, and one from a byte array (`bytes_at`) is refused, named;
with the rows' own alignment (1) every offset in bounds reads, as rustc
computes.

**F9, A-S7 on the record.** The record of a build whose functions read
from MIR form a raw pointer lists the library `unsafe fn`s crate code may
call (`ptr::admitted_unsafe_fns`: `add`, `sub`, `offset` of `*const T` and
`*mut T`, under `core::` and `std::`).

**F4, the memory-safety statement, generated.** `mir::safety` (untrusted:
it restates what each MIR theorem implies and can misdescribe, never
admit) reads, per function read from MIR, the facts the narrow reading
itself read — each formation with its window verdict (its kind, the `&mut`
parameters its base is reached through), its family's base
(`ptr::bases`), the family's moves and its loads and stores through the
admitted table with their byte counts and constant offsets, the
intrinsics called with the features they need and where the body has them
(its own `#[target_feature]`, or the target's static features bound to the
build's), the `#[target_feature]` functions and the other functions read
from MIR it calls — and the record prints one statement per function.
For rs_engine it states what the hand-written statement (stage neon-mul,
above) states (`tests/verified_roots.rs`
`the_rs_engine_record_states_its_memory_safety` checks each fact):

| the hand-written statement | the record, generated |
| --- | --- |
| `mul_neon`'s 4 loads and 4 stores each touch 16 bytes inside that chunk's 64, at offsets 0, 16, 32 and 48 | 4 loads (`vld1q_u8`, 16 bytes at offsets 0, 16, 32 and 48) and 4 stores (`vst1q_u8`, the same), each inside the base |
| one pointer formed from the chunk's `&mut [u8; 64]` (`as_mut_ptr`; 6 moves, each inside the chunk) | 1 raw pointer formed by `as_mut_ptr` from `chunk` (`[u8; 64]`: a mutable base of 64 bytes); 6 moves |
| nothing else touches the chunk while that pointer is in use (the window rule) | the window rule passed: nothing else reaches the base while the pointer is in use |
| `mul_neon` forms raw pointers from its `&mut` parameter `x`, which aliases no other parameter (A3) | reached through the `&mut` parameter `x`, assumed to alias no other parameter (A3) |
| each of the 8 table loads of a `mul_128` call (two calls per chunk) reads the 16 bytes of one `u128` table entry (`lut.lo[i]`, `lut.hi[i]`) through a pointer formed from a shared reference, which nothing writes in its window | `mul_128`: 8 raw pointers formed by `ptr::from_ref` from `lut.lo[0]` .. `lut.hi[3]` (`u128`: a shared base of 16 bytes); through each 1 load (`vld1q_u8`, 16 bytes at offset 0); nothing writes the base while the pointer is in use; `mul_neon` calls `mul_128` (2 call sites) |
| it calls `mul_neon`, a `#[target_feature(enable = "neon")]` function, with NEON static | `Neon::mul` calls `Neon::mul_neon`, a `#[target_feature(enable = "neon")]` function; `neon` enabled statically on `arm64-apple-macosx` (A-S3) |
| every NEON instruction it runs (`LD1`, `ST1`, `TBL`, `AND`, `USHR`, `EOR`, `DUP`) runs with NEON available | `mul_neon`'s intrinsics (`vld1q_u8`, `vst1q_u8`) need `neon`, its own `#[target_feature]`; `mul_128`'s (`vld1q_u8`, `vqtbl1q_u8`, `vandq_u8`, `vshrq_n_u8`, `veorq_u8`, `vdupq_n_u8`) need `neon`, static |
| `Neon::muladd_128`: the same 8 table loads of its `mul_128` call; no store | `Neon::muladd_128`: no raw pointer; it calls `Neon::mul_128` (1 call site); its intrinsic `veorq_u8` needs `neon`, static |
| `<Scalar as Engine>::mul`: safe code | `Scalar::mul`: no raw pointer; no intrinsic: safe code |

Not generated: that `x`'s chunks are yielded once each by `iter_mut`
(the `IterMut` model's disjointness, A-S4, which no per-function fact
shows), that no function panics (a theorem's outcome `Ret`; the record
lists panic contracts where there are some), and the instructions'
mnemonics.

**F3** (AUDIT.md §21.1 checklist item 3: `u128` is plain since stage
neon-mul) and **F8** (`docs/checked-structuring.md` §4 A3 restated as
§2.7 and A-S1 ask, with A3′; A4's mirx size) are fixed in the text.

**The lock-hash question** (stage neon-mul). The spec sheet's kernel
statement of `scalar_mul_multiplies_every_chunk` carries, as the proof of
the index bound `log_m as usize < 65536` in `s.mul16[log_m as usize]`, a
term the elaborator built under the call's facts: a λ over `h_ens`, the
type of `Scalar::mul::ensures` (PROOF.rs's summary, mentioning
`crate::proof::muls16_from`), applied to it. The lock does not cover it.
`canon` replaces every irrelevant subterm (a proof: an argument the
kernel's relevance table marks irrelevant, printed with a leading `.`) by
`•`, and the item's dependencies are the globals in relevant positions
only, so neither `muls16_from` nor `Scalar::mul::ensures` is hashed or a
dependency. Shown: the lock preview of a copy of the crate as it is, and
of one with PROOF.rs's `muls16_from` renamed (which changes that term), have
the same root (`581461cb`), the same item hash (`5e9eb968`), canon, source
hash and dependencies; only the entry's displayed `kernel type` line
differs, which `lock::compare` does not compare (it compares hashes and the
de-elaborated statement), so a PROOF.rs edit leaves a matching lock
matching (`spec --accept` would list the entry as restated: its displayed
text). Nothing to fix; the three accepted locks are untouched.

**Measured** (the final sources; logs in the stage's notes).

* Mutants of every trusted construct, each run then reverted, every one
  caught by its twin for its own reason: 14 in `window.rs` (a borrow into
  an ancestor no longer making a base; a base no longer an ancestor
  whatever its type; a base's storage marker skipped in W2; the `&raw`
  formation's place no longer a base; W3 letting through a base moved, an
  owning value (a `Box`) moved whole, a drop, an unprinted operation, a
  move out of a place, a borrow of an unknown kind, `&raw mut`, an
  assignment's destination; an unprinted rvalue or callee mentioning no
  local), 5 in `mod.rs` (the header
  comparison skipped; the `(rustflags ..)` record left out of it; the four
  records the review named left out, the old list; the type definitions
  not compared; `load`'s rustflags refusal skipped) and 2 in `literal.rs`
  (the alignment arm's base check and its offset check removed).
* The 52 checked-in window verdicts are byte-identical in full text
  before and after every window change (rs_engine's 9, `sd_neon_mul128`
  and its two twins 8 each, `sd_ptr` 5, `sd_ptr_twins` 14).
* `extract.sh` refuses `RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`,
  `CARGO_BUILD_RUSTFLAGS` and `CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS`
  when set (exit 2, nothing written).
* The Miri gate (`run.sh --engines`, 1,301 s): the positive fixtures clean
  under Stacked and Tree Borrows (4 tests each, one new: `sd_ptr_local`'s
  positive functions and its alignment fixtures at offsets 0, 8 and 16);
  all 28
  undefined-behaviour twins reported, the 23 new ones by both models but
  `ub_local_raw_write` (Stacked Borrows only), as `ub_two_formations`
  before; Commonware's NEON engine against its naive engine clean under
  both (2 tests each). `GATE.txt` rewritten: it now covers
  `sd_ptr_local/src/a.rs`, and the Miri crate's three changed files.
* `cargo check --all-targets` of the seven sandblaster packages: 0
  warnings; mirx's build: 0 warnings.
* `sandblaster check` of rs_engine (the release CLI, cache off), unchanged:
  331 definitions checked, 2,887 obligations proven (2,836 automated, 51
  hinted), the 3 laws proven, the gates boundary, examples (58), sections
  (2), law rules (0 errors, the 4 `law-resembles-impl` warnings) and
  MIR theorems (5 of 5, 47.8 s) passed, the lock missing (52 items, not
  accepted): NOT VERIFIED for the lock only.
* The full front suite (its lib and all 77 test binaries, one at a time),
  `sandblaster-kernel` and `sandblaster-targets`: 80 runs, 1,389 tests
  passed, 16 ignored, 0 failed — among them `reader_widen` 4 (red before),
  `unsafe_simd` 18 (+1 ignored), `mir` 51, `literal` 41, `simd` 10,
  `hardware` 10, `fault_injection` 4, `theorem_gate` 13, `verified_roots`
  8, `lift_open` 28, `typeck` 27, `panic_contracts` 14 (+2), `walker` 4.
  One more test was added to `unsafe_simd` afterwards (the two struct
  twins read with the module's types declared) and the binary run again:
  19 passed, 1 ignored.
* The review's own probes against the final tree (its harness, outside the
  repository): every `fx/rv_local` program refused and stuck in L where it
  gave a value; `fx/rv_cfg`'s window extraction refused; `fx/rv_green_x`
  (`local_xor` with its laws and proofs) refused by the front end, no
  permit, where the review's build gave one.
* Codec and storage, the cache off: `cargo test -p commonware-codec`
  (308 s; 147 + 16 + 5 passed): "verified module `varint` ... 21250
  obligation(s) proven, 603 definition(s) kernel-checked; every §15 gate
  passed; lift conformance passed; SPEC.lock: matches (116 item(s), root
  38c1c9c0..)"; `cargo test -p commonware-storage --lib` (1,629 s; 3,776
  passed, 2 ignored): "`mmr` verified in place ... 4263 ..., 741 ...;
  SPEC.lock: matches (211 item(s), root d87803e2..)" and "`verifier`
  verified in place ... 2339 ..., 588 ...; SPEC.lock: matches (272
  item(s), root a7563685..)". The three accepted locks are unchanged.

**Deviations, and why.**

1. *W3 refuses more than the prototype*: a base moved, an owning value
   moved, a drop, a move out of a place, any borrow kind but `shared` and
   `fake`, and an unprinted rvalue or callee. Re-deriving "every direct
   use" showed the prototype's W3 (writes, `"mut"` borrows, `&mut`
   ancestors, a base's storage) let a moved base through; the rest close
   the rule on what it cannot read. None changes a checked-in verdict.
2. *F2's record*: besides refusing inherited rustflags, `extract.sh` sets
   `CARGO_ENCODED_RUSTFLAGS` (overriding Cargo's configuration files) and
   mirx records the flags, `(rustflags "..")`, so that the comparison
   sees a `--cfg` difference no other record shows, and `load` refuses a
   main extraction made with any. The checked-in extractions before this
   stage (the shipped modules', the older fixtures', rs_engine's) were not
   re-extracted: each pair lacks the record on both sides and compares
   equal; every new extraction carries it.
3. *Type definitions are compared too*, with the text of a type the
   printer does not print blanked (it carries rustc's internal ids, which
   differ between the two runs of the printer: five of rs_engine's shared
   definitions differ only there).
4. *F5 through a test hook in L* (`test_fault::set_row_align`, beside the
   `IterMut` fault), since no admitted row needs alignment: a build never
   sets it.
5. *F4 is generated from the MIR the readings read*, through the trusted
   tables (`ptr::bases`, `ptr::derivation`, `ptr::MEM_INTRINSICS`, the
   window verdicts), not from the structured reading: what the statement
   says does not depend on S's bookkeeping. It does not state what no
   per-function fact shows (the `IterMut` model's disjointness, A-S4).
6. *An immutable static and a promoted constant* pass the window rule but
   L does not read a constant reference to an array: stuck, named (a
   conservative refusal the engines do not meet).

**Open.**

* The independent human review of `mir/window.rs` and of L's pointer arms
  (A-process).
* The review's F6 and F7 (conservative refusals: a store through a
  `split_at_mut` half; an `IterMut` through `enumerate`, `zip`, `rev`).
* The crate's configuration beyond flags (Cargo features) is not
  recorded: both extractions are made from one manifest by one run of
  `extract.py`, and a feature changed between them would not show. A
  record of the crate's `cfg` set would close it (a printer change).
  *Closed in stage leftovers* (the `(cfg ..)` record, below).
* The build's own `--cfg` rustflags are not checked against the
  extraction's (A-S3 binds `-C target-cpu` and `-C target-feature` only).
  *Closed in stage leftovers* where a build script verifies the module.

### Stage "prover-gaps" (2026-10-07; neon-mul's open prover gaps)

Notes, scripts, logs and probes:
`sandblaster-wt/recovery/unsafe-simd/impl/prover-gaps/` (outside the
repository). Every change is in untrusted code — `auto` (the prover), the
elaborator's `calc!`, the structured reading S (`mir/read.rs`) and the
conformance check's generator — so the trusted lines of DESIGN.md §1.1
item 8 and `kernel/AUDIT.md` §21.1 are unchanged (both give S's size, now
4,127 code lines, 3,992 before); the kernel, L, the window rule,
SEMANTICS.md and every law are untouched.

**The five gaps, fixed in the prover** (each on shapes other than
rs_engine's: `tests/prover_gaps.rs` §5, four tests, each with negative
twins; a mutation removing each fix fails its test — logs/mutations-gaps.log,
7 of 7 caught):

* (a) *A `bool` spec's conjuncts as facts* (`auto::terms::term_conjuncts`).
  A fact `P(ā) == true` whose transparent `P` unfolds, on its term, to the
  elaborator's conjunction (`if c { rest } else { false }`) is split into
  its conjuncts: `c == true` by a match on `c` whose `false` arm transports
  the fact to `false == true`, the rest by the transport to `c == true`;
  a conjunct comparing two arrays of machine integers (`array::eq`) becomes
  the arrays' equation (`array::eq_sound_<w>`). Each link is a fact naming
  the previous one by its variable (nesting the transports copied each
  proof into the next: 197k kernel steps became 8M). Test: `split_of(w, v,
  h)`, eight 16-byte comparisons; a late conjunct, all of them reordered,
  one as a `rewrite`'s equation. Twins: rows the fact does not pair, a
  conjunct of a disjunction.
* (b) *Array literals equal element by element*
  (`auto::terms::term_array_split`, `term_backward`). A target `a == b`
  whose sides unfold on their terms (transparent functions; never an
  intrinsic, which the kernel unfolds only on closed arguments) to array
  literals of one length is proven element by element — each pair by a
  fact, by a ∀-fact matched on the element's term (`using(lemma)`), or by
  the search — and the arrays' equation by `array::ext` over a list
  congruence built as a `let` chain (linear; nested motives were
  quadratic, 14.7 s for `chunk_split`, now about 3 s). Test: two literals
  of 24 table lookups, by 24 element facts and by `using(sub_eq)`. Twins:
  the elements in another order, a ∀-fact about other terms.
* (c) *`calc!` through views* (`elab/apply.rs`, `calc_view_ext`). A chain
  from a slice (or array) through its view to another concludes the
  slices' own equation by `slice::ext` (`array::ext`). Test: slices and
  arrays; twin: a chain whose last link does not hold.
* (d) *A loop bound as one equation* (`auto/rewrite.rs`). A fact that
  fixes a field of a variable to a literal (`iter.end == 32usize`) and
  occurs in the target only inside arguments of folded recursive
  applications is rewritten last: rewritten first, it made the loop's
  application unfold at every step and exhausted the budget. Test:
  `rw_mix::mix_grid`'s nested loops, bounds `iter.end == 3u32` and
  `4u32`; twins: a wrong bound, a wrong `ensures`.
* (e) *Source names for loop iterators* (`mir/read.rs`, `loop_scopes`).
  When several locals of one source name are live at a loop's header (an
  outer loop's `iter`, still needed after the inner loop's), the
  attachment's name is the innermost binding: the one whose definition is
  dominated by every other one's (the CFG's dominators, each local's first
  definition). Same test (both loops' iterators are `iter`).

A regression the suites caught on the way: the term-level unfolding of
(b) first went through hardware models (`vqtbl1q_u8`, `_mm_shuffle_epi8`),
which the kernel's conversion does not unfold on symbolic arguments; the
goal's proof was refused by the kernel (`simd` and `hardware`, 2 tests
each). The unfolding now stops at an intrinsic (`elab::tm::head_unfold_if`).

**rs_engine's `PROOF.rs`**: 818 → 726 lines (667 → 578 code; 38 → 36
lemmas): `split_rows` and its two calls removed (a); `chunk_split`'s 64
`rewrite`s replaced by `using(lo_byte_split, hi_byte_split); follows();`
(b); `same_chunks` removed, the `calc!` ends `== b by {
scalar_mul_multiplies_every_chunk(..) }` (c); the scalar inner loop's
bound `iter.end == 32usize` (d); `iter` for `iter_9` and `iter_24` (e).
`sandblaster check`: 329 definitions, 2,671 obligations proven (2,620
automated, 51 hinted; were 331 and 2,887), the 3 laws, MIR theorems 5 of
5, every gate but the lock, 108 s. Lock preview: 52 items, root
`581461cb..`, identical to the neon-mul stage's (`PROOF.rs` is not part of
the surface: its 76 items are proof internals). `lo_byte_split` and
`hi_byte_split` keep their four `rewrite(row_bytes(..) == lo_bytes(..))`
steps each: without them both are unproven, the facts being there (from
(a)) but `auto` not rewriting the target with an equation between two
stuck spec applications (open).

**The pending laws** (`tests/unsafe_simd.rs`). `mul_chunks`' loop body is
read as an element function with its contract (`chunk64`), the loop's
contract is `muls_from` one chunk at a time, the summary follows, and the
length law is proven from them: new test
`the_loop_contract_and_the_length_law_are_proven` (1,296 obligations, 6/6
MIR theorems, every gate but the sections gate, which names the
functions without laws). The law of every byte stays `#[ignore]`d: its
last step reads a 64-byte literal at a symbolic index, and enumerating
the index (`by_cases(j, 0..64)`) runs the kernel's check out of fuel; with
a `requires(j < 64)` the elaborator's `by_cases` produced an ill-typed
proof (the hypothesis kept `j` where the split had replaced it: the
kernel refused it, `TypeMismatch` for `h_req0`) — an elaborator bug,
open.

**Conformance on the real tables** (`conform.rs`,
`conform/in_place.rs`, `conform/literal.rs`; untrusted). A parameter whose
type holds more than 65,536 elements was skipped; now, in place, when the
host gives its type a `Default` (`impl Default for Neon`), it is fixed to
the host's own value: the harness, built before the inputs are
generated, writes `<T as Default>::default()` once (48 MB of JSON for both
engines), read back as one kernel term with its equal subterms shared
(heap 2.2 → 1.1 GB); every call passes the host's own value; the other
parameters vary, on 8 inputs per function in one round (a sample of the
whole candidate list), and the model is evaluated by the reference
strategy (the kernel's closed evaluation type-checks its term first:
checking the scalar engine's 4.26 million entries outgrew the memory cap
where evaluating them takes 1.4 GB). Result
(`sandblaster conform` on the root, cache off, 428 s): 824 inputs on 5
functions, the literal reading on 152 of them, 0 mismatches. `Neon::mul`,
`mul_neon` and `Scalar::mul`, skipped before, are compared on 8 inputs
each with the real tables (1,114,111 and 4,259,839 elements; slices of 0 to
16 chunks, `log_m` from 0 to 65,535 — `GF_MODULUS`, 59,036, 32,767, 8,192,
..; 8 outcome classes each), the literal reading on all 24. A first run
evaluating the model by `eval_closed` failed `Scalar::mul` on every input
(the kernel's check of the table ran into the memory cap, `OutOfFuel`):
the reason for the reference strategy.
Mutation (`mutate-conform.py` in the notes): with each array field of the
fixed value rotated by one entry before it becomes the model's (row
`log_m` of the model's table is the host's row `log_m + 1`), the check
fails with 44 mismatches on the three table functions, the structured
model's and the literal reading's, and none elsewhere. Its first run
aborted instead: a mismatch printed L's outcome whole, a value holding
the table (an 8 GiB string); a mismatch now prints a value only when its
read-back is small (`literal::printed`), else its size.

**Validation** (the final sources; one release binary for the root, the
conformance runs and the lock preview):

* Suites: `prover_gaps` 19, `auto_*` (7 binaries) 71, `prover_ergonomics_*`
  (7) 95, `simd` 10, `hardware` 10, `unsafe_simd` 20 (1 ignored), `mir`
  51, `literal` 41, `loop_post` 28, `reader_widen` 4, `walker` 4,
  `theorem_gate` 13, `verified_roots` 8, `lift_conformance` 13 (1
  ignored), the front's unit tests 35 (among them the new
  `the_types_the_host_gives_a_default_value`): all pass.
* rs_engine as above (329 definitions, 2,671 obligations, 5/5 MIR
  theorems, the lock preview's root unchanged).
* Codec and storage builds, the cache off: `varint` VERIFIED, 21,250
  obligations, 603 definitions, lift conformance passed, `SPEC.lock`
  matches (116 items, root `38c1c9c0..`); `mmr` VERIFIED in place, 4,263
  and 741, lock `d87803e2..` (211 items); `verifier` VERIFIED in place,
  2,339 and 588, lock `a7563685..` (272 items). The counts are the
  previous stage's; the three accepted locks are unchanged.

**Open.**

* `auto` does not rewrite the target with a fact equating two stuck spec
  applications (`row_bytes(lut.lo[0]) == lo_bytes(lut16[0])`): the eight
  `rewrite`s of `lo_byte_split`/`hi_byte_split` stay. *Closed in stage
  leftovers.*
* `by_cases(j, ..)` under a `requires` mentioning `j`: the elaborator
  builds an ill-typed proof (refused by the kernel). The per-byte law of
  `mul_chunks` (`pending_chunk_and_slice_laws`) is still open. *Both
  closed in stage leftovers.*
* Layer 3 and `fft`/`ifft` (step 8), as before.

### Stage "leftovers" (2026-10-07; the fix round's open items)

Notes, scripts, logs and probes:
`sandblaster-wt/recovery/unsafe-simd/impl/leftovers/` (outside the
repository). Five items, in order; the first is trusted (62 code lines,
DESIGN.md §1.1 item 8, `kernel/AUDIT.md` §21.1), the rest untrusted or
proof text. The kernel, SEMANTICS.md, every law and Commonware's sources
are untouched; no `spec --accept`.

**1. The extraction's cfg set (trusted).** `(rustflags ..)` repeats what
`extract.sh` passed, and nothing recorded the crate's configuration: a body
behind `#[cfg(feature = "..")]` compiled in one extraction and out of the
other showed in no record. mirx now prints the session's cfg set,
`(cfg ("debug_assertions") ("feature" "std") ..)` — `Session::config`, the
set `#[cfg]` and `cfg!` were evaluated against: the crate's Cargo features,
the target's and the profile's cfgs, every `--cfg` whatever passed it
(+3), parsed (+9). The window extraction must record its main extraction's
(it is a header record: `load_window`'s fail-closed comparison covers it
unchanged). `load` binds a main extraction's record to the build's
configuration where a build script knows it (+8): `target::build_cfg`
(+39) reads the features (`CARGO_CFG_FEATURE`), the builtin cfgs a stable
compiler shows (`BUILD_CFGS`, from `CARGO_CFG_<NAME>` in Cargo's form) and
the `--cfg`s of `CARGO_ENCODED_RUSTFLAGS`; `target::build_sees` restricts
the record to what a build script can know (not `target_feature`, A-S3's,
nor the nightly-only `NIGHTLY_CFGS`; any other name is compared, fail
closed); the lift passes the build's set on (+3). `extract.sh` takes
`--features`, `--no-default-features` and `--profile` (Cargo's options).
Not bound, and recorded as assumptions (AUDIT §21.1): `sandblaster check`
(no build configuration; rs_engine's record states its features), the
extractions older than the record (the legacy rule), the cfgs only a
nightly shows and the unstable target features, flags no build script sees
(its own `rustc-cfg`, `cargo rustc -- --cfg`, a wrapper's flags). A bound
extraction serves one configuration: a release build of a dev extraction,
or a dependent's other feature set, is refused.

*Measured on the build side* (a probe crate's build script, stable 1.98.1):
`CARGO_CFG_FEATURE` holds the exact feature names (empty without one),
`CARGO_CFG_DEBUG_ASSERTIONS` follows the profile, a `--cfg` of `RUSTFLAGS`
shows as `CARGO_CFG_<NAME>` and in `CARGO_ENCODED_RUSTFLAGS`, `cargo clippy`
adds nothing; a nightly build script also shows the gated cfgs and the
unstable features (left out on both sides).

*Twins* (`front/tests/mir_fixtures/sd_ptr_feat`: `param_write`'s shape, the
aliasing write behind the feature `alias`; extracted without and with it
at both levels): each pair loads, the formation passing without the write
and failing W2 with it; a window extraction of the other features is
refused both ways, the feature named; without the record the two programs
differ in no header record and the verdict carried from the window
extraction without the write passes the main extraction's formation with
it (the hole); a build script's variables of the other feature set (both
ways), of a release profile, or with a `--cfg` (both forms) refuse the
extraction, through the lift too; not bound without the record or without
a build configuration. Mutants: 13, every one caught.

*The shipped extractions.* rs_engine's two were extracted again: they
differ from the checked-in ones by exactly two header lines each,
`(rustflags "")` and `(cfg ..)` (features `bls12381`, `crc-fast`,
`default`, `num-rational`, `num-traits`, `std`), so its theorems, window
verdicts and lock preview are unchanged (measured below). varint's, the
MMR's and the verifier's were not (the legacy rule): binding them would
refuse their ordinary builds, which run under several feature sets
(`commonware-codec` is `default,std` in its own tests, `std` alone inside
storage's, `arbitrary,default,std` in the workspace's; storage adds
`test-utils` in its own tests), and today's printer would also change more
than the record (a probe re-extraction of varint adds nine header records
and the `(local)` markers of its 92 functions).

**2. `by_cases` under a precondition the goal uses** (the elaborator,
`elab/script.rs` `case_generalized`). A case's motive abstracted the index
in the goal's value, leaving its proofs alone, but the goal holds proofs of
the index's bound — the precondition `h_req0` itself, or proofs built from
it — whose types mention the index, so the kernel rejected the proof
(TypeMismatch on `h_req0`). When the goal mentions facts whose types
mention the split variable, the motive now generalizes them with it,
syntactically, like a refining `match`: `y. Π(h′ : F[k := y]).. G[k := y,
h := h′]`; each case proves `Π(h′ : F[k := v]).. G[k := v, h := h′]`, the
`h′` as facts; the transport is applied to the facts. Without such facts
the old path runs. Test (`tests/prover_gaps.rs` §12): a 16-entry table at
one bound, a 4×4 grid at two bounds split twice, both bounds in one
conjunction, a bound the goal derives (`n + 1` under `n < 15`); twins
refuted, never rejected. Without the fix all four positives are rejected
exactly as reported. rs_engine's `lo_bytes_at` and `hi_bytes_at` now state
their bound as a precondition (their `implies(..)` form and its `if`/`else`
were the workaround).

**3. Equations between applications on the target's term** (`auto`,
`auto::terms::term_rewrite`). A fact `row_bytes(lut.lo[0]) ==
lo_bytes(lut16[0])` (a conjunct of `is_split_of`) was no rewrite rule:
both sides unfold, to array literals of stuck bytes, so neither is stuck.
On the root target's term an occurrence of one side of such an equation
(both sides applications of transparent definitions; stated as an
equation, or as `array::eq(..) == true` over machine integers) is now
rewritten to the other when another fact names that other side and not
the first, each equation once; the rewritten target is closed by a fact or
a quantified fact on its term, or by the search (bounded). Test
(`tests/prover_gaps.rs` §13, the `le16`/`lows16` rows of `split_of` and two
nibble lookups): proven; twins (the lemma's rows swapped, a row the fact
does not pair, no fact naming the other side) refuted. `lo_byte_split` and
`hi_byte_split` lose their four `rewrite`s each.

**4. The per-byte law** (`tests/unsafe_simd.rs`, test data). Its last step
read the 64-byte literal `mul64(c)` at a symbolic byte by enumerating the
bytes: 64 cases, each evaluating the literal, outgrew the kernel's fuel and
the memory cap. The generic way: a per-width lemma reading an array
literal at a symbolic index through its element function, `map64_at(c, g,
j)`: `[g(c[0]), .., g(c[63])][j] == g(c[j])` under `j < 64`, proven once for
the width by its 64 cases with `g` and `c` symbolic (cheap: each case reads
one element of a literal of applications of a variable), which needed
item 2; `mul64_at` is its instance at `|b| mul_byte(b, lo, hi)`. The byte
is stated over the opaque `chunk64` (`chunk64_at`), so the law's goal never
holds the 64 bytes (over `mul64` it had more than 100,000 nodes, too many
for a motive), and the loop's chunk `k = i` reads through
`seq::index_update_same`. The law proves; the test is now
`the_law_of_every_byte_of_every_chunk_is_proven`, with twins (the tables
swapped; the lemma claiming another element). A generic `<T, U>` lemma
cannot live in a `#[lift]` proof module (only sealed-trait generics are
monomorphized); the standard library could hold it, but the accepted MMR
and verifier roots mount that library, so it stays in the test.

**5.** rs_engine's calc ends its last step with `follows();`: the
`warning[script]` is gone.

**Measured** (the final sources; logs in the stage's notes).

* `cargo check --all-targets` of the seven sandblaster packages: 0
  warnings; mirx's build: 0 warnings.
* The full front suite (its lib and all 77 test binaries, one at a time),
  `sandblaster-kernel` and `sandblaster-targets`: 80 runs, 1,402 tests
  passed, 15 ignored, 0 failed (`unsafe_simd` 24, the byte law no longer
  ignored; `prover_gaps` 21).
* Mutants (each run, then reverted): the 13 of item 1, every one caught;
  item 2's fix removed, caught by its test and by the byte law; item 3's
  step removed and its `names_apart` inverted, both caught.
* The window verdicts: the 52 recorded by stage soundness-fixes (rs_engine's
  9, `sd_neon_mul128` and its two twins 8 each, `sd_ptr` 5, `sd_ptr_twins`
  14) are identical in full text.
* rs_engine (the release CLI, cache off): 329 definitions, 2,653
  obligations (2,602 automated, 51 hinted), the 3 laws, the gates boundary,
  examples (58), sections (2), law rules (0 errors, the 4
  `law-resembles-impl` warnings) and MIR theorems (5 of 5) passed, the lock
  missing (52 items): NOT VERIFIED for the lock only; no `warning[script]`.
  The lock preview is byte-identical to stage prover-gaps' (root
  `581461cb..`). `PROOF.rs`: 714 lines (564 code lines), 726 (578) before.
* Codec and storage, the cache off: `cargo test -p commonware-codec` (147 +
  16 + 5 passed), `varint` VERIFIED (21,250 obligations, 603 definitions,
  lift conformance passed, `SPEC.lock` matches, root `38c1c9c0..`);
  `cargo test -p commonware-storage --lib` (3,776 passed, 2 ignored), `mmr`
  VERIFIED in place (4,263, 741, lock `d87803e2..`) and `verifier`
  (2,339, 588, lock `a7563685..`). The counts and the three accepted locks
  are unchanged.
* The Miri gate (`run.sh --engines`, 947 s): the positive fixtures clean
  under Stacked and Tree Borrows (4 tests each), all 28 undefined-behaviour
  twins reported (`ub_two_formations` and `ub_local_raw_write` by Stacked
  Borrows only, as recorded), the NEON engine against the naive one clean
  under both (2 tests each); `GATE.txt` rewritten byte-identical.

**Open.**

* A bound extraction serves one configuration (one extraction per module):
  a crate verified by its build script under several feature sets or
  profiles would need one extraction per configuration, selected by the
  build's; the shipped varint, MMR and verifier extractions stay unbound
  (the legacy rule) until then.
* The human audit (A-process) of the trusted files, now with this stage's
  62 lines; rs_engine's laws and lock await the user; layer 3 and
  `fft`/`ifft` (step 8).

### Stage "cfg-binding-fixes" (2026-10-07; the validation of stage leftovers)

Notes, scripts, logs and probes:
`sandblaster-wt/recovery/unsafe-simd/impl/cfg-binding-fixes/` (outside the
repository). The independent validation of stage leftovers
(`validate-leftovers/NOTES.md`) found the cfg binding failing open under
`-C debug-assertions` in the build's rustflags (V1, demonstrated), a
profile's `panic` and the test harness's `cfg(test)` claimed bound (V2,
V4), the dependencies' configuration not recorded (V3), the legacy rule
still admitting an extraction by the narrow reading's printer without the
record (V5), two exotic cfg values printing the same record (V6), no
negative twin for the parse's refusal of a malformed entry (N6), and two
counts of the lift glue (V8). All closed here: 46 trusted code lines
(DESIGN.md §1.1 item 8, `kernel/AUDIT.md` §21.1). The kernel, SEMANTICS.md,
every law and Commonware's sources are untouched; no `spec --accept`.

**V1: rustflags that change the configuration where a build script cannot
see it (trusted, `target.rs` +42, `mir/mod.rs` +1).** rustc derives
`debug_assertions` from `-C debug-assertions`, or without it from the
optimization level, and the overflow checks from `-C overflow-checks`, or
without it from `debug_assertions`; Cargo's `CARGO_CFG_DEBUG_ASSERTIONS`
follows the profile, and the rustflags come last on rustc's command line
(measured: `cargo build -v`). A build whose rustflags set
`-C debug-assertions`, `-C opt-level` (`-O`), `-C overflow-checks`, any
`-Z` option (the cfgs only a nightly shows follow them) or an `@file`
(rustc reads arguments from it) now has an unknowable configuration
(`target::build_cfg` returns `Err`), and `mir::load` refuses every
extraction with the record under it, naming the flag. The rustflags are
read as rustc's option parser (getopts) reads them (`rustc_options`):
`--codegen v`, `--codegen=v`, short options grouped (`-gO`,
`-gCdebug-assertions=off`), a value in the next argument (`-L -O` is no
`-O`), a long option's value (`--allow -L -O` is), an empty argument as
an argument (Cargo passes one on: `-A '' -O` is), and a codegen option's
`_` as `-` (rustc's lookup), each measured against rustc 1.98.1 and
Cargo. A-S3's `-C target-cpu`/`-C target-feature` reader now goes through
it: it missed `-C target_feature` and dropped empty arguments before. The other codegen options change no stable
cfg in the pinned release (`-C panic` is in `CARGO_CFG_PANIC`, which
follows the rustflags; `-C relocation-model` sets a cfg only a nightly
shows).

**V2, V4, V3: assumptions, AUDIT corrected.** No build-script variable
carries a profile's `panic` (measured: a profile that inherits `dev` and
sets `panic = "abort"` leaves every variable as under `dev` but the paths
holding the profile's directory; `CARGO_CFG_PANIC` stays `unwind`), and
none tells a `--test` compile from the library's (the variables of `cargo
test --lib`'s build-script run are the library build's; Cargo sets no
`CARGO_CFG_TEST`). Both are stated as assumptions: the build's profile
sets the extraction's panic strategy (no Commonware profile sets `panic`,
no Commonware source tests `cfg(panic ..)`; under `abort` a panic still
panics), and the test harness compiles the verified functions as the
library does (each verified module tests `cfg(test)` only for its `mod
tests`); the library's compile is bound, and an extraction recorded with
`test` (`extract.sh --profile test`) is refused by every build. The
dependencies' configuration is not recorded: a crate's `StableCrateId`
(and its SVH) hashes Cargo's `-C metadata`, which for a workspace member
hashes the `RUSTC_WORKSPACE_WRAPPER` path, mirx's own binary (measured:
two wrapper paths, two metadata values), so a record of them would change
with the extractor's target directory and extractions would stop being
reproducible; a build's stable compiler gives other ids anyway. Stated in
AUDIT §21.1 and `docs/mir-lift.md` §20.1 (rs_engine's extractions carry
only its own crate's, core's and std's bodies).

**V5: the records required (trusted, `mir/ir.rs` +3).** An extraction with
`(unsafe-reading 1)` must record `(rustflags ..)` and `(cfg ..)`, else it
is malformed. The fixtures that lacked them were extracted again
(`sd_ptr`, `sd_ptr_twins`, `sd_ptr_local`, `sd_ptr_cfg` with its three
window twins, `sd_neon_mul128` with its two twins: 16 files): each gained
exactly its missing header records, its functions and type definitions
byte-identical, so the 92 window verdicts (compared in full text) and the
theorems are unchanged. `tests/simd.rs`'s in-place build now gives the
build script a stable build's whole configuration (it gave four
variables: the build's set came out empty and refused the re-extracted
`sd_neon_mul128`).

**V6: the printer's quoting (trusted, `mirx`, one line changed).** mirx
quoted with `{:?}`, whose escapes the reader reads back without their
backslash (`\t` as `t`, `\u{301}` as `u{301}`): it now escapes only `"`
and `\` and writes every other character as it is. No checked-in
extraction holds another escaped character, so each prints as before
(`sd_ptr_feat`'s four came out byte-identical; rs_engine's, extracted again
into scratch, too). Twin: `sd_ptr_cfg`'s window extraction under
`--cfg sd_quote="a\tc\u{301}\u{7f}"` reads back exactly (Cargo itself
refuses a newline in a cfg value).

**N6, V8.** `a_malformed_cfg_entry_is_refused` feeds eight malformed
records. DESIGN.md §1.1 item 8 now gives the lift glue as AUDIT counts it,
about 394 (it said about 350, the count before the narrow reading).

*Tests* (`tests/unsafe_simd.rs`, untrusted):
`a_build_whose_rustflags_change_its_configuration_refuses_the_extraction`,
`the_lift_refuses_a_build_whose_rustflags_change_its_configuration`,
`an_extraction_by_the_printer_records_its_rustflags_and_cfg_set`,
`a_malformed_cfg_entry_is_refused`, `a_cfg_value_reads_back_as_rustc_holds_it`;
updated: the F2 twins (the `--cfg` twin differs in its rustflags and cfg
records), the feature twins (without the record: refused), the build's
side (a `--cfg` beside a benign codegen option; an extraction recorded
with `test`; refused without the record).

**Measured** (the final sources; logs in the stage's notes).

* `cargo check --all-targets` of the seven sandblaster packages: 0
  warnings.
* The full front suite (its lib and all 77 test binaries, one at a time),
  `sandblaster-kernel` and `sandblaster-targets`: 80 runs, 1,407 tests
  passed, 15 ignored, 0 failed (`unsafe_simd` 29: five new).
* Mutants (each run, then reverted; the runner restores a file even when
  it is killed): the 23 of this stage's trusted lines — the refusal, each
  option of it, the reader's every rule (grouping, values, long options
  and long flags, empty arguments, `_`, `-O`, `--codegen`), `load`'s
  refusal, A-S3's flags through the reader, the parse's requirement and
  each record's, N6, the printer's quoting with its twin extracted again
  under the mutant — every one caught, the reader's 17 again on the final
  code; the 21 cfg mutants of stages leftovers and validate-leftovers,
  again on the final code: every one caught.
* The window verdicts: 92 (rs_engine's 9, `sd_neon_mul128` and its two
  twins 8 each, `sd_ptr` 5, `sd_ptr_twins` 14, `sd_ptr_local` 37,
  `sd_ptr_cfg` 2, `sd_ptr_feat` 1), identical in full text before and
  after the re-extraction.
* rs_engine (the release CLI, cache off): 329 definitions, 2,653
  obligations (2,602 automated, 51 hinted), the 3 laws, the gates
  boundary, examples (58), sections (2), law rules (0 errors, the 4
  `law-resembles-impl` warnings) and MIR theorems (5 of 5) passed, the lock
  missing (52 items): NOT VERIFIED for the lock only; no
  `warning[script]`. The lock preview's root is `581461cb..`, as before;
  its two extractions, made again into scratch with the final printer,
  are byte-identical to the checked-in ones.
* Codec and storage, the cache off: `cargo test -p commonware-codec` (147 +
  16 + 5 passed), `varint` VERIFIED (21,250 obligations, 603 definitions,
  lift conformance passed, `SPEC.lock` matches, root `38c1c9c0..`);
  `cargo test -p commonware-storage --lib` (3,776 passed, 2 ignored), `mmr`
  VERIFIED in place (4,263, 741, lock `d87803e2..`) and `verifier`
  (2,339, 588, lock `a7563685..`). The counts and the three accepted locks
  are unchanged.
* The Miri gate (`run.sh --engines`, 947 s): the positive fixtures clean
  under Stacked and Tree Borrows (4 tests each), all 28 undefined-behaviour
  twins reported (`ub_two_formations` and `ub_local_raw_write` by Stacked
  Borrows only, as recorded), the NEON engine against the naive one clean
  under both (2 tests each); `GATE.txt` rewritten byte-identical.

**Open.**

* The shipped varint, MMR and verifier extractions stay unbound (the
  legacy rule); a bound extraction serves one configuration.
* The assumptions this stage states rather than closes: a profile's
  `panic`, the test harness's `cfg(test)`, the dependencies' features.
* Once a module is bound, a build whose rustflags carry a `--cfg` of their
  own (the benchmark workflow's `--cfg full_bench`, for one: refused since
  stage leftovers) or a `-Z` option (a nightly build's) is refused: fail
  closed, by design; such a build verifies nothing.
* The human audit (A-process) of the trusted files, now with this stage's
  46 lines; rs_engine's laws and lock await the user; layer 3 and
  `fft`/`ifft` (step 8).

### Stage "cfg-final" (2026-10-08; the validation of stage cfg-binding-fixes)

Notes, scripts, logs and probes:
`sandblaster-wt/recovery/unsafe-simd/impl/cfg-final/` (outside the
repository). The independent validation of stage cfg-binding-fixes
(`validate-cfg-fixes/NOTES.md`) found the build binding failing open three
ways, each needing a deliberate rustflag, variable or `[env]` entry, none
reaching a shipped verified module: a `--cfg` that rustc reads as another
option's value counted as the build's (F1, shown end to end), a builtin
cfg set by `--cfg` past rustc's lint (F3), and `CARGO_CFG_*` variables
inherited from the environment or Cargo's `[env]` (F2); also that a
`--cfg` is read as text (F4, fail closed) and two counts of the
precondition check (F5). F1 and F3 are closed in code, F2 is stated as an
assumption, F4 is noted and F5 recounted: 6 trusted code lines, all in
`target.rs` (DESIGN.md §1.1 item 8, `kernel/AUDIT.md` §21.1). The kernel,
SEMANTICS.md, every law and Commonware's sources are untouched; no `spec
--accept`; no extraction changed.

**F1: the build's `--cfg`s where rustc reads them (trusted).** rustc
1.98.1 reads `-L --cfg=x`, `-A --cfg=x`, `--allow --cfg=x` and
`--remap-path-prefix --cfg=x` as the first option's value and sets no `x`;
`build_cfg` scanned the arguments for `--cfg`, so a release build whose
rustflags held `-L --cfg=debug_assertions` claimed `debug_assertions` and
took a dev extraction. `rustc_options` now reads every long option by
getopts' one rule (its `=v`, else the next argument, but for the four
flags) and keeps `--cfg`'s values beside `--codegen`'s; `build_cfg` takes
its `--cfg`s from it.

**F3: a builtin cfg set by `--cfg` (trusted).** Past `-A
explicit_builtin_cfgs_in_flags` or `--cap-lints allow`, rustc takes `--cfg
debug_assertions` and sets the cfg, but derives the overflow checks and
`ub_checks` from `-C debug-assertions` (measured: in a release build the
cfg holds and `255u8 + 1` wraps); Cargo's `CARGO_CFG_DEBUG_ASSERTIONS`
follows the profile. A `--cfg` whose name is a builtin cfg's (of
`BUILD_CFGS` or `NIGHTLY_CFGS`, or `target_feature`, whatever its value)
now makes the build's configuration unknowable, and every extraction with
the record is refused, the cfg named. The three lists are the pinned
release's builtin cfgs: rustc's lint denies every name of them but `test`
in some shape, and `test` is refused too (fail closed).

**F2: an assumption.** Cargo sets a bare builtin's `CARGO_CFG_<NAME>` only
when the cfg holds and removes none it leaves unset, so a
`CARGO_CFG_DEBUG_ASSERTIONS` in the shell or in Cargo's `[env]` reaches a
release build's script as Cargo's; a build script cannot tell. Stated in
AUDIT §21.1, DESIGN.md §1.1 item 7 and `docs/mir-lift.md` §20.1: neither
the build's environment nor Cargo's `[env]` sets any `CARGO_CFG_*`
variable.

**F4, F5.** AUDIT notes that a `--cfg` is read as text (no escapes, raw
strings or comments), which can only refuse a build that agrees. The
precondition check, counted again from the code as it stands, is 61 lines
(`elab/items.rs` 27, `typeck` 33, `hir.rs` 1), where DESIGN gave 39 and
AUDIT 53; the total grows by 8 with it.

*Tests* (`tests/unsafe_simd.rs`, untrusted):
`a_cfg_that_is_another_options_value_is_not_the_builds` (F1's
release-build twin and the feature's), `a_build_that_sets_a_builtin_cfg_by_cfg_refuses_the_extraction`
(F3, 13 builtin `--cfg`s under both profiles, and the names that are no
builtin); `the_lift_refuses_a_build_whose_rustflags_change_its_configuration`
gained both through the lift.

**Measured** (the final sources; logs in the stage's notes).

* `cargo check --all-targets` of the seven sandblaster packages: 0
  warnings.
* The front tests that cover the binding and the gate: `unsafe_simd` 31
  (two new), `simd` 10, `mir` 51, `literal` 41, `theorem_gate` 13,
  `verified_roots` 8: all passed.
* Mutants (each run, then reverted; the runner restores a file even when
  it is killed): the 12 of this stage's trusted lines — F1's, the old scan
  of the arguments, no `--cfg` value kept, a long option's value not
  consumed, the long flags taking one, a long option's `=v` not read,
  `--codegen` not kept; F3's, the refusal skipped, each list's names let
  through, the refusal only for a bare cfg, a bare name not trimmed —:
  every one caught.
* End to end, the validator's probe again (the variables Cargo really gave
  each build): the release builds with `-L --cfg=debug_assertions` and
  `-A explicit_builtin_cfgs_in_flags --cfg debug_assertions` refuse the dev
  extraction; the dev builds with `-L --cfg=spec` and
  `--remap-path-prefix --cfg=spec` load it; the two with an inherited
  `CARGO_CFG_DEBUG_ASSERTIONS` load it (F2).
* Codec and storage, the cache off: `cargo test -p commonware-codec` (147 +
  16 + 5 passed), `varint` VERIFIED (21,250 obligations, 603 definitions,
  lift conformance passed, `SPEC.lock` matches, root `38c1c9c0..`);
  `cargo test -p commonware-storage --lib` (3,776 passed, 2 ignored), `mmr`
  VERIFIED in place (4,263, 741, lock `d87803e2..`) and `verifier`
  (2,339, 588, lock `a7563685..`). rs_engine's lock preview: root
  `581461cb..`, byte-identical to the last stage's.

**Open.**

* F2 is an assumption, not a check: a build script cannot tell an
  inherited `CARGO_CFG_*` variable from Cargo's.
* The assumptions stated before (a profile's `panic`, the test harness's
  `cfg(test)`, the dependencies' features, flags no build script sees) and
  the legacy rule for the shipped extractions are unchanged.
* The human audit (A-process) of the trusted files, now with this stage's
  6 lines; rs_engine's laws and lock await the user; layer 3 and
  `fft`/`ifft` (step 8).
