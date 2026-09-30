# sandblaster target models

This file states the lane-level semantics of the intrinsic models in
`sandblaster-targets` (DESIGN.md §9.2, the target-semantics part of the TCB).
Every model exists twice, and both follow this file:

* the **executable Rust model** in `src/aarch64/` / `src/x86_64/` (the
  reference, compared with the hardware). Each one is a transcription of the
  vendor pseudocode (Arm ARM DDI 0487 for A64 SIMD&FP/SHA256, Intel SDM Vol. 2
  for SSE/SSSE3/SSE4.1/SHA, AVX/AVX2 and AVX-512F/BW/VL/DQ/IFMA/VBMI/VBMI2/
  VPOPCNTDQ/BITALG, GFNI), and its doc comment quotes the pseudocode it
  follows;
* the **core-text model** in `core/aarch64.core` / `core/x86_64.core`: a
  `def[intrinsic]` kernel global with the same lane-level transcription,
  loaded by the front end and used by every proof (§9 below).

The model list, feature requirements, instructions and hashed source items
are in `src/registry.rs`; the core globals and their signatures in
`src/coretext.rs`. The chain hardware ↔ Rust model ↔ core model is tested
end to end (§8, §9.4).

## 1. Notation

| Symbol | Meaning |
| --- | --- |
| `Uₙ` | unsigned n-bit word (the kernel's `U8`, `U16`, `U32`, `U64`) |
| `T^N` | `Array(T, N)`, lanes listed low to high: `[x₀, x₁, …]`, lane 0 first |
| `x ⊞ y` | addition mod 2³² (`wadd`) |
| `x ⊕ y`, `x ∧ y`, `x ∨ y`, `¬x` | bitwise xor, and, or, not |
| `ROTR(x, n)`, `x ≫ n`, `x ≪ n` | rotate right; logical shifts (bits shifted out are dropped) |
| `a ++ b` | array concatenation (`a` first = low lanes) |
| `c ? x : y` | if-then-else |
| `le32(b₀, b₁, b₂, b₃)` | `from_le_bytes` = `b₀ + 2⁸b₁ + 2¹⁶b₂ + 2²⁴b₃` |

SHA-256 functions (FIPS 180-4 §4.1.2). The Intel SDM defines them in exactly
these forms:

```
Ch(x, y, z)  = (x ∧ y) ⊕ (¬x ∧ z)
Maj(x, y, z) = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z)
Σ0(x) = ROTR(x, 2)  ⊕ ROTR(x, 13) ⊕ ROTR(x, 22)
Σ1(x) = ROTR(x, 6)  ⊕ ROTR(x, 11) ⊕ ROTR(x, 25)
σ0(x) = ROTR(x, 7)  ⊕ ROTR(x, 18) ⊕ (x ≫ 3)
σ1(x) = ROTR(x, 17) ⊕ ROTR(x, 19) ⊕ (x ≫ 10)
```

The Arm ARM spells Ch and Maj differently. The Arm models keep the Arm forms,
and bvnorm rule 5 (truth tables) equates them with the FIPS forms:

```
SHAchoose(x, y, z)   = ((y ⊕ z) ∧ x) ⊕ z                 ≡ Ch(x, y, z)
SHAmajority(x, y, z) = (x ∧ y) ∨ ((x ∨ y) ∧ z)           ≡ Maj(x, y, z)
SHAhashSIGMA0 = Σ0,  SHAhashSIGMA1 = Σ1
```

## 2. Representation and byte order

**NEON** (`src/aarch64/mod.rs`). A typed vector is the array of its lanes,
lane 0 at the lowest address, which is what `LD1` loads on a little-endian
target:

| stdarch | model | core |
| --- | --- | --- |
| `uint8x16_t` | `Uint8x16 = [u8; 16]` | `U8^16` |
| `uint8x8_t` | `Uint8x8 = [u8; 8]` | `U8^8` |
| `uint32x4_t` | `Uint32x4 = [u32; 4]` | `U32^4` |

Arm's `Elem[V, e, esize]` is lane `e`. Bits `V<32e+31:32e>` of a 128-bit
register are lane `e` of the `u32` view. Bytes and words are related
little-endian: `vreinterpretq_u32_u8(b)[i] = le32(b[4i], b[4i+1], b[4i+2], b[4i+3])`.
Bit-level pseudocode over 128/256 bits is transcribed at lane level, because
the kernel has no u128/u256. For example, the words of `Y : X` low to high are
`X ++ Y`, so `ROL(Y : X, 32)` is `(X', Y') = ([Y₃, X₀, X₁, X₂], [X₃, Y₀, Y₁, Y₂])`.

**x86** (`src/x86_64/mod.rs`). `__m128i` has no element type. It is
canonically `M128i = [u8; 16]` (`U8^16`), where byte `i` holds bits `8i+7:8i`
(little-endian). Typed views and their inverse constructors:

```
view_u16(v)[i] = le16(v[2i], v[2i+1])                        i < 8   (SDM word i)
view_u32(v)[i] = le32(v[4i], …, v[4i+3])                     i < 4   (SDM dword i = bits 32i+31:32i)
view_u64(v)[i] = le64(v[8i], …, v[8i+7])                     i < 2   (SDM qword i)
from_u16x8 / from_u32x4 / from_u64x2 = the inverses (from_u32x4 is the prelude `m128i_from_u32x4`)
```

In the kernel, the §5.7 byte simplifications collapse `view_u32 ∘ from_u32x4`,
so chains of `epi32` operations stay clean `U32` terms.

**Big-endian message words.** The prelude defines `from_be_bytes = from_le_bytes ∘ rev`.
Then `vreinterpretq_u32_u8(vrev32q_u8(b))[i]` and
`view_u32(_mm_shuffle_epi8(b, MASK))[i]` (with the `sha2` crate's `MASK`)
both equal `from_be_bytes(b[4i..4i+4])` by definition. The consistency
properties `sha2_be_load_vs_from_be_bytes` and `shani_be_load_vs_from_be_bytes`
check this.

**Immediates** are ordinary `i32` arguments (stdarch `const N: i32`), and each
model states its accepted range. rustc rejects out-of-range immediates at
compile time; the executable models panic on them, and in the kernel such an
application is ill-typed or stuck. **Loads and stores** are modelled on typed
arrays, like the generated helpers of §9.2 (`load_u8x16(a: &[u8; 16])`). A
load returns the elements as lanes. A store returns the array it writes.
Only unaligned forms exist. **Only little-endian targets** are modelled
(variants are gated `target_endian = "little"`).

## 3. aarch64 NEON (`src/aarch64/neon.rs`, feature `neon`)

| Model (instruction) | Type | Semantics |
| --- | --- | --- |
| `vld1q_u8` (`LD1 {Vt.16B}`) | `&U8^16 → U8^16` | `r[e] = mem[e]` |
| `vld1q_u32` (`LD1 {Vt.4S}`) | `&U32^4 → U32^4` | `r[e] = mem[e]` |
| `vld1_u8` (`LD1 {Vt.8B}`) | `&U8^8 → U8^8` | `r[e] = mem[e]` |
| `vst1q_u8` (`ST1 {Vt.16B}`) | `U8^16 → U8^16` (bytes written) | `mem[e] = a[e]` |
| `vst1q_u32` (`ST1 {Vt.4S}`) | `U32^4 → U32^4` | `mem[e] = a[e]` |
| `vrev32q_u8` (`REV32 .16B`) | `U8^16 → U8^16` | `r[4c + 3 − j] = a[4c + j]`, `c, j < 4` |
| `vreinterpretq_u32_u8` (none) | `U8^16 → U32^4` | `r[i] = le32(a[4i], a[4i+1], a[4i+2], a[4i+3])` |
| `vreinterpretq_u8_u32` (none) | `U32^4 → U8^16` | `r[4i + j] = (a[i] ≫ 8j) mod 2⁸` |
| `vaddq_u32` (`ADD .4S`) | `U32^4 × U32^4 → U32^4` | `r[e] = a[e] ⊞ b[e]` |
| `veorq_u32` (`EOR .16B`) | same | `r[e] = a[e] ⊕ b[e]` |
| `vandq_u32` (`AND .16B`) | same | `r[e] = a[e] ∧ b[e]` |
| `vorrq_u32` (`ORR .16B`) | same | `r[e] = a[e] ∨ b[e]` |
| `vshlq_n_u32::<N>` (`SHL .4S, #N`) | `U32^4 → U32^4`, `N ∈ [0, 31]` | `r[e] = a[e] ≪ N` |
| `vshrq_n_u32::<N>` (`USHR .4S, #N`) | `U32^4 → U32^4`, `N ∈ [1, 32]` | `r[e] = (N = 32) ? 0 : a[e] ≫ N` |
| `vextq_u32::<N>` (`EXT .16B, #4N`) | `U32^4 × U32^4 → U32^4`, `N ∈ [0, 3]` | `r[i] = (a ++ b)[i + N]` |
| `vdupq_n_u32` (`DUP .4S, Wn`) | `U32 → U32^4` | `r[e] = x` |
| `vgetq_lane_u32::<L>` (`UMOV Wd, Vn.S[L]`) | `U32^4 → U32`, `L ∈ [0, 3]` | `v[L]` |
| `vsetq_lane_u32::<L>` (`INS Vd.S[L], Wn`) | `U32 × U32^4 → U32^4`, `L ∈ [0, 3]` | `r = b` with `r[L] = a` (scalar first, as in stdarch) |
| `vsetq_lane_u8::<L>` (`INS Vd.B[L], Wn`) | `U8 × U8^16 → U8^16`, `L ∈ [0, 15]` | `r = b` with `r[L] = a` |

Notes. `USHR #32` yields 0 (the pseudocode shifts the zero-extended element).
`EXT`'s `concat = V[m] : V[n]` puts the first argument in the low lanes.

### 3.1 NEON u8 / u64 / u32×2 (`src/aarch64/neon2.rs`, feature `neon`; plan O10)

Types: `U8^8` (`uint8x8_t`), `U16^8` (`uint16x8_t`), `U32^2` (`uint32x2_t`),
`U64^2` (`uint64x2_t`) besides §3's. The byte search (P12), Reed–Solomon
tables, curve25519 limb products and the `seq::eq` candidate use them.

| Model (instruction) | Type | Semantics |
| --- | --- | --- |
| `vld1q_u64` (`LD1 {Vt.2D}`) | `&U64^2 → U64^2` | `r[e] = mem[e]` |
| `vst1q_u64` (`ST1 {Vt.2D}`) | `U64^2 → U64^2` (words written) | `mem[e] = a[e]` |
| `veorq_u8`, `vandq_u8`, `vorrq_u8` (`EOR/AND/ORR .16B`) | `U8^16 × U8^16 → U8^16` | lanewise `⊕`, `∧`, `∨` |
| `vdupq_n_u8` (`DUP .16B, Wn`) | `U8 → U8^16` | `r[e] = x` |
| `vshrq_n_u8::<N>` (`USHR .16B, #N`) | `U8^16 → U8^16`, `N ∈ [1, 8]` | `r[e] = (N = 8) ? 0 : a[e] ≫ N` |
| `vcltq_u8(a, b)` (`CMHI Vd, Vm, Vn`: operands swapped) | `U8^16 × U8^16 → U8^16` | `r[e] = a[e] < b[e] ? 0xff : 0` (unsigned) |
| `vcgeq_u8(a, b)` (`CMHS`) | same | `r[e] = a[e] ≥ b[e] ? 0xff : 0` |
| `vceqq_u8(a, b)` (`CMEQ`, register) | same | `r[e] = a[e] = b[e] ? 0xff : 0` |
| `vqtbl1q_u8(t, idx)` (`TBL Vd.16B, {Vn.16B}, Vm.16B`) | `U8^16 × U8^16 → U8^16` | `r[i] = idx[i] < 16 ? t[idx[i]] : 0` (TBL, not TBX) |
| `vcntq_u8` (`CNT .16B`) | `U8^16 → U8^16` | `r[e] = popcount(a[e])` |
| `vaddvq_u8` (`ADDV Bd, Vn.16B`) | `U8^16 → U8` | `Σ a[e] mod 2⁸` |
| `vmaxvq_u8` (`UMAXV Bd, Vn.16B`) | `U8^16 → U8` | `max a[e]` |
| `vreinterpretq_u16_u8` (none) | `U8^16 → U16^8` | `r[i] = le16(a[2i], a[2i+1])` |
| `vreinterpretq_u64_u8` (none) | `U8^16 → U64^2` | `r[i] = le64(a[8i..8i+8])` |
| `vcombine_u8(low, high)` (`INS Vd.D[1]`) | `U8^8 × U8^8 → U8^16` | `high : low`, `low` in lanes 0..8 |
| `vgetq_lane_u64::<L>` (`UMOV Xd, Vn.D[L]`) | `U64^2 → U64`, `L ∈ [0, 1]` | `v[L]` |
| `vshrn_n_u16::<N>` (`SHRN .8B, .8H, #N`) | `U16^8 → U8^8`, `N ∈ [1, 8]` | `r[e] = (a[e] ≫ N) mod 2⁸` |
| `vshrn_n_u64::<N>` (`SHRN .2S, .2D, #N`) | `U64^2 → U32^2`, `N ∈ [1, 32]` | `r[e] = (a[e] ≫ N) mod 2³²` |
| `vmovn_u64` (`XTN .2S, .2D`) | `U64^2 → U32^2` | `r[e] = a[e] mod 2³²` |
| `vaddq_u64` (`ADD .2D`) | `U64^2 × U64^2 → U64^2` | `r[e] = a[e] ⊞ b[e]` |
| `vsraq_n_u64::<N>(a, b)` (`USRA .2D, #N`; `Vd = a`) | `U64^2 × U64^2 → U64^2`, `N ∈ [1, 64]` | `r[e] = a[e] ⊞ (N = 64 ? 0 : b[e] ≫ N)` |
| `vbslq_u64(m, b, c)`, `vbslq_u32(m, b, c)` (`BSL`; `Vd = m`) | `V × V × V → V` | `r = c ⊕ ((c ⊕ b) ∧ m)`: each mask bit picks `b` (1) or `c` (0) |
| `vmull_u32(a, b)` (`UMULL .2D, .2S, .2S`) | `U32^2 × U32^2 → U64^2` | `r[e] = a[e] · b[e]` (exact) |
| `vmlal_u32(a, b, c)` (`UMLAL`; `Vd = a`) | `U64^2 × U32^2 × U32^2 → U64^2` | `r[e] = a[e] ⊞ b[e] · c[e]` |

Notes. `vcltq_u8` has no instruction of its own: it is `CMHI` with the
operands swapped (`b > a`), and the model follows the intrinsic, not the
instruction's operand order. `SHRN` truncates (no rounding: `round_const =
0`); the byte search narrows the compare's `0xff/0` lanes with `vshrn_n_u16::<4>`,
one nibble per byte (the search-mask case of `neon2::tests::known_answers`). `USRA #64` adds 0.

### 3.2 SHA3 and SHA512 (`src/aarch64/sha3.rs`, feature `sha3`, FEAT_SHA3 + FEAT_SHA512)

`sha3` in `std::arch` names both FEAT_SHA3 and FEAT_SHA512 (the M5 has
both). With `W = Vd`, `X = Vn`, `Y = Vm` as in the Arm ARM:

| Model (instruction) | Semantics |
| --- | --- |
| `veor3q_u8(a, b, c)` (`EOR3`; `Vn = a`, `Vm = b`, `Va = c`) | `a ⊕ b ⊕ c` |
| `vbcaxq_u8(a, b, c)` (`BCAX`) | `a ⊕ (b ∧ ¬c)` |
| `vrax1q_u64(a, b)` (`RAX1`) | `r[e] = a[e] ⊕ rotl(b[e], 1)` |
| `vxarq_u64::<I>(a, b)` (`XAR #I`, `I ∈ [0, 63]`) | `r[e] = rotr(a[e] ⊕ b[e], I)` |
| `vsha512hq_u64(W, X, Y)` (`SHA512H`) | two Σ1/Ch half rounds: `hi = Ch(Y.hi, X.lo, X.hi) ⊞ Σ1(Y.hi) ⊞ W.hi`; `t = hi ⊞ Y.lo`; `lo = Ch(t, Y.hi, X.lo) ⊞ Σ1(t) ⊞ W.lo` |
| `vsha512h2q_u64(W, X, Y)` (`SHA512H2`) | two Σ0/Maj half rounds: `hi = Maj(X.lo, Y.hi, Y.lo) ⊞ Σ0(Y.lo) ⊞ W.hi`; `lo = Maj(hi, Y.lo, Y.hi) ⊞ Σ0(hi) ⊞ W.lo` |
| `vsha512su0q_u64(W, X)` (`SHA512SU0`) | `lo = W.lo ⊞ σ0(W.hi)`; `hi = W.hi ⊞ σ0(X.lo)` |
| `vsha512su1q_u64(W, X, Y)` (`SHA512SU1`) | `r[e] = W[e] ⊞ σ1(X[e]) ⊞ Y[e]` |

`Σ1 = ROR 14 ⊕ ROR 18 ⊕ ROR 41`, `Σ0 = ROR 28 ⊕ ROR 34 ⊕ ROR 39`, `σ0 = ROR 1
⊕ ROR 8 ⊕ SHR 7`, `σ1 = ROR 19 ⊕ ROR 61 ⊕ SHR 6` (FIPS 180-4). Transcription
trap: SHA512H's second half uses the **new** high word `t = hi ⊞ Y.lo`, not
an input word. The unit test `sha3::tests::sha512_schedule_through_the_models`
runs the FIPS 180-4 schedule of the "abc" block through SU0/SU1; the rounds
rest on the hardware campaign.

## 4. aarch64 SHA2 (`src/aarch64/sha2.rs`, feature `sha2`, FEAT_SHA256)

`SHA256hash` (Arm ARM `shared/functions/crypto`), at lane level with
`X = [a, b, c, d]`, `Y = [e, f, g, h]` and `W = K + W` for four rounds:

```
SHA256hash(X, Y, W, part1):
  for e in 0..4:
    chs = SHAchoose(Y₀, Y₁, Y₂)
    maj = SHAmajority(X₀, X₁, X₂)
    t   = Y₃ ⊞ Σ1(Y₀) ⊞ chs ⊞ W[e]
    X₃  := t ⊞ X₃
    Y₃  := t ⊞ Σ0(X₀) ⊞ maj
    (X, Y) := ([Y₃, X₀, X₁, X₂], [X₃, Y₀, Y₁, Y₂])        -- ROL(Y : X, 32)
  return part1 ? X : Y
```

| Model (instruction) | Semantics |
| --- | --- |
| `vsha256hq_u32(abcd, efgh, wk)` (`SHA256H Qd, Qn, Vm.4S`; `Qd = abcd`) | `SHA256hash(abcd, efgh, wk, true)`: the `abcd` half after 4 rounds |
| `vsha256h2q_u32(efgh, abcd, wk)` (`SHA256H2 Qd, Qn, Vm.4S`; `Qd = efgh`, `Qn = abcd`) | `SHA256hash(abcd, efgh, wk, false)`: the `efgh` half after 4 rounds |
| `vsha256su0q_u32(a, b)` (`SHA256SU0 Vd, Vn`) | `T = [a₁, a₂, a₃, b₀]`; `r[e] = σ0(T[e]) ⊞ a[e]` |
| `vsha256su1q_u32(x, n, m)` (`SHA256SU1 Vd, Vn, Vm`) | `T0 = [n₁, n₂, n₃, m₀]`; `r₀ = σ1(m₂) ⊞ x₀ ⊞ T0₀`; `r₁ = σ1(m₃) ⊞ x₁ ⊞ T0₁`; `r₂ = σ1(r₀) ⊞ x₂ ⊞ T0₂`; `r₃ = σ1(r₁) ⊞ x₃ ⊞ T0₃` |

Transcription traps:

* **SHA256H2's argument order is the reverse of the pseudocode.** The
  intrinsic's first argument is `Vd = efgh` and its second is `Vn = abcd`.
  stdarch names its parameters `hash_abcd, hash_efgh` in that position order,
  which is misleading, but it passes them as `(Vd, Vn)` to
  `llvm.aarch64.crypto.sha256h2`.
* **H2 takes the pre-update `abcd`.** Kernels save `abcd_prev` before
  `vsha256hq_u32` and pass it to `vsha256h2q_u32`. The unit test
  `four_rounds_of_abc` shows that the post-update value gives a wrong result.
* **SU1's upper half depends on its own lower half** (`r₂`, `r₃` use `r₀`, `r₁`).

## 5. x86_64 SSE2 / SSSE3 / SSE4.1 (`src/x86_64/sse.rs`)

Two-operand legacy-SSE forms take `DEST = xmm1 =` the first argument and
`SRC = xmm2/m128 =` the second.

| Model (instruction, feature) | Type | Semantics |
| --- | --- | --- |
| `_mm_loadu_si128` (`MOVDQU xmm, m128`, sse2) | `&U8^16 → U8^16` | `r[i] = mem[i]` |
| `_mm_storeu_si128` (`MOVDQU m128, xmm`, sse2) | `U8^16 → U8^16` (bytes written) | `mem[i] = a[i]` |
| `_mm_shuffle_epi8(a, m)` (`PSHUFB`, ssse3) | `U8^16 × U8^16 → U8^16` | `r[i] = (m[i] ∧ 0x80 ≠ 0) ? 0 : a[m[i] ∧ 15]` (bits 6..4 of `m[i]` ignored) |
| `_mm_shuffle_epi32::<IMM>(a)` (`PSHUFD`, sse2) | `U8^16 → U8^16`, `IMM ∈ [0, 255]` | on `view_u32`: `r[i] = a[(IMM ≫ 2i) ∧ 3]` |
| `_mm_alignr_epi8::<IMM>(a, b)` (`PALIGNR`, ssse3) | `U8^16 × U8^16 → U8^16`, `IMM ∈ [0, 255]` | `c = b ++ a` (32 bytes, `b` low); `r[i] = (i + IMM < 32) ? c[i + IMM] : 0` |
| `_mm_blend_epi16::<IMM>(a, b)` (`PBLENDW`, sse4.1) | `U8^16 × U8^16 → U8^16`, `IMM ∈ [0, 255]` | on `view_u16`: `r[i] = ((IMM ≫ i) ∧ 1 = 1) ? b[i] : a[i]` |
| `_mm_add_epi32(a, b)` (`PADDD`, sse2) | `U8^16 × U8^16 → U8^16` | on `view_u32`: `r[i] = a[i] ⊞ b[i]` |
| `_mm_set_epi32(e3, e2, e1, e0)` (composite, sse2) | `I32⁴ → U8^16` | `from_u32x4([e0, e1, e2, e3] mod 2³²)`: **first argument is the highest lane** |
| `_mm_set_epi64x(e1, e0)` (composite, sse2) | `I64² → U8^16` | `from_u64x2([e0, e1] mod 2⁶⁴)` |
| `_mm_xor_si128` / `_mm_and_si128` / `_mm_or_si128` (`PXOR`/`PAND`/`POR`, sse2) | `U8^16 × U8^16 → U8^16` | bytewise `⊕` / `∧` / `∨` |

`_mm_set_*` take signed scalars as in stdarch and are reinterpreted in two's
complement. DSL code uses the unsigned prelude constructors instead (§9.2).

## 6. x86_64 SHA-NI (`src/x86_64/sha.rs`, feature `sha`)

All three instructions work on `view_u32` (`SRC[32i+31:32i]` is lane `i`).

**`_mm_sha256rnds2_epu32(src1 = cdgh, src2 = abef, k)`** (`SHA256RNDS2 xmm1, xmm2/m128, <XMM0>`),
transcribed in the SDM's shape. The SDM spells out `A` and `E` separately,
with no shared `T1`:

```
A₀ = src2[3]  B₀ = src2[2]  E₀ = src2[1]  F₀ = src2[0]
C₀ = src1[3]  D₀ = src1[2]  G₀ = src1[1]  H₀ = src1[0]
for i in 0, 1:
  A_{i+1} = Ch(Eᵢ, Fᵢ, Gᵢ) ⊞ Σ1(Eᵢ) ⊞ k[i] ⊞ Hᵢ ⊞ Maj(Aᵢ, Bᵢ, Cᵢ) ⊞ Σ0(Aᵢ)
  E_{i+1} = Ch(Eᵢ, Fᵢ, Gᵢ) ⊞ Σ1(Eᵢ) ⊞ k[i] ⊞ Hᵢ ⊞ Dᵢ
  (B, C, D)_{i+1} = (Aᵢ, Bᵢ, Cᵢ);  (F, G, H)_{i+1} = (Eᵢ, Fᵢ, Gᵢ)
result = [F₂, E₂, B₂, A₂]            -- lanes 0..3; k[2], k[3] are ignored
```

**`_mm_sha256msg1_epu32(a, b)`**: `[a₀ ⊞ σ0(a₁), a₁ ⊞ σ0(a₂), a₂ ⊞ σ0(a₃), a₃ ⊞ σ0(b₀)]`.

**`_mm_sha256msg2_epu32(a, b)`**: `W16 = a₀ ⊞ σ1(b₂)`, `W17 = a₁ ⊞ σ1(b₃)`,
`W18 = a₂ ⊞ σ1(W16)`, `W19 = a₃ ⊞ σ1(W17)`, and the result is `[W16, W17, W18, W19]`.

The state packing is `abef = [f, e, b, a]` and `cdgh = [h, g, d, c]`. The
`sha2` crate's four-round group runs `cdgh := RNDS2(cdgh, abef, t)`, then
`abef := RNDS2(abef, cdgh, shuffle_epi32(t, 0x0E))`. The old `abef` register
already holds the new `cdgh` layout, so no special rules are needed.

## 7. Compositions

`src/compress.rs` assembles one-block SHA-256 compressions from the models,
statement for statement the `sha2` 0.11 crate's `aarch64_sha2.rs` and
`x86_sha.rs` sequences. `src/consistency.rs` checks them, and the SHA models
individually, against plain FIPS 180-4 (`src/fips.rs`). This is the
executable form of the §9.3 `VariantEquiv` obligation:

| Property | Statement |
| --- | --- |
| `vsha256hq_u32` / `vsha256h2q_u32` | = the `abcd` / `efgh` half of 4 FIPS rounds with `K + W = wk` (H2 with efgh first, pre-update abcd) |
| `vsha256su0q_u32`, `_mm_sha256msg1_epu32` | `r[i] = Wᵢ ⊞ σ0(W_{i+1})` |
| `vsha256su1q_u32`, `_mm_sha256msg2_epu32` | the FIPS schedule tail given the SU0/MSG1 part |
| `_mm_sha256rnds2_epu32` | = 2 FIPS rounds with `k[0]`, `k[1]` on the ABEF/CDGH packing |
| `sha2_schedule4_vs_fips`, `shani_schedule4_vs_fips` | `su1(su0(s0, s1), s2, s3)` and the `sha2` crate's `schedule` = `W16..W19` |
| `sha2_rounds4_vs_fips`, `shani_rounds4_vs_fips` | the kernels' 4-round groups = 4 FIPS rounds |
| `*_be_load_vs_from_be_bytes`, `shani_state_packing` | byte order and state packing are definitional |
| `compress_sha2_models_vs_fips`, `compress_shani_models_vs_fips` | whole compressions = `fips::compress` |
| `compress_sha2_intrinsics_vs_fips` (hardware) | the compression built from the **real** SHA2 intrinsics = `fips::compress` (and = the model compression) |

## 8. Validation status

Evidence: `evidence/aarch64.json` and `evidence/x86_64.json` (schema
`sandblaster-targets-evidence/3`, per-CPU entries). Each record holds the model's source hash
(SHA-256 of the token stream of its source items, so formatting and comments
do not count), the campaign counts and seeds, the machine (`sysctl
machdep.cpu.brand_string`, native or Rosetta 2), `rustc -V` and the date, and
a `core` record: the core global, its core items (the global and every helper
of the core file it uses), `core_hash` (SHA-256 of their comment-free,
whitespace-normalized text) and the kernel cross-check counts (§9.4). The
top-level `kernel_crosscheck` object records the kernel campaign (toolchain,
date, a hash of the kernel prelude it ran on) and the core-text compression
checks. A model counts as validated only if its record is current (the hash
matches the model as compiled now), its status is `validated`, it had zero
mismatches, it ran at least 10⁷ random cases, **and** its core record is
current with a passing kernel cross-check of at least 1000 random cases and
every immediate (`evidence::is_validated`, fail closed: proofs are about the
core model). `tests/evidence.rs` fails when a record goes stale, including
when the core text changes.

Campaign (per model, against the real `core::arch` intrinsic): at least
10⁷ random cases, where each lane comes from the corner list with
probability 1/8. On top of that come the corner cases: the full cartesian
product of corners for two-argument ops, and per-position corners plus the
product of the first four corners otherwise. The corners are 0, ~0,
0x8000_0000, 1, 0x7fff_ffff, every single-bit word, and byte patterns
(pshufb masks with high bits set, bits 6..4 set, the byte-swap pattern).
Every immediate is tested exhaustively through one monomorphization per
value. The reference side runs behind `black_box` so the instruction really
executes on run-time data.

| Model | Status | Where |
| --- | --- | --- |
| all 19 NEON models (§3) | **hardware-validated** | Apple M5 Pro, native aarch64 |
| the 27 NEON u8/u64/u32×2 models (§3.1) and the 8 SHA3/SHA512 models (§3.2) (plan O10) | **hardware-validated** (10⁷ random cases each + corners + every immediate, 0 mismatches; kernel cross-check of the core text) | Apple M5 Pro, native aarch64 |
| `vsha256hq_u32`, `vsha256h2q_u32`, `vsha256su0q_u32`, `vsha256su1q_u32` | **hardware-validated** (+ FIPS consistency) | Apple M5 Pro, native aarch64 |
| `_mm_loadu_si128`, `_mm_storeu_si128`, `_mm_shuffle_epi8`, `_mm_shuffle_epi32`, `_mm_alignr_epi8`, `_mm_blend_epi16`, `_mm_add_epi32`, `_mm_set_epi32`, `_mm_set_epi64x`, `_mm_xor_si128`, `_mm_and_si128`, `_mm_or_si128` | **validated under Rosetta 2** (x86_64 translated on Apple M5 Pro; `executor: rosetta2`) | Rosetta 2, not an Intel/AMD CPU |
| `_mm_sha256rnds2_epu32`, `_mm_sha256msg1_epu32`, `_mm_sha256msg2_epu32` | **hardware-validated natively** on AMD Zen 5 (`AuthenticAMD/1a-02-01/0xb002162`, AVX-512 host rounds 0 and the §10 campaign); `pending-hardware` (FIPS 180-4 consistency only) on the Rosetta 2 CPU | AWS c8a (EPYC 9R45) |
| the 98 models of §10 (AVX-512F/BW/VL/DQ, IFMA, GFNI, VBMI/VBMI2, VPOPCNTDQ/BITALG, AVX/AVX2) | **hardware-validated natively** on AMD Zen 5 (10⁷ random cases each + corners + every immediate, 0 mismatches; reference consistency 10⁷ each) | AWS c8a (EPYC 9R45); `docs/avx512-models.md` |

**Lane kernels (plan O10).** A lane kernel composes validated models, and
a host must also run the kernel itself before it is dispatched. Those runs
are `sets` entries named `lanes:<target>:<hash>`, where the hash covers the
kernel as the optimizer prints it, the load/store and checked-arithmetic
helpers it calls, and `rustc -V` (`evidence::LANE_SET_PREFIX`,
`BUILD_RUSTC`). The helpers' Rust templates are trusted glue: the kernel
cross-check of §9.4 compares their core wrappers with the executable
models, not the template text, so the lane record's name is what ties a
template to hardware evidence. `evidence/aarch64.json` holds one native M5
run: `lanes:neon_x4:c53f7fb16b23b45f09b7610030b8c910` (SHA-256 ×4 on NEON
from `sandblaster/front/tests/samples/lanes`, 10⁶ inputs, 0
mismatches, rustc 1.98.1). The M5 cost model still rejects that kernel.
The run was recorded under the project's former name as
`lanes:neon_x4:5222668939255c807bed68cfd1dfd838`; the rename changed only the
fingerprint's tag and the generated module name (`__sandblaster`), and the
record was relabelled after checking that the renamed emission text, with the
old names put back, hashes to exactly the recorded name.
`evidence/x86_64.json` has no lane run yet, so no x86 lane kernel is
dispatched.

The whole-compression hardware checks (`compress_sha2_intrinsics_vs_fips`
natively on the M5, `compress_shani_intrinsics_vs_fips` natively on Zen 5)
pass. The evidence is per CPU (schema 3): the x86_64 record keeps the
Rosetta 2 campaign and the Zen 5 campaigns side by side, merged with
`--merge-files` (never by copying one record over another).

Regenerate the records (release build, about 10 s each):

```
CARGO_TARGET_DIR=target/targets cargo run --release -p sandblaster-targets --bin sandblaster-targets-evidence
CARGO_TARGET_DIR=target/targets cargo run --release -p sandblaster-targets --target x86_64-apple-darwin \
    --bin sandblaster-targets-evidence
CARGO_TARGET_DIR=target/targets cargo run --release -p sandblaster-targets --bin sandblaster-targets-evidence -- --check
```

On a machine with SHA-NI, the second command validates the SHA-NI models and
the SHA-NI compression, and flips their status to `validated`. Without the
`kernel` feature a full run carries the existing core records over; the core
records of both files are regenerated on any host (about 20 s release) by

```
CARGO_TARGET_DIR=target/targets cargo run --release -p sandblaster-targets --features kernel \
    --bin sandblaster-targets-evidence -- --core-only
```

## 9. Core text

`core/aarch64.core`, `core/x86_64.core` and `core/x86_64_avx.core` (the
256/512-bit families, §10.9, loaded together with `core/x86_64.core`) are
kernel core text
(`sandblaster/kernel/CORE_SYNTAX.md`). They load with
`Env::load_core` after `Env::with_prelude()`, each on its own or both into
one environment (`sandblaster_targets::kernel::load`, feature `kernel`;
`sandblaster_targets::coretext::core_text(arch)` returns the text without the
kernel). Every item's name starts with `aarch64::` / `x86_64::`.

### 9.1 Conventions

* **Types.** A vector is the prelude `Array` of its lanes, lane 0 first:
  `uint8x16_t = Array U8 16usize`, `uint8x8_t = Array U8 8usize`,
  `uint32x4_t = Array U32 4usize` (and, for future models, `uint64x2_t =
  Array U64 2usize`, `uint32x2_t = Array U32 2usize`); `__m128i = Array U8
  16usize`, byte `i` = bits `8i+7:8i`. `[T; N]` arguments of the
  pointer-free loads are arrays (`&T` is `T` in the core, DESIGN.md §3.5).
  Signed stdarch scalars (`_mm_set_epi32`, `_mm_set_epi64x`) are passed as
  their two's-complement bits (`U32`, `U64`).
* **Globals.** Each intrinsic is `def[intrinsic] <arch>::<stdarch name>`. The
  kernel unfolds an intrinsic only when every relevant argument is a closed
  value (DESIGN.md §5.6), so on symbolic data it is an opaque neutral head, and on
  constants (padding blocks, `W + K` of constant words) it computes.
  Apart from the three x86 load/store helper wrappers below, everything else
  in the files is a transparent `def[prelude]` helper: lane
  constructors (`u32x4 x0 x1 x2 x3`), lane-wise maps (`map2_u32x4 f a b`),
  the typed views `view_u16/32/64` and their inverses `from_u16x8/u32x4/u64x2`,
  and the vendor pseudocode functions (`sha_choose`, `sha_majority`,
  `sha_hash_sigma0/1`, `sha256hash`, `sdm_ch`, …) under their Arm/Intel names.
* **Immediates** come **first**, as relevant `U32` parameters, each followed
  by irrelevant range proofs: `(.hN0 : Eq(Bool, #le_u32(lo, N), true))` if
  `lo > 0`, then `(.hN : Eq(Bool, #le_u32(N, hi), true))`. A caller passes
  `.refl(Bool, true)` for a literal in range (`CoreModel::apply_text`,
  `kernel::Kit::apply`); an out-of-range immediate is ill-typed. Then come
  the value parameters in stdarch order.
* **Lane access** is `array::index T N a Kusize .refl(Bool, true)` for a
  literal lane `K`; a computed lane (PSHUFB, PSHUFD, EXT, PALIGNR, lane
  get/set) carries a `linarith` certificate for its bound.
* **Byte order** uses the prelude only: `u32::from_le_bytes` (kind intrinsic,
  so the DESIGN.md §5.7 byte rules turn `view_u32 (from_u32x4 l)` back into `l` on
  symbolic data) and, for the inverse direction, byte `k` of a lane `x` is
  `#cast_u32_u8(#wshr_u32(x, 8k))` (`#cast_u32_u8(x)` for `k = 0`), exactly the
  pattern of that rule.
* **Arithmetic** is the wrapping primitives (`#wadd_u32`, `#wshl_u32`,
  `#rotr_u32`, …), in the operand order of the pseudocode
  (`t = Y3 + Σ1(Y0) + chs + W[e]` is `#wadd_u32(#wadd_u32(#wadd_u32(y3, Σ1 y0),
  chs), w)`).
* Load/store helpers of `sandblaster::arch` map to core globals
  (`coretext::CORE_HELPERS`): the NEON ones and the x86 byte ones to the
  load/store intrinsics themselves, `x86_64::load_u32x4` /
  `m128i_from_u32x4` / `store_u32x4` to `def[intrinsic]` wrappers
  `_mm_loadu_si128 (from_u32x4 a)` / `view_u32 (_mm_storeu_si128 v)` (opaque
  on symbolic data like the intrinsics they wrap; cross-checked against the
  same compositions of the executable models). Plan O10 adds the 256/512-bit
  word helpers `x86_64::load_u32x8` / `store_u32x8` / `load_u32x16` /
  `store_u32x16` (the lane kernels' state vectors; `def[intrinsic]`
  wrappers of `loadu/storeu` over `from_u32xN` / `view_u32`, generated with
  `core/x86_64_avx.core`) and cross-checks them the same way
  (`tests/kernel_crosscheck.rs`).
* **The O10 aarch64 section** of `core/aarch64.core` (§3.1, §3.2) adds the
  constructors `u16x8`, `u64x2`, `u32x2`, `u8x2`, the lane maps
  `map2/map3_u8x16`, `map/map2/map3_u64x2`, `map3_u32x4`, the TBL lane
  `tbl1_byte` (a `linarith`-bounded element read) and the SHA-512 helpers
  (Σ0/Σ1/σ0/σ1, Ch, Maj). It is hand-maintained text like the rest of the
  file and checked the same way: registry signatures, core hashes (§9.3) and
  the kernel cross-check against the executable models (§9.4).

### 9.2 Registry

`coretext::AARCH64_CORE_MODELS` / `X86_64_CORE_MODELS` list, in registry
order, each model's global, immediates (`CoreImm { name, lo, hi }`), value
parameters and result (`CoreTy`). `CoreModel::telescope()` gives the full Π
telescope with each binder's role (immediate, range proof, value),
`type_text()` the global's type, `apply_text()` / `kernel::Kit::apply` a
call. `coretext::find_by_path("::core::arch::aarch64::vsha256hq_u32")` and
`coretext::find_helper("sandblaster::arch::x86_64::load_u32x4")` look them up
by Rust path. Unit tests check that the declared type of every global in the
file is its registry signature (text), and the kernel tests that it is so by
conversion, that the global is `Intrinsic` with the right arity and
relevances, and that `Kit::apply` builds well-typed calls.

### 9.3 Core hashes

`coretext::core_items(arch, global)` is the global and, transitively, every
item of the same file its text references, in file order; `core_hash` is
SHA-256 over `"<name>\n<normalized text>\n"` of those items, with `--`
comments removed and whitespace runs collapsed. The prelude is not part of
the hash (it is TCB item 3, versioned with the kernel; its hash is recorded
in `kernel_crosscheck.prelude_hash` for information). A kernel test checks
that `core_items` equals the set of core globals the kernel's checked body
references.

### 9.4 Kernel cross-checks

`tests/kernel_crosscheck.rs` (feature `kernel`) and the evidence binary run:

| Check | Statement |
| --- | --- |
| per model (136) | kernel evaluation of the core global = the executable model, on the [`diff`](src/diff.rs) campaign inputs: the corner phase, ≥ 1000 random cases (split over the immediates, at least one each) and **every** immediate; the 256/512-bit models (§10) take their vectors as `kernel::Kv<N>`, whose corner list is a curated 28-vector subset of the wide corners (the hardware and reference campaigns use all of them) |
| `core_fips_vs_executable_fips` | `checks::fips::compress` (core-text FIPS 180-4, `core/checks/fips180_4.core`) = `fips::compress` |
| `core_compress_sha2_vs_core_fips` | `checks::aarch64::compress_sha2` (the `sha2` crate's sequence assembled in core text from the aarch64 core models) = the core FIPS compression |
| `core_compress_sha2_vs_executable_model` | the same = `compress::compress_aarch64_models` |
| `core_compress_shani_vs_core_fips`, `..._vs_executable_model` | the same for SHA-NI (`checks::x86_64::compress_shani`) |

The compression checks run on 15 corner inputs (H0 / zero / all-ones states ×
five blocks, including the padded "abc" block and the fixed padding block of a
64-byte message) plus random inputs (64 in the tests, 256 in the evidence).
The fixtures in `core/checks/` are untrusted test code. The tests also show
that the checks catch the transcription traps of §4-§5 (H2's argument order,
SU1's dependency on its lower half, EXT/PALIGNR operand order, `USHR #32`,
`_mm_set_epi32` lane order, PSHUFB's ignored bits): each mutation of the core
text is caught.

```
CARGO_TARGET_DIR=target/targets cargo test -p sandblaster-targets --features kernel --test kernel_crosscheck
```

The per-model campaign runs on worker threads (`kernel::crosscheck_all` on
`kernel::default_threads()`: available parallelism, at most 16;
`SANDBLASTER_KERNEL_THREADS=N` overrides it). Kernel threads scale because the
counting allocator of `sandblaster-memguard` accounts per thread.

### 9.5 Adding a model

1. Write the executable model in `src/<arch>/` (doc comment quoting the vendor
   pseudocode), add it to `registry.rs` (features, instruction, immediates,
   source items), wire the real intrinsic into `src/hw/<arch>.rs`, and run the
   hardware campaign (§8) so its record is `validated`.
2. State its lane-level semantics in this file.
3. Transcribe it into `core/<arch>.core` as `def[intrinsic] <arch>::<name>`
   following §9.1, reusing the helpers; add any new helper as `def[prelude]`.
   Computed lane indices need a `linarith` certificate (find one with the
   kernel's `Env::linearize`, as the kernel tests' reference search does).
4. Add its `CoreModel` to `src/coretext.rs` (same position as in the
   registry) and a line to `kernel::crosscheck_model` pairing the core global
   with the executable model.
5. Run `cargo test -p sandblaster-targets --features kernel` (the signature,
   item and cross-check tests), then `--core-only` (above) to record its core
   evidence; `tests/evidence.rs` fails until both records are current.

## 10. x86_64 256/512-bit families

`src/x86_64/wide.rs` (representation), `src/x86_64/vec.rs` (instruction
semantics), `src/x86_64/{avx512,avx2,ifma,gfni,vbmi}.rs` (intrinsics);
core text `core/x86_64_avx.core`. These models serve the design §13.4
workloads: QMDB SHA-256 ×16 multi-buffer (VPTERNLOGD, VPROLD/VPRORD, VPADDD,
the 32-bit transposes), Reed–Solomon GF(2^16) (GFNI affine, VPERMB/VPERMI2B,
VPSHUFB, VSHUFI64X2), curve25519 and BLS12-381/VROOM (IFMA, VPMULUDQ,
VPMULLQ, VPERMQ/VPERMI2Q, compares into masks, masked blends) and the AVX2
fallbacks for x86 CPUs without AVX-512.

### 10.1 Representation

`__m256i` = `M256i = [u8; 32]` (`U8^32`) and `__m512i` = `M512i = [u8; 64]`
(`U8^64`), byte `i` = bits `8i+7:8i`, the byte order of `__m128i` (§2). The
SDM's element slices are accessors on the bytes, for any width `N`:

```
word(v, j)  = le16(v[2j], v[2j+1])            SRC[16j+15:16j]
dword(v, j) = le32(v[4j], …, v[4j+3])         SRC[32j+31:32j]
qword(v, j) = le64(v[8j], …, v[8j+7])         SRC[64j+63:64j]
```

and `set_word` / `set_dword` / `set_qword` write them. On an `M128i`,
`dword(v, j) = view_u32(v)[j]`. The core text reads lanes with the typed
views `view_u16x32`, `view_u32x8/x16`, `view_u64x4/x8` (little-endian through
the prelude's `from_le_bytes`) and writes them with their inverses
`from_*` (byte `b` of lane `x` = `cast_u8(x ≫ 8b)`), so `view ∘ from`
collapses on symbolic data like the 128-bit views.

**Opmasks.** `__mmask8/16/32/64` are `u8/u16/u32/u64` (`U8`, `U16`, …); bit
`j` (SDM `k1[j]`) belongs to element `j`.

**One model per instruction page.** Each VEX/EVEX instruction is modelled
once, generic over the vector width in bytes (the SDM's `(KL, VL)` table,
`KL = N / element size`), and each intrinsic instantiates it: `_mm512_add_epi32`
and `_mm256_add_epi32` are `vpaddd::<64>` and `vpaddd::<32>`. The models are
the unmasked register forms (`*no writemask*`, register `SRC2`, so the
broadcast and masking branches of the pseudocode are dropped); the masking
instructions keep their mask operand. `DEST[MAXVL-1:VL] := 0` concerns bits
above the intrinsic's result and is not modelled. Immediates are `U32`
parameters in `[0, 255]` named after the stdarch const (`IMM8`, `MASK`, `B`);
the stdarch `const IMM8: u32` of `_mm512_slli/srli_*` is also `[0, 255]`.

### 10.2 AVX-512F / BW / DQ (512-bit)

Notation: `a[j]` is element `j` of the view named in the row; ⊞/⊟ wrap at
the element width.

| Model (instruction, feature) | Semantics |
| --- | --- |
| `_mm512_loadu_si512` (`VMOVDQU32 zmm, m512`, avx512f) | `&U8^64 → U8^64`, `r[i] = mem[i]` |
| `_mm512_storeu_si512` (`VMOVDQU32 m512, zmm`) | `U8^64 → U8^64` (bytes written), `mem[i] = a[i]` |
| `_mm512_add_epi32` / `_mm512_sub_epi32` (`VPADDD` / `VPSUBD`) | dwords: `r[j] = a[j] ⊞ b[j]` / `a[j] ⊟ b[j]` |
| `_mm512_add_epi64` / `_mm512_sub_epi64` (`VPADDQ` / `VPSUBQ`) | qwords, mod 2⁶⁴ |
| `_mm512_xor_si512` / `_and_` / `_or_` (`VPXORD`/`VPANDD`/`VPORD`) | bitwise (transcribed on dwords) |
| `_mm512_andnot_si512(a, b)` (`VPANDND`) | `¬a ∧ b` (**the first argument is inverted**) |
| `_mm512_ternarylogic_epi32::<IMM8>(a, b, c)` (`VPTERNLOGD`) | bit `k` of dword `j`: `IMM8[(a_k ≪ 2) + (b_k ≪ 1) + c_k]` (`a` = DEST, `b` = SRC1, `c` = SRC2) |
| `_mm512_ternarylogic_epi64::<IMM8>` (`VPTERNLOGQ`) | the same on qwords |
| `_mm512_rol_epi32::<IMM8>` / `_ror_` (`VPROLD`/`VPRORD`) | `ROTL/ROTR(a[j], IMM8 mod 32)` |
| `_mm512_rol_epi64::<IMM8>` / `_ror_` (`VPROLQ`/`VPRORQ`) | `ROTL/ROTR(a[j], IMM8 mod 64)` |
| `_mm512_rolv_epi32` / `_rorv_` (`VPROLVD`/`VPRORVD`) | `ROTL/ROTR(a[j], b[j] mod 32)` |
| `_mm512_rolv_epi64` / `_rorv_` (`VPROLVQ`/`VPRORVQ`) | `ROTL/ROTR(a[j], b[j] mod 64)` |
| `_mm512_slli_epi32::<IMM8>` / `_srli_` (`VPSLLD`/`VPSRLD` imm8) | `IMM8 > 31 ? 0 : a[j] ≪/≫ IMM8` (**not** mod 32) |
| `_mm512_slli_epi64::<IMM8>` / `_srli_` (`VPSLLQ`/`VPSRLQ` imm8) | `IMM8 > 63 ? 0 : a[j] ≪/≫ IMM8` |
| `_mm512_sllv_epi64(a, count)` / `_srlv_` (`VPSLLVQ`/`VPSRLVQ`) | `count[j] < 64 ? a[j] ≪/≫ count[j] : 0` (the whole 64-bit count) |
| `_mm512_shuffle_epi8(a, b)` (`VPSHUFB`, avx512bw) | bytes: `r[j] = b[j] ∧ 0x80 ≠ 0 ? 0 : a[(b[j] ∧ 15) + (j ∧ 0x30)]`: a PSHUFB **per 128-bit lane** |
| `_mm512_permutexvar_epi32(idx, a)` (`VPERMD`) | `r[j] = a[idx[j] ∧ 15]` (**index first**) |
| `_mm512_permutexvar_epi64(idx, a)` (`VPERMQ`) | `r[j] = a[idx[j] ∧ 7]` |
| `_mm512_permutex2var_epi64(a, idx, b)` (`VPERMI2Q`/`VPERMT2Q`) | `r[j] = (idx[j] ∧ 8 ≠ 0 ? b : a)[idx[j] ∧ 7]` |
| `_mm512_shuffle_i32x4::<MASK>(a, b)` / `_i64x2` (`VSHUFI32X4`/`VSHUFI64X2`) | 128-bit lanes `[A_{m₀}, A_{m₁}, B_{m₂}, B_{m₃}]`, `mᵢ = (MASK ≫ 2i) ∧ 3` (SDM `Select4`) |
| `_mm512_unpacklo_epi32` / `_unpackhi_epi32` (`VPUNPCKLDQ`/`HDQ`) | per 128-bit lane `L` (dwords `4L..4L+3`): lo `[a₀, b₀, a₁, b₁]`, hi `[a₂, b₂, a₃, b₃]` |
| `_mm512_unpacklo_epi64` / `_unpackhi_epi64` (`VPUNPCKLQDQ`/`HQDQ`) | per lane: lo `[a₀, b₀]`, hi `[a₁, b₁]` |
| `_mm512_set1_epi32(x)` / `_set1_epi64(x)` (composite: `VPBROADCASTD/Q`) | every element `x` (two's-complement bits) |
| `_mm512_mask_blend_epi32(k, a, b)` / `_epi64` (`VPBLENDMD/Q`) | `r[j] = k[j] ? b[j] : a[j]` |
| `_mm512_cmplt_epu64_mask(a, b)` (`VPCMPUQ …, 1`) | `U8` mask, bit `j` = `a[j] < b[j]` (unsigned) |
| `_mm512_cmpeq_epi64_mask` / `_cmpeq_epi32_mask` (`VPCMPEQQ`/`VPCMPEQD`) | `U8` / `U16` mask, bit `j` = `a[j] = b[j]` |
| `_mm512_maskz_mov_epi32(k, a)` / `_epi64` (`VMOVDQA32/64 {z}`) | `r[j] = k[j] ? a[j] : 0` |
| `_mm512_mask_mov_epi32(src, k, a)` / `_epi64` (`VMOVDQA32/64 {k}`) | `r[j] = k[j] ? a[j] : src[j]` |
| `_mm512_mullo_epi64` (`VPMULLQ`, avx512dq) | `r[j] = (a[j] · b[j]) mod 2⁶⁴` |
| `_mm512_mul_epu32` (`VPMULUDQ`) | `r[j] = (a[j] mod 2³²) · (b[j] mod 2³²)` (qwords; the full product) |

### 10.3 AVX-512VL (EVEX.256)

`_mm256_ternarylogic_epi32/epi64`, `_mm256_rol_epi32/epi64`,
`_mm256_ror_epi32/epi64` (features `avx512f`, `avx512vl`): the 512-bit
semantics on `U8^32` (the same generic model at `N = 32`). They serve the
EVEX-256 twins of the `v4` set chosen by tuning evidence (design §13.1).

### 10.4 IFMA (`src/x86_64/ifma.rs`)

`_mm512_madd52lo_epu64(a, b, c)` / `_madd52hi_` (`VPMADD52LUQ`/`HUQ`,
avx512ifma; `_mm256_*` with avx512vl), on qwords, **the accumulator first**:

```
p = (b[j] mod 2⁵²) · (c[j] mod 2⁵²)            exact 104-bit product (Int in the core)
lo: r[j] = a[j] + (p mod 2⁵²)          mod 2⁶⁴
hi: r[j] = a[j] + (⌊p / 2⁵²⌋ mod 2⁵²)  mod 2⁶⁴
```

Bits 63:52 of `b` and `c` are ignored; the core helpers `madd52lo/hi`
compute `p` over `Int` (`#imul`, `#imod`, `#idiv`, then `#int_to_sat_u64`,
exact because the part is below 2⁵²).

### 10.5 GFNI (`src/x86_64/gfni.rs`; 512 = gfni+avx512f, 256 = gfni+avx, 128 = gfni)

The field is GF(2⁸) mod `x⁸+x⁴+x³+x+1` (`0x11B`), the SDM's:

```
gf2p8mul_byte(a, b): t := 0; for i in 0..8: if b.bit[i] then t := t ⊕ (a ≪ i)
                     for i = 14 downto 8: if t.bit[i] then t := t ⊕ (0x11B ≪ (i−8)); return t mod 2⁸
parity(x)          = ⊕_{i<8} x.bit[i]                          (an xor of bit extractions)
affine_byte(A, x, imm).bit[i] = parity(A.byte[7−i] ∧ x) ⊕ imm.bit[i]
inverse(x)         = x²⁵⁴ (= the SDM's inverse table; inverse(0) = 0)
```

| Model | Semantics |
| --- | --- |
| `_mm*_gf2p8mul_epi8(a, b)` (`GF2P8MULB`) | `r[i] = gf2p8mul_byte(a[i], b[i])` |
| `_mm*_gf2p8affine_epi64_epi8::<B>(x, a)` (`GF2P8AFFINEQB`) | byte `b` of qword `j`: `affine_byte(a.qword[j], x[8j+b], B)`: **`x` is the data, `a` the matrices** |
| `_mm*_gf2p8affineinv_epi64_epi8::<B>(x, a)` (`GF2P8AFFINEINVQB`) | `affine_byte(a.qword[j], inverse(x[8j+b]), B)` |

Matrix row `i` (for result bit `i`) is **byte `7 − i`** of the qword. With
`A = 0xF1E3C78F1F3E7CF8`, `B = 0x63`, GF2P8AFFINEINVQB is the AES S-box
(unit and kernel known answers).

### 10.6 VBMI, VBMI2, VPOPCNTDQ, BITALG (`src/x86_64/vbmi.rs`)

| Model (instruction, feature) | Semantics |
| --- | --- |
| `_mm512_permutexvar_epi8(idx, a)` (`VPERMB`, avx512vbmi) | `r[j] = a[idx[j] ∧ 63]` |
| `_mm512_permutex2var_epi8(a, idx, b)` (`VPERMI2B`/`VPERMT2B`) | `r[j] = (idx[j] ∧ 64 ≠ 0 ? b : a)[idx[j] ∧ 63]` |
| `_mm512_multishift_epi64_epi8(a, b)` (`VPMULTISHIFTQB`) | byte `j` of qword `i`: bit `k` = `b.qword[i]` bit `((a[8i+j] ∧ 63) + k) mod 64` (= the low byte of `ROTR(b.qword[i], ctrl)`) |
| `_mm512_shldv_epi64(a, b, c)` (`VPSHLDVQ`, avx512vbmi2) | `s = c[j] ∧ 63`: upper qword of `(a[j] : b[j]) ≪ s` (`a` high) |
| `_mm512_shrdv_epi64(a, b, c)` (`VPSHRDVQ`) | lower qword of `(b[j] : a[j]) ≫ s` (**`b` high, `a` low**) |
| `_mm512_shldv_epi32` / `_shrdv_epi32` (`VPSHLDVD`/`VPSHRDVD`) | the same on dwords, `s = c[j] ∧ 31` |
| `_mm512_shldi_epi64::<IMM8>(a, b)` / `_epi32` (`VPSHLDQ`/`VPSHLDD`) | upper half of `(a[j] : b[j]) ≪ (IMM8 ∧ 63 / 31)` |
| `_mm512_popcnt_epi64` / `_epi32` (`VPOPCNTQ/D`, avx512vpopcntdq) | `r[j] = popcount(a[j])` |
| `_mm512_popcnt_epi8` / `_epi16` (`VPOPCNTB/W`, avx512bitalg) | `r[j] = popcount(a[j])` on bytes / words |

### 10.7 AVX / AVX2 (`src/x86_64/avx2.rs`)

`_mm256_loadu_si256`, `_mm256_storeu_si256`, `_mm256_set1_epi32`,
`_mm256_set1_epi64x` (avx); `_mm256_add_epi32/epi64`, `_mm256_xor/and/or_si256`,
`_mm256_shuffle_epi8`, `_mm256_slli/srli_epi32/epi64` (avx2): as the 512-bit
rows on `U8^32` (VPSHUFB per 128-bit lane; shift counts above the width give
0). Plus:

| Model | Semantics |
| --- | --- |
| `_mm256_permutevar8x32_epi32(a, idx)` (`VPERMD ymm`) | `r[j] = a[idx[j] ∧ 7]`: **the table is the first argument** (the instruction's second source) |
| `_mm256_blend_epi32::<IMM8>(a, b)` (`VPBLENDD`) | dword `j` from `b` iff `IMM8[j]` |
| `_mm256_alignr_epi8::<IMM8>(a, b)` (`VPALIGNR ymm`) | **per 128-bit lane** `L`: `c = b_L ++ a_L`; `r[16L+i] = i + IMM8 < 32 ? c[i + IMM8] : 0` |

### 10.8 Validation of the 256/512-bit models

* **Independent references** (`src/reference.rs`): every model is compared
  with a non-SDM implementation of the intrinsic (chunked iterators,
  `rotate_left`/`checked_shl`, a bitsliced VPTERNLOG truth table,
  Russian-peasant GF multiplication and a brute-force inverse table,
  `count_ones` parity, 128-bit IFMA arithmetic, concatenated two-table
  permutes, nibble-table popcounts) on corners + random inputs + every
  immediate (`consistency::x86_wide_models`; `tests/consistency.rs`, which
  also shows that plausible transcription slips are caught). On a CPU without
  the feature this is the model's recorded consistency (`reference_consistency`,
  status `pending-hardware`).
* **Known answers**: the AES S-box through GF2P8AFFINEINVQB, FIPS-197
  products, the first row of the SDM inverse table, IFMA at the 52-bit
  edges, VPTERNLOG 0x96/0xCA/0xE8 (xor3/Ch/Maj), shifts and rotates at the
  width, lane-bounded shuffles (unit tests of each file).
* **Kernel cross-check**: each core model = its executable model by kernel
  evaluation (§9.4), and mutations of the transcription traps below are
  caught (`tests/kernel_crosscheck.rs`).
* **Hardware**: the campaign compares each model with the real intrinsic
  (≥ 10⁷ random cases + corners + every immediate; corners include every
  byte splat, the sign bit / largest value / 1 of every element width,
  alternating elements, permute index patterns with the select and zeroing
  bits, single bytes at element and lane boundaries, and the mask corners
  0, ~0, 0x5555, 0xAAAA and every single bit). `host-results/avx512-models/`
  and `docs/avx512-models.md` hold the Zen 5 runs: the campaign (`out/`),
  its bit-for-bit reproduction from a fresh tree and a second 10⁷-case
  campaign under another seed (`v2/`, not merged), all with 0 mismatches.

Transcription traps (each has a test): the first argument is the index of
`_mm512_permutexvar_*` but the table of `_mm256_permutevar8x32_epi32`;
`andnot` inverts the first argument; VPSHUFB and VPALIGNR (ymm) work per
128-bit lane; VPERMI2Q/B select the second table with bit 3 / bit 6; VPSLLD/Q
by an immediate zero the element above the width (rotates reduce mod the
width); VPSLLVQ compares the whole 64-bit count; IFMA ignores bits 63:52 and
takes the accumulator first; GF affine rows are byte `7 − i`; VPSHRDVQ's
destination is the low half; VPBLENDM takes the second source where the mask
is set; VPTERNLOG's first source is the high index bit.

### 10.9 Core text

`core/x86_64_avx.core` is generated by `gen/x86_64_avx.py` from the same
model table that emits the `wide!` rows of `src/registry.rs`, the `x86!` rows
of `src/coretext.rs` and the hardware wrappers `src/hw/x86_64_wide.rs`. It is
loaded **together with** `core/x86_64.core` as one text
(`coretext::core_text(Arch::X86_64)` is their concatenation) and reuses its
helpers (`u8x16`, `view_u64`, `pshufb_byte`, `palignr_byte`,
`concat_u8x16`). Model bodies are `from (mapN f (view a) …)` with `f` the
per-element pseudocode, cross-lane ones use literal lanes, the 128-bit lanes
of a vector (`lanes128_u8x64`), `select4` (a computed lane with a `linarith`
bound) or computed indices with `linarith` bounds. VPTERNLOG is transcribed as
the OR of the minterms its immediate selects, the SDM's per-bit table lookup
restated per element (the kernel cross-check compares it with the executable
per-bit model). Appending the file leaves every earlier model's core hash
unchanged.
