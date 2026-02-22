# Erasure Coding Performance Analysis

This document summarizes performance profiling of the Reed-Solomon erasure coding
pipeline and identifies optimization opportunities. All measurements were taken on
an x86-64 machine with SHA-NI and AVX512 support.

## Workload

The reference workload is **4 MB payload, 100 total shards (33 original + 67 recovery)**,
which produces ~127 KB shards. This matches the expected block size and participant
count in production.

## Current Pipeline Breakdown (conc=8)

### Encode (SHA-256)

| Phase | Time | Share |
|---|---|---|
| RS encode (`reed-solomon-simd`) | 4.6 ms | 51% |
| Shard hashing (100 x 127 KB, conc=8) | 2.4 ms | 27% |
| BMT build + proof generation | 0.05 ms | <1% |
| Other (alloc, data prep) | ~1.9 ms | 21% |
| **Total** | **~9.0 ms** | |

### Decode (SHA-256)

| Phase | Time | Share |
|---|---|---|
| `check()` -- verify 33 shard proofs | 2.2 ms | 12% |
| `decode()` -- RS decode + re-encode + hash + BMT | 15.8 ms | 88% |
| &nbsp;&nbsp;&nbsp;&nbsp;RS decode | 1.2 ms | |
| &nbsp;&nbsp;&nbsp;&nbsp;RS re-encode (consistency check) | 4.0 ms | |
| &nbsp;&nbsp;&nbsp;&nbsp;Shard hashing (100 x 127 KB, conc=8) | 2.4 ms | |
| &nbsp;&nbsp;&nbsp;&nbsp;Other (alloc, reconstruction) | ~8.2 ms | |
| **Total** | **~18.0 ms** | |

Note: `check()` is parallelized in production via `strategy.map_partition_collect_vec`.
The `decode()` function re-encodes all shards to verify the BMT root matches,
which is necessary to detect a malicious encoder who builds a valid tree over
an invalid RS encoding.

### BLAKE3 vs SHA-256

Switching from SHA-256 to BLAKE3 reduces shard hashing from 6.6 ms to 1.9 ms
(sequential) -- a 3.5x improvement on the hashing portion. With conc=8, this
goes from 2.4 ms to ~0.7 ms. The RS codec and BMT are unaffected.

## Completed Optimization: BMT `hash_node`

Standard SHA-256 of two 32-byte digests (`H(left || right)`) requires 2 compression
calls (64 bytes of data + padding block). By using `sha2::compress256` directly,
internal nodes are computed in 1 compression call.

| Operation | Before | After | Improvement |
|---|---|---|---|
| BMT build (n=10K) | 1.37 ms | 880 us | **-35%** |
| BMT build (n=100K) | 13.7 ms | 8.9 ms | **-35%** |
| RS decode (256B, 100 chunks) | 57.4 us | 39.5 us | **-32%** |

At the 4 MB workload, BMT is <1% of total time so this optimization has
negligible impact there. It matters most for small payloads and proof-heavy
workloads.

## Future Work: GF(2^8) Reed-Solomon Implementation

### The Opportunity

`reed-solomon-simd` uses GF(2^16) to support up to 65535 shards. Production
only needs ~100 shards, well within the 255-shard limit of GF(2^8). Benchmarks
comparing `reed-solomon-simd` against Intel ISA-L (a C library using GF(2^8)
with AVX512+GFNI) show dramatic differences:

| Operation | reed-solomon-simd (GF(2^16)) | ISA-L (GF(2^8)) | Speedup |
|---|---|---|---|
| Encode | 4,317 us | 1,750 us | **2.5x** |
| Decode | 18,493 us | 962 us | **19.2x** |
| Re-encode | 3,921 us | 1,743 us | **2.2x** |

Combined with BLAKE3 for shard hashing, the projected full decode pipeline
drops from ~29 ms to ~4.5 ms -- a **6.4x improvement**.

### Why Not Use ISA-L Directly?

- The Rust bindings (`erasure-isa-l`) only support x86-64, not ARM64.
- ISA-L is a C library requiring autoconf/nasm, adding build complexity.
- Violates the "own core mechanisms" design principle.

The underlying C library does support aarch64 (NEON, SVE), but the Rust
bindings do not wire this up.

### Recommended Approach: Native Rust GF(2^8) RS

A new crate implementing GF(2^8) Reed-Solomon with platform-specific SIMD:

**Architecture:**
- GF(2^8) arithmetic via SIMD byte-shuffle lookup tables
- x86-64: AVX2/SSSE3 (with optional GFNI for newer CPUs)
- aarch64: NEON (has good byte-shuffle via `vtbl`/`vqtbl1q`)
- Pure Rust fallback for WASM and other platforms
- Runtime feature detection (same approach as `reed-solomon-simd`)

**Core operations:**
- GF(2^8) multiply/add via split-table SIMD (two 4-bit lookups per byte)
- Matrix-vector products for encode
- Matrix inversion (Gaussian elimination in GF(2^8)) + products for decode
- Standard Vandermonde or Cauchy encoding matrix

**Why the decode gap is so large (19x):**
- GF(2^8) operations are fundamentally cheaper than GF(2^16)
- ISA-L uses GFNI (dedicated Galois Field hardware instructions)
- `reed-solomon-simd`'s Leopard-RS algorithm has FFT overhead that hurts
  at small shard counts (optimized for thousands of shards, not 100)
- A direct matrix approach in GF(2^8) avoids FFT entirely for small N

**Scope estimate:** The core math (GF arithmetic, encode, decode, SIMD kernels)
is a focused but non-trivial effort. The `reed-solomon-simd` crate is a good
reference for the SIMD dispatch and runtime detection patterns.

**Constraint:** GF(2^8) limits total shards to 255. This is sufficient for
current production needs (100 shards) but would need revisiting if shard
counts grow significantly.

### Projected Impact

For the 4 MB / 100 shard workload at conc=8:

| Pipeline | Encode | Decode | Total Round-Trip |
|---|---|---|---|
| Current (rs-simd + SHA-256) | ~9 ms | ~18 ms | ~27 ms |
| GF(2^8) + BLAKE3 (projected) | ~3 ms | ~4 ms | ~7 ms |
| **Improvement** | **3x** | **4.5x** | **~4x** |

The RS codec is the dominant cost at this payload size. Optimizing the hash
function or tree structure yields diminishing returns -- the field arithmetic
is the bottleneck.
