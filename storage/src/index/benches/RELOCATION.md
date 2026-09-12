# Partition buffer relocation experiment

Compare the existing slab allocation with two individual-allocation policies. All binaries use
mimalloc 0.1.52, the same index operations, five-byte translated suffixes, and either eight-byte
or five-byte locations. Default builds retain the existing slab implementation. The baseline
is slab PR #4744 at `0bf6ac7f8`, not main.

## Results

The free list recovers much of exact growth's insertion cost, but increases RSS relative to
freeing old allocations directly. At 1B-equivalent occupancy, eight-byte values get essentially
no memory benefit from exact allocation; adding a free list makes memory worse. Five-byte values
benefit more, but their encoding still needs the integration described in [PACKED_LOCATIONS.md](PACKED_LOCATIONS.md).

Median of three fresh processes on macOS/arm64 (Mac16,7, 48 GiB), nightly rustc 1.100.0
(`fd7ed57df`, 2026-08-29), optimized bench profile, seed 0. All use mimalloc 0.1.52
(`libmimalloc-sys` 0.1.49), with no `MIMALLOC_*` overrides. The 42 individual runs, hashes,
checkpoint RSS, timings, and free-list counters are saved in [relocation-results.csv](relocation-results.csv).

Initial 3,906,250 keys, P=2 (1B/P=3 mean occupancy), then another 3,906,250 new keys:

| Policy | Value bytes | Build RSS B/key | Build ns/key | Replace ns/key | New-key growth ns/key |
| --- | ---: | ---: | ---: | ---: | ---: |
| Slabs | 8 | 22.17 | 164.74 | 118.67 | 305.51 |
| Exact | 8 | 21.95 | 192.09 | 115.92 | 361.96 |
| Free list, 1 MiB | 8 | 25.79 | 181.90 | 117.54 | 310.71 |
| Free list, 64 KiB | 8 | 24.63 | 180.87 | 114.88 | 319.81 |
| Slabs | 5 | 21.87 | 157.17 | 122.91 | 278.57 |
| Exact | 5 | 18.24 | 175.08 | 115.05 | 317.73 |
| Free list, 1 MiB | 5 | 19.81 | 170.56 | 116.30 | 282.71 |
| Free list, 64 KiB | 5 | 18.68 | 165.34 | 113.49 | 287.53 |

The one-MiB free list reused about 91% of allocation requests; 64 KiB still reused 89%.
Both respected their retained-buffer budgets. RSS includes live spare capacity, allocator
rounding/retention, pool metadata, and other process memory, so its increase can exceed the
free-list byte budget. The hit rate alone does not explain the memory result.

A second tier starts at 7,812,500 keys and grows to 15,625,000, with a two-MiB free list:

| Policy | Value bytes | Build (2B) B/key | +25% (2.5B) | +50% (3B) | +75% (3.5B) | +100% (4B) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Slabs | 8 | 20.00 | 22.64 | 31.04 | 26.61 | 23.28 |
| Exact | 8 | 21.41 | 21.07 | 19.55 | 21.39 | 20.11 |
| Free list | 8 | 23.97 | 22.69 | 21.96 | 23.66 | 21.66 |
| Slabs | 5 | 19.82 | 16.00 | 14.00 | 23.14 | 23.31 |
| Exact | 5 | 15.73 | 16.00 | 15.19 | 15.23 | 14.73 |
| Free list | 5 | 17.66 | 19.16 | 17.96 | 18.10 | 16.58 |

Parentheses indicate equivalent P=3 occupancy, not actual billion-key runs. These are current
RSS measurements at each checkpoint, not peak RSS. Slab growth thresholds produce large swings:
exact five-byte storage wins by 37% at the final checkpoint, but loses to slabs at 3B-equivalent
occupancy. In this tier, exact growth takes about 20-22% longer than slabs, while reuse is within
2-3%. Existing-key replacement does not relocate and was no slower in either experiment.

This supports investigating tighter allocation together with packed values, but does not justify
replacing the eight-byte slab implementation with this free list. Full-scale parallel builds and
steady workloads still need measurement; matching occupancy does not reproduce their allocator,
cache, or contention behavior.

## Policies

- `slabs`: existing geometric growth and two-KiB slabs.
- `exact`: on a full partition, allocate capacity `len + 1` directly through the Rust global
  allocator, copy entries around the insertion point, and free the old buffer.
- `reuse`: the same exact-fit allocation on a free-list miss. First try the smallest retained capacity
  from `len + 1` through `len + 5`, with an exactly matching layout for that capacity. Return the
  old empty buffer to the free list. Existing-key replacements stay in place; deletion does not shrink
  a nonempty buffer. There is no custom slab layer in either new policy.

The free list defaults to one MiB per pool, configured once with `INDEX_BUFFER_CACHE_BYTES`. Evict
whole sizes with the oldest allocation requests when a return would exceed the byte budget.
Store links inside the empty buffers, so bookkeeping does not allocate a node per retained buffer.
The lazily allocated 513-bin table adds about 16 KiB of metadata on this target. Capacities above 512 (including cursor
overshoot), allocations smaller than a pointer, and allocations exceeding the budget bypass the
free list. A returned buffer must have its original allocation layout. Pool destruction frees every
retained allocation, and retained buffers hold no references back to the pool.

Buffers retain their build worker's pool across range installation. Both experimental policies
keep the same 32-byte partition header as the slab baseline on 64-bit targets. Relocation copies
only initialized entries, fuses insertion with the copy, and transfers value ownership without
dropping the old copies. Zero-sized types, alignment, spilling, and cursor behavior retain the
same contracts. No public API, storage format, QMDB integration, or default policy changes.

Exact growth also copies on every append through an oversized held cursor. Before production
adoption, that path would need geometric growth beyond the normal spill threshold to preserve
amortized append cost. The occupancy proxies below remain well below that threshold.

## Validation and reproduction

Build three versions of `index_scale`, copying each emitted executable before the next build:

```text
cargo bench -p commonware-storage --bench index_scale --no-run
RUSTFLAGS='--cfg index_alloc="exact"' cargo bench -p commonware-storage --bench index_scale --no-run
RUSTFLAGS='--cfg index_alloc="reuse"' cargo bench -p commonware-storage --bench index_scale --no-run
```

Name the saved binaries `index_scale_slabs`, `index_scale_exact`, and `index_scale_reuse`.
Run the existing index tests with each policy. Run the array and free-list tests under Miri for the
experimental policies; these exercise ownership, panicking destructors, alignment, zero-sized
types, size limits, incompatible layouts, eviction, and concurrent reuse.

`relocate_u64_2` and `relocate_packed_2` opt into the workload (also available with `_3`). Build the
initial key count, verify all locations, replace every value in place, verify replacements, grow
by four batches of 25%, delete one percent of the final entries, and verify all surviving and
deleted locations. The growth phases continue the same seeded random stream. Timings include
key generation and location verification. Collision-aware deletion removes only the target value.

The runner samples RSS with `ps` at phase boundaries while the benchmark waits on stdin, outside
the measured interval. It also records process peak RSS with `/usr/bin/time`, executable hashes,
allocator environment overrides, and final free-list counters. Eviction counts include teardown.
Memory returned to mimalloc is not necessarily returned immediately to the OS.

```text
python3 storage/src/index/benches/relocate_run.py --binaries /path/to/binaries --output /path/to/results --items 3906250 --cache-bytes 1048576
python3 storage/src/index/benches/relocate_run.py --binaries /path/to/binaries --output /path/to/larger-results --items 7812500 --cache-bytes 2097152
python3 storage/src/index/benches/relocate_run.py --binaries /path/to/binaries --output /path/to/small-list-results --items 3906250 --cache-bytes 65536 --policies reuse
```

Three fresh-process runs per policy/value width, with rotated/reversed ordering and no concurrent
compilation. P=2 at 3,906,250 keys matches the mean partition occupancy of 1B keys at P=3; doubling
the proxy reaches the occupancy of 2B. These are occupancy proxies, not billion-key measurements.
Scale the free-list budget with the proxy size when comparing occupancy tiers. Report current RSS
at build and growth checkpoints separately from peak RSS across the entire growing workload.
Growth timing is the median of each run's total growth time divided by added keys.

Validation passed: 183 index tests for slabs, 178 for exact, and 182 for reuse; eight array tests
under Miri for each experimental policy plus four reuse-pool tests; default no-std WASM release
build; formatting; and Clippy for the storage library and index-scale bench under all three
policies. Clippy allows the existing `needless_borrows_for_generic_args` findings in unrelated
QMDB/journal code. No workspace-wide checks or end-to-end QMDB benchmark are claimed.
