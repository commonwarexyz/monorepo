# [runtime/codec] Avoid repeated scans in fragmented buffers

Fragmented buffers can repeatedly scan chunks that an operation does not need to inspect. Taking the first chunk through `IoBufs::split_to` sums every remaining length, bulk writes into `IoBufsMut` repeatedly search past already-filled chunks, and codec scalar getters sum remaining lengths before inspecting the current chunk.

This change adds four fast paths:

- `IoBufs::split_to` handles splits within or exactly at a deque's first chunk without summing the tail or allocating a temporary output deque. The existing small representations are already constant-time. Cross-chunk splits retain their existing validation and implementation.
- `IoBufsMut::put_slice` checks total writable capacity once, then visits each chunk once and writes through `IoBufMut::put_slice`. Oversized inputs still panic before modifying any chunk. Readable bytes, writable capacity, and chunk order are preserved.
- Codec scalar, numeric vector/array, byte-array, and varint reads share a helper that reads directly from the current chunk when enough bytes are present. Cross-chunk reads fall back to checked copying. Numeric vectors and arrays retain their upfront size checks, including multiplication-overflow rejection, before allocation or decoding.
- `IoBufsMut::is_empty` stops at the first readable chunk, and `has_remaining` delegates to it. Unlike immutable buffers, mutable buffers can retain capacity in multiple readable-empty chunks, so the worst case remains linear.

Repeated first-chunk extraction and a single bulk mutable write spanning all chunks now perform linear rather than quadratic chunk traversal. Chunk-first codec reads avoid total-length queries when the value fits in the current chunk. General splits, cross-chunk codec reads, and repeated separate small mutable writes can still scan chunks.

The implementation adds no cached state, public API changes, wire-format changes, or new unsafe code. The immutable split fast path uses the existing canonical representation invariant. This branch follows #4802 at `dbfd55679955543fd62e390df0e7c0629b9527bb`.

## Validation

- `just test -p commonware-codec`: 147 passed.
- `just test -p commonware-runtime`: 841 passed, 4 skipped by the test configuration.
- `just test-conformance -p commonware-codec`: 49 passed; fixtures unchanged.
- `just build -p commonware-codec --no-default-features`: passed.
- `just clippy -p commonware-codec -p commonware-runtime --features commonware-runtime/bench`: passed.
- `just lint`: passed, including workspace Clippy, documentation, custom lints, and stability checks.

New tests cover wrapped deques, zero-copy split views, invalid splits leaving contents unchanged, mutable writes compared with the generic chunked write path, oversized writes leaving every chunk unchanged, empty mutable buffers with reserved capacity, all numeric widths across every two-chunk boundary and truncation point, and the number of total-length queries made by codec readers. Existing varint tests continue to cover malformed encodings and overflow.

## Benchmarks

Adds Criterion cases for first-chunk extraction, bulk mutable writes, mutable emptiness, and scalar/vector/array/varint decoding. Fragmentation ranges from 1 to 256 chunks; decoding also includes contiguous `Bytes` and `IoBuf` inputs. Buffer preparation is outside the timed operation through batched setup.

Local ARM64 measurements with Rust 1.97.1 compared the original #4802 head against this change using separate build directories and sequential runs. Each case used 30 samples, a 0.3-second warmup, and a 1-second measurement period. Representative mean times at 256 chunks:

| Operation | Before | After |
| --- | ---: | ---: |
| Extract all first chunks, 8 bytes each | 24.35 us | 1.08 us |
| Bulk write 4 KiB | 27.57 us | 0.73 us |
| Read 1,024 individual u32 values | 68.13 us | 4.52 us |
| Read a vector of 1,024 u32 values | 68.19 us | 4.72 us |
| Read 4,096 one-byte varints | 265.05 us | 19.62 us |
| Mutable emptiness, first chunk readable | 119.88 ns | 1.01 ns |
| Mutable emptiness, all chunks empty | 120.22 ns | 75.55 ns |

Contiguous controls included approximately 2% slower `IoBuf` scalar/varint reads and `Bytes` array reads, alongside faster `Bytes` scalar/vector/varint reads. Small differences should be treated cautiously; the clear improvements are the fragmented cases.

Run the new cases with:

```sh
cargo bench -p commonware-runtime --features bench --bench iobuf -- 'iobuf::(split_front|put_slice|decode|emptiness)/'
```

These microbenchmarks isolate the changed operations; they do not establish an end-to-end storage or networking throughput improvement.
