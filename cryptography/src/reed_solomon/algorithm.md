Algorithm documentation.

As I don't understand algorithm fully myself,
I'll just document some parts which I do understand.

# Shard

- Reed-Solomon `GF(2^16)` erasure coding works on 16-bit elements ([`GfElement`]).
- A **shard** is a byte-array which is interpreted as an array of [`GfElement`]:s.

A naive implementation could e.g. require shards to be a multiple of **2 bytes**
and then interpret each byte-pair as low/high parts of a single [`GfElement`]:

```text
[ low_0, high_0, low_1, high_1, ...]
```

However that approach isn't good for SIMD optimizations.
Instead shards are required to be a multiple of **64 bytes**.
In each 64-byte block first 32 bytes are low parts of 32 [`GfElement`]:s
and last 32 bytes are high parts of those 32 [`GfElement`]:s.

```text
[ low_0, low_1, ..., low_31, high_0, high_1, ..., high_31 ]
```

A shard then consists of one or more of these 64-byte blocks:

```text
// -------- first 64-byte block --------- | --------- second 64-byte block ---------- | ...
[ low_0, ..., low_31, high_0, ..., high_31, low_32, ..., low_63, high_32, ..., high_63, ... ]
```

# Rate

Encoding and decoding both have two variations:

- **High rate** refers to having more original shards than recovery shards.
    - High rate must be used when there are over 32768 original shards.
    - High rate encoding uses **chunks** of `recovery_count.next_power_of_two()` shards.
- **Low rate** refers to having more recovery shards than original shards.
    - Low rate must be used when there are over 32768 recovery shards.
    - Low rate encoding uses **chunks** of `original_count.next_power_of_two()` shards.
- Because of padding either rate can be used when there are
  at most 32768 original shards and at most 32768 recovery shards.
    - High rate and low rate are not [^1] compatible with each other,
      i.e. decoding must use same rate that encoding used.
    - With multiple chunks "correct" rate is generally faster in encoding
      and not-slower in decoding.
    - With single chunk "wrong" rate is generally faster in decoding
      if `original_count` and `recovery_count` differ a lot.

[^1]: They seem to be compatible with single chunk. However I don't quite
    understand why and I don't recommend relying on this.

## Benchmarks

- These benchmarks are from `cargo bench rate`
  and use similar setup than [main benchmarks],
  except with maximum possible shard loss.

| original : recovery | Chunks  | `HighRateEncoder` | `LowRateEncoder` | `HighRateDecoder` | `LowRateDecoder` |
| ------------------- | ------- | ----------------- | ---------------- | ----------------- | ---------------- |
| 1024 : 1024         | 1x 1024 | 175 MiB/s         | 176 MiB/s        | 76 MiB/s          | 75 MiB/s         |
| 1024 : 1025 (Low)   | 2x 1024 | 140               | **153**          | 47                | **59**           |
| 1025 : 1024 (High)  | 2x 1024 | **152**           | 132              | **60**            | 46               |
| 1024 : 2048 (Low)   | 2x 1024 | 157               | **169**          | 70                | 70               |
| 2048 : 1024 (High)  | 2x 1024 | **167**           | 151              | 69                | 68               |
| 1025 : 1025         | 1x 2048 | 125               | 126              | 44                | 43               |
| 1025 : 2048 (Low)   | 1x 2048 | 144               | 144              | **65** **!!!**    | 53               |
| 2048 : 1025 (High)  | 1x 2048 | 144               | 145              | 53                | **62** **!!!**   |
| 2048 : 2048         | 1x 2048 | 156               | 157              | 70                | 69               |

[main benchmarks]: crate::reed_solomon#benchmarks

# Encoding

Encoding takes original shards as input and generates recovery shards.

## High rate encoding

- Encoding is done in **chunks** of `recovery_count.next_power_of_two()` shards.
- Original shards are split into chunks and last chunk
  is padded with zero-filled shards if needed.
    - In theory original shards are padded to [`GF_ORDER`]` - chunk_size` shards
      but since `IFFT([0u8; x]) == [0u8; x]` and `xor` with `0` is no-op,
      the chunks which contain only `0u8`:s can be ignored.
- Recovery shards fit into a single chunk
  which is padded with unused shards if needed.
- Recovery chunk is generated with following algorithm

```text
recovery_chunk = FFT(
    IFFT(original_chunk_0, skew_0) xor
    IFFT(original_chunk_1, skew_1) xor
    ...
)
```

This is implemented in [`HighRateEncoder`].

## Low rate encoding

- Encoding is done in **chunks** of `original_count.next_power_of_two()` shards.
- Original shards fit into a single chunk
  which is padded with zero-filled shards if needed.
- Recovery shards are generated in chunks and last chunk
  is padded with unused shards if needed.
    - In theory recovery shards are padded to [`GF_ORDER`]` - chunk_size` shards
      but chunks which contain only unused shards can be ignored.
- Recovery chunks are generated with following algorithm

```text
recovery_chunk_0 = FFT( IFFT(original_chunk), skew_0 )
recovery_chunk_1 = FFT( IFFT(original_chunk), skew_1 )
...
```

This is implemented in [`LowRateEncoder`].

[`GfElement`]: crate::reed_solomon::engine::GfElement
[`HighRateEncoder`]: crate::reed_solomon::rate::HighRateEncoder
[`LowRateEncoder`]: crate::reed_solomon::rate::LowRateEncoder

[`GF_ORDER`]: crate::reed_solomon::engine::GF_ORDER
