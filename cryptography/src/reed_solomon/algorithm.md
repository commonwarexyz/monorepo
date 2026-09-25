Shard layout and additive FFT encoding over GF(2^16).

# Shard

- Reed-Solomon `GF(2^16)` erasure coding works on 16-bit elements ([`GfElement`]).
- A **shard** is a byte-array which is interpreted as an array of [`GfElement`]:s.

Shards have a nonzero, even byte length. The engines process them in 64-byte blocks
whose first 32 bytes are the low parts of 32 [`GfElement`]s and whose last 32 bytes
are the corresponding high parts. This layout lets SIMD instructions operate on
many field elements at once.

```text
[ low_0, low_1, ..., low_31, high_0, high_1, ..., high_31 ]
```

A shard consists of complete blocks followed by an optional partial block:

```text
// -------- first 64-byte block --------- | --------- second 64-byte block ---------- | ...
[ low_0, ..., low_31, high_0, ..., high_31, low_32, ..., low_63, high_32, ..., high_63, ... ]
```

For a tail of `2 * n` bytes, the first `n` bytes are the low parts and the last `n`
bytes are the high parts. Encoders and decoders copy them to offsets `0..n` and
`32..32+n` of a full working block and pack output tails back into `2 * n` bytes.
Other positions in that block do not affect the returned elements.

Field elements are independent across positions, so a shard can be split into
independent encoding or decoding jobs. Splits on 64-byte block boundaries keep
every low/high byte pairing, so the jobs together produce the same bytes as one
job. Other even splits pair different bytes into field elements.

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
    - Decoding must use the same rate and shard counts as encoding.
    - With multiple chunks "correct" rate is generally faster in encoding
      and not-slower in decoding.
    - With single chunk "wrong" rate is generally faster in decoding
      if `original_count` and `recovery_count` differ a lot.

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
