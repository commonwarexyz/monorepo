# Multi-buffer encoding for zero-copy of large `Bytes` fields

## Problem

When encoding a message for the network, `Write::write()` copies every field into a single contiguous buffer. For types containing large `Bytes` fields -- like `Chunk`, which holds up to 1 MB of erasure-coded shard data -- this memcpy is unnecessary. The data is already in an Arc-backed `Bytes` that could be passed by reference, but `Write` targets `impl BufMut` (a contiguous buffer) and has no way to express "just reference this allocation."

The network layer downstream already supports multi-buffer output (`IoBufs`), but the encoding layer cannot produce them.

The most affected path is **shard broadcasting**: every consensus round, the proposer encodes one shard (~1 MB) per participant. Each encoding memcpy's the shard payload even though it is already in memory.

Note that the encryption layer also copies the payload into a contiguous buffer (the cipher requires contiguous memory). That copy is unavoidable. Today the payload is copied twice (encoding + encryption); this PR reduces it to once (encryption only).

## Solution

**`BufsMut` trait and `Write::write_bufs`** (`codec/src/codec.rs`, `codec/src/types/bytes.rs`):

Following the `IoBuf`/`IoBufs` naming convention, `BufsMut: BufMut` is a multi-buffer target that accepts zero-copy `Bytes` via `push()`. `Write::write_bufs` is a default method on the existing `Write` trait that delegates to `Write::write`. Types containing large `Bytes` fields override it to call `push()` instead of copying.

The `Bytes` override writes the varint length prefix inline and pushes the payload via `push()` (Arc clone, no memcpy). The wire format is identical.

**`EncodeSize::encode_inline_size`** (`codec/src/codec.rs`):

New default method on `EncodeSize` returning the encoded size excluding bytes that go via `BufsMut::push`. Used to right-size the `Builder`'s working buffer. Types that override `write_bufs` should also override `encode_inline_size`; failing to do so over-allocates but is not incorrect.

**`Builder` in runtime** (`runtime/src/iobuf/mod.rs`):

The concrete `BufsMut` implementation (re-exported as `IoBufsBuilder`). All inline writes go into a single pool-backed buffer. `push()` records boundaries without flushing. `finish()` freezes the buffer once and uses `IoBuf::slice` to carve it into pieces at the recorded boundaries, interleaved with the pushed `Bytes`. All inline slices share the same underlying pool allocation.

If inline writes exceed the initial capacity, the buffer grows via reallocation.

**`encode_with_pool` now returns `IoBufs`** (`runtime/src/iobuf/mod.rs`):

`EncodeExt::encode_with_pool` is changed from returning a flat `IoBuf` (via `Write::write`) to returning `IoBufs` (via `Write::write_bufs` through a `Builder`). The `Builder` is sized to `encode_inline_size()`. For types that don't override `write_bufs`, the output is a single contiguous piece -- same as before. For types that do, large `Bytes` fields become zero-copy pieces. All downstream consumers already accept `impl Into<IoBufs>`, so this is transparent.

**`write_bufs` and `encode_inline_size` overrides for hot-path types**:

Each type in the chain from `WrappedSender::send` to the `Bytes` field overrides both methods in its `Write` and `EncodeSize` impls. Types without `Bytes` fields inherit the defaults. The encoding chain for a shard:

```
Shard::write_bufs -> Chunk::write_bufs -> Bytes::write_bufs (push)
```

Produces:

```
Piece 0: [commitment | shard_index | varint_length]  (~40 bytes, pool slice)
Piece 1: [------------ 1 MB shard payload ---------]  (Arc clone, no copy)
Piece 2: [chunk_index | proof]                        (~200 bytes, pool slice)
```

Pieces 0 and 2 are slices of a single ~240 byte pool allocation.
