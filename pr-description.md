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

**`Builder` in runtime** (`runtime/src/iobuf/mod.rs`):

The concrete `BufsMut` implementation (re-exported as `IoBufsBuilder`). Maintains a pool-backed `IoBufMut` as a working buffer for inline writes. When `push()` is called, the working buffer is flushed as one piece and the pushed `Bytes` is appended as another. A new working buffer is allocated lazily on the next inline write. The result is an `IoBufs` with interleaved inline and zero-copy pieces, ready for vectored I/O.

**`encode_with_pool` now returns `IoBufs`** (`runtime/src/iobuf/mod.rs`):

`EncodeExt::encode_with_pool` is changed from returning a flat `IoBuf` (via `Write::write`) to returning `IoBufs` (via `Write::write_bufs` through a `Builder`). For types that don't override `write_bufs`, the output is a single contiguous piece -- same as before. For types that do, large `Bytes` fields become zero-copy pieces. All downstream consumers already accept `impl Into<IoBufs>`, so this is transparent.

**`write_bufs` overrides for hot-path types**:

Each type in the chain from `WrappedSender::send` to the `Bytes` field overrides `write_bufs` in its `Write` impl. Types without `Bytes` fields inherit the default (which just calls `write`). The encoding chain for a shard:

```
Shard::write_bufs -> Chunk::write_bufs -> Bytes::write_bufs (push)
```

Produces:

```
Piece 0: [commitment | shard_index | varint_length]  (~40 bytes, pool-allocated)
Piece 1: [------------ 1 MB shard payload ---------]  (Arc clone, no copy)
Piece 2: [chunk_index | proof]                        (~200 bytes, pool-allocated)
```
