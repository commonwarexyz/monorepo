//! P4: `Chunk::max_encode_size` bounds the encoded size of a chunk that decodes.
//!
//! # Documented contract (asserted in every build: this is the gate)
//!
//! `kani_chunk_max_encode_size`: for EVERY chunk of the shape below, if it decodes, its
//! encoded size is at most `Chunk::max_encode_size` of the widest shard the maximum allows and
//! of 32 sibling digests.
//!
//! 1. coding/src/reed_solomon.rs, `Chunk::max_encode_size`: "Returns an upper bound on the
//!    encoded size of a chunk whose shard holds at most `shard` bytes and whose proof holds at
//!    most `siblings` sibling digests."
//! 2. A decoded shard is no wider than the width the configuration allows.
//!    coding/src/reed_solomon.rs, `Read for Chunk`: "A chunk decodes only if its shard is no
//!    wider than encoding that many bytes under the config would produce."; `ReedSolomon`: "The
//!    canonical shard width is the payload length plus its four-byte prefix, divided by `k` and
//!    rounded up to an even number of bytes." The helper `reference_width` is the independent
//!    translation of that sentence; for one minimum shard and 4 data bytes it is 8.
//! 3. A chunk's proof has at most 32 sibling digests. coding/src/reed_solomon.rs, the field
//!    `Chunk::proof`: "The multi-proof of the shard in the [`bmt`] at the given index." (one
//!    shard, so one proven item); storage/src/bmt/mod.rs, `MAX_LEVELS`: "There should never be
//!    more than 32 sibling levels in a proof." and "which requires at most `u32::BITS` sibling
//!    hashes per proven item."
//!
//! # Implementation consistency (asserted only with `--features consistency`; not a gate)
//!
//! - the chunk decodes, and its encoded size is the input length (the docs of `Chunk` say
//!   neither).
//!
//! # Bounds
//!
//! One chunk shape: one minimum shard and a maximum of 4 data bytes (so the widest allowed
//! shard is 8 bytes), a shard of 8 bytes, and no sibling digest. Every content of
//! the shard, every index and every leaf count. Not covered (see `README.md`): other
//! shard lengths, other configurations and maxima, and sibling digests. A shard length, a
//! configuration or a sibling count left symbolic gave no answer within 3 to 10 minutes, or
//! a solver above 12 GB.

use crate::common::{MAXIMUM, Shard, chunk_bytes, consistency, decode, reference_width};
use commonware_codec::EncodeSize;

#[kani::proof]
#[kani::unwind(10)]
fn kani_chunk_max_encode_size() {
    let content: [u8; 8] = kani::any();
    let fields: [u8; 6] = kani::any();
    let bytes: [u8; 16] = chunk_bytes(&content, &fields);

    let result = decode(&bytes);
    consistency!(result.is_ok());
    if let Ok(chunk) = result {
        let bound = Shard::max_encode_size(reference_width(MAXIMUM, 1), u32::BITS as usize);
        assert!(chunk.encode_size() <= bound);
        consistency!(chunk.encode_size() == bytes.len());
        kani::cover!(fields[5] != 0, "a chunk with a nonzero leaf count decodes");
    }
}
