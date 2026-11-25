//! P6: a decoded `Chunk` encodes to the bytes it was decoded from.
//!
//! # Documented contract (asserted in every build: this is the gate)
//!
//! `kani_chunk_reencode`: for EVERY chunk of the shape below that decodes, encoding it gives
//! exactly the input bytes.
//!
//! 1. Decoding reads exactly the value's bytes and refuses leftovers. codec/src/codec.rs,
//!    `Read::read_cfg`: "Implementations should consume the exact number of bytes required from
//!    `buf` to reconstruct the value."; `Decode`: "Ensures that *all* bytes from the input
//!    buffer were consumed during decoding."
//! 2. The fields are read and written in the same order, and the decoded values are the ones
//!    stored. The documentation does not give this; the item rests on the code.
//!    coding/src/reed_solomon.rs, `Write for Chunk`: "self.shard.write(writer);
//!    self.index.write(writer); self.proof.write(writer);"; `Read for Chunk`: "let shard =
//!    Bytes::read_cfg(reader, &RangeCfg::new(..=width))?; let index = u16::read(reader)?; let
//!    proof = bmt::Proof::<D>::read_cfg(reader, &1)?; Ok(Self { shard, index, proof, })".
//!    storage/src/bmt/mod.rs, `Write for Proof`: "self.leaf_count.write(writer);
//!    self.siblings.write(writer);"; `Read for Proof`: "let leaf_count = u32::read(reader)?;
//!    let max_siblings = max_items.saturating_mul(MAX_LEVELS); let siblings =
//!    Vec::<D>::read_range(reader, ..=max_siblings)?; Ok(Self { leaf_count, siblings, })".
//! 3. The integers (the index and the leaf count) have one encoding each: their big-endian
//!    bytes. codec/src/types/primitives.rs, module docs: "All fixed-size integers and floats
//!    are written big-endian to avoid host- endian ambiguity."; a test of that file: "A valid
//!    read decodes big-endian values and consumes the exact bytes."
//! 4. The shard and the sibling list are a length prefix followed by their contents. This item
//!    rests on the code, plus the documentation of length prefixes:
//!    - The shard. codec/src/types/bytes.rs, `Write for Bytes`: "self.len().write(buf);
//!      buf.put_slice(self);"; `Read for Bytes`: "let len = usize::read_cfg(buf, range)?;
//!      buf.try_take_owned(len)".
//!    - The sibling list. codec/src/types/vec.rs, `Write for Vec<T>`: "self.as_slice().write(buf)";
//!      `Write for &[T]`: "self.len().write(buf); T::write_slice(self, buf);"; `Read for Vec<T>`:
//!      "let len = usize::read_cfg(buf, range)?; T::read_vec(buf, len, cfg)".
//!      codec/src/extensions.rs, `ReadRangeExt::read_range`: "Self::read_cfg(buf,
//!      &(RangeCfg::new(range), X::default()))". codec/src/codec.rs, `Write::write_slice`: "for
//!      item in values { item.write(buf); }"; `Read::read_vec`: "for _ in 0..len {
//!      values.push(Self::read_cfg(buf, cfg)?); }". In the shape below the list is empty: a
//!      length prefix of 0 and no digests.
//!    - The prefixes. codec/src/lib.rs, module docs: "128 bytes of data and a five-byte
//!      [`UInt<u32>`](varint::UInt) length prefix". A length prefix is a varint with one
//!      encoding per value; codec/src/varint.rs, a comment in `Decoder::feed`: "we ensure that
//!      every value has exactly one unique, valid encoding."
//!
//! # Implementation consistency (asserted only with `--features consistency`; not a gate)
//!
//! - the chunk decodes (the shard is within the allowed width; the docs say only that a wider
//!   one does not).
//!
//! # Bounds
//!
//! One chunk shape: one minimum shard and a maximum of 4 data bytes (so the widest allowed
//! shard is 8 bytes), a shard of 8 bytes, and no sibling digest. Every content of
//! the shard, every index and every leaf count. Loops unwound 18 times (the
//! byte comparison runs over 16 bytes). Not covered (see `README.md`): other
//! shard lengths, other configurations and maxima, and sibling digests. A shard length, a
//! configuration or a sibling count left symbolic gave no answer within 3 to 10 minutes, or
//! a solver above 12 GB.

use crate::common::{chunk_bytes, consistency, decode, same_bytes};
use commonware_codec::Encode;

#[kani::proof]
#[kani::unwind(18)]
fn kani_chunk_reencode() {
    let content: [u8; 8] = kani::any();
    let fields: [u8; 6] = kani::any();
    let bytes: [u8; 16] = chunk_bytes(&content, &fields);

    let result = decode(&bytes);
    consistency!(result.is_ok());
    if let Ok(chunk) = result {
        let encoded = chunk.encode();
        assert!(same_bytes(encoded.as_ref(), &bytes));
        kani::cover!(
            content[7] != content[0],
            "a chunk with distinct shard bytes"
        );
    }
}
