//! Helpers shared by the proofs.

use commonware_codec::{Copying, Decode};
use commonware_coding::{Config, ReedSolomon, Scheme};
use commonware_cryptography::Sha256;
use std::num::NonZeroU16;

/// The Reed-Solomon scheme of the proofs, with SHA-256 digests.
pub type Rs = ReedSolomon<Sha256>;

/// The shard type of that scheme (`Chunk<Digest>`): the public name of a chunk.
pub type Shard = <Rs as Scheme>::Shard;

/// The configuration of the chunk proofs: one minimum shard (and one extra shard, which does
/// not change decoding).
pub fn one_minimum_shard() -> Config {
    Config {
        minimum_shards: NonZeroU16::new(1).unwrap(),
        extra_shards: NonZeroU16::new(1).unwrap(),
    }
}

/// The decoding maximum of the chunk proofs, in data bytes.
pub const MAXIMUM: usize = 4;

/// The widest shard that encoding `maximum` data bytes under `minimum_shards` produces.
///
/// An independent translation of the documented formula, not a call of the crate's private
/// function. coding/src/reed_solomon.rs, `ReedSolomon`: "The canonical shard width is the
/// payload length plus its four-byte prefix, divided by `k` and rounded up to an even number of
/// bytes." Here `k` is `minimum_shards`.
pub const fn reference_width(maximum: usize, minimum_shards: usize) -> usize {
    let width = (maximum + 4).div_ceil(minimum_shards);
    if width % 2 == 1 { width + 1 } else { width }
}

/// The bytes of a chunk whose shard has `L` bytes of `content`, followed by the 2-byte index
/// and the 4-byte leaf count in `fields`, and a sibling count of 0: a one-byte shard length
/// (a varint below 0x80), the shard, the fields, and the one-byte count. `N` is `L + 8`.
pub fn chunk_bytes<const L: usize, const N: usize>(content: &[u8; L], fields: &[u8; 6]) -> [u8; N] {
    assert!(N == L + 8 && L < 0x80);
    let mut bytes = [0u8; N];
    bytes[0] = L as u8;
    bytes[1..1 + L].copy_from_slice(content);
    bytes[1 + L..7 + L].copy_from_slice(fields);
    bytes
}

/// Decodes `bytes` as a chunk under `one_minimum_shard()` and `MAXIMUM`.
pub fn decode(bytes: &[u8]) -> Result<Shard, commonware_codec::Error> {
    Shard::decode_cfg(Copying(bytes), &(one_minimum_shard(), MAXIMUM))
}

/// An implementation-consistency check: an assertion that is STRONGER than the documented
/// contract.
///
/// It is compiled into the proof only with `--features consistency`. The default build (the
/// contract gate) does not assert it, so a valid change of the implementation cannot fail the
/// gate through one of these.
macro_rules! consistency {
    ($($arg:tt)*) => {
        if cfg!(feature = "consistency") {
            assert!($($arg)*);
        }
    };
}
pub(crate) use consistency;

/// Returns `true` when `a` and `b` have the same length and hold the same bytes.
///
/// A plain loop, so that a proof does not depend on how the compiler lowers a slice
/// comparison. A harness that calls it needs an unwind bound above the slice length.
pub fn same_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}
