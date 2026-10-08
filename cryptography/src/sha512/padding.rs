//! SHA-512 parameters and message padding shared by the multi-message kernels.

use super::BLOCK_LENGTH;

/// SHA-512 round constants (FIPS 180-4, section 4.2.3).
#[rustfmt::skip]
pub(super) const K: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

/// SHA-512 initial hash value (FIPS 180-4, section 5.3.5).
#[rustfmt::skip]
pub(super) const IV: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

/// The number of blocks in the padded encoding of a `len`-byte message: the fewest that hold the
/// message, one `0x80` byte, and the 16-byte bit length.
pub(super) const fn block_count(len: usize) -> usize {
    (len + 16) / BLOCK_LENGTH + 1
}

/// Block `index` of the padded encoding of `message`.
///
/// Always inlined: an outlined call returns the block through memory, and the caller's wide
/// loads of it stall on store forwarding.
#[inline(always)]
pub(super) fn block(message: &[u8], index: usize) -> [u8; BLOCK_LENGTH] {
    // A block wholly inside the message is a plain copy.
    let start = index * BLOCK_LENGTH;
    let rest = message.get(start..).unwrap_or_default();
    if let Some(block) = rest.first_chunk() {
        return *block;
    }

    // Any other block starts with what remains of the message. The block holding the message's
    // end appends `0x80`, and the last block ends with the message length in bits. A tail too
    // long to leave room for the length pushes it into one more block.
    let mut bytes = [0u8; BLOCK_LENGTH];
    bytes[..rest.len()].copy_from_slice(rest);
    if start <= message.len() {
        bytes[rest.len()] = 0x80;
    }
    if index + 1 == block_count(message.len()) {
        let bits = message.len() as u128 * 8;
        bytes[BLOCK_LENGTH - 16..].copy_from_slice(&bits.to_be_bytes());
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha512::{CoreSha512, DIGEST_LENGTH};
    use sha2::{Digest as _, block_api::compress512};

    /// Compressing the padded blocks of a message one at a time from [`IV`] gives its SHA-512
    /// digest, for every length across the first three blocks' padding boundaries.
    #[test]
    fn test_blocks_pad_messages() {
        let data: Vec<u8> = (0..400).map(|i| (i * 7) as u8).collect();
        for len in 0..=data.len() {
            let message = &data[..len];
            let mut state = IV;
            for index in 0..block_count(len) {
                compress512(&mut state, &[block(message, index)]);
            }

            // The digest is the final state's words in big-endian order.
            let mut digest = [0u8; DIGEST_LENGTH];
            for (bytes, word) in digest.as_chunks_mut::<8>().0.iter_mut().zip(state) {
                *bytes = word.to_be_bytes();
            }
            assert_eq!(
                digest,
                <[u8; DIGEST_LENGTH]>::from(CoreSha512::digest(message))
            );
        }
    }
}
