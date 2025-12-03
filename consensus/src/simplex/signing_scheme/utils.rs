//! Utilities for simplex signing schemes.

use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, Write};
use commonware_utils::bitmap::BitMap;

/// Bitmap wrapper that tracks which validators signed a certificate.
///
/// Internally, it stores bits in 1-byte chunks for compact encoding.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Signers {
    bitmap: BitMap<1>,
}

impl Signers {
    /// Builds [`Signers`] from an iterator of signer indices.
    ///
    /// # Panics
    ///
    /// Panics if the sequence contains indices larger than the size of the participant set
    /// or duplicates.
    pub fn from(participants: usize, signers: impl IntoIterator<Item = u32>) -> Self {
        let mut bitmap = BitMap::zeroes(participants as u64);
        for signer in signers.into_iter() {
            assert!(
                !bitmap.get(signer as u64),
                "duplicate signer index: {signer}",
            );
            // We opt to not assert order here because some signing schemes allow
            // for commutative aggregation of signatures (and sorting is unnecessary
            // overhead).

            bitmap.set(signer as u64, true);
        }

        Self { bitmap }
    }

    /// Returns the length of the bitmap (the size of the participant set).
    #[allow(clippy::len_without_is_empty)]
    pub const fn len(&self) -> usize {
        self.bitmap.len() as usize
    }

    /// Returns how many validators are marked as signers.
    pub fn count(&self) -> usize {
        self.bitmap.count_ones() as usize
    }

    /// Iterates over signer indices in ascending order.
    pub fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        self.bitmap
            .iter()
            .enumerate()
            .filter_map(|(index, bit)| bit.then_some(index as u32))
    }
}

impl Write for Signers {
    fn write(&self, writer: &mut impl BufMut) {
        self.bitmap.write(writer);
    }
}

impl EncodeSize for Signers {
    fn encode_size(&self) -> usize {
        self.bitmap.encode_size()
    }
}

impl Read for Signers {
    type Cfg = usize;

    fn read_cfg(reader: &mut impl Buf, max_participants: &usize) -> Result<Self, Error> {
        let bitmap = BitMap::read_cfg(reader, &(*max_participants as u64))?;
        // The participant count is treated as an upper bound for decoding flexibility, e.g. one
        // might use `Scheme::certificate_codec_config_unbounded` for decoding certificates from
        // local storage.
        //
        // Exact length validation **must** be enforced at verification time by the signing schemes
        // against the actual participant set size.
        Ok(Self { bitmap })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Decode, Encode};

    #[test]
    fn test_from_signers() {
        let signers = Signers::from(6, [0, 3, 5]);
        let collected: Vec<_> = signers.iter().collect();
        assert_eq!(collected, vec![0, 3, 5]);
        assert_eq!(signers.count(), 3);
    }

    #[test]
    #[should_panic(expected = "bit 4 out of bounds (len: 4)")]
    fn test_from_out_of_bounds() {
        Signers::from(4, [0, 4]);
    }

    #[test]
    #[should_panic(expected = "duplicate signer index: 0")]
    fn test_from_duplicate() {
        Signers::from(4, [0, 0, 1]);
    }

    #[test]
    fn test_from_not_increasing() {
        Signers::from(4, [2, 1]);
    }

    #[test]
    fn test_codec_round_trip() {
        let signers = Signers::from(9, [1, 6]);
        let encoded = signers.encode();
        let decoded = Signers::decode_cfg(encoded, &9).unwrap();
        assert_eq!(decoded, signers);
    }

    #[test]
    fn test_decode_respects_participant_limit() {
        let signers = Signers::from(8, [0, 3, 7]);
        let encoded = signers.encode();
        // More participants than expected should fail.
        assert!(Signers::decode_cfg(encoded.clone(), &2).is_err());
        // Exact participant bound succeeds.
        assert!(Signers::decode_cfg(encoded.clone(), &8).is_ok());
        // Less participants than expected succeeds (upper bound).
        assert!(Signers::decode_cfg(encoded, &10).is_ok());
    }
}
