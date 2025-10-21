//! Utilities for simplex signing schemes.

use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, Write};
use commonware_utils::bitmap::BitMap;

/// Bitmap wrapper that tracks which validators signed a certificate.
///
/// Internally it stores bits in 1-byte chunks for compact encoding.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SignersBitMap {
    bitmap: BitMap<1>,
}

impl SignersBitMap {
    /// Builds a bitmap from an iterator of signer indices.
    ///
    /// The caller must provide indices in strictly increasing order with no duplicates.
    /// Returns `None` if the sequence violates that contract or contains indices outside
    /// the participant set.
    pub fn from_signers(
        participants: usize,
        signers: impl IntoIterator<Item = u32>,
    ) -> Option<Self> {
        let mut bitmap = BitMap::zeroes(participants as u64);
        let mut last = None;

        for signer in signers.into_iter() {
            if signer as usize >= participants {
                return None;
            }
            if let Some(last) = last {
                if signer <= last {
                    return None;
                }
            }
            last = Some(signer);
            bitmap.set(signer as u64, true);
        }

        Some(SignersBitMap { bitmap })
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

impl Write for SignersBitMap {
    fn write(&self, writer: &mut impl BufMut) {
        self.bitmap.write(writer);
    }
}

impl EncodeSize for SignersBitMap {
    fn encode_size(&self) -> usize {
        self.bitmap.encode_size()
    }
}

impl Read for SignersBitMap {
    type Cfg = usize;

    fn read_cfg(reader: &mut impl Buf, participants: &usize) -> Result<Self, Error> {
        let bitmap = BitMap::read_cfg(reader, &(*participants as u64))?;
        Ok(SignersBitMap { bitmap })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Decode, Encode};

    #[test]
    fn test_from_signers() {
        let signers = SignersBitMap::from_signers(6, [0, 3, 5]).unwrap();
        let collected: Vec<_> = signers.iter().collect();
        assert_eq!(collected, vec![0, 3, 5]);
        assert_eq!(signers.count(), 3);
    }

    #[test]
    fn test_from_signers_validation() {
        // Out of bounds
        assert!(SignersBitMap::from_signers(4, [0, 4]).is_none());
        // Not strictly increasing
        assert!(SignersBitMap::from_signers(4, [0, 0, 1]).is_none());
        assert!(SignersBitMap::from_signers(4, [2, 1]).is_none());
    }

    #[test]
    fn test_codec_round_trip() {
        let signers = SignersBitMap::from_signers(9, [1, 6]).unwrap();
        let encoded = signers.encode();
        let decoded = SignersBitMap::decode_cfg(encoded, &9).unwrap();
        assert_eq!(decoded, signers);
    }

    #[test]
    fn test_decode_respects_participant_limit() {
        let signers = SignersBitMap::from_signers(8, [0, 3, 7]).unwrap();
        let encoded = signers.encode();
        // Fewer participants than highest signer should fail.
        assert!(SignersBitMap::decode_cfg(encoded.clone(), &2).is_err());
        // Exact participant bound succeeds.
        assert!(SignersBitMap::decode_cfg(encoded.clone(), &8).is_ok());
        // As well as higher participant bound.
        assert!(SignersBitMap::decode_cfg(encoded, &10).is_ok());
    }
}
