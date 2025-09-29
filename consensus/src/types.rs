//! Consensus types shared across the crate.

use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Error, FixedSize, Read, ReadExt, Write};
use commonware_coding::Config as CodingConfig;
use commonware_cryptography::Digest;
use commonware_utils::{Array, Span};
use rand_core::CryptoRngCore;
use std::{fmt::Display, ops::Deref};

/// Epoch is the type used to represent a distinct set of validators.
///
/// Represents a contiguous sequence of views in which the set of validators is constant.
/// When the set of participants changes, the epoch increments.
pub type Epoch = u64;

/// View is a monotonically increasing counter that represents the current slot of a single
/// consensus engine (i.e. within a single epoch).
pub type View = u64;

/// Round is a tuple of ([Epoch], [View]).
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Round(Epoch, View);

impl Round {
    pub fn new(epoch: Epoch, view: View) -> Self {
        Self(epoch, view)
    }

    pub fn epoch(&self) -> Epoch {
        self.0
    }

    pub fn view(&self) -> View {
        self.1
    }
}

impl From<(Epoch, View)> for Round {
    fn from((epoch, view): (Epoch, View)) -> Self {
        Self(epoch, view)
    }
}

impl From<Round> for (Epoch, View) {
    fn from(round: Round) -> Self {
        (round.epoch(), round.view())
    }
}

impl Read for Round {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self(Epoch::read(buf)?, View::read(buf)?))
    }
}

impl Write for Round {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch().write(buf);
        self.view().write(buf);
    }
}

impl EncodeSize for Round {
    fn encode_size(&self) -> usize {
        self.epoch().encode_size() + self.view().encode_size()
    }
}

impl Display for Round {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Round({}, {})", self.0, self.1)
    }
}

const CODING_COMMITMENT_SIZE: usize = 32 + CodingConfig::SIZE;

/// A [Digest] containing a coding commitment and encoded [CodingConfig].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CodingCommitment([u8; CODING_COMMITMENT_SIZE]);

impl CodingCommitment {
    /// Extracts the [CodingConfig] from this [CodingCommitment].
    pub fn config(&self) -> CodingConfig {
        let mut buf = &self.0[32..];
        CodingConfig::read(&mut buf).expect("CodingCommitment always contains a valid config")
    }

    /// Extracts a [Digest] from this [CodingCommitment].
    ///
    /// ## Panics
    ///
    /// Panics if the [Digest]'s [FixedSize::SIZE] is > 32 bytes.
    pub fn inner<D: Digest>(&self) -> D {
        const {
            if D::SIZE > 32 {
                panic!("Cannot extract Digest with size > 32 from CodingCommitment");
            }
        }

        D::read(&mut self.0[..D::SIZE].as_ref())
            .expect("CodingCommitment always contains a valid digest")
    }
}

impl Digest for CodingCommitment {
    fn random<R: CryptoRngCore>(rng: &mut R) -> Self {
        let mut buf = [0u8; CODING_COMMITMENT_SIZE];
        rng.fill_bytes(&mut buf);
        Self(buf)
    }
}

impl Write for CodingCommitment {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        buf.put_slice(&self.0);
    }
}

impl FixedSize for CodingCommitment {
    const SIZE: usize = CODING_COMMITMENT_SIZE;
}

impl Read for CodingCommitment {
    type Cfg = ();

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        _cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let mut arr = [0u8; CODING_COMMITMENT_SIZE];
        buf.copy_to_slice(&mut arr);
        Ok(CodingCommitment(arr))
    }
}

impl AsRef<[u8]> for CodingCommitment {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for CodingCommitment {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Display for CodingCommitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", commonware_utils::hex(self.as_ref()))
    }
}

impl std::fmt::Debug for CodingCommitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", commonware_utils::hex(self.as_ref()))
    }
}

impl Default for CodingCommitment {
    fn default() -> Self {
        Self([0u8; CODING_COMMITMENT_SIZE])
    }
}

impl<D: Digest> From<(D, CodingConfig)> for CodingCommitment {
    fn from((digest, config): (D, CodingConfig)) -> Self {
        const {
            if D::SIZE > 32 {
                panic!("Cannot create CodingCommitment from Digest with size > 32");
            }
        }

        let mut buf = [0u8; CODING_COMMITMENT_SIZE];
        buf[..D::SIZE].copy_from_slice(&digest);
        buf[32..].copy_from_slice(&config.encode());
        Self(buf)
    }
}

impl Span for CodingCommitment {}
impl Array for CodingCommitment {}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode, EncodeSize};

    #[test]
    fn test_round_cmp() {
        assert!(Round::from((1, 2)) < Round::from((1, 3)));
        assert!(Round::from((1, 2)) < Round::from((2, 1)));
    }

    #[test]
    fn test_round_encode_decode_roundtrip() {
        let r = Round::new(42, 1_000_000);
        let encoded = r.encode();
        assert_eq!(encoded.len(), r.encode_size());
        let decoded = Round::decode(encoded).unwrap();
        assert_eq!(r, decoded);
    }

    #[test]
    fn test_round_conversions() {
        let r: Round = (5u64, 6u64).into();
        assert_eq!(r.epoch(), 5);
        assert_eq!(r.view(), 6);
        let tuple: (Epoch, View) = r.into();
        assert_eq!(tuple, (5, 6));
    }
}
