//! Consensus types shared across the crate.

use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use std::fmt::Display;

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
