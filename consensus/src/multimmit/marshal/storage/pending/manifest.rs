//! The durable manifest of pending custody.

use crate::types::Height;
use bytes::BufMut;
use commonware_codec::{Buf, EncodeSize, Error, RangeCfg, Read, ReadExt as _, Write};

/// Version byte leading every encoded [`PendingState`].
const STATE_VERSION: u8 = 1;

/// Segment geometry, live segments, and per-chain prune floors of pending custody.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub(super) struct PendingState {
    /// Positions in each segment. Fixed when the namespace is created.
    pub(super) segment_capacity: u64,
    /// Lowest retained height on each chain, in chain order.
    pub(super) floors: Vec<Height>,
    /// Live segment identifiers, strictly ascending.
    pub(super) segments: Vec<u64>,
}

/// Bounds used to decode a [`PendingState`].
#[derive(Clone, Copy)]
pub(super) struct PendingStateCfg {
    /// Number of producer chains.
    pub(super) chains: usize,
    /// Largest number of live segments.
    pub(super) max_segments: usize,
}

impl Read for PendingState {
    type Cfg = PendingStateCfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let version = u8::read(buf)?;
        if version != STATE_VERSION {
            return Err(Error::InvalidEnum(version));
        }
        Ok(Self {
            segment_capacity: u64::read(buf)?,
            floors: Vec::<Height>::read_cfg(buf, &(RangeCfg::exact(cfg.chains), ()))?,
            segments: Vec::<u64>::read_cfg(buf, &(RangeCfg::from(0..=cfg.max_segments), ()))?,
        })
    }
}

impl Write for PendingState {
    fn write(&self, buf: &mut impl BufMut) {
        STATE_VERSION.write(buf);
        self.segment_capacity.write(buf);
        self.floors.write(buf);
        self.segments.write(buf);
    }
}

impl EncodeSize for PendingState {
    fn encode_size(&self) -> usize {
        STATE_VERSION.encode_size()
            + self.segment_capacity.encode_size()
            + self.floors.encode_size()
            + self.segments.encode_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Decode as _, Encode as _};

    const CFG: PendingStateCfg = PendingStateCfg {
        chains: 2,
        max_segments: 4,
    };

    fn state() -> PendingState {
        PendingState {
            segment_capacity: 1024,
            floors: vec![Height::new(3), Height::zero()],
            segments: vec![1, 4],
        }
    }

    #[test]
    fn manifest_is_versioned_and_bounded() {
        let encoded = state().encode();
        assert_eq!(encoded.len(), state().encode_size());
        assert_eq!(
            PendingState::decode_cfg(encoded.clone(), &CFG).unwrap(),
            state()
        );

        let mut wrong_version = encoded.to_vec();
        wrong_version[0] = STATE_VERSION.wrapping_add(1);
        assert!(matches!(
            PendingState::decode_cfg(wrong_version, &CFG),
            Err(Error::InvalidEnum(_))
        ));

        let too_many = PendingState {
            segments: (0..5).collect(),
            ..state()
        };
        assert!(PendingState::decode_cfg(too_many.encode(), &CFG).is_err());
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::generate_value;
        use commonware_conformance::Conformance;

        struct PendingStateConformance;

        impl Conformance for PendingStateConformance {
            async fn commit(seed: u64) -> Vec<u8> {
                let state = generate_value::<PendingState>(seed);
                let cfg = PendingStateCfg {
                    chains: state.floors.len(),
                    max_segments: state.segments.len(),
                };
                let encoded = state.encode();
                assert_eq!(
                    PendingState::decode_cfg(encoded.clone(), &cfg).unwrap(),
                    state
                );
                encoded.to_vec()
            }
        }

        commonware_conformance::conformance_tests! {
            PendingStateConformance => 128,
        }
    }
}
