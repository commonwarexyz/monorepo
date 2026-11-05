//! Meta: marshal's one durable record of progress.
//!
//! It holds the acknowledged cut, the floor marshal last installed or pruned to, the commitment
//! local ordinals count from, and every chain's block retention floor. It is written whole, at
//! most once at a time: after each drained group of acknowledgements, at floor installs, and at
//! prunes, always before anything those writes make obsolete is deleted.

use super::{Error, record::DurableRecord};
use crate::{
    multimmit::{
        order::Cut,
        types::{BlockRef, CertificateId},
    },
    types::{Epoch, Height},
};
use bytes::BufMut;
use commonware_codec::{Buf, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt as _, Write};
use commonware_cryptography::Digest;
use commonware_storage::Context;

/// Version byte leading every encoded [`State`].
const VERSION: u8 = 1;

/// A cut marshal acknowledged: the newest incorporated record with its tips, and the exact last
/// emitted block of every chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Ack<D: Digest> {
    /// Commitment of the newest incorporated record.
    pub(crate) history: D,
    /// That record's tips, in chain order.
    pub(crate) ordered: Vec<BlockRef<D>>,
    /// The last emitted block of every chain, in chain order.
    pub(crate) emitted: Vec<BlockRef<D>>,
}

impl<D: Digest> Ack<D> {
    /// Returns the output index of the last acknowledged output (zero before any).
    pub(crate) fn index(&self) -> u64 {
        self.emitted.iter().map(|block| block.height().get()).sum()
    }

    /// Returns the symbolic cut, or `None` when the vectors are malformed.
    pub(crate) fn cut(&self) -> Option<Cut<D>> {
        Cut::new(
            self.history,
            self.ordered.clone().into(),
            self.emitted.iter().map(BlockRef::height).collect(),
        )
        .ok()
    }
}

/// The durable progress record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct State<D: Digest> {
    /// The epoch of the stream.
    pub(crate) epoch: Epoch,
    /// The acknowledged cut.
    pub(crate) ack: Ack<D>,
    /// The floor last installed or pruned to, if any.
    pub(crate) floor: Option<CertificateId<D>>,
    /// The commitment local ordinals count from.
    pub(crate) base: D,
    /// The lowest retained block height of every chain.
    pub(crate) retained: Vec<Height>,
}

impl<D: Digest> Write for State<D> {
    fn write(&self, buf: &mut impl BufMut) {
        VERSION.write(buf);
        self.epoch.write(buf);
        self.ack.history.write(buf);
        self.ack.ordered.write(buf);
        self.ack.emitted.write(buf);
        self.floor.write(buf);
        self.base.write(buf);
        self.retained.write(buf);
    }
}

impl<D: Digest> EncodeSize for State<D> {
    fn encode_size(&self) -> usize {
        VERSION.encode_size()
            + self.epoch.encode_size()
            + self.ack.history.encode_size()
            + self.ack.ordered.encode_size()
            + self.ack.emitted.encode_size()
            + self.floor.encode_size()
            + self.base.encode_size()
            + self.retained.encode_size()
    }
}

impl<D: Digest> Read for State<D> {
    /// The number of chains.
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, chains: &usize) -> Result<Self, CodecError> {
        let version = u8::read(buf)?;
        if version != VERSION {
            return Err(CodecError::InvalidEnum(version));
        }
        let chains = RangeCfg::exact(*chains);
        let epoch = Epoch::read(buf)?;
        let history = D::read(buf)?;
        let ordered = Vec::<BlockRef<D>>::read_cfg(buf, &(chains, ()))?;
        let emitted = Vec::<BlockRef<D>>::read_cfg(buf, &(chains, ()))?;
        let floor = Option::<CertificateId<D>>::read(buf)?;
        let base = D::read(buf)?;
        let retained = Vec::<Height>::read_cfg(buf, &(chains, ()))?;
        let state = Self {
            epoch,
            ack: Ack {
                history,
                ordered,
                emitted,
            },
            floor,
            base,
            retained,
        };
        if state.ack.cut().is_none()
            || state
                .ack
                .emitted
                .iter()
                .enumerate()
                .any(|(chain, block)| block.chain().get() as usize != chain)
        {
            return Err(CodecError::Invalid(
                "consensus::multimmit::marshal::State",
                "acknowledged cut is malformed",
            ));
        }
        Ok(state)
    }
}

/// A write of the progress record.
pub(crate) struct WriteJob<E: Context, D: Digest> {
    record: DurableRecord<E, State<D>>,
    state: State<D>,
}

/// A completed write, to hand back through [`Meta::finish`].
pub(crate) struct Written<E: Context, D: Digest> {
    record: DurableRecord<E, State<D>>,
    state: State<D>,
}

impl<E: Context, D: Digest> WriteJob<E, D> {
    /// Writes the record durably.
    pub(crate) async fn run(mut self) -> Result<Written<E, D>, Error> {
        self.record.put_sync(self.state.clone()).await?;
        Ok(Written {
            record: self.record,
            state: self.state,
        })
    }
}

/// The durable progress record and the value last made durable.
pub(crate) struct Meta<E: Context, D: Digest> {
    /// Absent while a write holds it.
    record: Option<DurableRecord<E, State<D>>>,
    durable: State<D>,
}

impl<E: Context, D: Digest> Meta<E, D> {
    /// Opens the record in `partition`, storing `initial` when none exists.
    pub(crate) async fn open(
        context: E,
        partition: String,
        chains: usize,
        initial: State<D>,
    ) -> Result<Self, Error> {
        let mut record = DurableRecord::init(context, partition, chains, None).await?;
        let durable = match record.get()?.cloned() {
            Some(state) => state,
            None => {
                record.put_sync(initial.clone()).await?;
                initial
            }
        };
        Ok(Self {
            record: Some(record),
            durable,
        })
    }

    /// Returns the value last made durable.
    pub(crate) const fn durable(&self) -> &State<D> {
        &self.durable
    }

    /// Starts writing `state`, or returns `None` while another write runs.
    pub(crate) fn start(&mut self, state: State<D>) -> Option<WriteJob<E, D>> {
        Some(WriteJob {
            record: self.record.take()?,
            state,
        })
    }

    /// Takes back a completed write.
    pub(crate) fn finish(&mut self, written: Written<E, D>) {
        self.record = Some(written.record);
        self.durable = written.state;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multimmit::types::ChainId;
    use commonware_codec::{Decode as _, Encode as _};
    use commonware_cryptography::{Hasher as _, Sha256};
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};

    fn state(height: u64) -> State<commonware_cryptography::sha256::Digest> {
        let block = |chain: u32, height: u64| {
            BlockRef::new(
                ChainId::new(chain),
                Height::new(height),
                Sha256::hash(&[&height.to_be_bytes()]),
            )
        };
        State {
            epoch: Epoch::new(3),
            ack: Ack {
                history: Sha256::hash(&[b"history"]),
                ordered: vec![block(0, 1), block(1, 1)],
                emitted: vec![block(0, height), block(1, 1)],
            },
            floor: Some(CertificateId::new(Sha256::hash(&[b"floor"]))),
            base: Sha256::hash(&[b"base"]),
            retained: vec![Height::new(1), Height::zero()],
        }
    }

    #[test]
    fn state_round_trips_and_rejects_malformed_cuts() {
        let encoded = state(4).encode();
        let decoded = State::decode_cfg(encoded.clone(), &2).unwrap();
        assert_eq!(decoded, state(4));
        assert_eq!(decoded.ack.index(), 5);
        assert!(State::<commonware_cryptography::sha256::Digest>::decode_cfg(encoded, &3).is_err());
        let mut swapped = state(4);
        swapped.ack.emitted.swap(0, 1);
        assert!(
            State::<commonware_cryptography::sha256::Digest>::decode_cfg(swapped.encode(), &2)
                .is_err()
        );
    }

    #[test]
    fn writes_replace_the_durable_state() {
        deterministic::Runner::default().start(|context| async move {
            let mut meta = Meta::open(context.child("first"), "meta".into(), 2, state(1))
                .await
                .unwrap();
            assert_eq!(meta.durable(), &state(1));
            let job = meta.start(state(2)).unwrap();
            assert!(meta.start(state(3)).is_none());
            meta.finish(job.run().await.unwrap());
            assert_eq!(meta.durable(), &state(2));
            drop(meta);
            // The initial state applies only to a fresh record.
            let meta = Meta::open(context.child("second"), "meta".into(), 2, state(9))
                .await
                .unwrap();
            assert_eq!(meta.durable(), &state(2));
        });
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use crate::multimmit::types::arbitrary_codec_config;
        use arbitrary::{Arbitrary, Unstructured};
        use commonware_codec::conformance::generate_value;
        use commonware_conformance::Conformance;
        use commonware_cryptography::sha256::Digest as Sha256Digest;

        impl<'a> Arbitrary<'a> for State<Sha256Digest> {
            fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
                let chains = arbitrary_codec_config().chains();
                let mut ordered = Vec::with_capacity(chains);
                let mut emitted = Vec::with_capacity(chains);
                let mut retained = Vec::with_capacity(chains);
                for chain in 0..chains {
                    let id = ChainId::new(chain as u32);
                    // Heights stay small enough that the cut's index fits the output index.
                    let tip = u64::from(u.arbitrary::<u32>()?);
                    let done = u.int_in_range(0..=tip)?;
                    ordered.push(BlockRef::new(id, Height::new(tip), u.arbitrary()?));
                    emitted.push(BlockRef::new(id, Height::new(done), u.arbitrary()?));
                    retained.push(Height::new(u.int_in_range(0..=done)?));
                }
                Ok(Self {
                    epoch: u.arbitrary()?,
                    ack: Ack {
                        history: u.arbitrary()?,
                        ordered,
                        emitted,
                    },
                    floor: u.arbitrary()?,
                    base: u.arbitrary()?,
                    retained,
                })
            }
        }

        struct StateConformance;

        impl Conformance for StateConformance {
            async fn commit(seed: u64) -> Vec<u8> {
                let state = generate_value::<State<Sha256Digest>>(seed);
                let encoded = state.encode();
                assert_eq!(
                    State::decode_cfg(encoded.clone(), &state.retained.len()).unwrap(),
                    state
                );
                encoded.to_vec()
            }
        }

        commonware_conformance::conformance_tests! {
            StateConformance => 128,
        }
    }
}
