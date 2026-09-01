//! The durable delivery cursor.

use crate::multimmit::marshal::{
    storage::{
        Error,
        record::{DurableRecord, OnMissing},
    },
    types::OutputIndex,
};
use commonware_codec::{Buf, EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_runtime::Handle;
use commonware_storage::Context;

/// Version byte leading every encoded [`CursorState`].
const STATE_VERSION: u8 = 1;

/// One canonical durable delivery cursor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CursorState {
    floor_generation: u64,
    acknowledged: Option<OutputIndex>,
}

/// The catalog's durable recovery cut that the cursor must not exceed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CatalogCut {
    /// Floor generation of the recovered catalog checkpoint.
    pub(crate) generation: u64,
    /// Committed output of the recovered catalog checkpoint.
    pub(crate) committed: Option<OutputIndex>,
}

/// Exclusive durable cursor state owned by the delivery actor.
pub(crate) struct DeliveryCursor<E: Context> {
    record: DurableRecord<E, CursorState>,
    state: CursorState,
}

impl<E: Context> DeliveryCursor<E> {
    /// Opens the delivery cursor against the catalog's durable recovery cut.
    ///
    /// A missing cursor is valid only at a catalog cut that cannot skip application output. A
    /// catalog generation ahead of the cursor identifies the crash cut after floor publication
    /// and before delivery reset; open makes that reset durable before returning.
    pub(crate) async fn init(
        context: E,
        partition: String,
        on_missing: OnMissing,
        cut: CatalogCut,
    ) -> Result<Self, Error> {
        let record = DurableRecord::init(context, partition, (), None).await?;
        let recovered = record.get()?.copied();
        if recovered.is_none() && on_missing == OnMissing::Reject {
            return Err(Error::Inconsistent("delivery cursor metadata is missing"));
        }

        let catalog = CursorState {
            floor_generation: cut.generation,
            acknowledged: cut.committed,
        };
        let state = recovered.unwrap_or(catalog);
        if state.floor_generation > cut.generation {
            return Err(Error::Inconsistent(
                "delivery generation exceeds catalog generation",
            ));
        }
        if state.floor_generation == cut.generation && state.acknowledged > cut.committed {
            return Err(Error::Inconsistent(
                "delivery acknowledgement exceeds catalog commit",
            ));
        }

        let mut store = Self { record, state };
        if recovered.is_none() || state.floor_generation < cut.generation {
            store.sync_state(catalog).await?;
        }
        Ok(store)
    }

    /// Returns the generation that owns the durable cursor.
    pub(crate) const fn floor_generation(&self) -> u64 {
        self.state.floor_generation
    }

    /// Returns the highest acknowledged output.
    ///
    /// The cursor advances when [`Self::start_acknowledgement`] starts its sync, so it may name an
    /// output whose acknowledgement is not yet durable.
    pub(crate) const fn acknowledged(&self) -> Option<OutputIndex> {
        self.state.acknowledged
    }

    /// Begins durability for a strictly advancing acknowledgement in the current generation.
    pub(crate) async fn start_acknowledgement(
        &mut self,
        floor_generation: u64,
        acknowledged: OutputIndex,
    ) -> Result<Handle<()>, Error> {
        if floor_generation != self.state.floor_generation {
            return Err(Error::Invalid(
                "acknowledgement generation does not match delivery generation",
            ));
        }
        if Some(acknowledged) <= self.state.acknowledged {
            return Err(Error::Invalid("delivery acknowledgement does not advance"));
        }
        let state = CursorState {
            floor_generation,
            acknowledged: Some(acknowledged),
        };
        let sync = self.record.put_start_sync(state).await?;
        self.state = state;
        Ok(sync)
    }

    /// Durably replaces the cursor for a newer installed generation.
    pub(crate) async fn reset(
        &mut self,
        floor_generation: u64,
        acknowledged: Option<OutputIndex>,
    ) -> Result<(), Error> {
        if floor_generation <= self.state.floor_generation {
            return Err(Error::Invalid("delivery reset does not advance generation"));
        }
        self.sync_state(CursorState {
            floor_generation,
            acknowledged,
        })
        .await
    }

    async fn sync_state(&mut self, state: CursorState) -> Result<(), Error> {
        self.record.put_sync(state).await?;
        self.state = state;
        Ok(())
    }
}

impl Read for CursorState {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let version = u8::read(buf)?;
        if version != STATE_VERSION {
            return Err(CodecError::InvalidEnum(version));
        }
        Ok(Self {
            floor_generation: u64::read(buf)?,
            acknowledged: Option::<OutputIndex>::read(buf)?,
        })
    }
}

impl Write for CursorState {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        STATE_VERSION.write(buf);
        self.floor_generation.write(buf);
        self.acknowledged.write(buf);
    }
}

impl EncodeSize for CursorState {
    fn encode_size(&self) -> usize {
        STATE_VERSION.encode_size()
            + self.floor_generation.encode_size()
            + self.acknowledged.encode_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt as _, Encode};
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};

    const fn cut(generation: u64, committed: Option<OutputIndex>) -> CatalogCut {
        CatalogCut {
            generation,
            committed,
        }
    }

    #[test]
    fn state_codec_is_versioned_and_canonical() {
        let state = CursorState {
            floor_generation: 7,
            acknowledged: Some(OutputIndex::new(11)),
        };
        let encoded = state.encode();
        assert_eq!(encoded.len(), state.encode_size());
        assert_eq!(CursorState::decode(encoded.clone()).unwrap(), state);

        let mut malformed = encoded.to_vec();
        malformed[0] = STATE_VERSION.wrapping_add(1);
        assert!(matches!(
            CursorState::decode(malformed),
            Err(CodecError::InvalidEnum(version))
                if version == STATE_VERSION.wrapping_add(1)
        ));
    }

    #[test]
    fn missing_metadata_requires_an_initialization_cut() {
        deterministic::Runner::default().start(|context| async move {
            let present = "delivery_present".to_string();
            let store = DeliveryCursor::init(
                context.child("create"),
                present.clone(),
                OnMissing::Initialize,
                cut(0, None),
            )
            .await
            .unwrap();
            drop(store);

            DeliveryCursor::init(
                context.child("present"),
                present,
                OnMissing::Reject,
                cut(0, None),
            )
            .await
            .unwrap();
            assert!(matches!(
                DeliveryCursor::init(
                    context.child("missing"),
                    "delivery_missing".to_string(),
                    OnMissing::Reject,
                    cut(0, None),
                )
                .await,
                Err(Error::Inconsistent(_))
            ));
        });
    }

    #[test]
    fn acknowledgement_recovers_and_invalid_catalog_cuts_are_rejected() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "delivery_recovery".to_string();
            let mut store = DeliveryCursor::init(
                context.child("create"),
                partition.clone(),
                OnMissing::Initialize,
                cut(3, None),
            )
            .await
            .unwrap();
            let sync = store
                .start_acknowledgement(3, OutputIndex::new(5))
                .await
                .unwrap();
            sync.await.unwrap();
            drop(store);

            let store = DeliveryCursor::init(
                context.child("reopen"),
                partition.clone(),
                OnMissing::Reject,
                cut(3, Some(OutputIndex::new(8))),
            )
            .await
            .unwrap();
            assert_eq!(store.floor_generation(), 3);
            assert_eq!(store.acknowledged(), Some(OutputIndex::new(5)));
            drop(store);

            assert!(matches!(
                DeliveryCursor::init(
                    context.child("generation_ahead"),
                    partition.clone(),
                    OnMissing::Reject,
                    cut(2, Some(OutputIndex::new(8))),
                )
                .await,
                Err(Error::Inconsistent(_))
            ));
            assert!(matches!(
                DeliveryCursor::init(
                    context.child("acknowledgement_ahead"),
                    partition,
                    OnMissing::Reject,
                    cut(3, Some(OutputIndex::new(4))),
                )
                .await,
                Err(Error::Inconsistent(_))
            ));
        });
    }

    #[test]
    fn catalog_generation_ahead_is_durably_reconciled() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "delivery_reconciliation".to_string();
            let store = DeliveryCursor::init(
                context.child("create"),
                partition.clone(),
                OnMissing::Initialize,
                cut(4, Some(OutputIndex::new(6))),
            )
            .await
            .unwrap();
            drop(store);

            let store = DeliveryCursor::init(
                context.child("advance"),
                partition.clone(),
                OnMissing::Reject,
                cut(7, Some(OutputIndex::new(19))),
            )
            .await
            .unwrap();
            assert_eq!(store.floor_generation(), 7);
            assert_eq!(store.acknowledged(), Some(OutputIndex::new(19)));
            drop(store);

            let store = DeliveryCursor::init(
                context.child("reopen"),
                partition,
                OnMissing::Reject,
                cut(7, Some(OutputIndex::new(19))),
            )
            .await
            .unwrap();
            assert_eq!(store.floor_generation(), 7);
            assert_eq!(store.acknowledged(), Some(OutputIndex::new(19)));
        });
    }

    #[test]
    fn mutations_require_monotone_generations_and_acknowledgements() {
        deterministic::Runner::default().start(|context| async move {
            let mut store = DeliveryCursor::init(
                context.child("store"),
                "delivery_monotone".to_string(),
                OnMissing::Initialize,
                cut(2, None),
            )
            .await
            .unwrap();
            store
                .start_acknowledgement(2, OutputIndex::new(3))
                .await
                .unwrap()
                .await
                .unwrap();

            assert!(matches!(
                store.start_acknowledgement(1, OutputIndex::new(4)).await,
                Err(Error::Invalid(_))
            ));
            assert!(matches!(
                store.start_acknowledgement(2, OutputIndex::new(3)).await,
                Err(Error::Invalid(_))
            ));
            assert!(matches!(store.reset(2, None).await, Err(Error::Invalid(_))));

            store.reset(5, Some(OutputIndex::new(17))).await.unwrap();
            assert_eq!(store.floor_generation(), 5);
            assert_eq!(store.acknowledged(), Some(OutputIndex::new(17)));
        });
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_conformance::Conformance;

        struct StateConformance;

        impl Conformance for StateConformance {
            async fn commit(seed: u64) -> Vec<u8> {
                let state = CursorState {
                    floor_generation: seed,
                    acknowledged: seed
                        .is_multiple_of(2)
                        .then_some(OutputIndex::new(seed.rotate_left(17))),
                };
                let encoded = state.encode();
                assert_eq!(CursorState::decode(encoded.clone()).unwrap(), state);
                encoded.to_vec()
            }
        }

        commonware_conformance::conformance_tests! {
            StateConformance => 128,
        }
    }
}
