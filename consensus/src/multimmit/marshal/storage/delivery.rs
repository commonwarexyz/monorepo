//! Durable application-delivery progress owned by the delivery actor.

use crate::multimmit::marshal::types::OutputIndex;
use commonware_codec::{
    EncodeSize, Error as CodecError, FixedSize as _, Read, ReadExt as _, Write,
};
use commonware_cryptography::crc32;
use commonware_runtime::Handle;
use commonware_storage::{
    Context,
    metadata::{self, Metadata},
};
use commonware_utils::sequence::Unit;
use std::num::NonZeroUsize;

const STATE_VERSION: u8 = 1;

/// One canonical durable delivery cursor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct State {
    generation: u64,
    acknowledged: Option<OutputIndex>,
}

impl Read for State {
    type Cfg = ();

    fn read_cfg(buf: &mut impl commonware_codec::Buf, _: &()) -> Result<Self, CodecError> {
        let version = u8::read(buf)?;
        if version != STATE_VERSION {
            return Err(CodecError::InvalidEnum(version));
        }
        Ok(Self {
            generation: u64::read(buf)?,
            acknowledged: Option::<OutputIndex>::read(buf)?,
        })
    }
}

impl Write for State {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        STATE_VERSION.write(buf);
        self.generation.write(buf);
        self.acknowledged.write(buf);
    }
}

impl EncodeSize for State {
    fn encode_size(&self) -> usize {
        STATE_VERSION.encode_size()
            + self.generation.encode_size()
            + self.acknowledged.encode_size()
    }
}

fn max_metadata_blob_size() -> NonZeroUsize {
    let largest = State {
        generation: u64::MAX,
        acknowledged: Some(OutputIndex::new(u64::MAX)),
    };
    let size = u64::SIZE
        .checked_add(Unit::SIZE)
        .and_then(|size| size.checked_add(largest.encode_size()))
        .and_then(|size| size.checked_add(crc32::Digest::SIZE))
        .expect("fixed delivery metadata size fits usize");
    NonZeroUsize::new(size).expect("delivery metadata is non-empty")
}

/// Delivery-cursor storage failed or contradicted the catalog's durable cut.
#[derive(Debug, thiserror::Error)]
pub(in crate::multimmit::marshal) enum Error {
    #[error("invalid delivery cursor state: {0}")]
    Invalid(&'static str),
    #[error("delivery cursor storage failed: {0}")]
    Storage(#[from] metadata::Error),
}

/// Exclusive durable cursor state owned by the delivery actor.
pub(in crate::multimmit::marshal) struct Store<E: Context> {
    metadata: Option<Metadata<E, Unit, State>>,
    state: State,
}

impl<E: Context> Store<E> {
    /// Opens the delivery cursor against the catalog's durable recovery cut.
    ///
    /// A missing cursor is valid only at a catalog cut that cannot skip application output. A
    /// catalog generation ahead of the cursor identifies the crash cut after floor publication
    /// and before delivery reset; open makes that reset durable before returning.
    pub(in crate::multimmit::marshal) async fn init(
        context: E,
        partition: String,
        allow_initialize: bool,
        catalog_generation: u64,
        catalog_committed: Option<OutputIndex>,
    ) -> Result<Self, Error> {
        let metadata = Metadata::init_bounded(
            context,
            metadata::Config {
                partition,
                codec_config: (),
            },
            max_metadata_blob_size(),
        )
        .await?;
        let recovered = metadata.get(&Unit).copied();
        if recovered.is_none() && !allow_initialize {
            return Err(Error::Invalid("delivery cursor metadata is missing"));
        }

        let catalog = State {
            generation: catalog_generation,
            acknowledged: catalog_committed,
        };
        let state = recovered.unwrap_or(catalog);
        if state.generation > catalog_generation {
            return Err(Error::Invalid(
                "delivery generation exceeds catalog generation",
            ));
        }
        if state.generation == catalog_generation && state.acknowledged > catalog_committed {
            return Err(Error::Invalid(
                "delivery acknowledgement exceeds catalog commit",
            ));
        }

        let mut store = Self {
            metadata: Some(metadata),
            state,
        };
        if recovered.is_none() || state.generation < catalog_generation {
            store.sync_state(catalog).await?;
        }
        Ok(store)
    }

    /// Returns the generation that owns the durable cursor.
    pub(in crate::multimmit::marshal) const fn generation(&self) -> u64 {
        self.state.generation
    }

    /// Returns the highest durably acknowledged output.
    pub(in crate::multimmit::marshal) const fn acknowledged(&self) -> Option<OutputIndex> {
        self.state.acknowledged
    }

    /// Begins durability for a strictly advancing acknowledgement in the current generation.
    pub(in crate::multimmit::marshal) async fn start_acknowledgement(
        &mut self,
        generation: u64,
        acknowledged: OutputIndex,
    ) -> Result<Handle<()>, Error> {
        if generation != self.state.generation {
            return Err(Error::Invalid(
                "acknowledgement generation does not match delivery generation",
            ));
        }
        if Some(acknowledged) <= self.state.acknowledged {
            return Err(Error::Invalid("delivery acknowledgement does not advance"));
        }
        self.start_sync_state(State {
            generation,
            acknowledged: Some(acknowledged),
        })
        .await
    }

    /// Durably replaces the cursor for a newer installed generation.
    pub(in crate::multimmit::marshal) async fn reset(
        &mut self,
        generation: u64,
        acknowledged: Option<OutputIndex>,
    ) -> Result<(), Error> {
        if generation <= self.state.generation {
            return Err(Error::Invalid("delivery reset does not advance generation"));
        }
        self.sync_state(State {
            generation,
            acknowledged,
        })
        .await
    }

    async fn sync_state(&mut self, state: State) -> Result<(), Error> {
        let metadata = self
            .metadata
            .take()
            .expect("delivery actor owns cursor metadata");
        self.metadata = Some(metadata.put_sync(Unit, state).await?);
        self.state = state;
        Ok(())
    }

    async fn start_sync_state(&mut self, state: State) -> Result<Handle<()>, Error> {
        let mut metadata = self
            .metadata
            .take()
            .expect("delivery actor owns cursor metadata");
        metadata.put(Unit, state);
        let (metadata, sync) = metadata.start_sync().await?;
        self.metadata = Some(metadata);
        self.state = state;
        Ok(sync)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt as _, Encode};
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};

    #[test]
    fn state_codec_is_versioned_and_canonical() {
        let state = State {
            generation: 7,
            acknowledged: Some(OutputIndex::new(11)),
        };
        let encoded = state.encode();
        assert_eq!(encoded.len(), state.encode_size());
        assert_eq!(State::decode(encoded.clone()).unwrap(), state);

        let mut malformed = encoded.to_vec();
        malformed[0] = STATE_VERSION.wrapping_add(1);
        assert!(matches!(
            State::decode(malformed),
            Err(CodecError::InvalidEnum(version))
                if version == STATE_VERSION.wrapping_add(1)
        ));
    }

    #[test]
    fn missing_metadata_requires_an_initialization_cut() {
        deterministic::Runner::default().start(|context| async move {
            let present = "delivery_present".to_string();
            let store = Store::init(context.child("create"), present.clone(), true, 0, None)
                .await
                .unwrap();
            drop(store);

            Store::init(context.child("present"), present, false, 0, None)
                .await
                .unwrap();
            assert!(matches!(
                Store::init(
                    context.child("missing"),
                    "delivery_missing".to_string(),
                    false,
                    0,
                    None,
                )
                .await,
                Err(Error::Invalid(_))
            ));
        });
    }

    #[test]
    fn acknowledgement_recovers_and_invalid_catalog_cuts_are_rejected() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "delivery_recovery".to_string();
            let mut store = Store::init(context.child("create"), partition.clone(), true, 3, None)
                .await
                .unwrap();
            let sync = store
                .start_acknowledgement(3, OutputIndex::new(5))
                .await
                .unwrap();
            sync.await.unwrap();
            drop(store);

            let store = Store::init(
                context.child("reopen"),
                partition.clone(),
                false,
                3,
                Some(OutputIndex::new(8)),
            )
            .await
            .unwrap();
            assert_eq!(store.generation(), 3);
            assert_eq!(store.acknowledged(), Some(OutputIndex::new(5)));
            drop(store);

            assert!(matches!(
                Store::init(
                    context.child("generation_ahead"),
                    partition.clone(),
                    false,
                    2,
                    Some(OutputIndex::new(8)),
                )
                .await,
                Err(Error::Invalid(_))
            ));
            assert!(matches!(
                Store::init(
                    context.child("acknowledgement_ahead"),
                    partition,
                    false,
                    3,
                    Some(OutputIndex::new(4)),
                )
                .await,
                Err(Error::Invalid(_))
            ));
        });
    }

    #[test]
    fn catalog_generation_ahead_is_durably_reconciled() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "delivery_reconciliation".to_string();
            let store = Store::init(
                context.child("create"),
                partition.clone(),
                true,
                4,
                Some(OutputIndex::new(6)),
            )
            .await
            .unwrap();
            drop(store);

            let store = Store::init(
                context.child("advance"),
                partition.clone(),
                false,
                7,
                Some(OutputIndex::new(19)),
            )
            .await
            .unwrap();
            assert_eq!(store.generation(), 7);
            assert_eq!(store.acknowledged(), Some(OutputIndex::new(19)));
            drop(store);

            let store = Store::init(
                context.child("reopen"),
                partition,
                false,
                7,
                Some(OutputIndex::new(19)),
            )
            .await
            .unwrap();
            assert_eq!(store.generation(), 7);
            assert_eq!(store.acknowledged(), Some(OutputIndex::new(19)));
        });
    }

    #[test]
    fn mutations_require_monotone_generations_and_acknowledgements() {
        deterministic::Runner::default().start(|context| async move {
            let mut store = Store::init(
                context.child("store"),
                "delivery_monotone".to_string(),
                true,
                2,
                None,
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
            assert_eq!(store.generation(), 5);
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
                let state = State {
                    generation: seed,
                    acknowledged: seed
                        .is_multiple_of(2)
                        .then_some(OutputIndex::new(seed.rotate_left(17))),
                };
                let encoded = state.encode();
                assert_eq!(State::decode(encoded.clone()).unwrap(), state);
                encoded.to_vec()
            }
        }

        commonware_conformance::conformance_tests! {
            StateConformance => 128,
        }
    }
}
