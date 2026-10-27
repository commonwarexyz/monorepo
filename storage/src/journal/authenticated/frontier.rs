//! The frontier, the one record an authenticated journal persists besides its operations. It holds
//! the pruning boundary and the digests pinned there. A journal without one was never pruned.

use crate::{
    Context,
    journal::Error,
    merkle::{Family, Location},
    metadata::{self, Metadata},
};
use commonware_cryptography::Digest;
use commonware_utils::sequence::prefixed_u64::U64;

const KEY: U64 = U64::new(0, 0);

/// A pruning boundary and the digests pinned there, in [`Family::nodes_to_pin`] order.
type Boundary<F, D> = (Location<F>, Vec<D>);

/// An authenticated journal's frontier, kept in a metadata partition.
pub(crate) struct Frontier<F: Family, E: Context, D: Digest> {
    metadata: Metadata<E, U64, Boundary<F, D>>,
}

impl<F: Family, E: Context, D: Digest> Frontier<F, E, D> {
    /// Open the frontier, rejecting records that fail to decode.
    pub(crate) async fn open(context: E, partition: String) -> Result<Self, Error> {
        let metadata = Metadata::init(
            context,
            metadata::Config {
                partition,
                codec_config: ((), ((..=64).into(), ())),
            },
        )
        .await?;
        Ok(Self { metadata })
    }

    /// The pruning boundary and the digests pinned there, or genesis if none was recorded.
    pub(crate) fn boundary(&self) -> Boundary<F, D> {
        self.metadata.get(&KEY).cloned().unwrap_or_default()
    }

    /// Durably record `location` as the boundary, with `pins`.
    pub(crate) async fn set(mut self, location: Location<F>, pins: Vec<D>) -> Result<Self, Error> {
        self.metadata.put(KEY, (location, pins));
        self.metadata = self.metadata.sync().await?;
        Ok(self)
    }

    /// Remove the durable frontier.
    pub(crate) async fn destroy(self) -> Result<(), Error> {
        Ok(self.metadata.destroy().await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::mmr;
    use commonware_cryptography::sha256::Digest as D;
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};

    #[test]
    fn rejects_legacy_metadata() {
        deterministic::Runner::default().start(|context| async move {
            let mut metadata = Metadata::<_, U64, Vec<u8>>::init(
                context.child("legacy"),
                metadata::Config {
                    partition: "frontier".into(),
                    codec_config: ((0..=4096).into(), ()),
                },
            )
            .await
            .unwrap();
            metadata.put(KEY, vec![0; 8]);
            drop(metadata.sync().await.unwrap());
            assert!(matches!(
                Frontier::<mmr::Family, _, D>::open(context.child("open"), "frontier".into()).await,
                Err(Error::Metadata(metadata::Error::Corruption(_)))
            ));
        });
    }
}
