//! The frontier, the one record an authenticated journal persists besides its operations. It holds
//! the pruning boundary and the digests pinned there, plus up to [MAX_ANCHORS] anchors: later
//! locations with their pins, from which initialization can replay instead. A journal without a
//! boundary was never pruned.

use crate::{
    Context,
    journal::Error,
    merkle::{Family, Location, MAX_PINNED_NODES},
    metadata::{self, Metadata},
};
use commonware_cryptography::Digest;
use commonware_runtime::Handle;
use commonware_utils::sequence::prefixed_u64::U64;

const BOUNDARY: U64 = U64::new(0, 0);

/// Key prefix of anchors, each keyed by its location.
const ANCHOR_PREFIX: u8 = 1;

/// The most anchors a frontier keeps. Recording another drops the oldest.
pub(crate) const MAX_ANCHORS: usize = 4;

/// A location and the digests pinned there, in [`Family::nodes_to_pin`] order.
pub(crate) type Boundary<F, D> = (Location<F>, Vec<D>);

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
                codec_config: ((), ((..=MAX_PINNED_NODES).into(), ())),
            },
        )
        .await?;
        Ok(Self { metadata })
    }

    /// The pruning boundary and the digests pinned there, or genesis if none was recorded.
    pub(crate) fn boundary(&self) -> Boundary<F, D> {
        self.metadata.get(&BOUNDARY).cloned().unwrap_or_default()
    }

    /// The anchors, oldest first.
    pub(crate) fn anchors(&self) -> Vec<Boundary<F, D>> {
        let mut anchors: Vec<_> = self
            .metadata
            .keys()
            .filter(|key| key.prefix() == ANCHOR_PREFIX)
            .filter_map(|key| self.metadata.get(key).cloned())
            .collect();
        anchors.sort_by_key(|(location, _)| *location);
        anchors
    }

    /// Durably record `location` as the boundary, with `pins`, dropping the anchors at or before
    /// it in the same write.
    pub(crate) async fn set(mut self, location: Location<F>, pins: Vec<D>) -> Result<Self, Error> {
        self.metadata.put(BOUNDARY, (location, pins));
        self.metadata
            .retain(|key, (anchor, _)| key.prefix() != ANCHOR_PREFIX || *anchor > location);
        self.metadata = self.metadata.sync().await?;
        Ok(self)
    }

    /// Like [Self::set], but drops every anchor.
    pub(crate) async fn set_without_anchors(
        mut self,
        location: Location<F>,
        pins: Vec<D>,
    ) -> Result<Self, Error> {
        self.metadata.put(BOUNDARY, (location, pins));
        self.metadata.retain(|key, _| key.prefix() != ANCHOR_PREFIX);
        self.metadata = self.metadata.sync().await?;
        Ok(self)
    }

    /// Begin durably recording an anchor at `location`, with `pins`, dropping the oldest if there
    /// would be more than [MAX_ANCHORS]. The returned handle completes once the record is durable.
    pub(crate) async fn start_anchor(
        mut self,
        location: Location<F>,
        pins: Vec<D>,
    ) -> Result<(Self, Handle<()>), Error> {
        self.metadata
            .put(U64::new(ANCHOR_PREFIX, *location), (location, pins));
        let anchors = self.anchors();
        for (oldest, _) in anchors
            .iter()
            .take(anchors.len().saturating_sub(MAX_ANCHORS))
        {
            self.metadata.remove(&U64::new(ANCHOR_PREFIX, **oldest));
        }
        let (metadata, handle) = self.metadata.start_sync().await?;
        self.metadata = metadata;
        Ok((self, handle))
    }

    /// Durably drop every anchor.
    pub(crate) async fn drop_anchors(mut self) -> Result<Self, Error> {
        let before = self.metadata.keys().count();
        self.metadata.retain(|key, _| key.prefix() != ANCHOR_PREFIX);
        if self.metadata.keys().count() != before {
            self.metadata = self.metadata.sync().await?;
        }
        Ok(self)
    }

    /// Durably drop the anchors after `location`.
    pub(crate) async fn drop_anchors_after(mut self, location: Location<F>) -> Result<Self, Error> {
        let before = self.metadata.keys().count();
        self.metadata
            .retain(|key, (anchor, _)| key.prefix() != ANCHOR_PREFIX || *anchor <= location);
        if self.metadata.keys().count() != before {
            self.metadata = self.metadata.sync().await?;
        }
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
            metadata.put(BOUNDARY, vec![0; 8]);
            drop(metadata.sync().await.unwrap());
            assert!(matches!(
                Frontier::<mmr::Family, _, D>::open(context.child("open"), "frontier".into()).await,
                Err(Error::Metadata(metadata::Error::Corruption(_)))
            ));
        });
    }
}
