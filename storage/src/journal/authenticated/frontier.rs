//! The frontier, the records an authenticated journal persists besides its operations. It holds
//! the pruning boundary and the digests pinned there, and optionally a later replay start and the
//! digests pinned there. A journal without a boundary was never pruned. A journal without a replay
//! start replays from its boundary.

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
const START: U64 = U64::new(0, 1);

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

    /// The replay start and the digests pinned there, if one was recorded.
    pub(crate) fn start(&self) -> Option<Boundary<F, D>> {
        self.metadata.get(&START).cloned()
    }

    /// Durably record `location` as the boundary, with `pins`, dropping a replay start that does
    /// not lie past it.
    pub(crate) async fn set(mut self, location: Location<F>, pins: Vec<D>) -> Result<Self, Error> {
        if self
            .metadata
            .get(&START)
            .is_some_and(|(start, _)| *start <= location)
        {
            self.metadata.remove(&START);
        }
        self.metadata.put(BOUNDARY, (location, pins));
        self.metadata = self.metadata.sync().await?;
        Ok(self)
    }

    /// Durably replace the boundary with `boundary` and the replay start with `start`.
    pub(crate) async fn replace(
        mut self,
        boundary: Boundary<F, D>,
        start: Option<Boundary<F, D>>,
    ) -> Result<Self, Error> {
        match start {
            Some(start) => self.metadata.put(START, start),
            None => self.metadata.remove(&START),
        };
        self.metadata.put(BOUNDARY, boundary);
        self.metadata = self.metadata.sync().await?;
        Ok(self)
    }

    /// Record `location` as the replay start, with `pins`, returning a handle that completes once
    /// the record is durable. A failure surfaces on the handle and again on the next write.
    pub(crate) async fn start_set_start(
        mut self,
        location: Location<F>,
        pins: Vec<D>,
    ) -> Result<(Self, Handle<()>), Error> {
        self.metadata.put(START, (location, pins));
        let (metadata, handle) = self.metadata.start_sync().await?;
        self.metadata = metadata;
        Ok((self, handle))
    }

    /// Durably drop the replay start, if any.
    pub(crate) async fn clear_start(mut self) -> Result<Self, Error> {
        if self.metadata.remove(&START).is_some() {
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
