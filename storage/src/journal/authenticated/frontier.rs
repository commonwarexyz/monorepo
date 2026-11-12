//! The frontier, the one record an authenticated journal persists besides its operations. It holds
//! the pruning boundary and the digests pinned there, and whether a state sync has appended
//! operations that no recorded boundary covers yet. A journal without one was never pruned.

use crate::{
    Context,
    journal::Error,
    merkle::{Family, Location, MAX_PINNED_NODES},
    metadata::{self, Metadata},
};
use commonware_cryptography::Digest;
use commonware_utils::sequence::prefixed_u64::U64;

/// Metadata key of the frontier, the only record in its partition. It is part of the storage
/// format.
const FRONTIER_KEY: U64 = U64::new(0, 0);

/// A pruning boundary and the digests pinned there, in [`Family::nodes_to_pin`] order.
type Boundary<F, D> = (Location<F>, Vec<D>);

/// A [Boundary] and whether a state sync left operations it does not cover.
type Record<F, D> = (Location<F>, Vec<D>, bool);

/// An authenticated journal's frontier, kept in a metadata partition.
pub(crate) struct Frontier<F: Family, E: Context, D: Digest> {
    metadata: Metadata<E, U64, Record<F, D>>,
}

impl<F: Family, E: Context, D: Digest> Frontier<F, E, D> {
    /// Open the frontier, rejecting records that fail to decode.
    pub(crate) async fn open(context: E, partition: String) -> Result<Self, Error> {
        let metadata = Metadata::init(
            context,
            metadata::Config {
                partition,
                codec_config: ((), ((..=MAX_PINNED_NODES).into(), ()), ()),
            },
        )
        .await?;
        Ok(Self { metadata })
    }

    /// The pruning boundary and the digests pinned there, or genesis if none was recorded.
    pub(crate) fn boundary(&self) -> Boundary<F, D> {
        let (location, pins, _) = self.record();
        (location, pins)
    }

    /// Whether a state sync appended operations that no boundary has been recorded for since.
    pub(crate) fn sync_incomplete(&self) -> bool {
        self.record().2
    }

    /// Durably record `location` as the boundary, with `pins`. This ends an incomplete sync.
    pub(crate) async fn set(self, location: Location<F>, pins: Vec<D>) -> Result<Self, Error> {
        self.write((location, pins, false)).await
    }

    /// Durably record that a state sync is appending operations the boundary does not cover.
    pub(crate) async fn mark_sync_incomplete(self) -> Result<Self, Error> {
        if self.sync_incomplete() {
            return Ok(self);
        }
        let (location, pins) = self.boundary();
        self.write((location, pins, true)).await
    }

    /// Remove the durable frontier.
    pub(crate) async fn destroy(self) -> Result<(), Error> {
        Ok(self.metadata.destroy().await?)
    }

    fn record(&self) -> Record<F, D> {
        self.metadata
            .get(&FRONTIER_KEY)
            .cloned()
            .unwrap_or_default()
    }

    async fn write(mut self, record: Record<F, D>) -> Result<Self, Error> {
        self.metadata.put(FRONTIER_KEY, record);
        self.metadata = self.metadata.sync().await?;
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::mmr;
    use commonware_cryptography::sha256::Digest as D;
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};

    /// Main's Merkle metadata, raw byte values in this partition, fails to decode as a frontier, so
    /// a database written by main fails to open with `Corruption` instead of panicking.
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
            metadata.put(FRONTIER_KEY, vec![0; 8]);
            drop(metadata.sync().await.unwrap());
            assert!(matches!(
                Frontier::<mmr::Family, _, D>::open(context.child("open"), "frontier".into()).await,
                Err(Error::Metadata(metadata::Error::Corruption(_)))
            ));
        });
    }

    /// Marking an incomplete sync keeps the boundary and survives a reopen, and recording a
    /// boundary ends it.
    #[test]
    fn incomplete_sync_until_boundary_set() {
        deterministic::Runner::default().start(|context| async move {
            let open = |label: &'static str| {
                Frontier::<mmr::Family, _, D>::open(context.child(label), "frontier".into())
            };
            let boundary = Location::new(4);
            let pins = vec![D::from([1; 32])];
            let frontier = open("set").await.unwrap();
            drop(frontier.set(boundary, pins.clone()).await.unwrap());

            let frontier = open("mark").await.unwrap();
            assert!(!frontier.sync_incomplete());
            drop(frontier.mark_sync_incomplete().await.unwrap());

            let frontier = open("marked").await.unwrap();
            assert!(frontier.sync_incomplete());
            assert_eq!(frontier.boundary(), (boundary, pins.clone()));
            drop(frontier.set(Location::new(8), pins).await.unwrap());

            let frontier = open("recorded").await.unwrap();
            assert!(!frontier.sync_incomplete());
            assert_eq!(frontier.boundary().0, Location::new(8));
        });
    }
}
