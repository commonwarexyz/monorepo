//! A small durable record holding the pruning boundary and its pinned nodes.
//!
//! Pruning removes journal blobs holding nodes that root and proof generation still need. The
//! `Pins` record preserves exactly that set: the pruning boundary and the digests of
//! [`Family::nodes_to_pin`] at that boundary. Every owner stages the record rewrite in the
//! SAME batch as the journal prune it describes (or writes it alone, for owners with no
//! journal), so record and journal can never describe different histories.
//!
//! # Format
//!
//! The record is a single codec-encoded blob (blob name `pins` in the configured metadata
//! partition), rewritten wholesale on every boundary change and staged with a batch — the
//! owner's, or a one-op batch for [Pins::write]. The storage backend's atomic commit makes
//! each rewrite (its resize and its bytes together) an old-record-or-new-record transition.
//! An empty blob is a never-pruned record. Any other content must decode exactly — a `u64`
//! boundary followed by precisely the digests `nodes_to_pin` prescribes for it — or the record
//! is corrupt.

use crate::{
    merkle::{Error, Family, Location, Position},
    Context,
};
use commonware_codec::{FixedSize as _, ReadExt as _, Write as _};
use commonware_cryptography::Digest;
use commonware_runtime::{Blob as _, Buf as _, WriteBatch as _};
use std::collections::BTreeMap;

/// Name of the blob holding the encoded record.
const BLOB_NAME: &[u8] = b"pins";

/// The durable pruning boundary and the pinned node digests it requires.
pub(crate) struct Pins<F: Family, E: Context, D: Digest> {
    context: E,
    partition: String,
    blob: E::Blob,
    /// The recorded pruning boundary (zero if never pruned).
    pruned_to: Location<F>,
    /// Digests for `F::nodes_to_pin(pruned_to)`, keyed by position.
    nodes: BTreeMap<Position<F>, D>,
}

impl<F: Family, E: Context, D: Digest> Pins<F, E, D> {
    /// Open the record stored in `partition`.
    pub(crate) async fn open(context: E, partition: String) -> Result<Self, Error<F>> {
        let (blob, size) = context
            .open(&partition, BLOB_NAME)
            .await
            .map_err(Error::Runtime)?;

        // An empty blob is a never-pruned record. Anything else is a whole record: the backend
        // restores the blob to exactly its last-synced state, so a decode failure is corruption.
        let (pruned_to, nodes) = if size == 0 {
            (Location::new(0), BTreeMap::new())
        } else {
            let size = usize::try_from(size)
                .map_err(|_| Error::DataCorrupted("pins record exceeds usize"))?;
            let mut buf = blob
                .read_at(0, size)
                .await
                .map_err(Error::Runtime)?
                .coalesce();
            let pruned_to = Location::<F>::new(
                u64::read(&mut buf).map_err(|_| Error::DataCorrupted("pins record too short"))?,
            );
            if !pruned_to.is_valid() {
                return Err(Error::DataCorrupted("pins boundary exceeds MAX_LEAVES"));
            }
            let mut nodes = BTreeMap::new();
            for pos in F::nodes_to_pin(pruned_to) {
                let digest = D::read(&mut buf)
                    .map_err(|_| Error::DataCorrupted("pins record missing digest"))?;
                nodes.insert(pos, digest);
            }
            if buf.remaining() != 0 {
                return Err(Error::DataCorrupted("pins record has trailing bytes"));
            }
            (pruned_to, nodes)
        };

        Ok(Self {
            context,
            partition,
            blob,
            pruned_to,
            nodes,
        })
    }

    /// The recorded pruning boundary (zero if never pruned).
    pub(crate) const fn pruned_to(&self) -> Location<F> {
        self.pruned_to
    }

    /// The recorded digest at `pos`, if pinned.
    pub(crate) fn get(&self, pos: Position<F>) -> Option<&D> {
        self.nodes.get(&pos)
    }

    /// Encode the record wholesale: `nodes` must hold exactly the digests of
    /// `F::nodes_to_pin(pruned_to)`.
    ///
    /// # Panics
    ///
    /// Panics if `nodes` does not hold exactly the pinned positions for `pruned_to`.
    fn encode(pruned_to: Location<F>, nodes: &BTreeMap<Position<F>, D>) -> Vec<u8> {
        // Digests are encoded in `nodes_to_pin` order (which decode mirrors), not map order.
        let mut bytes = Vec::with_capacity(u64::SIZE + nodes.len() * D::SIZE);
        pruned_to.as_u64().write(&mut bytes);
        let mut written = 0;
        for pos in F::nodes_to_pin(pruned_to) {
            let digest = nodes
                .get(&pos)
                .expect("nodes must hold every pinned position");
            digest.write(&mut bytes);
            written += 1;
        }
        assert_eq!(
            written,
            nodes.len(),
            "nodes must hold exactly the pinned positions"
        );
        bytes
    }

    /// Durably rewrite the record wholesale (see [Self::encode] for the `nodes` contract), in
    /// ONE atomic commit.
    pub(crate) async fn write(
        &mut self,
        pruned_to: Location<F>,
        nodes: BTreeMap<Position<F>, D>,
    ) -> Result<(), Error<F>> {
        let mut batch = self.context.batch().await.map_err(Error::Runtime)?;
        self.write_into(pruned_to, nodes, &mut batch).await?;
        batch.apply_sync().await.map_err(Error::Runtime)
    }

    /// [Self::write], staged with `batch`: the rewrite lands when the caller applies the
    /// batch with `apply_sync`, atomically with everything else it stages.
    pub(crate) async fn write_into(
        &mut self,
        pruned_to: Location<F>,
        nodes: BTreeMap<Position<F>, D>,
        batch: &mut E::Batch,
    ) -> Result<(), Error<F>> {
        let bytes = Self::encode(pruned_to, &nodes);
        batch
            .resize(&self.blob, bytes.len() as u64)
            .await
            .map_err(Error::Runtime)?;
        batch
            .write_at(&self.blob, 0, bytes)
            .await
            .map_err(Error::Runtime)?;
        self.pruned_to = pruned_to;
        self.nodes = nodes;
        Ok(())
    }

    /// Remove the record's partition.
    pub(crate) async fn destroy(self) -> Result<(), Error<F>> {
        drop(self.blob);
        self.context
            .remove(&self.partition, None)
            .await
            .map_err(Error::Runtime)
    }

    /// Stage the removal of the record's partition with `batch`.
    ///
    /// The partition always exists: the record blob is created at open.
    pub(crate) fn destroy_into(self, batch: &mut E::Batch) {
        drop(self.blob);
        batch.remove(&self.partition, None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::mmr::Family as MmrFamily;
    use commonware_cryptography::{sha256, Hasher as _, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner as _, Supervisor as _};

    type TestPins = Pins<MmrFamily, deterministic::Context, sha256::Digest>;

    #[test_traced]
    fn test_write_round_trips_across_reopen() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let boundary = Location::new(11);
            let nodes: BTreeMap<_, _> = MmrFamily::nodes_to_pin(boundary)
                .map(|pos| (pos, Sha256::hash(&pos.to_be_bytes())))
                .collect();
            assert!(!nodes.is_empty());
            {
                let mut pins = TestPins::open(context.child("a"), "rt".into())
                    .await
                    .unwrap();
                assert_eq!(pins.pruned_to(), Location::new(0));
                pins.write(boundary, nodes.clone()).await.unwrap();
            }
            let pins = TestPins::open(context.child("b"), "rt".into())
                .await
                .unwrap();
            assert_eq!(pins.pruned_to(), boundary);
            for (pos, digest) in &nodes {
                assert_eq!(pins.get(*pos), Some(digest));
            }
        });
    }

    #[test_traced]
    fn test_undecodable_record_is_corruption() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            {
                let mut pins = TestPins::open(context.child("a"), "bad".into())
                    .await
                    .unwrap();
                let boundary = Location::new(4);
                let nodes: BTreeMap<_, _> = MmrFamily::nodes_to_pin(boundary)
                    .map(|pos| (pos, Sha256::hash(&pos.to_be_bytes())))
                    .collect();
                pins.write(boundary, nodes).await.unwrap();

                // Truncate mid-digest so the record no longer holds every pinned node.
                pins.blob.resize(u64::SIZE as u64 + 1).await.unwrap();
                pins.blob.sync().await.unwrap();
            }
            let result = TestPins::open(context.child("b"), "bad".into()).await;
            assert!(matches!(result, Err(Error::DataCorrupted(_))));
        });
    }
}
