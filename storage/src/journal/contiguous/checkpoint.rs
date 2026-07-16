//! A small durable record that recovery reads before trusting anything on disk.
//!
//! A journal's contents are recovered from its blobs: blob indexes give positions and blob
//! lengths give item counts. The [Checkpoint] records the one fact that blob state alone
//! cannot provide: the pruning boundary, when it cannot be derived from the oldest blob —
//! either because it falls mid-blob (from
//! [Journal::init_at_size](super::fixed::Journal::init_at_size)) or because a clear removed
//! every blob and the new tail has not been recreated yet.
//!
//! A clear (reset) writes the boundary record in the SAME batch as the blob removals, so the
//! whole reset is one old-state-or-new-state transition and no staged intent is needed
//! (torn-write immunity and clear atomicity both come from the runtime's atomic storage).
//!
//! # Format
//!
//! The record is a single codec-encoded blob (`{partition_prefix}-metadata`, blob name
//! `checkpoint`), rewritten wholesale on every change and then synced. The storage backend's
//! per-blob atomic sync makes each rewrite an old-record-or-new-record transition, so no
//! versioning or redundancy is needed. An empty blob is a fresh checkpoint. Any other content
//! must decode exactly or the checkpoint is corrupt.
//!
//! # Invariants
//!
//! [Checkpoint] is a passive store; the journal upholds these by ordering its calls:
//!
//! - The boundary advances only after the blob state it describes is durable (or in the same
//!   batch as it).

use crate::{journal::Error, Context};
use commonware_codec::{DecodeExt as _, Encode as _, EncodeSize, Read, ReadExt as _, Write};
use commonware_runtime::{Blob as _, Buf, BufMut, WriteBatch as _};

/// Name of the blob holding the encoded record.
const BLOB_NAME: &[u8] = b"checkpoint";

/// The durable contents of a checkpoint.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
struct Record {
    /// The pruning boundary, when blob state cannot derive it. Kept while the boundary is
    /// mid-blob; also written (possibly blob-aligned) by a clear, whose batch removes every
    /// blob. A blob-aligned hint is dropped by the next persist once the recreated blob state
    /// derives it.
    boundary_hint: Option<u64>,
}

impl Write for Record {
    fn write(&self, buf: &mut impl BufMut) {
        self.boundary_hint.write(buf);
    }
}

impl EncodeSize for Record {
    fn encode_size(&self) -> usize {
        self.boundary_hint.encode_size()
    }
}

impl Read for Record {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            boundary_hint: Option::<u64>::read(buf)?,
        })
    }
}

/// The journal's durable recovery checkpoint.
pub(super) struct Checkpoint<E: Context> {
    context: E,
    partition: String,
    blob: E::Blob,
    record: Record,
}

impl<E: Context> Checkpoint<E> {
    /// Open the checkpoint stored in `{partition_prefix}-metadata`.
    pub(super) async fn open(context: E, partition_prefix: &str) -> Result<Self, Error> {
        let partition = format!("{partition_prefix}-metadata");
        let (blob, size) = context
            .open(&partition, BLOB_NAME)
            .await
            .map_err(Error::Runtime)?;

        // An empty blob is a fresh checkpoint. Anything else is a whole record: the backend
        // restores the blob to exactly its last-synced state, so a decode failure is corruption.
        let record = if size == 0 {
            Record::default()
        } else {
            let size = usize::try_from(size).map_err(|_| Error::OffsetOverflow)?;
            let bytes = blob.read_at(0, size).await.map_err(Error::Runtime)?;
            Record::decode(bytes.coalesce())
                .map_err(|err| Error::Corruption(format!("invalid checkpoint record: {err}")))?
        };

        Ok(Self {
            context,
            partition,
            blob,
            record,
        })
    }

    /// The recorded pruning boundary, if any.
    pub(super) const fn boundary_hint(&self) -> Option<u64> {
        self.record.boundary_hint
    }

    /// Rewrite the record wholesale and make it durable.
    async fn write(&mut self, record: Record) -> Result<(), Error> {
        let bytes = record.encode();
        // Trim any longer previous record before the sync publishes the new one atomically.
        self.blob
            .resize(bytes.len() as u64)
            .await
            .map_err(Error::Runtime)?;
        self.blob
            .write_at_sync(0, bytes)
            .await
            .map_err(Error::Runtime)?;
        self.record = record;
        Ok(())
    }

    /// Stage a wholesale record rewrite with `batch` (durable when the
    /// batch is applied, atomically with everything else it stages).
    async fn write_into(&mut self, record: Record, batch: &mut E::Batch) -> Result<(), Error> {
        let bytes = record.encode();
        batch
            .resize(&self.blob, bytes.len() as u64)
            .await
            .map_err(Error::Runtime)?;
        batch
            .write_at(&self.blob, 0, bytes)
            .await
            .map_err(Error::Runtime)?;
        self.record = record;
        Ok(())
    }

    /// Durably record the boundary, writing only if it changed.
    ///
    /// A blob-aligned boundary is derived from the oldest blob, so the hint is only kept while
    /// the boundary is mid-blob.
    pub(super) async fn persist(
        &mut self,
        items_per_blob: u64,
        boundary: u64,
    ) -> Result<(), Error> {
        let boundary_hint = (!boundary.is_multiple_of(items_per_blob)).then_some(boundary);
        let record = Record { boundary_hint };
        if record != self.record {
            self.write(record).await?;
        }
        Ok(())
    }

    /// [Self::persist], staged with `batch` instead of written durably.
    pub(super) async fn persist_into(
        &mut self,
        items_per_blob: u64,
        boundary: u64,
        batch: &mut E::Batch,
    ) -> Result<(), Error> {
        let boundary_hint = (!boundary.is_multiple_of(items_per_blob)).then_some(boundary);
        let record = Record { boundary_hint };
        if record != self.record {
            self.write_into(record, batch).await?;
        }
        Ok(())
    }

    /// Stage the cleared-boundary record with `batch`: the hint is written even when
    /// blob-aligned, because the cleared journal has no blobs to derive the boundary from
    /// until its tail is recreated on the next open.
    #[commonware_macros::stability(ALPHA)]
    pub(super) async fn clear_into(
        &mut self,
        target: u64,
        batch: &mut E::Batch,
    ) -> Result<(), Error> {
        let record = Record {
            boundary_hint: Some(target),
        };
        if record != self.record {
            self.write_into(record, batch).await?;
        }
        Ok(())
    }

    /// Remove the checkpoint's partition.
    pub(super) async fn destroy(self) -> Result<(), Error> {
        drop(self.blob);
        self.context
            .remove(&self.partition, None)
            .await
            .map_err(Error::Runtime)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner as _, Supervisor as _};

    /// Direct-injection helpers used by tests (here and in the fixed and variable journals)
    /// to plant states the production API only produces mid-crash-window: a boundary hint, or
    /// an undecodable record.
    impl<E: Context> Checkpoint<E> {
        /// Set and persist the pruning boundary directly.
        pub(crate) async fn set_boundary_hint(&mut self, boundary: u64) -> Result<(), Error> {
            let record = Record {
                boundary_hint: Some(boundary),
            };
            self.write(record).await
        }

        /// Overwrite the record blob with undecodable bytes, simulating corruption.
        pub(crate) async fn corrupt(&mut self) -> Result<(), Error> {
            self.blob.resize(0).await.map_err(Error::Runtime)?;
            self.blob
                .write_at_sync(0, vec![0xFFu8; 3])
                .await
                .map_err(Error::Runtime)
        }

        /// Durably erase the record, simulating metadata deletion.
        pub(crate) async fn clear(&mut self) -> Result<(), Error> {
            self.record = Record::default();
            self.blob.resize(0).await.map_err(Error::Runtime)?;
            self.blob.sync().await.map_err(Error::Runtime)
        }
    }

    #[test_traced]
    fn test_persist_round_trips_across_reopen() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            {
                let mut checkpoint = Checkpoint::open(context.child("a"), "rt").await.unwrap();
                // A mid-blob boundary is kept.
                checkpoint.persist(10, 13).await.unwrap();
            }
            let checkpoint = Checkpoint::open(context.child("b"), "rt").await.unwrap();
            assert_eq!(checkpoint.boundary_hint(), Some(13));
        });
    }

    #[test_traced]
    fn test_persist_boundary_hint_tracks_alignment() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut checkpoint = Checkpoint::open(context, "align").await.unwrap();

            // A mid-blob boundary is recorded as a hint.
            checkpoint.persist(10, 13).await.unwrap();
            assert_eq!(checkpoint.boundary_hint(), Some(13));

            // A later blob-aligned boundary drops the stale hint (it is derived from the
            // oldest blob).
            checkpoint.persist(10, 20).await.unwrap();
            assert_eq!(checkpoint.boundary_hint(), None);
        });
    }

    #[test_traced]
    fn test_clear_records_boundary_atomically() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            use commonware_runtime::{Batchable as _, WriteBatch as _};
            {
                let mut checkpoint = Checkpoint::open(context.child("a"), "clear").await.unwrap();
                checkpoint.persist(10, 13).await.unwrap();
                // A clear stages the target as the boundary — even blob-aligned,
                // since the cleared journal has no blobs to derive it from.
                let mut batch = context.batch().await.unwrap();
                checkpoint.clear_into(20, &mut batch).await.unwrap();
                batch.apply_sync().await.unwrap();
                assert_eq!(checkpoint.boundary_hint(), Some(20));
            }
            {
                let mut checkpoint = Checkpoint::open(context.child("b"), "clear").await.unwrap();
                assert_eq!(checkpoint.boundary_hint(), Some(20));
                // Once blob state derives an aligned boundary again, persist
                // drops the hint.
                checkpoint.persist(10, 20).await.unwrap();
            }
            let checkpoint = Checkpoint::open(context.child("c"), "clear").await.unwrap();
            assert_eq!(checkpoint.boundary_hint(), None);
        });
    }

    #[test_traced]
    fn test_undecodable_record_is_corruption() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            {
                let mut checkpoint = Checkpoint::open(context.child("a"), "bad").await.unwrap();
                checkpoint.corrupt().await.unwrap();
            }
            let result = Checkpoint::open(context.child("b"), "bad").await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }
}
