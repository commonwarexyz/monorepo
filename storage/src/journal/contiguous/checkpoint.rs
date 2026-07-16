//! A small durable record that recovery reads before trusting anything on disk.
//!
//! A journal's contents are recovered from its blobs: blob indexes give positions and blob
//! lengths give item counts. The [Checkpoint] records the two facts that blob state alone
//! cannot provide:
//!
//! - The pruning boundary, when it falls mid-blob (from
//!   [Journal::init_at_size](super::fixed::Journal::init_at_size)): recovery needs the exact
//!   position where the oldest blob's items begin.
//! - The clear target, while a clear/reset is in progress: the target is recorded before any
//!   blob is deleted, so a crash mid-clear is finished on reopen instead of being misread as
//!   corruption.
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
//! - The boundary advances only after the blob state it describes is durable.
//! - A clear target is recorded before any blob is deleted.

use crate::{journal::Error, Context};
use commonware_codec::{DecodeExt as _, Encode as _, EncodeSize, Read, ReadExt as _, Write};
use commonware_runtime::{Blob as _, Buf, BufMut};

/// Name of the blob holding the encoded record.
const BLOB_NAME: &[u8] = b"checkpoint";

/// The durable contents of a checkpoint.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
struct Record {
    /// The mid-blob pruning boundary, if any. Absent when the boundary is blob-aligned (it is
    /// then derived from the oldest blob).
    boundary_hint: Option<u64>,

    /// The target of an in-progress clear, if one was staged.
    clear_target: Option<u64>,
}

impl Write for Record {
    fn write(&self, buf: &mut impl BufMut) {
        self.boundary_hint.write(buf);
        self.clear_target.write(buf);
    }
}

impl EncodeSize for Record {
    fn encode_size(&self) -> usize {
        self.boundary_hint.encode_size() + self.clear_target.encode_size()
    }
}

impl Read for Record {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            boundary_hint: Option::<u64>::read(buf)?,
            clear_target: Option::<u64>::read(buf)?,
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

    /// The recorded mid-blob pruning boundary, if any.
    pub(super) const fn boundary_hint(&self) -> Option<u64> {
        self.record.boundary_hint
    }

    /// The target of an in-progress clear, if one was staged.
    pub(super) const fn clear_target(&self) -> Option<u64> {
        self.record.clear_target
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
        let record = Record {
            boundary_hint,
            ..self.record
        };
        if record != self.record {
            self.write(record).await?;
        }
        Ok(())
    }

    /// Durably record the intent to clear to `target`.
    pub(super) async fn stage_clear(&mut self, target: u64) -> Result<(), Error> {
        let record = Record {
            clear_target: Some(target),
            ..self.record
        };
        if record != self.record {
            self.write(record).await?;
        }
        Ok(())
    }

    /// Durably complete a clear to `target`: drop the intent and record `target` as the
    /// boundary.
    pub(super) async fn finish_clear(
        &mut self,
        items_per_blob: u64,
        target: u64,
    ) -> Result<(), Error> {
        let record = Record {
            boundary_hint: (!target.is_multiple_of(items_per_blob)).then_some(target),
            clear_target: None,
        };
        if record != self.record {
            self.write(record).await?;
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

    /// Direct-injection helpers used by tests (here and in the fixed journal) to plant states
    /// the production API never produces: a stray boundary hint or clear intent, or an
    /// undecodable record.
    impl<E: Context> Checkpoint<E> {
        /// Set and persist the mid-blob pruning boundary directly.
        pub(crate) async fn set_boundary_hint(&mut self, boundary: u64) -> Result<(), Error> {
            let record = Record {
                boundary_hint: Some(boundary),
                ..self.record
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
            assert_eq!(checkpoint.clear_target(), None);
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
    fn test_clear_lifecycle_survives_crash() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            {
                let mut checkpoint = Checkpoint::open(context.child("a"), "clear").await.unwrap();
                checkpoint.persist(10, 13).await.unwrap();
                // Staging records the intent alongside the existing boundary.
                checkpoint.stage_clear(20).await.unwrap();
                assert_eq!(checkpoint.clear_target(), Some(20));
                assert_eq!(checkpoint.boundary_hint(), Some(13));
            }
            // A crash after staging leaves the intent durable.
            {
                let mut checkpoint = Checkpoint::open(context.child("b"), "clear").await.unwrap();
                assert_eq!(checkpoint.clear_target(), Some(20));
                // Completing drops the intent and records the target as the boundary.
                checkpoint.finish_clear(10, 20).await.unwrap();
            }
            let checkpoint = Checkpoint::open(context.child("c"), "clear").await.unwrap();
            assert_eq!(checkpoint.clear_target(), None);
            // 20 is blob-aligned, so no hint is retained.
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
