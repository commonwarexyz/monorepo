//! A durable, at-least-once delivery queue backed by a journal.
//!
//! [Queue] provides a persistent message queue with at-least-once delivery semantics.
//! Items are durably stored in a journal and will survive crashes. The reader must
//! explicitly acknowledge each item after processing. If a crash occurs before
//! acknowledgment, items will be re-delivered on restart.
//!
//! # Concurrent Access
//!
//! For concurrent access from separate writer and reader tasks, use the [shared] module.
//! Writers can be cloned for multiple producer tasks.
//!
//! ```rust,ignore
//! use commonware_storage::queue::shared;
//! use commonware_macros::select;
//!
//! let (writer, mut reader) = shared::init(context, config).await?;
//!
//! // Writer task (can clone for multiple producers)
//! writer.enqueue(item).await?;
//!
//! // Reader task
//! loop {
//!     select! {
//!         result = reader.recv() => {
//!             let Some((pos, item)) = result? else { break };
//!             // Process item...
//!             reader.ack(pos).await?;
//!         }
//!         _ = shutdown => break,
//!     }
//! }
//! ```
//!
//! # At-Least-Once Delivery
//!
//! The queue guarantees that every enqueued item will be delivered at least once.
//! Duplicate delivery may occur if:
//! - The reader processes an item but crashes before acknowledging it
//! - The reader acknowledges items but the process crashes before the journal syncs
//!
//! Applications must be prepared to handle duplicate messages (idempotent processing).
//!
//! # Per-Item Acknowledgment
//!
//! Unlike watermark-based acking, this queue supports acknowledging items out of order.
//! This enables:
//! - Parallel processing with multiple workers
//! - Selective retries (one stuck item doesn't block others)
//! - More efficient crash recovery (only truly unprocessed items are re-delivered)
//!
//! Acknowledged items are tracked using an "ack floor" plus ranges of acked items above
//! the floor. When items are acked contiguously from the floor, the floor advances and
//! acknowledged items are automatically pruned from storage.
//!
//! # Example
//!
//! ```rust
//! use commonware_codec::RangeCfg;
//! use commonware_runtime::{Spawner, Runner, deterministic, buffer::paged::CacheRef};
//! use commonware_storage::{queue::{Queue, Config}, Persistable};
//! use std::num::{NonZeroU16, NonZeroU64, NonZeroUsize};
//!
//! let executor = deterministic::Runner::default();
//! executor.start(|context| async move {
//!     // Create a queue
//!     let mut queue = Queue::<_, Vec<u8>>::init(context.clone(), Config {
//!         partition: "my_queue".to_string(),
//!         items_per_section: NonZeroU64::new(1000).unwrap(),
//!         compression: None,
//!         codec_config: ((0..).into(), ()), // RangeCfg for Vec length, () for u8
//!         page_cache: CacheRef::new(NonZeroU16::new(1024).unwrap(), NonZeroUsize::new(10).unwrap()),
//!         write_buffer: NonZeroUsize::new(4096).unwrap(),
//!     }).await.unwrap();
//!
//!     // Enqueue items
//!     queue.enqueue(b"task1".to_vec()).await.unwrap();
//!     queue.enqueue(b"task2".to_vec()).await.unwrap();
//!
//!     // Dequeue and process items (can be done out of order)
//!     while let Some((position, item)) = queue.dequeue().await.unwrap() {
//!         // Process the item...
//!         println!("Processing item at position {}", position);
//!
//!         // Acknowledge after successful processing (auto-prunes)
//!         queue.ack(position).await.unwrap();
//!     }
//!
//!     queue.destroy().await.unwrap();
//! });
//! ```

mod metrics;
pub mod shared;
mod storage;

pub use shared::{QueueReader, QueueWriter};
pub use storage::{Config, Queue};
use thiserror::Error;

/// Errors that can occur when interacting with [Queue].
#[derive(Debug, Error)]
pub enum Error {
    #[error("journal error: {0}")]
    Journal(#[from] crate::journal::Error),

    #[error("metadata error: {0}")]
    Metadata(#[from] crate::metadata::Error),

    #[error("position out of range: {0} (queue size is {1})")]
    PositionOutOfRange(u64, u64),
}
