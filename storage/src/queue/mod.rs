//! A durable, at-least-once delivery queue backed by a [`variable::Journal`](crate::journal::contiguous::variable).
//!
//! [Queue] provides a persistent message queue with at-least-once delivery semantics.
//! Items are durably stored in a journal and will survive crashes. The reader must
//! explicitly acknowledge each item after processing. On restart, all non-pruned
//! items are re-delivered (acknowledged or not).
//!
//! # Ownership
//!
//! Methods that write to storage (`append`, `enqueue`, `commit`, `sync`) take the queue by value
//! and return it on success. If one returns an error, or its future is dropped before it finishes,
//! the queue is gone: state that was not yet durable is discarded, but everything already on disk
//! stays recoverable. Reads and in-memory bookkeeping (`dequeue`, `ack`, `ack_up_to`, `reset`)
//! borrow the queue. A failed `dequeue` read does not invalidate it.
//!
//! # Concurrent Access
//!
//! For concurrent access from separate writer and reader tasks, use [init].
//!
//! ```rust,ignore
//! use commonware_storage::queue;
//! use commonware_macros::select;
//!
//! let (writer, mut reader) = queue::init(context, config).await?;
//!
//! // Writer task
//! let (writer, position) = writer.enqueue(item).await?;
//!
//! // Reader task
//! loop {
//!     select! {
//!         result = reader.recv() => {
//!             let Some((pos, item)) = result? else { break };
//!             // Process item...
//!             reader.ack(pos)?;
//!         }
//!         _ = shutdown => break,
//!     }
//! }
//! ```
//!
//! # Example
//!
//! ```rust
//! use commonware_codec::RangeCfg;
//! use commonware_runtime::{Spawner, Runner, deterministic, buffer::paged::CacheRef};
//! use commonware_storage::{queue::{Queue, Config}};
//! use std::num::{NonZeroU16, NonZeroU64, NonZeroUsize};
//!
//! let executor = deterministic::Runner::default();
//! executor.start(|context| async move {
//!     // Create a page cache
//!     let page_cache = CacheRef::from_pooler(
//!         &context,
//!         NonZeroU16::new(1024).unwrap(),
//!         NonZeroUsize::new(10).unwrap(),
//!     );
//!
//!     // Create a queue
//!     let mut queue = Queue::<_, Vec<u8>>::init(context, Config {
//!         partition: "my-queue".into(),
//!         items_per_section: NonZeroU64::new(1000).unwrap(),
//!         compression: None,
//!         codec_config: ((0..).into(), ()), // RangeCfg for Vec length, () for u8
//!         page_cache,
//!         write_buffer: NonZeroUsize::new(4096).unwrap(),
//!         replay_buffer: NonZeroUsize::new(4096).unwrap(),
//!     }).await.unwrap();
//!
//!     // Enqueue items
//!     (queue, _) = queue.enqueue(b"task1".to_vec()).await.unwrap();
//!     (queue, _) = queue.enqueue(b"task2".to_vec()).await.unwrap();
//!
//!     // Dequeue and process items (can be done out of order)
//!     while let Some((position, item)) = queue.dequeue().await.unwrap() {
//!         // Process the item...
//!         println!("Processing item at position {}", position);
//!
//!         // Acknowledge after successful processing
//!         queue.ack(position).unwrap();
//!     }
//! });
//! ```

#[cfg(all(test, feature = "arbitrary"))]
mod conformance;
mod cursor;
mod handles;
mod metrics;
mod storage;

pub use handles::{Reader, Writer, init};
pub use storage::{Config, Queue};
use thiserror::Error;

/// Errors that can occur when interacting with [Queue].
#[derive(Debug, Error)]
pub enum Error {
    #[error("journal error: {0}")]
    Journal(#[from] crate::journal::Error),
    #[error("position out of range: {0} (queue size is {1})")]
    PositionOutOfRange(u64, u64),
}
