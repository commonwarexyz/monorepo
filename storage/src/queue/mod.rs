//! A durable, at-least-once delivery queue backed by a [`variable::Journal`](crate::journal::contiguous::variable).
//!
//! [Queue] provides a persistent message queue with at-least-once delivery semantics.
//! Items are durably stored in a journal and will survive crashes. The reader must
//! explicitly acknowledge each item after processing. On restart, all non-pruned
//! items are re-delivered (acknowledged or not).
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
//!         partition: "my_queue".to_string(),
//!         items_per_section: NonZeroU64::new(1000).unwrap(),
//!         compression: None,
//!         codec_config: ((0..).into(), ()), // RangeCfg for Vec length, () for u8
//!         page_cache,
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
//!         // Acknowledge after successful processing
//!         queue.ack(position).unwrap();
//!     }
//! });
//! ```

#[cfg(test)]
mod conformance;
mod metrics;
pub mod shared;
mod storage;

pub use shared::{Reader, Writer};
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
