//! Shared logic for streaming a contiguous journal during replay.
//!
//! Both the fixed and variable journals replay by draining each data blob, then the writable
//! tail, into batches of items. [Source::into_batches] owns that loop so each source only
//! supplies its own [Source::drain] logic.

use crate::journal::Error;
use futures::{stream, Stream};
use std::future::Future;

/// A source of journal items decoded in batches for replay.
pub(super) trait Source: Send + Sized {
    type Item: Send;

    /// Append the next batch of consecutive `(position, item)` results to `out`. An empty batch
    /// means the source is drained; an `Err` is its last word (the driver appends it and stops).
    fn drain(
        &mut self,
        out: &mut Vec<Result<(u64, Self::Item), Error>>,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Stream this source as item batches, stopping at the first error.
    ///
    /// The `Option` state owns the source between polls. An empty batch ends this
    /// source, and an error is emitted once as the source's final item.
    fn into_batches(self) -> impl Stream<Item = Vec<Result<(u64, Self::Item), Error>>> + Send {
        stream::unfold(Some(self), |state| async move {
            let mut source = state?;
            let mut batch = Vec::new();
            match source.drain(&mut batch).await {
                Ok(()) if batch.is_empty() => None,
                Ok(()) => Some((batch, Some(source))),
                Err(err) => {
                    batch.push(Err(err));
                    Some((batch, None))
                }
            }
        })
    }
}
