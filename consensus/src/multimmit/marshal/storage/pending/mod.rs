//! Pending custody for producer blocks from every chain.
//!
//! Each reclaimable segment stores fixed-size index records and variable-size bodies in an
//! Oversized journal. Records hold direct body locations. A durable manifest preserves the global
//! append position and each chain's prune floor across crashes.

mod manifest;
mod plan;
mod read;
mod record;
mod store;
#[cfg(test)]
mod tests;

pub(crate) use read::{BodyRead, BodyReadGroup, BodyReader, BodySource, ColdSource};
pub(crate) use store::{
    Append, BODY_READ_CONCURRENCY, ChainFloors, JournalBuffers, PendingBlocks, PendingConfig,
    Retirement,
};
