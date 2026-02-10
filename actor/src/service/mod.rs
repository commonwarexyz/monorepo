//! Shared service loop primitive for actors.

use commonware_utils::NZUsize;
use std::num::NonZeroUsize;

mod builder;
pub use builder::{MultiLaneServiceBuilder, MultiLaneUnboundedServiceBuilder, ServiceBuilder};

mod driver;
pub use driver::ActorService;

mod types;
pub use types::{DuplicateLaneError, Lanes};

const DEFAULT_MAILBOX_CAPACITY: NonZeroUsize = NZUsize!(64);
const DEFAULT_MAX_INFLIGHT_READS: NonZeroUsize = NZUsize!(64);

#[cfg(test)]
mod tests;
