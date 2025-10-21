use commonware_utils::NZUsize;
use std::{num::NonZeroUsize, time::Duration};

pub mod fuzzer;
pub mod invariants;
pub mod types;
pub mod utils;

pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(500);
pub const PAGE_SIZE: NonZeroUsize = NZUsize!(1024);
pub const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
