use arbitrary::Arbitrary;
use commonware_p2p::simulated::helpers::PartitionStrategy;
use commonware_utils::NZUsize;
use std::{num::NonZeroUsize, time::Duration};

pub mod simplex_fuzzer;
pub mod threshold_simplex_fuzzer;

pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(500);
pub const PAGE_SIZE: NonZeroUsize = NZUsize!(1024);
pub const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);

#[derive(Debug, Clone, Arbitrary)]
pub enum Mutation {
    Payload,
    View,
    Parent,
    All,
}

#[derive(Debug, Clone, Arbitrary)]
pub enum Message {
    Notarize,
    Nullify,
    Finalize,
    Random,
}

#[derive(Debug, Arbitrary)]
pub struct FuzzInput {
    pub seed: u64, // Seed for rng
    pub partition: PartitionStrategy,
}
