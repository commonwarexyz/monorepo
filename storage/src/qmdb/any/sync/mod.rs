//! Shared synchronization logic for any databases.

pub(crate) mod impls;

#[cfg(test)]
pub(crate) mod tests;

use crate::mmr::journaled::Config as MmrConfig;
use commonware_runtime::Metrics;

/// Database configurations that support sync operations.
///
/// Both `FixedConfig` and `VariableConfig` implement this trait,
/// allowing the sync implementation to extract common configuration
/// without knowing the specific config type.
pub trait Config: Clone {
    /// Extract the MMR configuration for sync initialization.
    fn mmr_config(&self) -> MmrConfig;
}

/// Indexes that can be constructed during sync operations.
///
/// Both `ordered::Index` and `unordered::Index` have the same
/// constructor signature: `fn new(ctx: impl Metrics, translator: T)`
pub trait Index: Sized {
    type Translator: crate::translator::Translator + Clone;
    /// Create a new index for use during sync.
    fn new(ctx: impl Metrics, translator: Self::Translator) -> Self;
}
