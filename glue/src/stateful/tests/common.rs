use crate::simulate::processed::ProcessedHeight;
use commonware_consensus::{
    marshal::{self, core::Variant, Identifier as MarshalIdentifier},
    simplex::mocks::scheme::Scheme as MockScheme,
    types::Height,
};
use commonware_cryptography::{ed25519, sha256, Digestible};
use commonware_runtime::{buffer::paged::CacheRef, Quota};
use commonware_storage::{archive::prunable, translator::TwoCap};
use commonware_utils::{NZUsize, NZU16, NZU64};
use std::{
    future::Future,
    num::{NonZeroU16, NonZeroU32, NonZeroU64, NonZeroUsize},
    pin::Pin,
    sync::Arc,
};

/// Type-erased accessor returning the oldest operation location still retained
/// by a validator's database set (the minimum across all databases).
///
/// Used by pruning properties to observe that QMDB actually discarded
/// historical operations through the live actor.
pub(crate) type OldestRetained =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = u64> + Send>> + Send + Sync>;

pub(super) const EPOCH_LENGTH: NonZeroU64 = NZU64!(u64::MAX);
pub(super) const NAMESPACE: &[u8] = b"stateful_e2e_test";
pub(super) const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
pub(super) const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
pub(super) const IO_BUFFER_SIZE: NonZeroUsize = NZUsize!(2048);
pub(super) const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

pub(super) fn u64_to_digest(v: u64) -> sha256::Digest {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&v.to_be_bytes());
    sha256::Digest::from(bytes)
}

pub(super) fn digest_to_u64(d: &sha256::Digest) -> u64 {
    let bytes: &[u8] = d.as_ref();
    u64::from_be_bytes(bytes[..8].try_into().unwrap())
}

/// Prunable archive config so marshal can actually prune finalized history.
///
/// Production marshals back finalized blocks and certificates with prunable
/// archives; immutable archives never prune, so the glue e2e tests use prunable
/// archives to exercise marshal pruning.
pub(super) fn archive_config<C>(
    prefix: &str,
    name: &str,
    page_cache: CacheRef,
    codec_config: C,
) -> prunable::Config<TwoCap, C> {
    prunable::Config {
        translator: TwoCap,
        key_partition: format!("{prefix}-{name}-key"),
        key_page_cache: page_cache,
        value_partition: format!("{prefix}-{name}-value"),
        compression: None,
        codec_config,
        items_per_section: NZU64!(10),
        key_write_buffer: IO_BUFFER_SIZE,
        value_write_buffer: IO_BUFFER_SIZE,
        replay_buffer: IO_BUFFER_SIZE,
    }
}

/// Per-validator state inspectable by test properties.
///
/// Generic over the marshal variant so both single-db and multi-db engines
/// can share the same state type and property implementations.
#[derive(Clone)]
pub(crate) struct MockValidatorState<V: Variant> {
    pub(super) marshal: marshal::core::Mailbox<MockScheme<ed25519::PublicKey>, V>,
    pub(super) state_sync_entries: u64,
    pub(super) state_sync_height: Option<u64>,
    pub(super) oldest_retained: OldestRetained,
}

impl<V: Variant> PartialEq for MockValidatorState<V> {
    fn eq(&self, other: &Self) -> bool {
        self.state_sync_entries == other.state_sync_entries
            && self.state_sync_height == other.state_sync_height
    }
}

impl<V> MockValidatorState<V>
where
    V: Variant,
    V::ApplicationBlock: Digestible<Digest = sha256::Digest>,
{
    pub(crate) async fn digest_at_height(&self, height: u64) -> Option<sha256::Digest> {
        self.marshal
            .get_block(MarshalIdentifier::Height(Height::new(height)))
            .await
            .map(|b| b.digest())
    }

    pub(crate) const fn state_sync_height(&self) -> Option<u64> {
        self.state_sync_height
    }

    pub(crate) const fn state_sync_entries(&self) -> u64 {
        self.state_sync_entries
    }

    pub(crate) async fn oldest_retained(&self) -> u64 {
        (self.oldest_retained)().await
    }
}

impl<V> ProcessedHeight for MockValidatorState<V>
where
    V: Variant,
    V::ApplicationBlock: Digestible<Digest = sha256::Digest>,
{
    async fn processed_height(&self) -> u64 {
        self.marshal
            .get_processed_height()
            .await
            .map_or(0, |height| height.get())
    }
}
