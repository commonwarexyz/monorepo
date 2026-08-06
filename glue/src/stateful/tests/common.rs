use crate::{
    simulate::processed::ProcessedHeight,
    stateful::db::{AttachableResolver, ServeSource},
};
use commonware_consensus::{
    marshal::{self, Identifier as MarshalIdentifier, core::Variant},
    simplex::mocks::scheme::Scheme as MockScheme,
    types::Height,
};
use commonware_cryptography::{Digestible, ed25519, sha256};
use commonware_runtime::{Quota, buffer::paged::CacheRef};
use commonware_storage::{
    archive::prunable,
    qmdb::sync::{FeedbackTx, Request, Response, Source},
    translator::TwoCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize, sync::Mutex};
use std::{
    future::Future,
    num::{NonZeroU16, NonZeroU32, NonZeroU64, NonZeroUsize},
    pin::Pin,
    sync::Arc,
};

/// Type-erased accessor returning the oldest operation location still retained
/// by a validator's database set (tests observe one representative member).
///
/// Used by pruning properties to observe that QMDB actually discarded
/// historical operations through the live actor.
pub(crate) type OldestRetained =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = u64> + Send>> + Send + Sync>;

/// Type-erased accessor returning `(committed op count, root)` for every
/// database in a validator's set, in set order.
///
/// Used by the root-agreement property: the root is a pure function of the
/// committed operation history, so validators whose databases committed the
/// same number of operations must report identical roots.
pub(crate) type StorageRoots =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Vec<(u64, sha256::Digest)>> + Send>> + Send + Sync>;

/// Wraps one sync resolver and captures the serving source the stateful actor attaches,
/// so tests can observe published durable snapshots without a production read API.
#[derive(Clone)]
pub(crate) struct CapturingResolver<R, Src> {
    inner: R,
    pub(crate) source: Arc<Mutex<Option<Src>>>,
}

impl<R, Src> CapturingResolver<R, Src> {
    pub(crate) fn new(inner: R) -> Self {
        Self {
            inner,
            source: Arc::new(Mutex::new(None)),
        }
    }
}

impl<R, Src> AttachableResolver<Src> for CapturingResolver<R, Src>
where
    R: AttachableResolver<Src>,
    Src: ServeSource,
{
    async fn attach_source(&self, source: Src) {
        *self.source.lock() = Some(source.clone());
        self.inner.attach_source(source).await;
    }
}

impl<R, Src> Source for CapturingResolver<R, Src>
where
    R: Source,
    Src: Send + Sync + 'static,
{
    type Family = R::Family;
    type Digest = R::Digest;
    type Op = R::Op;
    type Error = R::Error;

    async fn serve(
        &self,
        request: Request<Self::Family>,
    ) -> Result<(Response<Self::Family, Self::Op, Self::Digest>, FeedbackTx), Self::Error> {
        self.inner.serve(request).await
    }
}

pub(super) const EPOCH_LENGTH: NonZeroU64 = NZU64!(u64::MAX);
pub(super) const NAMESPACE: &[u8] = b"stateful_e2e_test";
pub(super) const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
pub(super) const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
pub(super) const IO_BUFFER_SIZE: NonZeroUsize = NZUsize!(2048);
pub(super) const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);
pub(super) const SLOW_SYNC_MARSHAL_RETENTION: usize = 128;

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
    pub(super) storage_roots: StorageRoots,
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

    pub(crate) async fn storage_roots(&self) -> Vec<(u64, sha256::Digest)> {
        (self.storage_roots)().await
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
