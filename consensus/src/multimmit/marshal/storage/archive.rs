//! Finalized archive backend adapters.

use commonware_codec::{BufsMut, CodecShared, EncodeSize, Read, Write};
use commonware_runtime::Handle;
use commonware_storage::{
    Context,
    archive::{self, Archive as _, Identifier, immutable, prunable},
    translator::Translator,
};
use commonware_utils::Array;
use std::sync::Arc;
use thiserror::Error;

/// An archive value that decodes once and remains cheaply shareable thereafter.
pub(in crate::multimmit::marshal) struct Shared<T>(Arc<T>);

impl<T> Clone for Shared<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<T> Shared<T> {
    pub(in crate::multimmit::marshal) const fn new(value: Arc<T>) -> Self {
        Self(value)
    }

    pub(in crate::multimmit::marshal) fn into_inner(self) -> Arc<T> {
        self.0
    }
}

impl<T: Read> Read for Shared<T> {
    type Cfg = T::Cfg;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        T::read_cfg(buf, cfg).map(|value| Self(Arc::new(value)))
    }
}

impl<T: Write> Write for Shared<T> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.0.write(buf);
    }

    fn write_bufs(&self, buf: &mut impl BufsMut) {
        self.0.write_bufs(buf);
    }
}

impl<T: EncodeSize> EncodeSize for Shared<T> {
    fn encode_size(&self) -> usize {
        self.0.encode_size()
    }

    fn encode_inline_size(&self) -> usize {
        self.0.encode_inline_size()
    }
}

/// Errors returned by a finalized archive.
#[derive(Debug, Error)]
pub(in crate::multimmit::marshal) enum Error {
    /// The requested index is already bound to another key.
    #[error("archive index {index} is bound to another key")]
    KeyMismatch {
        /// Conflicting archive index.
        index: u64,
    },
    /// A key lookup returned a value carrying another key.
    #[error("archive key lookup returned a value bound to another key")]
    KeyLookupMismatch,
    /// The storage backend failed.
    #[error(transparent)]
    Storage(#[from] archive::Error),
}

/// A value paired with the key used to store it.
///
/// The storage archive does not expose an entry's key when reading by index. Keeping the key in
/// the value lets both backends verify the exact `(index, key)` identity before returning data or
/// accepting an idempotent put.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
struct Entry<K, V> {
    key: K,
    value: V,
}

/// Address of one finalized-archive read step.
pub(in crate::multimmit::marshal) enum ReadRequest<K: Array> {
    Index(u64),
    Key(K),
    Immutable {
        expected_key: Option<K>,
        request: immutable::ReadRequest<K>,
    },
}

/// Result of one owned finalized-archive read step.
pub(in crate::multimmit::marshal) enum ReadOutcome<K: Array, V: CodecShared> {
    Done(Option<(K, V)>),
    Continue(ReadRequest<K>),
}

/// Owned I/O captured synchronously from one finalized archive.
pub(in crate::multimmit::marshal) struct ReadStep<E: Context, K: Array, V: CodecShared> {
    inner: ReadStepInner<E, K, V>,
}

enum ReadStepInner<E: Context, K: Array, V: CodecShared> {
    Missing,
    PrunableIndex(prunable::IndexReadPlan<E::Blob, K, Entry<K, V>>),
    PrunableKey {
        expected_key: K,
        plan: prunable::KeyReadPlan<E::Blob, K, Entry<K, V>>,
    },
    Immutable {
        expected_key: Option<K>,
        step: immutable::ReadStep<E, K, Entry<K, V>>,
    },
}

impl<E: Context, K: Array, V: CodecShared> ReadStep<E, K, V> {
    /// Executes this step without borrowing the archive that captured it.
    pub(in crate::multimmit::marshal) async fn execute(self) -> Result<ReadOutcome<K, V>, Error> {
        let (expected_key, outcome) = match self.inner {
            ReadStepInner::Missing => return Ok(ReadOutcome::Done(None)),
            ReadStepInner::PrunableIndex(plan) => (None, plan.execute().await?),
            ReadStepInner::PrunableKey { expected_key, plan } => {
                (Some(expected_key), plan.execute().await?)
            }
            ReadStepInner::Immutable { expected_key, step } => {
                return match step.execute().await? {
                    immutable::ReadOutcome::Done(entry) => {
                        Self::finish(expected_key, entry).map(ReadOutcome::Done)
                    }
                    immutable::ReadOutcome::Continue(request) => {
                        Ok(ReadOutcome::Continue(ReadRequest::Immutable {
                            expected_key,
                            request,
                        }))
                    }
                };
            }
        };
        Self::finish(expected_key, outcome).map(ReadOutcome::Done)
    }

    fn finish(
        expected_key: Option<K>,
        entry: Option<Entry<K, V>>,
    ) -> Result<Option<(K, V)>, Error> {
        match entry {
            Some(entry) if expected_key.is_none_or(|key| key == entry.key) => {
                Ok(Some((entry.key, entry.value)))
            }
            Some(_) => Err(Error::KeyLookupMismatch),
            None => Ok(None),
        }
    }
}

impl<K: Array, V: CodecShared> Read for Entry<K, V> {
    type Cfg = V::Cfg;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            key: K::read_cfg(buf, &())?,
            value: V::read_cfg(buf, cfg)?,
        })
    }
}

impl<K: Array, V: CodecShared> Write for Entry<K, V> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.key.write(buf);
        self.value.write(buf);
    }

    fn write_bufs(&self, buf: &mut impl BufsMut) {
        self.key.write_bufs(buf);
        self.value.write_bufs(buf);
    }
}

impl<K: Array, V: CodecShared> EncodeSize for Entry<K, V> {
    fn encode_size(&self) -> usize {
        self.key.encode_size() + self.value.encode_size()
    }

    fn encode_inline_size(&self) -> usize {
        self.key.encode_inline_size() + self.value.encode_inline_size()
    }
}

/// A finalized write-once archive with static dispatch over the supported backends.
///
/// Mutating methods consume the archive and return it only on success. A mutation error or a
/// canceled mutation future therefore destroys the sole handle, matching the storage contract.
pub(in crate::multimmit::marshal) struct FinalizedArchive<T, E, K, V>(Backend<T, E, K, V>)
where
    T: Translator,
    E: Context,
    K: Array,
    V: CodecShared;

enum Backend<T, E, K, V>
where
    T: Translator,
    E: Context,
    K: Array,
    V: CodecShared,
{
    Prunable(prunable::Archive<T, E, K, Entry<K, V>>),
    Immutable(immutable::Archive<E, K, Entry<K, V>>),
}

impl<T, E, K, V> FinalizedArchive<T, E, K, V>
where
    T: Translator,
    E: Context,
    K: Array,
    V: CodecShared,
{
    /// Opens a prunable finalized archive.
    pub(in crate::multimmit::marshal) async fn init_prunable(
        context: E,
        config: prunable::Config<T, V::Cfg>,
    ) -> Result<Self, Error> {
        Ok(Self(Backend::Prunable(
            prunable::Archive::init(context, config).await?,
        )))
    }

    /// Opens an immutable finalized archive.
    pub(in crate::multimmit::marshal) async fn init_immutable(
        context: E,
        config: immutable::Config<V::Cfg>,
    ) -> Result<Self, Error> {
        Ok(Self(Backend::Immutable(
            immutable::Archive::init(context, config).await?,
        )))
    }

    /// Gets the exact key and value stored at an index.
    pub(in crate::multimmit::marshal) async fn get_at(
        &self,
        index: u64,
    ) -> Result<Option<(K, V)>, Error> {
        let entry = match &self.0 {
            Backend::Prunable(archive) => archive.get(Identifier::Index(index)).await?,
            Backend::Immutable(archive) => archive.get(Identifier::Index(index)).await?,
        };
        Ok(entry.map(|entry| (entry.key, entry.value)))
    }

    /// Gets a value by key after verifying the value carries the requested key.
    pub(in crate::multimmit::marshal) async fn get_by_key(
        &self,
        key: &K,
    ) -> Result<Option<V>, Error> {
        let entry = match &self.0 {
            Backend::Prunable(archive) => archive.get(Identifier::Key(key)).await?,
            Backend::Immutable(archive) => archive.get(Identifier::Key(key)).await?,
        };
        match entry {
            Some(entry) if entry.key == *key => Ok(Some(entry.value)),
            Some(_) => Err(Error::KeyLookupMismatch),
            None => Ok(None),
        }
    }

    /// Captures one exact read step without performing I/O.
    pub(in crate::multimmit::marshal) fn read_step(
        &self,
        request: ReadRequest<K>,
    ) -> Result<ReadStep<E, K, V>, Error> {
        let inner = match (&self.0, request) {
            (Backend::Prunable(archive), ReadRequest::Index(index)) => archive
                .index_read_plan(index)?
                .map_or(ReadStepInner::Missing, ReadStepInner::PrunableIndex),
            (Backend::Prunable(archive), ReadRequest::Key(key)) => {
                archive.key_read_plan(&key)?.map_or_else(
                    || ReadStepInner::Missing,
                    |plan| ReadStepInner::PrunableKey {
                        expected_key: key,
                        plan,
                    },
                )
            }
            (Backend::Prunable(_), ReadRequest::Immutable { .. }) => {
                unreachable!("immutable continuation belongs to an immutable archive")
            }
            (Backend::Immutable(archive), ReadRequest::Index(index)) => ReadStepInner::Immutable {
                expected_key: None,
                step: archive.read_step(immutable::ReadRequest::index(index))?,
            },
            (Backend::Immutable(archive), ReadRequest::Key(key)) => ReadStepInner::Immutable {
                expected_key: Some(key.clone()),
                step: archive.read_step(immutable::ReadRequest::key(key))?,
            },
            (
                Backend::Immutable(archive),
                ReadRequest::Immutable {
                    expected_key,
                    request,
                },
            ) => ReadStepInner::Immutable {
                expected_key,
                step: archive.read_step(request)?,
            },
        };
        Ok(ReadStep { inner })
    }

    /// Returns the lowest retained index, if the archive is non-empty.
    pub(in crate::multimmit::marshal) fn first_index(&self) -> Option<u64> {
        match &self.0 {
            Backend::Prunable(archive) => archive.first_index(),
            Backend::Immutable(archive) => archive.first_index(),
        }
    }

    /// Buffers a value at an exact `(index, key)` identity.
    ///
    /// Repeating the same identity is idempotent. Reusing an occupied index with another key is
    /// an error and consumes the archive handle.
    pub(in crate::multimmit::marshal) async fn put(
        self,
        index: u64,
        key: K,
        value: V,
    ) -> Result<Self, Error> {
        let existing = match &self.0 {
            Backend::Prunable(archive) => archive.get(Identifier::Index(index)).await?,
            Backend::Immutable(archive) => archive.get(Identifier::Index(index)).await?,
        };
        if let Some(existing) = existing {
            return if existing.key == key {
                Ok(self)
            } else {
                Err(Error::KeyMismatch { index })
            };
        }

        let entry = Entry {
            key: key.clone(),
            value,
        };
        match self.0 {
            Backend::Prunable(archive) => archive
                .put(index, key, entry)
                .await
                .map(|archive| Self(Backend::Prunable(archive)))
                .map_err(Into::into),
            Backend::Immutable(archive) => archive
                .put(index, key, entry)
                .await
                .map(|archive| Self(Backend::Immutable(archive)))
                .map_err(Into::into),
        }
    }

    /// Makes every buffered write durable.
    pub(in crate::multimmit::marshal) async fn sync(self) -> Result<Self, Error> {
        match self.0 {
            Backend::Prunable(archive) => archive
                .sync()
                .await
                .map(|archive| Self(Backend::Prunable(archive)))
                .map_err(Into::into),
            Backend::Immutable(archive) => archive
                .sync()
                .await
                .map(|archive| Self(Backend::Immutable(archive)))
                .map_err(Into::into),
        }
    }

    /// Starts durability for every buffered write and returns the archive immediately.
    pub(in crate::multimmit::marshal) async fn start_sync(
        self,
    ) -> Result<(Self, Handle<()>), Error> {
        match self.0 {
            Backend::Prunable(archive) => archive
                .start_sync()
                .await
                .map(|(archive, handle)| (Self(Backend::Prunable(archive)), handle))
                .map_err(Into::into),
            Backend::Immutable(archive) => archive
                .start_sync()
                .await
                .map(|(archive, handle)| (Self(Backend::Immutable(archive)), handle))
                .map_err(Into::into),
        }
    }

    /// Removes prunable rows below `min`; immutable archives retain all rows.
    pub(in crate::multimmit::marshal) async fn prune(self, min: u64) -> Result<Self, Error> {
        match self.0 {
            Backend::Prunable(archive) => archive
                .prune(min)
                .await
                .map(|archive| Self(Backend::Prunable(archive)))
                .map_err(Into::into),
            Backend::Immutable(archive) => Ok(Self(Backend::Immutable(archive))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{
        Runner as _, Supervisor as _,
        buffer::paged::CacheRef,
        deterministic::{self, Context as DeterministicContext},
    };
    use commonware_storage::translator::TwoCap;
    use commonware_utils::{NZU16, NZU64, NZUsize, sequence::FixedBytes};

    type Key = FixedBytes<32>;
    type TestArchive = FinalizedArchive<TwoCap, DeterministicContext, Key, u64>;

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Entry<Key, u64>> => 128,
        }
    }

    #[derive(Clone, Copy)]
    enum Backend {
        Prunable,
        Immutable,
    }

    async fn open(context: DeterministicContext, backend: Backend, prefix: &str) -> TestArchive {
        let key_page_cache = CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(10));
        match backend {
            Backend::Prunable => TestArchive::init_prunable(
                context,
                prunable::Config {
                    translator: TwoCap,
                    key_partition: format!("{prefix}-key"),
                    key_page_cache,
                    value_partition: format!("{prefix}-value"),
                    compression: None,
                    codec_config: (),
                    items_per_section: NZU64!(1),
                    key_write_buffer: NZUsize!(1024),
                    value_write_buffer: NZUsize!(1024),
                    replay_buffer: NZUsize!(1024),
                },
            )
            .await
            .unwrap(),
            Backend::Immutable => TestArchive::init_immutable(
                context,
                immutable::Config {
                    metadata_partition: format!("{prefix}-metadata"),
                    freezer_table_partition: format!("{prefix}-table"),
                    freezer_table_initial_size: 64,
                    freezer_table_resize_frequency: 4,
                    freezer_table_resize_chunk_size: 64,
                    freezer_key_partition: format!("{prefix}-freezer-key"),
                    freezer_key_page_cache: key_page_cache,
                    freezer_value_partition: format!("{prefix}-freezer-value"),
                    freezer_value_target_size: 1024,
                    freezer_value_compression: None,
                    ordinal_partition: format!("{prefix}-ordinal"),
                    items_per_section: NZU64!(1),
                    freezer_key_write_buffer: NZUsize!(1024),
                    freezer_value_write_buffer: NZUsize!(1024),
                    ordinal_write_buffer: NZUsize!(1024),
                    replay_buffer: NZUsize!(1024),
                    codec_config: (),
                },
            )
            .await
            .unwrap(),
        }
    }

    #[test]
    fn exact_identity_and_reopen_preserve_data() {
        for (backend, prefix) in [
            (Backend::Prunable, "final-prunable"),
            (Backend::Immutable, "final-immutable"),
        ] {
            let runner = deterministic::Runner::default();
            runner.start(|context| async move {
                let key = Key::new([1; 32]);
                let other = Key::new([2; 32]);
                let archive = open(context.child("first"), backend, prefix).await;
                let archive = archive.put(7, key.clone(), 11).await.unwrap();
                let archive = archive.sync().await.unwrap();

                assert_eq!(archive.get_at(7).await.unwrap(), Some((key.clone(), 11)));
                assert_eq!(archive.get_by_key(&key).await.unwrap(), Some(11));
                assert_eq!(archive.get_by_key(&Key::new([9; 32])).await.unwrap(), None);

                drop(archive);
                let archive = open(context.child("reopen"), backend, prefix).await;
                assert_eq!(archive.get_at(7).await.unwrap(), Some((key.clone(), 11)));

                let archive = archive.put(7, key, 99).await.unwrap();
                assert_eq!(
                    archive.get_by_key(&Key::new([1; 32])).await.unwrap(),
                    Some(11)
                );
                assert!(matches!(
                    archive.put(7, other, 22).await,
                    Err(Error::KeyMismatch { index: 7 })
                ));
            });
        }
    }

    #[test]
    fn prune_depends_on_backend() {
        for (backend, prefix, first_retained) in [
            (Backend::Prunable, "prune-prunable", false),
            (Backend::Immutable, "prune-immutable", true),
        ] {
            let runner = deterministic::Runner::default();
            runner.start(|context| async move {
                let first = Key::new([3; 32]);
                let second = Key::new([4; 32]);
                let archive = open(context.child("storage"), backend, prefix).await;
                let archive = archive.put(1, first.clone(), 10).await.unwrap();
                let archive = archive.put(2, second.clone(), 20).await.unwrap();
                let archive = archive.sync().await.unwrap();
                let archive = archive.prune(2).await.unwrap();

                assert_eq!(
                    archive.get_by_key(&first).await.unwrap().is_some(),
                    first_retained
                );
                assert_eq!(archive.get_by_key(&second).await.unwrap(), Some(20));
            });
        }
    }

    #[test]
    fn start_sync_returns_ownership_and_covers_prior_write() {
        for (backend, prefix) in [
            (Backend::Prunable, "start-sync-prunable"),
            (Backend::Immutable, "start-sync-immutable"),
        ] {
            let runner = deterministic::Runner::default();
            runner.start(|context| async move {
                let first_key = Key::new([5; 32]);
                let second_key = Key::new([6; 32]);
                let archive = open(context.child("storage"), backend, prefix).await;
                let archive = archive.put(1, first_key.clone(), 10).await.unwrap();
                let (archive, sync) = archive.start_sync().await.unwrap();

                // The returned archive remains usable while the prior writes synchronize.
                let archive = archive.put(2, second_key, 20).await.unwrap();
                sync.await.unwrap();
                drop(archive);

                let archive = open(context.child("reopen"), backend, prefix).await;
                assert_eq!(archive.get_at(1).await.unwrap(), Some((first_key, 10)));
                assert_eq!(archive.get_at(2).await.unwrap(), None);
            });
        }
    }
}
