//! Archive types for pending and finalized artifacts.
//!
//! Pending L-QCs and history are prunable multi-archives indexed by view, where several candidates
//! may share an index. Finalized artifacts use [`FinalizedArchive`], a write-once archive whose
//! backend (prunable or immutable) is fixed per family when the namespace is created.

use super::{Error, blocks::FinalBlockMeta};
use crate::multimmit::types::{Lqc, TipRecord, TransactionBlock};
use commonware_codec::{Buf, BufsMut, CodecShared, EncodeSize, Read, Write};
use commonware_cryptography::Hasher;
use commonware_runtime::Handle;
use commonware_storage::{
    Context,
    archive::{Archive as _, Identifier, MultiArchive as _, immutable, prunable},
    translator::Translator,
};
use commonware_utils::Array;
use std::sync::Arc;

type Digest<H> = <H as Hasher>::Digest;

/// Pending L-QCs, indexed by view and keyed by certificate digest.
pub(crate) type PendingLqc<T, E, H, V> = prunable::Archive<T, E, Digest<H>, Arc<Lqc<V, Digest<H>>>>;

/// Pending tip-history openings, indexed by view and keyed by commitment.
pub(crate) type PendingHistory<T, E, H> =
    prunable::Archive<T, E, Digest<H>, Arc<TipRecord<Digest<H>>>>;

/// Finalized L-QCs, indexed by L-QC ordinal and keyed by certificate digest.
pub(crate) type FinalLqc<T, E, H, V> = FinalizedArchive<T, E, Digest<H>, Arc<Lqc<V, Digest<H>>>>;

/// Finalized tip-history openings, indexed by history ordinal and keyed by commitment.
pub(crate) type FinalHistory<T, E, H> =
    FinalizedArchive<T, E, Digest<H>, Arc<TipRecord<Digest<H>>>>;

/// Dense finalized output rows, indexed by output and keyed by block digest.
///
/// Rows hold only block metadata; bodies stay in pending custody or the immutable body archive.
pub(crate) type FinalBlockRows<T, E, H> =
    FinalizedArchive<T, E, Digest<H>, FinalBlockMeta<Digest<H>>>;

/// Immutable finalized block bodies, indexed by output and keyed by block digest.
pub(crate) type FinalBody<T, E, H, B> =
    FinalizedArchive<T, E, Digest<H>, Arc<TransactionBlock<H, B>>>;

/// Buffers `value` at `(index, key)` unless that exact identity is already present.
///
/// The presence check does not decode stored values. Consumes the archive and returns it only on
/// success, so a failed or canceled put loses the handle.
pub(crate) async fn put_once<T, E, K, V>(
    archive: prunable::Archive<T, E, K, V>,
    index: u64,
    key: K,
    value: V,
) -> Result<prunable::Archive<T, E, K, V>, Error>
where
    T: Translator,
    E: Context,
    K: Array,
    V: CodecShared,
{
    if archive.has_at(index, &key).await? {
        return Ok(archive);
    }
    Ok(archive.put_multi(index, key, &value).await?)
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

impl<K: Array, V: CodecShared> Read for Entry<K, V> {
    type Cfg = V::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
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
pub(crate) struct FinalizedArchive<T, E, K, V>(Backend<T, E, K, V>)
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

/// Evaluates `$body` with `$archive` bound to whichever backend `$backend` holds.
macro_rules! dispatch {
    ($backend:expr, $archive:ident => $body:expr) => {
        match $backend {
            Backend::Prunable($archive) => $body,
            Backend::Immutable($archive) => $body,
        }
    };
}

/// Runs a consuming operation that returns the archive and rewraps it in its backend.
macro_rules! consume {
    ($backend:expr, $archive:ident => $op:expr) => {
        match $backend {
            Backend::Prunable($archive) => Backend::Prunable($op.await?),
            Backend::Immutable($archive) => Backend::Immutable($op.await?),
        }
    };
}

impl<T, E, K, V> FinalizedArchive<T, E, K, V>
where
    T: Translator,
    E: Context,
    K: Array,
    V: CodecShared,
{
    /// Opens a prunable finalized archive.
    pub(crate) async fn init_prunable(
        context: E,
        config: prunable::Config<T, V::Cfg>,
    ) -> Result<Self, Error> {
        let archive = prunable::Archive::init(context, config).await?;
        Ok(Self(Backend::Prunable(archive)))
    }

    /// Opens an immutable finalized archive.
    pub(crate) async fn init_immutable(
        context: E,
        config: immutable::Config<V::Cfg>,
    ) -> Result<Self, Error> {
        let archive = immutable::Archive::init(context, config).await?;
        Ok(Self(Backend::Immutable(archive)))
    }

    /// Gets the exact key and value stored at an index.
    pub(crate) async fn get_at(&self, index: u64) -> Result<Option<(K, V)>, Error> {
        let entry = dispatch!(&self.0, archive => archive.get(Identifier::Index(index)).await?);
        Ok(entry.map(|entry| (entry.key, entry.value)))
    }

    /// Gets a value by key after verifying the value carries the requested key.
    pub(crate) async fn get_by_key(&self, key: &K) -> Result<Option<V>, Error> {
        let entry = dispatch!(&self.0, archive => archive.get(Identifier::Key(key)).await?);
        match entry {
            Some(entry) if entry.key == *key => Ok(Some(entry.value)),
            Some(_) => Err(Error::Inconsistent(
                "archive key lookup returned a value bound to another key",
            )),
            None => Ok(None),
        }
    }

    /// Returns the lowest retained index, if the archive is non-empty.
    pub(crate) fn first_index(&self) -> Option<u64> {
        dispatch!(&self.0, archive => archive.first_index())
    }

    /// Returns the highest retained index, if the archive is non-empty.
    pub(crate) fn last_index(&self) -> Option<u64> {
        dispatch!(&self.0, archive => archive.last_index())
    }

    /// Buffers a value at an exact `(index, key)` identity.
    ///
    /// Repeating the same identity is idempotent. Reusing an occupied index with another key is
    /// an error and consumes the archive handle.
    pub(crate) async fn put(self, index: u64, key: K, value: V) -> Result<Self, Error> {
        let existing = dispatch!(&self.0, archive => archive.get(Identifier::Index(index)).await?);
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
        Ok(Self(
            consume!(self.0, archive => archive.put(index, key, &entry)),
        ))
    }

    /// Makes every buffered write durable.
    pub(crate) async fn sync(self) -> Result<Self, Error> {
        Ok(Self(consume!(self.0, archive => archive.sync())))
    }

    /// Starts durability for buffered writes and returns its completion handle.
    ///
    /// Backends without a background sync finish syncing before returning.
    pub(crate) async fn start_sync(self) -> Result<(Self, Handle<()>), Error> {
        Ok(match self.0 {
            Backend::Prunable(archive) => {
                let (archive, handle) = archive.start_sync().await?;
                (Self(Backend::Prunable(archive)), handle)
            }
            Backend::Immutable(archive) => {
                let (archive, handle) = archive.start_sync().await?;
                (Self(Backend::Immutable(archive)), handle)
            }
        })
    }

    /// Removes prunable rows below `min`; immutable archives retain all rows.
    pub(crate) async fn prune(self, min: u64) -> Result<Self, Error> {
        Ok(Self(match self.0 {
            Backend::Prunable(archive) => Backend::Prunable(archive.prune(min).await?),
            immutable @ Backend::Immutable(_) => immutable,
        }))
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
    type PendingArchive = prunable::Archive<TwoCap, DeterministicContext, Key, u64>;
    type PresenceArchive = prunable::Archive<TwoCap, DeterministicContext, Key, DecodePanics>;

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Entry<Key, u64>> => 128,
        }
    }

    #[derive(Clone, Copy)]
    enum Kind {
        Prunable,
        Immutable,
    }

    fn prunable_config(
        context: &DeterministicContext,
        prefix: &str,
    ) -> prunable::Config<TwoCap, ()> {
        prunable::Config {
            translator: TwoCap,
            metadata_partition: format!("{prefix}-metadata"),
            key_partition: format!("{prefix}-key"),
            key_page_cache: CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(10)),
            value_partition: format!("{prefix}-value"),
            compression: None,
            codec_config: (),
            items_per_section: NZU64!(1),
            key_write_buffer: NZUsize!(1024),
            value_write_buffer: NZUsize!(1024),
            replay_buffer: NZUsize!(1024),
        }
    }

    async fn open(context: DeterministicContext, kind: Kind, prefix: &str) -> TestArchive {
        match kind {
            Kind::Prunable => {
                let config = prunable_config(&context, prefix);
                TestArchive::init_prunable(context, config).await.unwrap()
            }
            Kind::Immutable => {
                let config = immutable::Config {
                    metadata_partition: format!("{prefix}-metadata"),
                    freezer_table_partition: format!("{prefix}-table"),
                    freezer_table_initial_size: 64,
                    freezer_table_resize_frequency: 4,
                    freezer_table_resize_chunk_size: 64,
                    freezer_key_partition: format!("{prefix}-freezer-key"),
                    freezer_key_page_cache: CacheRef::from_pooler(
                        &context,
                        NZU16!(1024),
                        NZUsize!(10),
                    ),
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
                };
                TestArchive::init_immutable(context, config).await.unwrap()
            }
        }
    }

    #[test]
    fn exact_identity_and_reopen_preserve_data() {
        for (kind, prefix) in [
            (Kind::Prunable, "final-prunable"),
            (Kind::Immutable, "final-immutable"),
        ] {
            let runner = deterministic::Runner::default();
            runner.start(|context| async move {
                let key = Key::new([1; 32]);
                let other = Key::new([2; 32]);
                let archive = open(context.child("first"), kind, prefix).await;
                let archive = archive.put(7, key.clone(), 11).await.unwrap();
                let archive = archive.sync().await.unwrap();

                assert_eq!(archive.get_at(7).await.unwrap(), Some((key.clone(), 11)));
                assert_eq!(archive.get_by_key(&key).await.unwrap(), Some(11));
                assert_eq!(archive.get_by_key(&Key::new([9; 32])).await.unwrap(), None);

                drop(archive);
                let archive = open(context.child("reopen"), kind, prefix).await;
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
        for (kind, prefix, first_retained) in [
            (Kind::Prunable, "prune-prunable", false),
            (Kind::Immutable, "prune-immutable", true),
        ] {
            let runner = deterministic::Runner::default();
            runner.start(|context| async move {
                let first = Key::new([3; 32]);
                let second = Key::new([4; 32]);
                let archive = open(context.child("storage"), kind, prefix).await;
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
        for (kind, prefix) in [
            (Kind::Prunable, "start-sync-prunable"),
            (Kind::Immutable, "start-sync-immutable"),
        ] {
            let runner = deterministic::Runner::default();
            runner.start(|context| async move {
                let first_key = Key::new([5; 32]);
                let second_key = Key::new([6; 32]);
                let archive = open(context.child("storage"), kind, prefix).await;
                let archive = archive.put(1, first_key.clone(), 10).await.unwrap();
                let (archive, sync) = archive.start_sync().await.unwrap();

                // Later writes are outside the returned handle's durability boundary.
                let archive = archive.put(2, second_key, 20).await.unwrap();
                sync.await.unwrap();
                drop(archive);

                let archive = open(context.child("reopen"), kind, prefix).await;
                assert_eq!(archive.get_at(1).await.unwrap(), Some((first_key, 10)));
                assert_eq!(archive.get_at(2).await.unwrap(), None);
            });
        }
    }

    struct DecodePanics(u64);

    impl Read for DecodePanics {
        type Cfg = ();

        fn read_cfg(_: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
            panic!("presence lookup decoded the stored value")
        }
    }

    impl Write for DecodePanics {
        fn write(&self, buf: &mut impl bytes::BufMut) {
            self.0.write(buf);
        }
    }

    impl EncodeSize for DecodePanics {
        fn encode_size(&self) -> usize {
            self.0.encode_size()
        }
    }

    fn key(suffix: u8) -> Key {
        let mut bytes = [1; 32];
        bytes[31] = suffix;
        Key::new(bytes)
    }

    async fn open_pending(context: &DeterministicContext, label: &'static str) -> PendingArchive {
        PendingArchive::init(
            context.child(label),
            prunable_config(context, "pending-candidates"),
        )
        .await
        .unwrap()
    }

    #[test]
    fn put_once_keeps_multiplicity_and_ignores_repeated_identities() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let first = key(1);
            let second = key(2);
            let retained = key(3);
            let missing = key(4);

            let archive = open_pending(&context, "first_open").await;
            let archive = put_once(archive, 5, first.clone(), 10).await.unwrap();
            let archive = put_once(archive, 5, second.clone(), 20).await.unwrap();
            let archive = put_once(archive, 7, retained.clone(), 30).await.unwrap();
            assert_eq!(archive.last_index(), Some(7));
            assert!(archive.has_at(5, &first).await.unwrap());
            assert!(!archive.has_at(5, &retained).await.unwrap());
            assert!(!archive.has_at(6, &first).await.unwrap());

            // Repeating an exact identity ignores the replacement value. Sync must still cover
            // every write accepted before the duplicate.
            let archive = put_once(archive, 5, first.clone(), 99).await.unwrap();
            assert_eq!(archive.get_all(5).await.unwrap(), Some(vec![10, 20]));
            assert_eq!(
                archive.get(Identifier::Key(&first)).await.unwrap(),
                Some(10)
            );
            assert_eq!(
                archive.get(Identifier::Key(&second)).await.unwrap(),
                Some(20)
            );
            assert_eq!(archive.get(Identifier::Key(&missing)).await.unwrap(), None);
            let (archive, synced) = archive.start_sync().await.unwrap();
            synced.await.unwrap();

            drop(archive);
            let archive = open_pending(&context, "second_open").await;
            assert_eq!(archive.get_all(5).await.unwrap(), Some(vec![10, 20]));
            assert_eq!(
                archive.get(Identifier::Key(&retained)).await.unwrap(),
                Some(30)
            );

            let archive = archive.prune(7).await.unwrap();
            assert_eq!(archive.get_all(5).await.unwrap(), None);
            assert_eq!(archive.get(Identifier::Key(&first)).await.unwrap(), None);
            assert_eq!(
                archive.get(Identifier::Key(&retained)).await.unwrap(),
                Some(30)
            );

            drop(archive);
            let archive = open_pending(&context, "third_open").await;
            assert_eq!(archive.get_all(5).await.unwrap(), None);
            assert_eq!(
                archive.get(Identifier::Key(&retained)).await.unwrap(),
                Some(30)
            );
        });
    }

    #[test]
    fn put_once_presence_check_does_not_decode_values() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let present = key(1);
            let absent = key(2);
            let archive = PresenceArchive::init(
                context.child("first_open"),
                prunable_config(&context, "pending-presence"),
            )
            .await
            .unwrap();
            let archive = put_once(archive, 5, present.clone(), DecodePanics(10))
                .await
                .unwrap();
            let archive = put_once(archive, 5, present.clone(), DecodePanics(11))
                .await
                .unwrap();
            let (archive, synced) = archive.start_sync().await.unwrap();
            synced.await.unwrap();
            drop(archive);

            let archive = PresenceArchive::init(
                context.child("second_open"),
                prunable_config(&context, "pending-presence"),
            )
            .await
            .unwrap();
            assert!(archive.has_at(5, &present).await.unwrap());
            assert!(!archive.has_at(5, &absent).await.unwrap());
            assert!(!archive.has_at(6, &present).await.unwrap());
        });
    }
}
