//! Prunable archive adapter for unfinalized candidates.

use commonware_codec::CodecShared;
use commonware_runtime::Handle;
use commonware_storage::{
    Context,
    archive::{self, Archive as _, Identifier, MultiArchive as _, prunable},
    translator::Translator,
};
use commonware_utils::Array;

/// One exact translated-key read captured from temporary storage.
pub(in crate::multimmit::marshal) struct ReadPlan<E: Context, K: Array, V: CodecShared>(
    prunable::KeyReadPlan<E::Blob, K, V>,
);

impl<E: Context, K: Array, V: CodecShared> ReadPlan<E, K, V> {
    pub(in crate::multimmit::marshal) async fn execute(self) -> Result<Option<V>, archive::Error> {
        self.0.execute().await
    }
}

/// A consuming-handle adapter for candidates that may share an index.
///
/// Mutations return the archive only on success. An error or canceled mutation future therefore
/// destroys the sole handle, matching the storage contract.
pub(in crate::multimmit::marshal) struct TemporaryArchive<T, E, K, V>(
    prunable::Archive<T, E, K, V>,
)
where
    T: Translator,
    E: Context,
    K: Array,
    V: CodecShared;

impl<T, E, K, V> TemporaryArchive<T, E, K, V>
where
    T: Translator,
    E: Context,
    K: Array,
    V: CodecShared,
{
    /// Opens a temporary archive.
    pub(in crate::multimmit::marshal) async fn init(
        context: E,
        config: prunable::Config<T, V::Cfg>,
    ) -> Result<Self, archive::Error> {
        Ok(Self(prunable::Archive::init(context, config).await?))
    }

    /// Gets the candidate stored under the exact key.
    pub(in crate::multimmit::marshal) async fn get(
        &self,
        key: &K,
    ) -> Result<Option<V>, archive::Error> {
        self.0.get(Identifier::Key(key)).await
    }

    /// Captures the candidates for an exact key without performing I/O.
    pub(in crate::multimmit::marshal) fn read_plan(
        &self,
        key: &K,
    ) -> Result<Option<ReadPlan<E, K, V>>, archive::Error> {
        self.0.key_read_plan(key).map(|plan| plan.map(ReadPlan))
    }

    /// Gets every candidate stored at `index`.
    pub(in crate::multimmit::marshal) async fn get_all(
        &self,
        index: u64,
    ) -> Result<Option<Vec<V>>, archive::Error> {
        self.0.get_all(index).await
    }

    /// Returns whether the exact `(index, key)` identity is present without decoding its value.
    pub(in crate::multimmit::marshal) async fn has_at(
        &self,
        index: u64,
        key: &K,
    ) -> Result<bool, archive::Error> {
        self.0.has_at(index, key).await
    }

    /// Returns the highest index containing at least one retained candidate.
    pub(in crate::multimmit::marshal) fn last_index(&self) -> Option<u64> {
        self.0.last_index()
    }

    /// Buffers a candidate unless its exact `(index, key)` identity is already present.
    pub(in crate::multimmit::marshal) async fn put(
        self,
        index: u64,
        key: K,
        value: V,
    ) -> Result<(Self, bool), archive::Error> {
        if self.has_at(index, &key).await? {
            return Ok((self, false));
        }

        self.0
            .put_multi(index, key, value)
            .await
            .map(|archive| (Self(archive), true))
    }

    /// Starts durability for every buffered write without consuming exclusive access.
    pub(in crate::multimmit::marshal) async fn start_sync(
        self,
    ) -> Result<(Self, Handle<()>), archive::Error> {
        let (archive, handle) = self.0.start_sync().await?;
        Ok((Self(archive), handle))
    }

    /// Removes candidates below `min`.
    pub(in crate::multimmit::marshal) async fn prune(
        self,
        min: u64,
    ) -> Result<Self, archive::Error> {
        self.0.prune(min).await.map(TemporaryArchive)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{EncodeSize, Read, Write};
    use commonware_runtime::{
        Runner as _, Supervisor as _,
        buffer::paged::CacheRef,
        deterministic::{self, Context as DeterministicContext},
    };
    use commonware_storage::translator::TwoCap;
    use commonware_utils::{NZU16, NZU64, NZUsize, sequence::FixedBytes};

    type Key = FixedBytes<32>;
    type TestArchive = TemporaryArchive<TwoCap, DeterministicContext, Key, u64>;
    type PresenceArchive = TemporaryArchive<TwoCap, DeterministicContext, Key, DecodePanics>;

    struct DecodePanics(u64);

    impl Read for DecodePanics {
        type Cfg = ();

        fn read_cfg(
            _: &mut impl bytes::Buf,
            _: &Self::Cfg,
        ) -> Result<Self, commonware_codec::Error> {
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

    fn config(context: &DeterministicContext, prefix: &str) -> prunable::Config<TwoCap, ()> {
        prunable::Config {
            translator: TwoCap,
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

    async fn open(context: &DeterministicContext, label: &'static str) -> TestArchive {
        TestArchive::init(
            context.child(label),
            config(context, "temporary-candidates"),
        )
        .await
        .unwrap()
    }

    #[test]
    fn multiplicity_idempotency_lookup_prune_and_reopen() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let first = key(1);
            let second = key(2);
            let retained = key(3);
            let missing = key(4);

            let archive = open(&context, "first_open").await;
            let (archive, inserted) = archive.put(5, first.clone(), 10).await.unwrap();
            assert!(inserted);
            let (archive, inserted) = archive.put(5, second.clone(), 20).await.unwrap();
            assert!(inserted);
            let (archive, inserted) = archive.put(7, retained.clone(), 30).await.unwrap();
            assert!(inserted);
            assert_eq!(archive.last_index(), Some(7));
            assert!(archive.has_at(5, &first).await.unwrap());
            assert!(!archive.has_at(5, &retained).await.unwrap());
            assert!(!archive.has_at(6, &first).await.unwrap());

            // Repeating an exact identity ignores the replacement value. Sync must still cover
            // every write accepted before the duplicate.
            let (archive, inserted) = archive.put(5, first.clone(), 99).await.unwrap();
            assert!(!inserted);
            assert_eq!(archive.get_all(5).await.unwrap(), Some(vec![10, 20]));
            assert_eq!(archive.get(&first).await.unwrap(), Some(10));
            assert_eq!(archive.get(&second).await.unwrap(), Some(20));
            assert_eq!(archive.get(&missing).await.unwrap(), None);
            let (archive, synced) = archive.start_sync().await.unwrap();
            synced.await.unwrap();

            drop(archive);
            let archive = open(&context, "second_open").await;
            assert_eq!(archive.get_all(5).await.unwrap(), Some(vec![10, 20]));
            assert_eq!(archive.get(&first).await.unwrap(), Some(10));
            assert_eq!(archive.get(&retained).await.unwrap(), Some(30));

            let archive = archive.prune(7).await.unwrap();
            assert_eq!(archive.get_all(5).await.unwrap(), None);
            assert_eq!(archive.get(&first).await.unwrap(), None);
            assert_eq!(archive.get(&second).await.unwrap(), None);
            assert_eq!(archive.get(&retained).await.unwrap(), Some(30));

            drop(archive);
            let archive = open(&context, "third_open").await;
            assert_eq!(archive.get_all(5).await.unwrap(), None);
            assert_eq!(archive.get(&retained).await.unwrap(), Some(30));
        });
    }

    #[test]
    fn exact_presence_does_not_decode_value() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let present = key(1);
            let absent = key(2);
            let archive = PresenceArchive::init(
                context.child("first_open"),
                config(&context, "temporary-presence"),
            )
            .await
            .unwrap();
            let (archive, inserted) = archive
                .put(5, present.clone(), DecodePanics(10))
                .await
                .unwrap();
            assert!(inserted);
            let (archive, synced) = archive.start_sync().await.unwrap();
            synced.await.unwrap();
            drop(archive);

            let archive = PresenceArchive::init(
                context.child("second_open"),
                config(&context, "temporary-presence"),
            )
            .await
            .unwrap();
            assert!(archive.has_at(5, &present).await.unwrap());
            assert!(!archive.has_at(5, &absent).await.unwrap());
            assert!(!archive.has_at(6, &present).await.unwrap());
        });
    }
}
