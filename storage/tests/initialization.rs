use commonware_codec::ReadExt;
use commonware_cryptography::Sha256;
use commonware_parallel::Sequential;
use commonware_runtime::{
    Blob, ReadOptions, Runner, Storage, Supervisor, WriteOptions,
    buffer::paged::{CacheRef, Writer, corrupt_page},
    deterministic,
};
use commonware_storage::{
    journal::{
        authenticated::Backing,
        contiguous::{Contiguous, fixed, variable},
        segmented::oversized::{Config as OversizedConfig, Oversized},
    },
    merkle::{Location, mmr::Family},
    qmdb::{keyless, sync},
};
use commonware_utils::{NZU16, NZU64, NZUsize, non_empty_range, probability};
use std::sync::Arc;

fn cfg(
    context: &deterministic::Context,
    partition: &str,
    per_section: u64,
) -> variable::Config<()> {
    variable::Config {
        partition: partition.into(),
        items_per_section: std::num::NonZeroU64::new(per_section).unwrap(),
        compression: None,
        codec_config: (),
        page_cache: CacheRef::from_pooler(context, NZU16!(16), NZUsize!(4)),
        write_buffer: NZUsize!(1),
        replay_buffer: NZUsize!(256),
    }
}

#[test]
fn test_recovery_failure_must_not_clear_durable_data() {
    deterministic::Runner::default().start(|context| async move {
        let config = cfg(&context, "initialization-recovery-clear", 20);
        let mut journal =
            variable::Journal::<_, u64>::init_at_size(context.child("seed"), config.clone(), 20)
                .await
                .unwrap();
        for value in 0..8 {
            (journal, _) = journal.append(&value).await.unwrap();
        }
        let (journal, handle) = journal.start_sync().await.unwrap();
        handle.await.unwrap();
        drop(journal);
        *context.storage_fault_config().write() = deterministic::FaultConfig {
            remove_rate: Some(probability!(1.0)),
            ..Default::default()
        };
        // Removing derived offsets may fail, but must never authorize clearing the data.
        drop(variable::Journal::<_, u64>::init(context.child("interrupted"), config.clone()).await);
        *context.storage_fault_config().write() = deterministic::FaultConfig::default();
        let journal = variable::Journal::<_, u64>::init(context.child("retry"), config)
            .await
            .unwrap();
        assert_eq!(
            journal.bounds(),
            20..28,
            "ordinary recovery must retain committed data after retry"
        );
        for pos in 20..28 {
            assert_eq!(journal.read(pos).await.unwrap(), pos - 20);
        }
    });
}

#[test]
fn test_sync_rejects_missing_acknowledged_data() {
    deterministic::Runner::default().start(|context| async move {
        let config = cfg(&context, "initialization-missing-anchor", 5);
        let mut journal = variable::Journal::<_, u64>::init(context.child("seed"), config.clone())
            .await
            .unwrap();
        for value in 0..20 {
            (journal, _) = journal.append(&value).await.unwrap();
        }
        _ = journal.sync().await.unwrap();
        for section in 1u64..=4 {
            context
                .remove(
                    "initialization-missing-anchor_data",
                    Some(&section.to_be_bytes()),
                )
                .await
                .unwrap();
        }
        let result = <variable::Journal<_, u64> as Backing<_>>::recover(
            context.child("sync"),
            config,
            Some(40),
        )
        .await;
        let error = result.err().expect("missing acknowledged data must fail");
        assert!(
            matches!(error, commonware_storage::journal::Error::Corruption(_)),
            "must reject missing data instead of authorizing a reset: {error}"
        );
    });
}

#[test]
fn test_keyless_synced_range_reopens() {
    type Db = keyless::fixed::Db<Family, deterministic::Context, u64, Sha256, Sequential>;
    deterministic::Runner::default().start(|context| async move {
        let make_config = |suffix: &str| {
            let cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            keyless::fixed::Config {
                merkle: commonware_storage::merkle::full::Config {
                    journal_partition: format!("{suffix}-merkle"),
                    metadata_partition: format!("{suffix}-metadata"),
                    items_per_blob: NZU64!(11),
                    write_buffer: NZUsize!(1024),
                    replay_buffer: NZUsize!(1024),
                    strategy: Sequential,
                    page_cache: cache.clone(),
                },
                log: fixed::Config {
                    partition: format!("{suffix}-log"),
                    items_per_blob: NZU64!(1),
                    page_cache: cache,
                    write_buffer: NZUsize!(1024),
                    replay_buffer: NZUsize!(1024),
                },
            }
        };
        let source = Db::init(context.child("source"), make_config("source"), None)
            .await
            .unwrap();
        let mut batch = source.new_batch();
        for value in 0..10 {
            batch = batch.append(value);
        }
        let batch = batch.merkleize(&source, None, Location::new(0)).await;
        let (source, _) = source.apply_batch(batch).await.unwrap();
        let source = Arc::new(source.sync().await.unwrap());
        let config = make_config("client");
        let client: Db = sync::sync(sync::engine::Config {
            context: context.child("client"),
            db_config: config.clone(),
            target: sync::Target {
                root: source.root(),
                range: non_empty_range!(Location::new(5), source.bounds().end),
            },
            source: source.clone(),
            apply_batch_size: NZU64!(10),
            fetch_batch_size: NZU64!(5),
            max_outstanding_requests: 1,
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 8,
        })
        .await
        .unwrap();
        assert_eq!(*client.bounds().start, 5);
        assert_eq!(*client.inactivity_floor_loc(), 0);
        _ = client.sync().await.unwrap();
        let reopened = Db::init(context.child("reopened"), config, None).await;
        assert!(
            reopened.is_ok(),
            "valid synced Keyless must reopen: {reopened:?}"
        );
    });
}

#[derive(Clone, Debug)]
struct Entry(u64, u64, u32);
impl commonware_codec::Write for Entry {
    fn write(&self, buf: &mut impl commonware_runtime::BufMut) {
        self.0.write(buf);
        self.1.write(buf);
        self.2.write(buf);
    }
}
impl commonware_codec::Read for Entry {
    type Cfg = ();
    fn read_cfg(
        buf: &mut impl commonware_codec::Buf,
        _: &(),
    ) -> Result<Self, commonware_codec::Error> {
        Ok(Self(u64::read(buf)?, u64::read(buf)?, u32::read(buf)?))
    }
}
impl commonware_codec::FixedSize for Entry {
    const SIZE: usize = 20;
}
impl commonware_storage::journal::segmented::oversized::Record for Entry {
    fn value_location(&self) -> (u64, u32) {
        (self.1, self.2)
    }
    fn with_location(self, offset: u64, size: u32) -> Self {
        Self(self.0, offset, size)
    }
}

#[test]
fn test_oversized_overshooting_cap_keeps_lazy_committed_validation() {
    deterministic::Runner::default().start(|context| async move {
        let cfg = OversizedConfig {
            index_partition: "initialization-oversized-index".into(),
            value_partition: "initialization-oversized-values".into(),
            index_page_cache: CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8)),
            index_write_buffer: NZUsize!(1024),
            value_write_buffer: NZUsize!(1024),
            replay_buffer: NZUsize!(4096),
            compression: None,
            codec_config: (),
        };
        let seed_context = context.child("seed");
        let mut replay = Oversized::<_, Entry, [u8; 16]>::init_with_metadata(
            &seed_context,
            cfg.clone(),
            "initialization-markers".into(),
            ReadOptions::default(),
        )
        .await
        .unwrap();
        while let Some(item) = replay.next().await {
            item.unwrap();
        }
        let mut journal = replay.finish_tracked().await.unwrap();
        (journal, _, _, _) = journal.append(1, Entry(1, 0, 0), &[1; 16]).await.unwrap();
        let offset;
        (journal, _, offset, _) = journal.append(1, Entry(2, 0, 0), &[2; 16]).await.unwrap();
        _ = journal.sync_all().await.unwrap();
        let mut markers = commonware_storage::metadata::Metadata::<
            _,
            commonware_utils::sequence::U64,
            u64,
        >::init(
            context.child("markers"),
            commonware_storage::metadata::Config {
                partition: "initialization-markers".into(),
                codec_config: (),
            },
        )
        .await
        .unwrap();
        markers.put(commonware_utils::sequence::U64::new(1), 2);
        _ = markers.sync().await.unwrap();
        let (blob, _) = context
            .open(&cfg.value_partition, &1u64.to_be_bytes())
            .await
            .unwrap();
        blob.write_at(offset, vec![0xff], WriteOptions::SYNC)
            .await
            .unwrap();
        drop(blob);
        let open_context = context.child("ordinary");
        let mut replay = Oversized::<_, Entry, [u8; 16]>::init_with_metadata(
            &open_context,
            cfg.clone(),
            "initialization-markers".into(),
            ReadOptions::default(),
        )
        .await
        .unwrap();
        while let Some(item) = replay.next().await {
            item.unwrap();
        }
        let journal = replay.finish_tracked().await.unwrap();
        assert_eq!(journal.size(1).unwrap(), 40);
        drop(journal);
        let cap_context = context.child("cap");
        let result = Oversized::<_, Entry, [u8; 16]>::init_with_metadata_at_most(
            &cap_context,
            cfg,
            "initialization-markers".into(),
            ReadOptions::default(),
            1,
            u64::MAX,
        )
        .await;
        assert!(
            result.is_ok(),
            "an overshooting cap must preserve ordinary lazy validation"
        );
    });
}

#[test]
fn test_unbounded_fixed_repairs_hole_after_full_capacity() {
    deterministic::Runner::default().start(|context| async move {
        let cache = CacheRef::from_pooler(&context, NZU16!(8), NZUsize!(8));
        let cfg = fixed::Config {
            partition: "initialization-extra-tail".into(),
            items_per_blob: NZU64!(2),
            page_cache: cache.clone(),
            write_buffer: NZUsize!(128),
            replay_buffer: NZUsize!(128),
        };
        let (blob, size) = context
            .open("initialization-extra-tail-blobs", &0u64.to_be_bytes())
            .await
            .unwrap();
        let mut writer = Writer::new(blob, size, 128, cache).await.unwrap();
        writer.append(&[1; 32]).await.unwrap();
        writer.sync().await.unwrap();
        drop(writer);
        corrupt_page(
            &context,
            "initialization-extra-tail-blobs",
            &0u64.to_be_bytes(),
            2,
            8,
        )
        .await;
        let result = fixed::Journal::<_, u64>::init(context.child("open"), cfg).await;
        assert!(
            result.is_ok(),
            "unbounded recovery must trim a hole after capacity: {result:?}"
        );
    });
}
