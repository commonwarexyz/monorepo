use commonware_codec::ReadExt;
use commonware_runtime::{
    Blob, ReadOptions, Runner, Storage, Supervisor, WriteOptions, buffer::paged::CacheRef,
    deterministic,
};
use commonware_storage::journal::segmented::oversized::{Config as OversizedConfig, Oversized};
use commonware_utils::{NZU16, NZUsize};
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
