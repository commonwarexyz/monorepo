//! Queue conformance tests

use crate::queue::{Config, Queue};
use commonware_codec::RangeCfg;
use commonware_conformance::{conformance_tests, Conformance};
use commonware_runtime::{buffer::paged::CacheRef, deterministic, Metrics, Runner};
use commonware_utils::{NZUsize, NZU16, NZU64};
use core::num::{NonZeroU16, NonZeroU64, NonZeroUsize};
use rand::Rng;

const WRITE_BUFFER: NonZeroUsize = NZUsize!(1024);
const ITEMS_PER_SECTION: NonZeroU64 = NZU64!(4096);
const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);

struct QueueConformance;

impl Conformance for QueueConformance {
    async fn commit(seed: u64) -> Vec<u8> {
        let runner = deterministic::Runner::seeded(seed);
        runner.start(|mut context| async move {
            let config = Config {
                partition: format!("queue-conformance-{seed}"),
                items_per_section: ITEMS_PER_SECTION,
                page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: WRITE_BUFFER,
                compression: None,
                codec_config: (RangeCfg::new(0..256), ()),
            };
            let mut queue =
                Queue::<_, Vec<u8>>::init(context.with_label("queue"), config)
                    .await
                    .unwrap();

            let items_count = context.gen_range(0..(ITEMS_PER_SECTION.get() as usize) * 4);
            let mut data_to_write = vec![Vec::new(); items_count];
            for item in data_to_write.iter_mut() {
                let size = context.gen_range(0..256);
                item.resize(size, 0);
                context.fill(item.as_mut_slice());
            }

            for item in data_to_write {
                queue.enqueue(item).await.unwrap();
            }
            drop(queue);

            context.storage_audit().to_vec()
        })
    }
}

conformance_tests! {
    QueueConformance => 512,
}
