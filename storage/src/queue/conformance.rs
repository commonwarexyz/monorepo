//! Queue conformance tests

use crate::{
    queue::{Config, Queue},
    Persistable,
};
use commonware_codec::RangeCfg;
use commonware_conformance::{conformance_tests, Conformance};
use commonware_runtime::{buffer::paged::CacheRef, deterministic, BufferPooler, Metrics, Runner};
use commonware_utils::{NZUsize, NZU16, NZU64};
use core::num::{NonZeroU16, NonZeroU64, NonZeroUsize};
use rand::Rng;

const WRITE_BUFFER: NonZeroUsize = NZUsize!(1024);
const ITEMS_PER_SECTION: NonZeroU64 = NZU64!(64);
const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);

fn config(seed: u64, pooler: &impl BufferPooler) -> Config<(RangeCfg<usize>, ())> {
    Config {
        partition: format!("queue-conformance-{seed}"),
        items_per_section: ITEMS_PER_SECTION,
        page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE),
        write_buffer: WRITE_BUFFER,
        compression: None,
        codec_config: (RangeCfg::new(0..256), ()),
    }
}

struct QueueConformance;

impl Conformance for QueueConformance {
    async fn commit(seed: u64) -> Vec<u8> {
        let runner = deterministic::Runner::seeded(seed);
        runner.start(|mut context| async move {
            let mut queue =
                Queue::<_, Vec<u8>>::init(context.with_label("queue"), config(seed, &context))
                    .await
                    .unwrap();

            // Enqueue random variable-length items across multiple sections
            let items_count = context.gen_range(1..(ITEMS_PER_SECTION.get() as usize) * 4);
            let mut data = vec![Vec::new(); items_count];
            for item in data.iter_mut() {
                let size = context.gen_range(0..256);
                item.resize(size, 0);
                context.fill(item.as_mut_slice());
            }
            for item in &data {
                queue.enqueue(item.clone()).await.unwrap();
            }

            // Dequeue half and ack them
            let dequeue_count = items_count / 2;
            for _ in 0..dequeue_count {
                let (pos, _) = queue.dequeue().await.unwrap().unwrap();
                queue.ack(pos).await.unwrap();
            }

            // Sync (commit + prune), then drop
            queue.sync().await.unwrap();
            drop(queue);

            // Re-open and verify surviving items are readable
            let mut queue =
                Queue::<_, Vec<u8>>::init(context.with_label("queue2"), config(seed, &context))
                    .await
                    .unwrap();
            while let Some((pos, item)) = queue.dequeue().await.unwrap() {
                assert_eq!(item, data[pos as usize]);
                queue.ack(pos).await.unwrap();
            }
            queue.sync().await.unwrap();
            drop(queue);

            context.storage_audit().to_vec()
        })
    }
}

conformance_tests! {
    QueueConformance => 512,
}
