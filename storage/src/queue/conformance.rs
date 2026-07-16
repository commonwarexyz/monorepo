//! Queue conformance tests

use crate::queue::{Config, Error, Queue};
use commonware_codec::RangeCfg;
use commonware_conformance::conformance_tests;
use commonware_runtime::{
    BufferPooler, Supervisor as _,
    buffer::paged::CacheRef,
    conformance::{StorageConformance, StorageWorkload},
};
use commonware_utils::{NZU16, NZU64, NZUsize};
use core::num::{NonZeroU16, NonZeroU64, NonZeroUsize};
use rand::RngExt as _;

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

struct QueueWorkload;

impl StorageWorkload for QueueWorkload {
    type Error = Error;

    async fn run(
        mut context: commonware_runtime::deterministic::Context,
        seed: u64,
    ) -> Result<(), Self::Error> {
        let mut queue = Queue::<_, Vec<u8>>::init(
            context.child("queue").with_attribute("index", 0),
            config(seed, &context),
        )
        .await?;

        let items_count = context.random_range(1..(ITEMS_PER_SECTION.get() as usize) * 4);
        let mut data = vec![Vec::new(); items_count];
        for item in data.iter_mut() {
            let size = context.random_range(0..256);
            item.resize(size, 0);
            context.fill(item.as_mut_slice());
        }
        for item in &data {
            queue.enqueue(item.clone()).await?;
        }

        let dequeue_count = items_count / 2;
        for _ in 0..dequeue_count {
            let (pos, _) = queue.dequeue().await?.expect("queue should have items");
            queue.ack(pos)?;
        }

        queue.sync().await?;
        drop(queue);

        let mut queue = Queue::<_, Vec<u8>>::init(
            context.child("queue").with_attribute("index", 1),
            config(seed, &context),
        )
        .await?;
        while let Some((pos, item)) = queue.dequeue().await? {
            assert_eq!(item, data[pos as usize]);
            queue.ack(pos)?;
        }
        queue.sync().await
    }
}

conformance_tests! {
    StorageConformance<QueueWorkload> => 512,
}
