//! Journal conformance tests

use crate::journal::contiguous::{fixed, variable};
use commonware_codec::RangeCfg;
use commonware_conformance::{conformance_tests, Conformance};
use commonware_runtime::{buffer::PoolRef, deterministic, Blob, Metrics, Runner};
use commonware_utils::{NZUsize, NZU64};
use core::num::{NonZeroU64, NonZeroUsize};
use rand::Rng;

const WRITE_BUFFER: NonZeroUsize = NZUsize!(1024);
const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(4096);
const PAGE_SIZE: NonZeroUsize = NZUsize!(1024);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);

struct FixedJournal;

impl Conformance for FixedJournal {
    async fn commit(seed: u64) -> Vec<u8> {
        let runner = deterministic::Runner::seeded(seed);
        runner.start(|mut context| async move {
            let config = fixed::Config {
                partition: format!("fixed-journal-conformance-{seed}"),
                items_per_blob: ITEMS_PER_BLOB,
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: WRITE_BUFFER,
            };
            let mut journal = fixed::Journal::<_, u64>::init(context.with_label("journal"), config)
                .await
                .unwrap();

            let mut data_to_write =
                vec![0u64; context.gen_range(0..(ITEMS_PER_BLOB.get() as usize) * 4)];
            context.fill(&mut data_to_write[..]);

            for item in data_to_write.iter() {
                journal.append(*item).await.unwrap();
            }
            journal.sync().await.unwrap();

            assert_eq!(
                journal.blobs.len(),
                data_to_write.len() / ITEMS_PER_BLOB.get() as usize
            );

            let mut contents: Vec<u8> = Vec::with_capacity(data_to_write.len() * size_of::<u64>());

            // Read all blobs and the tail into a single buffer.
            for (_, blob) in journal.blobs.iter() {
                let buf = vec![0u8; blob.size().await as usize];
                contents.extend(blob.read_at(buf, 0).await.unwrap().as_ref());
            }
            let buf = vec![0u8; journal.tail.size().await as usize];
            contents.extend(journal.tail.read_at(buf, 0).await.unwrap().as_ref());

            contents
        })
    }
}

struct VariableJournal;

impl Conformance for VariableJournal {
    async fn commit(seed: u64) -> Vec<u8> {
        let runner = deterministic::Runner::seeded(seed);
        runner.start(|mut context| async move {
            let config = variable::Config {
                partition: format!("variable-journal-conformance-{seed}"),
                items_per_section: ITEMS_PER_BLOB,
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: WRITE_BUFFER,
                compression: None,
                codec_config: (RangeCfg::new(0..256), ()),
            };
            let mut journal =
                variable::Journal::<_, Vec<u8>>::init(context.with_label("journal"), config)
                    .await
                    .unwrap();

            let mut data_to_write =
                vec![Vec::new(); context.gen_range(0..(ITEMS_PER_BLOB.get() as usize) * 4)];
            for item in data_to_write.iter_mut() {
                let size = context.gen_range(0..256);
                item.resize(size, 0);
                context.fill(item.as_mut_slice());
            }
            let data_len = data_to_write.len();
            let data_flat_len = data_to_write.iter().map(|v| v.len()).sum();

            for item in data_to_write {
                journal.append(item).await.unwrap();
            }
            journal.sync().await.unwrap();

            assert_eq!(
                journal.data.blobs.len(),
                data_len.div_ceil(ITEMS_PER_BLOB.get() as usize),
            );

            let mut contents: Vec<u8> = Vec::with_capacity(data_flat_len);

            // Read all of the data journal's blobs into the buffer.
            for (_, blob) in journal.data.blobs.iter() {
                let buf = vec![0u8; blob.size().await as usize];
                contents.extend(blob.read_at(buf, 0).await.unwrap().as_ref());
            }

            // Read all of the offsets journal's blobs into the buffer.
            for (_, blob) in journal.offsets.blobs.iter() {
                let buf = vec![0u8; blob.size().await as usize];
                contents.extend(blob.read_at(buf, 0).await.unwrap().as_ref());
            }
            let buf = vec![0u8; journal.offsets.tail.size().await as usize];
            contents.extend(journal.offsets.tail.read_at(buf, 0).await.unwrap().as_ref());

            contents
        })
    }
}

conformance_tests! {
    FixedJournal => 512,
    VariableJournal => 512,
}
