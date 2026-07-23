#![no_main]

use arbitrary::Arbitrary;
use commonware_runtime::{
    Blob, BufferPoolConfig, BufferPooler, Runner, Storage,
    buffer::{
        Read, Write,
        paged::{CacheRef, Writer},
    },
    deterministic,
};
use commonware_utils::{NZU16, NZU32, NZUsize};
use libfuzzer_sys::fuzz_target;

const MAX_SIZE: usize = 1024 * 1024;
const MAX_CACHE_BYTES: usize = 64 * 1024 * 1024;
const SHARED_BLOB: &[u8] = b"buffer_blob";
const MAX_OPERATIONS: usize = 50;

/// Smallest storage class exponent fuzzed (4 KiB).
const MIN_CLASS_EXPONENT: u32 = 12;
/// Largest storage class exponent fuzzed (8 MiB).
const MAX_CLASS_EXPONENT: u32 = 23;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    seed: u64,
    /// Bit `i` enables the storage class of size `1 << (MIN_CLASS_EXPONENT + i)`,
    /// so the fuzzer exercises sparse layouts whose gaps route to the next
    /// enabled class. The largest class is always enabled so every request the
    /// operations can produce stays within the pool's routing range.
    storage_class_mask: u16,
    operations: Vec<FuzzOperation>,
}

/// Builds a sparse storage pool layout from the fuzzed class mask.
fn storage_pool_config(mask: u16) -> BufferPoolConfig {
    let classes = (MIN_CLASS_EXPONENT..=MAX_CLASS_EXPONENT).filter_map(|exponent| {
        let bit = exponent - MIN_CLASS_EXPONENT;
        // Force the largest class on so the layout is never empty.
        let enabled = mask & (1 << bit) != 0 || exponent == MAX_CLASS_EXPONENT;
        enabled.then(|| (NZUsize!(1usize << exponent), NZU32!(32)))
    });
    BufferPoolConfig::for_storage()
        .with_size_classes(classes)
        .with_thread_cache_disabled()
}

#[derive(Arbitrary, Debug)]
enum FuzzOperation {
    CreateRead {
        blob_size: u16,
        buffer_size: u16,
    },
    CreateWrite {
        initial_size: u16,
        capacity: u16,
    },
    CreateAppend {
        initial_size: u16,
        buffer_size: u32,
        cache_page_size: u16,
        cache_capacity: u16,
    },
    Read {
        size: u16,
    },
    ReadSeekTo {
        position: u16,
    },
    ReadResize {
        new_size: u16,
    },
    WriteAt {
        data: Vec<u8>,
        offset: u16,
    },
    WriteResize {
        new_size: u16,
    },
    WriteSync,
    AppendData {
        data: Vec<u8>,
    },
    AppendResize {
        new_size: u16,
    },
    AppendSync,
    PageCache {
        blob_id: u16,
        data: Vec<u8>,
        offset: u16,
    },
    ReadPosition,
    ReadBufferRemaining,
    ReadBlobRemaining,
    ReadBlobSize,
    WriteSize,
    WriteReadAt {
        data_size: u16,
        offset: u16,
    },
    AppendSize,
    AppendAsReader {
        buffer_size: u16,
    },
    AppendReadAt {
        data_size: u16,
        offset: u16,
    },
}

fn fuzz(input: FuzzInput) {
    let executor = deterministic::Runner::new(
        deterministic::Config::new()
            .with_storage_buffer_pool_config(storage_pool_config(input.storage_class_mask)),
    );
    executor.start(|context| async move {
        let (blob, initial_size) = context
            .open("test_partition", SHARED_BLOB)
            .await
            .expect("cannot open context");

        let prefill = (input.seed as usize) & 0x0FFF;
        if prefill > 0 && initial_size == 0 {
            let initial_data: Vec<u8> = (0..prefill).map(|i| i as u8).collect();
            let _ = blob.write_at(0, initial_data).await;
        }

        let mut read_buffer = None;
        let mut write_buffer = None;
        let mut append_buffer = None;
        let mut cache_ref = None;
        let mut cache_page_size_ref = None;

        for op in input.operations.into_iter().take(MAX_OPERATIONS) {
            match op {
                FuzzOperation::CreateRead {
                    blob_size,
                    buffer_size,
                } => {
                    let blob_size = blob_size as u64;
                    let buffer_size = (buffer_size as usize).clamp(1, MAX_SIZE);

                    let (blob, size) = context
                        .open("test_partition", b"read_blob")
                        .await
                        .expect("cannot open context");

                    if size == 0 && blob_size > 0 {
                        let data: Vec<u8> = (0..blob_size).map(|i| i as u8).collect();
                        if (0u64).checked_add(data.len() as u64).is_some() {
                            blob.write_at(0, data).await.expect("cannot write");
                        }
                    }

                    read_buffer = Some(Read::from_pooler(
                        &context,
                        blob,
                        blob_size.min(size),
                        NZUsize!(buffer_size),
                    ));
                }

                FuzzOperation::CreateWrite {
                    initial_size,
                    capacity,
                } => {
                    let capacity = (capacity as usize).clamp(1, MAX_SIZE);

                    let (blob, _) = context
                        .open("test_partition", b"write_blob")
                        .await
                        .expect("cannot open context");

                    write_buffer = Some(Write::from_pooler(
                        &context,
                        blob,
                        initial_size as u64,
                        NZUsize!(capacity),
                    ));
                }

                FuzzOperation::CreateAppend {
                    initial_size,
                    buffer_size,
                    cache_page_size,
                    cache_capacity,
                } => {
                    let buffer_size = (buffer_size as usize).clamp(0, MAX_SIZE);
                    let cache_page_size = cache_page_size.max(1);
                    // Cache slots come from the storage pool, so each slot occupies
                    // the smallest enabled size class that fits the page, which in
                    // sparse layouts can be much larger than the page itself. Cap
                    // capacity against that class size. Pages larger than every
                    // class fall back to untracked allocations of their exact size.
                    let cache_slot_size = context
                        .storage_buffer_pool()
                        .config()
                        .class_for(cache_page_size as usize)
                        .map_or(cache_page_size as usize, |class| class.size.get());
                    let max_cache_capacity = (MAX_CACHE_BYTES / cache_slot_size).max(1);
                    let cache_capacity =
                        NZUsize!((cache_capacity as usize).clamp(1, max_cache_capacity));

                    let (blob, _) = context
                        .open("test_partition", b"append_blob")
                        .await
                        .expect("cannot open write blob");

                    // Only create a new cache if one doesn't exist. Reusing the same blob with
                    // a different page size would corrupt reads since page size is embedded
                    // in the CRC records.
                    if cache_ref.is_none() {
                        cache_ref = Some(CacheRef::from_pooler(
                            &context,
                            NZU16!(cache_page_size),
                            cache_capacity,
                        ));
                        cache_page_size_ref = Some(cache_page_size);
                    }

                    if let Some(ref cache) = cache_ref {
                        append_buffer =
                            Writer::new(blob, initial_size as u64, buffer_size, cache.clone())
                                .await
                                .ok();
                    }
                }

                FuzzOperation::Read { size } => {
                    if let Some(ref mut reader) = read_buffer {
                        let size = (size as usize).clamp(0, MAX_SIZE);
                        let current_pos = reader.position();
                        if current_pos.checked_add(size as u64).is_some() {
                            let _ = reader.read(size).await;
                        }
                    }
                }

                FuzzOperation::ReadSeekTo { position } => {
                    if let Some(ref mut reader) = read_buffer {
                        let _ = reader.seek_to(position as u64);
                    }
                }

                FuzzOperation::ReadResize { new_size } => {
                    if let Some(reader) = read_buffer.take() {
                        let _ = reader.resize(new_size as u64).await;
                    }
                }

                FuzzOperation::WriteAt { data, offset } => {
                    if let Some(ref mut writer) = write_buffer {
                        let data = if data.len() > MAX_SIZE {
                            &data[..MAX_SIZE]
                        } else {
                            &data
                        };
                        let offset = offset as u64;
                        if offset.checked_add(data.len() as u64).is_some() {
                            let _ = writer.write_at(offset, data.to_vec()).await;
                        }
                    }
                }

                FuzzOperation::WriteResize { new_size } => {
                    if let Some(ref mut writer) = write_buffer {
                        let _ = writer.resize(new_size as u64).await;
                    }
                }

                FuzzOperation::WriteSync => {
                    if let Some(ref mut writer) = write_buffer {
                        let _ = writer.sync().await;
                    }
                }

                FuzzOperation::AppendData { data } => {
                    if let Some(append) = append_buffer.as_mut() {
                        // Limit data size and check for overflow
                        let data = if data.len() > MAX_SIZE {
                            data[..MAX_SIZE].to_vec()
                        } else {
                            data
                        };
                        let current_size = append.size();
                        if current_size.checked_add(data.len() as u64).is_some() {
                            let _ = append.append(&data).await;
                        }
                    }
                }

                FuzzOperation::AppendResize { new_size } => {
                    if let Some(append) = append_buffer.as_mut() {
                        let _ = append.resize(new_size as u64).await;
                    }
                }

                FuzzOperation::AppendSync => {
                    if let Some(append) = append_buffer.as_mut() {
                        let _ = append.sync().await;
                    }
                }

                FuzzOperation::PageCache {
                    blob_id,
                    data,
                    offset,
                } => {
                    if let Some(ref cache) = cache_ref {
                        let offset = offset as u64;
                        if data.len() >= cache.page_size() as usize {
                            let data = &data[..cache.page_size() as usize];
                            if let Some(cache_page_size) = cache_page_size_ref {
                                let aligned_offset =
                                    (offset / cache_page_size as u64) * cache_page_size as u64;
                                let _ = cache.cache(blob_id as u64, data, aligned_offset);
                            }
                        }
                    }
                }

                FuzzOperation::ReadPosition => {
                    if let Some(ref reader) = read_buffer {
                        let _ = reader.position();
                    }
                }

                FuzzOperation::ReadBufferRemaining => {
                    if let Some(ref reader) = read_buffer {
                        let _ = reader.buffer_remaining();
                    }
                }

                FuzzOperation::ReadBlobRemaining => {
                    if let Some(ref reader) = read_buffer {
                        let _ = reader.blob_remaining();
                    }
                }

                FuzzOperation::ReadBlobSize => {
                    if let Some(ref reader) = read_buffer {
                        let _ = reader.blob_size();
                    }
                }

                FuzzOperation::WriteSize => {
                    if let Some(ref writer) = write_buffer {
                        let _ = writer.size();
                    }
                }

                FuzzOperation::WriteReadAt { data_size, offset } => {
                    if let Some(ref writer) = write_buffer {
                        let size = (data_size as usize).clamp(0, MAX_SIZE);
                        let offset = offset as u64;
                        if offset.checked_add(size as u64).is_some() {
                            let _ = writer.read_at(offset, size).await;
                        }
                    }
                }

                FuzzOperation::AppendSize => {
                    if let Some(append) = append_buffer.as_mut() {
                        let _ = append.size();
                    }
                }

                FuzzOperation::AppendAsReader { buffer_size } => {
                    if let Some(append) = append_buffer.as_mut() {
                        let buffer_size = NZUsize!((buffer_size as usize).clamp(1, MAX_SIZE));
                        // This fuzzer never corrupts data, so CRC validation in replay
                        // should always succeed. A failure here indicates a bug.
                        let _ = append
                            .replay(buffer_size)
                            .await
                            .expect("Failed to create replay");
                    }
                }

                FuzzOperation::AppendReadAt { data_size, offset } => {
                    if let Some(append) = append_buffer.as_mut() {
                        let size = (data_size as usize).clamp(0, MAX_SIZE);
                        let offset = offset as u64;
                        if offset.checked_add(size as u64).is_some() {
                            let _ = append.read_at(offset, size).await;
                        }
                    }
                }
            }
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
