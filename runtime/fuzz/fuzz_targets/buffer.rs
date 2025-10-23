#![no_main]

use arbitrary::Arbitrary;
use commonware_runtime::{
    buffer::{Append, PoolRef, Read, Write},
    deterministic, Blob, Runner, Storage,
};
use commonware_utils::NZUsize;
use libfuzzer_sys::fuzz_target;

const MAX_SIZE: usize = 1024 * 1024;
const SHARED_BLOB: &[u8] = b"buffer_blob";
const MAX_OPERATIONS: usize = 50;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    seed: u64,
    operations: Vec<FuzzOperation>,
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
        buffer_size: u16,
        pool_page_size: u16,
        pool_capacity: u16,
    },
    ReadExact {
        size: u16,
    },
    ReadExactRandomBuf {
        buf: Vec<u8>,
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
    PoolCache {
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
    AppendCloneBlob,
    AppendReadAt {
        data_size: u16,
        offset: u16,
    },
}

fn fuzz(input: FuzzInput) {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let (blob, initial_size) = context
            .open("test_partition", SHARED_BLOB)
            .await
            .expect("cannot open context");

        let prefill = (input.seed as usize) & 0x0FFF;
        if prefill > 0 && initial_size == 0 {
            let initial_data: Vec<u8> = (0..prefill).map(|i| i as u8).collect();
            let _ = blob.write_at(initial_data, 0).await;
        }

        let mut read_buffer = None;
        let mut write_buffer = None;
        let mut append_buffer = None;
        let mut pool_ref = None;
        let mut pool_page_size_ref = None;

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
                            blob.write_at(data, 0).await.expect("cannot write");
                        }
                    }

                    read_buffer = Some(Read::new(blob, blob_size.min(size), NZUsize!(buffer_size)));
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

                    write_buffer = Some(Write::new(blob, initial_size as u64, NZUsize!(capacity)));
                }

                FuzzOperation::CreateAppend {
                    initial_size,
                    buffer_size,
                    pool_page_size,
                    pool_capacity,
                } => {
                    let buffer_size = NZUsize!((buffer_size as usize).clamp(1, MAX_SIZE));
                    let pool_page_size = NZUsize!((pool_page_size as usize).clamp(1, MAX_SIZE));
                    let pool_capacity = NZUsize!((pool_capacity as usize).clamp(1, MAX_SIZE));

                    let (blob, _) = context
                        .open("test_partition", b"append_blob")
                        .await
                        .expect("cannot open write blob");

                    pool_ref = Some(PoolRef::new(pool_page_size, pool_capacity));
                    pool_page_size_ref = Some(pool_page_size);

                    if let Some(ref pool) = pool_ref {
                        append_buffer =
                            Append::new(blob, initial_size as u64, buffer_size, pool.clone())
                                .await
                                .ok();
                    }
                }

                FuzzOperation::ReadExact { size } => {
                    if let Some(ref mut reader) = read_buffer {
                        let size = (size as usize).clamp(0, MAX_SIZE);
                        let current_pos = reader.position();
                        if current_pos.checked_add(size as u64).is_some() {
                            let mut buf = vec![0u8; size];
                            let _ = reader.read_exact(&mut buf, size).await;
                        }
                    }
                }

                FuzzOperation::ReadExactRandomBuf { mut buf, size } => {
                    if size > buf.len() as u16 {
                        continue;
                    }
                    if let Some(ref mut reader) = read_buffer {
                        let _ = reader.read_exact(&mut buf, size as usize).await;
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
                    if let Some(ref writer) = write_buffer {
                        let data = if data.len() > MAX_SIZE {
                            &data[..MAX_SIZE]
                        } else {
                            &data
                        };
                        let offset = offset as u64;
                        if offset.checked_add(data.len() as u64).is_some() {
                            let _ = writer.write_at(data.to_vec(), offset).await;
                        }
                    }
                }

                FuzzOperation::WriteResize { new_size } => {
                    if let Some(ref writer) = write_buffer {
                        let _ = writer.resize(new_size as u64).await;
                    }
                }

                FuzzOperation::WriteSync => {
                    if let Some(ref writer) = write_buffer {
                        let _ = writer.sync().await;
                    }
                }

                FuzzOperation::AppendData { data } => {
                    if let Some(ref append) = append_buffer {
                        // Limit data size and check for overflow
                        let data = if data.len() > MAX_SIZE {
                            data[..MAX_SIZE].to_vec()
                        } else {
                            data
                        };
                        let current_size = append.size().await;
                        if current_size.checked_add(data.len() as u64).is_some() {
                            let _ = append.append(data).await;
                        }
                    }
                }

                FuzzOperation::AppendResize { new_size } => {
                    if let Some(ref append) = append_buffer {
                        let _ = append.resize(new_size as u64).await;
                    }
                }

                FuzzOperation::AppendSync => {
                    if let Some(ref append) = append_buffer {
                        let _ = append.sync().await;
                    }
                }

                FuzzOperation::PoolCache {
                    blob_id,
                    data,
                    offset,
                } => {
                    if let Some(ref pool) = pool_ref {
                        let offset = offset as u64;
                        let data = if data.len() > MAX_SIZE {
                            &data[..MAX_SIZE]
                        } else {
                            &data[..]
                        };
                        if let Some(pool_page_size) = pool_page_size_ref {
                            let aligned_offset = (offset / pool_page_size.get() as u64)
                                * pool_page_size.get() as u64;
                            let _ = pool.cache(blob_id as u64, data, aligned_offset).await;
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
                        let _ = writer.size().await;
                    }
                }

                FuzzOperation::WriteReadAt { data_size, offset } => {
                    if let Some(ref writer) = write_buffer {
                        let size = (data_size as usize).clamp(0, MAX_SIZE);
                        let offset = offset as u64;
                        if offset.checked_add(size as u64).is_some() {
                            let buf = vec![0u8; size];
                            let _ = writer.read_at(buf, offset).await;
                        }
                    }
                }

                FuzzOperation::AppendSize => {
                    if let Some(ref append) = append_buffer {
                        let _ = append.size().await;
                    }
                }

                FuzzOperation::AppendCloneBlob => {
                    if let Some(ref append) = append_buffer {
                        let _ = append.clone_blob();
                    }
                }

                FuzzOperation::AppendReadAt { data_size, offset } => {
                    if let Some(ref append) = append_buffer {
                        let size = (data_size as usize).clamp(0, MAX_SIZE);
                        let offset = offset as u64;
                        if offset.checked_add(size as u64).is_some() {
                            let buf = vec![0u8; size];
                            let _ = append.read_at(buf, offset).await;
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
