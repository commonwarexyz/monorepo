#![no_main]

use arbitrary::Arbitrary;
use commonware_runtime::{
    buffer::{Append, PoolRef, Read, Write},
    deterministic, Blob, Runner, Storage,
};
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, Rng, SeedableRng};

const MAX_SIZE: usize = 1024 * 1024;

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
    WriteClose,
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
    ExtremeSeekNearU64Max,
    ExtremeWriteNearU64Max {
        len: u64,
    },
}

fn fuzz(input: FuzzInput) {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let mut rng = StdRng::seed_from_u64(input.seed);

        let (blob, initial_size) = context
            .open("test_partition", b"test_blob")
            .await
            .expect("cannot open context");

        if rng.gen_bool(0.5) && initial_size == 0 {
            let initial_data: Vec<u8> =
                (0..rng.gen_range(0..MAX_SIZE)).map(|_| rng.gen()).collect();
            if !initial_data.is_empty() {
                blob.write_at(initial_data, 0).await.expect("cannot write");
            }
        }

        let mut read_buffer = None;
        let mut write_buffer = None;
        let mut append_buffer = None;
        let mut pool_ref = None;
        let mut pool_page_size = 1024;

        for op in input.operations {
            match op {
                FuzzOperation::CreateRead {
                    blob_size,
                    buffer_size,
                } => {
                    let blob_size = blob_size as u64;
                    // buffer size must be greater than zero
                    let buffer_size = (buffer_size as usize).clamp(1, MAX_SIZE);

                    let (blob, size) = context
                        .open("test_partition", b"read_blob")
                        .await
                        .expect("cannot open context");

                    if size == 0 && blob_size > 0 {
                        let data: Vec<u8> = (0..blob_size).map(|i| i as u8).collect();
                        blob.write_at(data, 0).await.expect("cannot write");
                    }

                    read_buffer = Some(Read::new(blob, blob_size.min(size), buffer_size));
                }

                FuzzOperation::CreateWrite {
                    initial_size,
                    capacity,
                } => {
                    // buffer capacity must be greater than zero
                    let capacity = (capacity as usize).clamp(1, MAX_SIZE);

                    let (blob, _) = context
                        .open("test_partition", b"write_blob")
                        .await
                        .expect("cannot open context");

                    write_buffer = Some(Write::new(blob, initial_size as u64, capacity));
                }

                FuzzOperation::CreateAppend {
                    initial_size,
                    buffer_size,
                    pool_page_size: page_size,
                    pool_capacity,
                } => {
                    let buffer_size = (buffer_size as usize).clamp(0, MAX_SIZE);
                    pool_page_size = (page_size as usize).clamp(0, MAX_SIZE);
                    let pool_capacity = (pool_capacity as usize).clamp(1, MAX_SIZE);

                    let (blob, _) = context
                        .open("test_partition", b"append_blob")
                        .await
                        .expect("cannot open write blob");

                    pool_ref = Some(PoolRef::new(pool_page_size, pool_capacity));

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
                        let mut buf = vec![0u8; size];
                        reader
                            .read_exact(&mut buf, size)
                            .await
                            .expect("read reader");
                    }
                }

                FuzzOperation::ReadSeekTo { position } => {
                    if let Some(ref mut reader) = read_buffer {
                        reader.seek_to(position as u64).expect("seek to position");
                    }
                }

                FuzzOperation::ReadResize { new_size } => {
                    if let Some(reader) = read_buffer.take() {
                        reader.resize(new_size as u64).await.expect("read resize");
                    }
                }

                FuzzOperation::WriteAt { data, offset } => {
                    if let Some(ref writer) = write_buffer {
                        let data = if data.len() > MAX_SIZE {
                            &data[..MAX_SIZE]
                        } else {
                            &data
                        };
                        writer
                            .write_at(data.to_vec(), offset as u64)
                            .await
                            .expect("write writer");
                    }
                }

                FuzzOperation::WriteResize { new_size } => {
                    if let Some(ref writer) = write_buffer {
                        writer.resize(new_size as u64).await.expect("write resize");
                    }
                }

                FuzzOperation::WriteSync => {
                    if let Some(ref writer) = write_buffer {
                        writer.sync().await.expect("write sync");
                    }
                }

                FuzzOperation::WriteClose => {
                    if let Some(writer) = write_buffer.take() {
                        writer.close().await.expect("write close");
                    }
                }

                FuzzOperation::AppendData { data } => {
                    if let Some(ref append) = append_buffer {
                        append.append(data).await.expect("append data");
                    }
                }

                FuzzOperation::AppendResize { new_size } => {
                    if let Some(ref append) = append_buffer {
                        append.resize(new_size as u64).await.expect("append resize");
                    }
                }

                FuzzOperation::AppendSync => {
                    if let Some(ref append) = append_buffer {
                        append.sync().await.expect("append sync");
                    }
                }

                FuzzOperation::PoolCache {
                    blob_id,
                    data,
                    offset,
                } => {
                    if let Some(ref pool) = pool_ref {
                        let offset = offset as u64;
                        let aligned_offset =
                            (offset / pool_page_size as u64) * pool_page_size as u64;
                        let data = if data.len() > MAX_SIZE {
                            &data[..MAX_SIZE]
                        } else {
                            &data
                        };
                        pool.cache(blob_id as u64, data, aligned_offset).await;
                    }
                }

                FuzzOperation::ExtremeSeekNearU64Max => {
                    if let Some(ref mut reader) = read_buffer {
                        let near = u64::MAX - rng.gen_range(0..=MAX_SIZE) as u64;
                        reader.seek_to(near).expect("seek to near");
                    }
                }

                FuzzOperation::ExtremeWriteNearU64Max { len } => {
                    if let Some(ref writer) = write_buffer {
                        let off =
                            u64::MAX - (len).saturating_add(rng.gen_range(0..=MAX_SIZE) as u64);
                        let data = vec![0; len as usize];
                        writer
                            .write_at(data, off)
                            .await
                            .expect("extreme write writer");
                    }
                }
            }
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
