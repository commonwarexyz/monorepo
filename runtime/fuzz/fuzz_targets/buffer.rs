#![no_main]

use arbitrary::Arbitrary;
use commonware_runtime::{
    buffer::{Append, PoolRef, Read, Write},
    deterministic, Blob, Runner, Storage,
};
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, Rng, SeedableRng};

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    seed: u64,
    operations: Vec<BufferOperation>,
}

#[derive(Arbitrary, Debug)]
enum BufferOperation {
    CreateRead {
        blob_size: u8,
        buffer_size: u8,
    },
    CreateWrite {
        initial_size: u8,
        capacity: u8,
    },
    CreateAppend {
        initial_size: u8,
        buffer_size: u8,
        pool_page_size: u8,
        pool_capacity: u8,
    },
    ReadExact {
        size: u8,
    },
    ReadSeekTo {
        position: u8,
    },
    ReadResize {
        new_size: u8,
    },
    WriteAt {
        data: Vec<u8>,
        offset: u8,
    },
    WriteResize {
        new_size: u8,
    },
    WriteSync,
    WriteClose,
    AppendData {
        data: Vec<u8>,
    },
    AppendResize {
        new_size: u8,
    },
    AppendSync,
    PoolCache {
        blob_id: u8,
        data: Vec<u8>,
        offset: u8,
    },
}

fn fuzz(input: FuzzInput) {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let mut rng = StdRng::seed_from_u64(input.seed);

        let (blob, initial_size) = context.open("test_partition", b"test_blob").await.unwrap();

        if rng.gen_bool(0.5) && initial_size == 0 {
            let initial_data: Vec<u8> = (0..rng.gen_range(0..256)).map(|_| rng.gen()).collect();
            if !initial_data.is_empty() {
                blob.write_at(initial_data, 0).await.unwrap();
            }
        }

        let mut read_buffer = None;
        let mut write_buffer = None;
        let mut append_buffer = None;
        let mut pool_ref = None;
        let mut pool_page_size = 1024; // Default page size

        for op in input.operations {
            match op {
                BufferOperation::CreateRead {
                    blob_size,
                    buffer_size,
                } => {
                    let blob_size = blob_size as u64;
                    let buffer_size = buffer_size.max(1) as usize;

                    let (blob, size) = context.open("test_partition", b"read_blob").await.unwrap();

                    if size == 0 && blob_size > 0 {
                        let data: Vec<u8> = (0..blob_size).map(|i| i as u8).collect();
                        blob.write_at(data, 0).await.unwrap();
                    }

                    read_buffer = Some(Read::new(blob, blob_size.min(size), buffer_size));
                }

                BufferOperation::CreateWrite {
                    initial_size,
                    capacity,
                } => {
                    let initial_size = initial_size as u64;
                    let capacity = capacity.max(1) as usize;

                    let (blob, _) = context.open("test_partition", b"write_blob").await.unwrap();

                    write_buffer = Some(Write::new(blob, initial_size, capacity));
                }

                BufferOperation::CreateAppend {
                    initial_size,
                    buffer_size,
                    pool_page_size: page_size,
                    pool_capacity,
                } => {
                    let initial_size = initial_size as u64;
                    let buffer_size = buffer_size.max(1) as usize;
                    pool_page_size = page_size.max(1) as usize;
                    let pool_capacity = pool_capacity.max(1) as usize;

                    let (blob, _) = context
                        .open("test_partition", b"append_blob")
                        .await
                        .unwrap();

                    pool_ref = Some(PoolRef::new(pool_page_size, pool_capacity));

                    if let Some(ref pool) = pool_ref {
                        append_buffer = Append::new(blob, initial_size, buffer_size, pool.clone())
                            .await
                            .ok();
                    }
                }

                BufferOperation::ReadExact { size } => {
                    if let Some(ref mut reader) = read_buffer {
                        let size = size as usize;
                        let mut buf = vec![0u8; size];
                        let _ = reader.read_exact(&mut buf, size).await;
                    }
                }

                BufferOperation::ReadSeekTo { position } => {
                    if let Some(ref mut reader) = read_buffer {
                        let _ = reader.seek_to(position as u64);
                    }
                }

                BufferOperation::ReadResize { new_size } => {
                    if let Some(reader) = read_buffer.take() {
                        let _ = reader.resize(new_size as u64).await;
                    }
                }

                BufferOperation::WriteAt { data, offset } => {
                    if let Some(ref writer) = write_buffer {
                        let _ = writer.write_at(data, offset as u64).await;
                    }
                }

                BufferOperation::WriteResize { new_size } => {
                    if let Some(ref writer) = write_buffer {
                        let _ = writer.resize(new_size as u64).await;
                    }
                }

                BufferOperation::WriteSync => {
                    if let Some(ref writer) = write_buffer {
                        let _ = writer.sync().await;
                    }
                }

                BufferOperation::WriteClose => {
                    if let Some(writer) = write_buffer.take() {
                        let _ = writer.close().await;
                    }
                }

                BufferOperation::AppendData { data } => {
                    if let Some(ref append) = append_buffer {
                        let _ = append.append(data).await;
                    }
                }

                BufferOperation::AppendResize { new_size } => {
                    if let Some(ref append) = append_buffer {
                        let _ = append.resize(new_size as u64).await;
                    }
                }

                BufferOperation::AppendSync => {
                    if let Some(ref append) = append_buffer {
                        let _ = append.sync().await;
                    }
                }

                BufferOperation::PoolCache {
                    blob_id,
                    data,
                    offset,
                } => {
                    if let Some(ref pool) = pool_ref {
                        // Ensure offset is page-aligned
                        let offset = offset as u64;
                        let aligned_offset =
                            (offset / pool_page_size as u64) * pool_page_size as u64;
                        let _ = pool.cache(blob_id as u64, &data, aligned_offset).await;
                    }
                }
            }
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
