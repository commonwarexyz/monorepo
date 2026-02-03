#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::{sha256, Digest, Sha256};
use commonware_runtime::{deterministic, Clock, Metrics, Runner, Storage};
use commonware_storage::{MerkleizedBitMap, UnmerkleizedBitMap};
use commonware_utils::bitmap::BitMap;
use libfuzzer_sys::fuzz_target;

const MAX_OPERATIONS: usize = 100;
const CHUNK_SIZE: usize = 32;

enum Bitmap<E: Clock + Storage + Metrics, D: Digest, const N: usize> {
    Merkleized(MerkleizedBitMap<E, D, N>),
    Unmerkleized(UnmerkleizedBitMap<E, D, N>),
}

#[derive(Arbitrary, Debug, Clone)]
enum BitmapOperation {
    Append { bit: bool },
    GetBit { bit_offset: u64 },
    SetBit { bit_offset: u64, bit: bool },
    GetChunk { bit_offset: u64 },
    LastChunk,
    Len,
    PrunedBits,
    PruneToBit { bit_offset: u64 },
    Merkleize,
    GetNode { position: u64 },
    Size,
    Proof { bit_offset: u64 },
    RestorePruned,
    WritePruned,
}

#[derive(Debug)]
struct FuzzInput {
    seed: u64,
    operations: Vec<BitmapOperation>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let seed = u.arbitrary()?;
        let num_ops = u.int_in_range(1..=MAX_OPERATIONS)?;
        let mut operations = Vec::with_capacity(num_ops);

        for _ in 0..num_ops {
            operations.push(u.arbitrary()?);
        }

        Ok(FuzzInput { seed, operations })
    }
}

fn fuzz(input: FuzzInput) {
    let runner = deterministic::Runner::seeded(input.seed);
    const PARTITION: &str = "fuzz_mmr_bitmap_test_partition";

    runner.start(|context| async move {
        let mut hasher = commonware_storage::mmr::StandardHasher::<Sha256>::new();
        let init_bitmap = MerkleizedBitMap::<_, _, CHUNK_SIZE>::init(
            context.with_label("bitmap"),
            PARTITION,
            None,
            &mut hasher,
        )
        .await
        .unwrap();
        let mut bitmap = Bitmap::Merkleized(init_bitmap);
        let mut bit_count = 0u64;
        let mut pruned_bits = 0u64;
        let mut restarts = 0usize;

        for op in input.operations {
            bitmap = match op {
                BitmapOperation::Append { bit } => {
                    let mut bitmap = match bitmap {
                        Bitmap::Merkleized(bitmap) => bitmap.into_dirty(),
                        Bitmap::Unmerkleized(bitmap) => bitmap,
                    };
                    bitmap.push(bit);
                    bit_count += 1;
                    Bitmap::Unmerkleized(bitmap)
                }

                BitmapOperation::GetBit { bit_offset } => {
                    if bit_count > 0 {
                        let live = bit_count.saturating_sub(pruned_bits);
                        if live > 0 {
                            let safe_offset = pruned_bits + (bit_offset % live);
                            let _ = match &bitmap {
                                Bitmap::Merkleized(bitmap) => bitmap.get_bit(safe_offset),
                                Bitmap::Unmerkleized(bitmap) => bitmap.get_bit(safe_offset),
                            };
                        }
                    }
                    bitmap
                }

                BitmapOperation::SetBit { bit_offset, bit } => {
                    let mut bitmap = match bitmap {
                        Bitmap::Merkleized(bitmap) => bitmap.into_dirty(),
                        Bitmap::Unmerkleized(bitmap) => bitmap,
                    };
                    if bit_count > 0 {
                        let safe_offset = (bit_offset % bit_count).max(pruned_bits);
                        if safe_offset < bit_count {
                            bitmap.set_bit(safe_offset, bit);
                        }
                    }
                    Bitmap::Unmerkleized(bitmap)
                }

                BitmapOperation::GetChunk { bit_offset } => {
                    if bit_count > 0 {
                        let safe_offset = (bit_offset % bit_count).max(pruned_bits);
                        let chunk_aligned = (safe_offset / BitMap::<CHUNK_SIZE>::CHUNK_SIZE_BITS)
                            * BitMap::<CHUNK_SIZE>::CHUNK_SIZE_BITS;
                        if chunk_aligned >= pruned_bits && chunk_aligned < bit_count {
                            let _ = match &bitmap {
                                Bitmap::Merkleized(bitmap) => {
                                    bitmap.get_chunk_containing(chunk_aligned)
                                }
                                Bitmap::Unmerkleized(bitmap) => {
                                    bitmap.get_chunk_containing(chunk_aligned)
                                }
                            };
                        }
                    }
                    bitmap
                }

                BitmapOperation::LastChunk => {
                    if bit_count > pruned_bits {
                        let (chunk, bits) = match &bitmap {
                            Bitmap::Merkleized(bitmap) => bitmap.last_chunk(),
                            Bitmap::Unmerkleized(bitmap) => bitmap.last_chunk(),
                        };
                        assert!(bits <= BitMap::<CHUNK_SIZE>::CHUNK_SIZE_BITS);
                        assert!(chunk.len() == CHUNK_SIZE);
                    }
                    bitmap
                }

                BitmapOperation::Len => {
                    let count = match &bitmap {
                        Bitmap::Merkleized(bitmap) => bitmap.len(),
                        Bitmap::Unmerkleized(bitmap) => bitmap.len(),
                    };
                    assert_eq!(count, bit_count);
                    bitmap
                }

                BitmapOperation::PrunedBits => {
                    let pruned = match &bitmap {
                        Bitmap::Merkleized(bitmap) => bitmap.pruned_bits(),
                        Bitmap::Unmerkleized(bitmap) => bitmap.pruned_bits(),
                    };
                    assert_eq!(pruned, pruned_bits);
                    bitmap
                }

                BitmapOperation::PruneToBit { bit_offset } => {
                    let mut bitmap = match bitmap {
                        Bitmap::Merkleized(bitmap) => bitmap,
                        Bitmap::Unmerkleized(bitmap) => {
                            bitmap.merkleize(&mut hasher).await.unwrap()
                        }
                    };
                    if bit_count > 0 {
                        let safe_offset = (bit_offset % (bit_count + 1)).min(bit_count);
                        if safe_offset >= pruned_bits {
                            bitmap.prune_to_bit(safe_offset).unwrap();
                            // Update pruned_bits to match what was actually pruned
                            pruned_bits = bitmap.pruned_bits();

                            assert_eq!(bitmap.pruned_bits(), pruned_bits);
                        }
                    }
                    Bitmap::Merkleized(bitmap)
                }

                BitmapOperation::Merkleize => {
                    let bitmap = match bitmap {
                        Bitmap::Merkleized(bitmap) => bitmap,
                        Bitmap::Unmerkleized(bitmap) => {
                            bitmap.merkleize(&mut hasher).await.unwrap()
                        }
                    };
                    Bitmap::Merkleized(bitmap)
                }

                BitmapOperation::GetNode { position } => {
                    let bitmap = match bitmap {
                        Bitmap::Merkleized(bitmap) => bitmap,
                        Bitmap::Unmerkleized(bitmap) => {
                            bitmap.merkleize(&mut hasher).await.unwrap()
                        }
                    };
                    if bitmap.size() > 0 {
                        let safe_pos = position % bitmap.size().as_u64();
                        let _ = bitmap.get_node(safe_pos.into());
                    }
                    Bitmap::Merkleized(bitmap)
                }

                BitmapOperation::Size => {
                    match &bitmap {
                        Bitmap::Merkleized(bitmap) => bitmap.size(),
                        Bitmap::Unmerkleized(bitmap) => bitmap.size(),
                    };
                    bitmap
                }

                BitmapOperation::Proof { bit_offset } => {
                    let bitmap = match bitmap {
                        Bitmap::Merkleized(bitmap) => bitmap,
                        Bitmap::Unmerkleized(bitmap) => {
                            bitmap.merkleize(&mut hasher).await.unwrap()
                        }
                    };
                    if bit_count > pruned_bits {
                        let bit_offset = (bit_offset % (bit_count - pruned_bits)) + pruned_bits;
                        if let Ok((proof, chunk)) = bitmap.proof(&mut hasher, bit_offset).await {
                            let root = bitmap.root();
                            assert!(
                                MerkleizedBitMap::<
                                    deterministic::Context,
                                    sha256::Digest,
                                    CHUNK_SIZE,
                                >::verify_bit_inclusion(
                                    &mut hasher,
                                    &proof,
                                    &chunk,
                                    bit_offset,
                                    &root
                                ),
                                "failed to verify bit {bit_offset}",
                            );
                        }
                    }
                    Bitmap::Merkleized(bitmap)
                }

                BitmapOperation::RestorePruned => {
                    let bitmap = MerkleizedBitMap::<_, _, CHUNK_SIZE>::init(
                        context
                            .with_label("bitmap")
                            .with_attribute("instance", restarts),
                        PARTITION,
                        None,
                        &mut hasher,
                    )
                    .await
                    .unwrap();
                    restarts += 1;
                    // Update tracking variables to match restored state
                    bit_count = bitmap.len();
                    pruned_bits = bitmap.pruned_bits();
                    Bitmap::Merkleized(bitmap)
                }

                BitmapOperation::WritePruned => {
                    let mut bitmap = match bitmap {
                        Bitmap::Merkleized(bitmap) => bitmap,
                        Bitmap::Unmerkleized(bitmap) => {
                            bitmap.merkleize(&mut hasher).await.unwrap()
                        }
                    };
                    let _ = bitmap.write_pruned().await;
                    Bitmap::Merkleized(bitmap)
                }
            }
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
