#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::{sha256, Digest, Sha256};
use commonware_runtime::{deterministic, Runner};
use commonware_storage::{CleanAuthenticatedBitMap, DirtyAuthenticatedBitMap};
use libfuzzer_sys::fuzz_target;

const MAX_OPERATIONS: usize = 100;
const CHUNK_SIZE: usize = 32;

enum Bitmap<D: Digest, const N: usize> {
    Clean(CleanAuthenticatedBitMap<D, N>),
    Dirty(DirtyAuthenticatedBitMap<D, N>),
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

    runner.start(|context| async move {
        let mut hasher = commonware_storage::mmr::StandardHasher::<Sha256>::new();
        let mut bitmap = Bitmap::Clean(CleanAuthenticatedBitMap::<_, CHUNK_SIZE>::new(&mut hasher, None));
        let mut bit_count = 0u64;
        let mut pruned_bits = 0u64;

        for op in input.operations {
            bitmap = match op {
                BitmapOperation::Append { bit } => {
                    let mut bitmap = match bitmap {
                        Bitmap::Clean(bitmap) => bitmap.into_dirty(),
                        Bitmap::Dirty(bitmap) => bitmap,
                    };
                    bitmap.push(bit);
                    bit_count += 1;
                    Bitmap::Dirty(bitmap)
                }

                BitmapOperation::GetBit { bit_offset } => {
                    if bit_count > 0 {
                        let live = bit_count.saturating_sub(pruned_bits);
                        if live > 0 {
                            let safe_offset = pruned_bits + (bit_offset % live);
                            let _ = match &bitmap {
                                Bitmap::Clean(bitmap) => bitmap.get_bit(safe_offset),
                                Bitmap::Dirty(bitmap) => bitmap.get_bit(safe_offset),
                            };
                        }
                    }
                    bitmap
                }

                BitmapOperation::SetBit { bit_offset, bit } => {
                    let mut bitmap = match bitmap {
                        Bitmap::Clean(bitmap) => bitmap.into_dirty(),
                        Bitmap::Dirty(bitmap) => bitmap,
                    };
                    if bit_count > 0 {
                        let safe_offset = (bit_offset % bit_count).max(pruned_bits);
                        if safe_offset < bit_count {
                            bitmap.set_bit(safe_offset, bit);
                        }
                    }
                    Bitmap::Dirty(bitmap)
                }

                BitmapOperation::GetChunk { bit_offset } => {
                    if bit_count > 0 {
                        let safe_offset = (bit_offset % bit_count).max(pruned_bits);
                        let chunk_aligned = (safe_offset
                            / CleanAuthenticatedBitMap::<sha256::Digest, CHUNK_SIZE>::CHUNK_SIZE_BITS)
                            * CleanAuthenticatedBitMap::<sha256::Digest, CHUNK_SIZE>::CHUNK_SIZE_BITS;
                        if chunk_aligned >= pruned_bits && chunk_aligned < bit_count {
                            let _ = match &bitmap {
                                Bitmap::Clean(bitmap) => bitmap.get_chunk_containing(chunk_aligned),
                                Bitmap::Dirty(bitmap) => bitmap.get_chunk_containing(chunk_aligned),
                            };
                        }
                    }
                    bitmap
                }

                BitmapOperation::LastChunk => {
                    if bit_count > pruned_bits {
                        let (chunk, bits) = match &bitmap {
                            Bitmap::Clean(bitmap) => bitmap.last_chunk(),
                            Bitmap::Dirty(bitmap) => bitmap.last_chunk(),
                        };
                        assert!(bits <= CleanAuthenticatedBitMap::<sha256::Digest, CHUNK_SIZE>::CHUNK_SIZE_BITS);
                        assert!(chunk.len() == CHUNK_SIZE);
                    }
                    bitmap
                }

                BitmapOperation::Len => {
                    let count = match &bitmap {
                        Bitmap::Clean(bitmap) => bitmap.len(),
                        Bitmap::Dirty(bitmap) => bitmap.len(),
                    };
                    assert_eq!(count, bit_count);
                    bitmap
                }

                BitmapOperation::PrunedBits => {
                    let pruned = match &bitmap {
                        Bitmap::Clean(bitmap) => bitmap.pruned_bits(),
                        Bitmap::Dirty(bitmap) => bitmap.pruned_bits(),
                    };
                    assert_eq!(pruned, pruned_bits);
                    bitmap
                }

                BitmapOperation::PruneToBit { bit_offset } => {
                    let mut bitmap = match bitmap {
                        Bitmap::Clean(bitmap) => bitmap,
                        Bitmap::Dirty(bitmap) => bitmap.merkleize(&mut hasher).await.unwrap(),
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
                    Bitmap::Clean(bitmap)
                }

                BitmapOperation::Merkleize => {
                    let bitmap = match bitmap {
                        Bitmap::Clean(bitmap) => bitmap,
                        Bitmap::Dirty(bitmap) => bitmap.merkleize(&mut hasher).await.unwrap(),
                    };
                    Bitmap::Clean(bitmap)
                }

                BitmapOperation::GetNode { position } => {
                    let bitmap = match bitmap {
                        Bitmap::Clean(bitmap) => bitmap,
                        Bitmap::Dirty(bitmap) => bitmap.merkleize(&mut hasher).await.unwrap(),
                    };
                    if bitmap.size() > 0 {
                        let safe_pos = position % bitmap.size().as_u64();
                        let _ = bitmap.get_node(safe_pos.into());
                    }
                    Bitmap::Clean(bitmap)
                }

                BitmapOperation::Size => {
                    match &bitmap {
                        Bitmap::Clean(bitmap) => bitmap.size(),
                        Bitmap::Dirty(bitmap) => bitmap.size(),
                    };
                    bitmap
                }

                BitmapOperation::Proof { bit_offset } => {
                    let bitmap = match bitmap {
                        Bitmap::Clean(bitmap) => bitmap,
                        Bitmap::Dirty(bitmap) => bitmap.merkleize(&mut hasher).await.unwrap(),
                    };
                    if bit_count > pruned_bits {
                        let bit_offset = (bit_offset % (bit_count - pruned_bits)) + pruned_bits;
                        if let Ok((proof, chunk)) = bitmap.proof(&mut hasher, bit_offset).await {
                            let root = bitmap.root();
                            assert!(
                                CleanAuthenticatedBitMap::<sha256::Digest, CHUNK_SIZE>::verify_bit_inclusion(
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
                    Bitmap::Clean(bitmap)
                }

                BitmapOperation::RestorePruned => {
                    let bitmap = CleanAuthenticatedBitMap::<_, CHUNK_SIZE>::restore_pruned(
                        context.clone(),
                        "fuzz_mmr_bitmap_test_partition",
                        None,
                        &mut hasher,
                    )
                    .await
                    .unwrap();
                    // Update tracking variables to match restored state
                    bit_count = bitmap.len();
                    pruned_bits = bitmap.pruned_bits();
                    Bitmap::Clean(bitmap)
                }

                BitmapOperation::WritePruned => {
                    let bitmap = match bitmap {
                        Bitmap::Clean(bitmap) => bitmap,
                        Bitmap::Dirty(bitmap) => bitmap.merkleize(&mut hasher).await.unwrap(),
                    };
                    let _ = bitmap
                        .write_pruned(context.clone(), "fuzz_mmr_bitmap_test_partition")
                        .await;
                    Bitmap::Clean(bitmap)
                }
            }
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
