#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::{sha256, Sha256};
use commonware_runtime::{deterministic, Runner};
use commonware_storage::AuthenticatedBitMap as BitMap;
use libfuzzer_sys::fuzz_target;

const MAX_OPERATIONS: usize = 100;
const CHUNK_SIZE: usize = 32;

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
    IsDirty,
    DirtyChunks,
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
        let mut bitmap = BitMap::new(&mut hasher, None);
        let mut bit_count = 0u64;
        let mut pruned_bits = 0u64;

        for op in input.operations {
            match op {
                BitmapOperation::Append { bit } => {
                    bitmap.push(bit);
                    bit_count += 1;

                    assert_eq!(bitmap.len(), bit_count);
                }

                BitmapOperation::GetBit { bit_offset } => {
                    if bit_count > 0 {
                        let live = bit_count.saturating_sub(pruned_bits);
                        if live > 0 {
                            let safe_offset = pruned_bits + (bit_offset % live);
                            let _ = bitmap.get_bit(safe_offset);
                        }
                    }
                }

                BitmapOperation::SetBit { bit_offset, bit } => {
                    if bit_count > 0 {
                        let safe_offset = (bit_offset % bit_count).max(pruned_bits);
                        if safe_offset < bit_count {
                            bitmap.set_bit(safe_offset, bit);
                        }
                    }
                }

                BitmapOperation::GetChunk { bit_offset } => {
                    if bit_count > 0 {
                        let safe_offset = (bit_offset % bit_count).max(pruned_bits);
                        let chunk_aligned = (safe_offset
                            / BitMap::<sha256::Digest, CHUNK_SIZE>::CHUNK_SIZE_BITS)
                            * BitMap::<sha256::Digest, CHUNK_SIZE>::CHUNK_SIZE_BITS;
                        if chunk_aligned >= pruned_bits && chunk_aligned < bit_count {
                            let _ = bitmap.get_chunk_containing(chunk_aligned);
                        }
                    }
                }

                BitmapOperation::LastChunk => {
                    if bit_count > pruned_bits {
                        let (chunk, bits) = bitmap.last_chunk();
                        assert!(bits <= BitMap::<sha256::Digest, CHUNK_SIZE>::CHUNK_SIZE_BITS);
                        assert!(chunk.len() == CHUNK_SIZE);
                    }
                }

                BitmapOperation::Len => {
                    let count = bitmap.len();
                    assert_eq!(count, bit_count);
                }

                BitmapOperation::PrunedBits => {
                    let pruned = bitmap.pruned_bits();
                    assert_eq!(pruned, pruned_bits);
                }

                BitmapOperation::PruneToBit { bit_offset } => {
                    if bit_count > 0 && !bitmap.is_dirty() {
                        let safe_offset = (bit_offset % (bit_count + 1)).min(bit_count);
                        if safe_offset >= pruned_bits {
                            bitmap.prune_to_bit(safe_offset).unwrap();
                            // Update pruned_bits to match what was actually pruned
                            pruned_bits = bitmap.pruned_bits();

                            assert_eq!(bitmap.pruned_bits(), pruned_bits);
                        }
                    }
                }

                BitmapOperation::Merkleize => {
                    bitmap.merkleize(&mut hasher).await.unwrap();
                    assert!(!bitmap.is_dirty());
                }

                BitmapOperation::IsDirty => {
                    let _ = bitmap.is_dirty();
                }

                BitmapOperation::DirtyChunks => {
                    let chunks = bitmap.dirty_chunks();
                    let bits_per_chunk = BitMap::<sha256::Digest, CHUNK_SIZE>::CHUNK_SIZE_BITS;
                    let max_chunks = if bit_count == 0 {
                        0
                    } else {
                        (bit_count - 1) / bits_per_chunk + 1
                    };
                    for chunk in chunks {
                        assert!(chunk < max_chunks);
                    }
                }

                BitmapOperation::GetNode { position } => {
                    if bitmap.size() > 0 {
                        let safe_pos = position % bitmap.size().as_u64();
                        let _ = bitmap.get_node(safe_pos.into());
                    }
                }

                BitmapOperation::Size => {
                    let _ = bitmap.size();
                }

                BitmapOperation::Proof { bit_offset } => {
                    if bit_count > pruned_bits && !bitmap.is_dirty() {
                        let bit_offset = (bit_offset % (bit_count - pruned_bits)) + pruned_bits;
                        if let Ok((proof, chunk)) = bitmap.proof(&mut hasher, bit_offset).await {
                            let root = bitmap.root(&mut hasher).await.unwrap();
                            assert!(
                                BitMap::<sha256::Digest, CHUNK_SIZE>::verify_bit_inclusion(
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
                }

                BitmapOperation::RestorePruned => {
                    BitMap::<_, CHUNK_SIZE>::restore_pruned(
                        context.clone(),
                        "fuzz_mmr_bitmap_test_partition",
                        None,
                        &mut hasher,
                    )
                    .await
                    .unwrap();
                }

                BitmapOperation::WritePruned => {
                    let _ = bitmap
                        .write_pruned(context.clone(), "fuzz_mmr_bitmap_test_partition")
                        .await;
                }
            }
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
