#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::{sha256, Digest, Sha256};
use commonware_parallel::Sequential;
use commonware_runtime::{
    deterministic, Clock, Metrics, Runner, Storage as RuntimeStorage, Supervisor as _,
};
use commonware_storage::{
    merkle::{storage::Storage as MerkleStorage, Bagging::ForwardFold, Family as MerkleFamily},
    metadata::{Config as MetadataConfig, Metadata},
    mmr, MerkleizedBitMap, UnmerkleizedBitMap,
};
use commonware_utils::{bitmap::BitMap, sequence::prefixed_u64::U64, FuzzRng};
use libfuzzer_sys::fuzz_target;

const MAX_OPERATIONS: usize = 100;
const MAX_RAW_BYTES: usize = 32_768;
const CHUNK_SIZE: usize = 32;
const NODE_PREFIX: u8 = 0;
const PRUNED_CHUNKS_PREFIX: u8 = 1;

type TestMerkleizedBitMap =
    MerkleizedBitMap<deterministic::Context, sha256::Digest, CHUNK_SIZE, Sequential>;

enum Bitmap<E: Clock + RuntimeStorage + Metrics, D: Digest, const N: usize> {
    Merkleized(MerkleizedBitMap<E, D, N, Sequential>),
    Unmerkleized(UnmerkleizedBitMap<E, D, N, Sequential>),
}

#[derive(Arbitrary, Debug, Clone)]
enum ProofMutation {
    InactivePeaks,
    ClearDigests,
    ExtraDigest,
    DropDigest,
}

#[derive(Arbitrary, Debug, Clone)]
enum BitmapOperation {
    Append {
        bit: bool,
    },
    AppendMany {
        pattern: u8,
        count: u16,
    },
    IsEmpty,
    GetBit {
        bit_offset: u64,
    },
    GetBitFromChunk {
        bit_offset: u64,
    },
    SetBit {
        bit_offset: u64,
        bit: bool,
    },
    GetChunk {
        bit_offset: u64,
    },
    LastChunk,
    Len,
    PrunedBits,
    PruneToBit {
        bit_offset: u64,
    },
    PruneBeforePruned,
    Merkleize,
    GetNode {
        position: u64,
    },
    StorageGetNode {
        position: u64,
    },
    Size,
    Proof {
        bit_offset: u64,
    },
    ProofOutOfBounds,
    VerifyMutatedProof {
        bit_offset: u64,
        mutation: ProofMutation,
    },
    DirtyChunks,
    RestorePruned,
    WritePruned,
    CorruptPrunedMetadata {
        len: u8,
    },
    Destroy,
}

#[derive(Debug)]
struct FuzzInput {
    operations: Vec<BitmapOperation>,
    raw_bytes: Vec<u8>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let prefix: u64 = u.arbitrary()?;
        let mut raw_bytes = prefix.to_be_bytes().to_vec();
        let num_ops = u.int_in_range(1..=MAX_OPERATIONS)?;
        let mut operations = Vec::with_capacity(num_ops);

        for _ in 0..num_ops {
            operations.push(u.arbitrary()?);
        }
        let remaining = u.len().min(MAX_RAW_BYTES);
        raw_bytes.extend_from_slice(u.bytes(remaining)?);

        Ok(FuzzInput {
            operations,
            raw_bytes,
        })
    }
}

fn fuzz(input: FuzzInput) {
    let cfg = deterministic::Config::new().with_rng(Box::new(FuzzRng::new(input.raw_bytes)));
    let runner = deterministic::Runner::new(cfg);
    const PARTITION: &str = "fuzz-mmr-bitmap-test-partition";

    runner.start(|context| async move {
        let hasher = commonware_storage::mmr::StandardHasher::<Sha256>::new(ForwardFold);
        let init_bitmap = MerkleizedBitMap::<_, _, CHUNK_SIZE, Sequential>::init(
            context.child("bitmap"),
            PARTITION,
            Sequential,
            &hasher,
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

                BitmapOperation::AppendMany { pattern, count } => {
                    let mut bitmap = match bitmap {
                        Bitmap::Merkleized(bitmap) => bitmap.into_dirty(),
                        Bitmap::Unmerkleized(bitmap) => bitmap,
                    };
                    let count = u64::from(count % 512) + 1;
                    for offset in 0..count {
                        let bit = (pattern & (1 << (offset % 8))) != 0;
                        bitmap.push(bit);
                    }
                    bit_count += count;
                    Bitmap::Unmerkleized(bitmap)
                }

                BitmapOperation::IsEmpty => {
                    let is_empty = match &bitmap {
                        Bitmap::Merkleized(bitmap) => bitmap.is_empty(),
                        Bitmap::Unmerkleized(bitmap) => bitmap.is_empty(),
                    };
                    assert_eq!(is_empty, bit_count == 0);
                    bitmap
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

                BitmapOperation::GetBitFromChunk { bit_offset } => {
                    let live = bit_count.saturating_sub(pruned_bits);
                    if live > 0 {
                        let safe_offset = pruned_bits + (bit_offset % live);
                        let (chunk, bit) = match &bitmap {
                            Bitmap::Merkleized(bitmap) => (
                                bitmap.get_chunk_containing(safe_offset),
                                bitmap.get_bit(safe_offset),
                            ),
                            Bitmap::Unmerkleized(bitmap) => (
                                bitmap.get_chunk_containing(safe_offset),
                                bitmap.get_bit(safe_offset),
                            ),
                        };
                        assert_eq!(
                            TestMerkleizedBitMap::get_bit_from_chunk(chunk, safe_offset),
                            bit
                        );
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
                        Bitmap::Unmerkleized(bitmap) => bitmap.merkleize(&hasher).unwrap(),
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

                BitmapOperation::PruneBeforePruned => {
                    let mut bitmap = match bitmap {
                        Bitmap::Merkleized(bitmap) => bitmap,
                        Bitmap::Unmerkleized(bitmap) => bitmap.merkleize(&hasher).unwrap(),
                    };
                    if pruned_bits > 0 {
                        bitmap.prune_to_bit(pruned_bits - 1).unwrap();
                        assert_eq!(bitmap.pruned_bits(), pruned_bits);
                    }
                    Bitmap::Merkleized(bitmap)
                }

                BitmapOperation::Merkleize => {
                    let bitmap = match bitmap {
                        Bitmap::Merkleized(bitmap) => bitmap,
                        Bitmap::Unmerkleized(bitmap) => bitmap.merkleize(&hasher).unwrap(),
                    };
                    Bitmap::Merkleized(bitmap)
                }

                BitmapOperation::GetNode { position } => {
                    let bitmap = match bitmap {
                        Bitmap::Merkleized(bitmap) => bitmap,
                        Bitmap::Unmerkleized(bitmap) => bitmap.merkleize(&hasher).unwrap(),
                    };
                    if bitmap.size() > 0 {
                        let safe_pos = position % bitmap.size().as_u64();
                        let _ = bitmap.get_node(safe_pos.into());
                    }
                    Bitmap::Merkleized(bitmap)
                }

                BitmapOperation::StorageGetNode { position } => {
                    let bitmap = match bitmap {
                        Bitmap::Merkleized(bitmap) => bitmap,
                        Bitmap::Unmerkleized(bitmap) => bitmap.merkleize(&hasher).unwrap(),
                    };
                    let size =
                        <TestMerkleizedBitMap as MerkleStorage<mmr::Family>>::size(&bitmap).await;
                    if size > 0 {
                        let safe_pos = position % size.as_u64();
                        let _ = <TestMerkleizedBitMap as MerkleStorage<mmr::Family>>::get_node(
                            &bitmap,
                            safe_pos.into(),
                        )
                        .await;
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
                        Bitmap::Unmerkleized(bitmap) => bitmap.merkleize(&hasher).unwrap(),
                    };
                    if bit_count > pruned_bits {
                        let bit_offset = (bit_offset % (bit_count - pruned_bits)) + pruned_bits;
                        if let Ok((proof, chunk)) = bitmap.proof(&hasher, bit_offset).await {
                            let root = bitmap.root();
                            assert!(
                                MerkleizedBitMap::<
                                    deterministic::Context,
                                    sha256::Digest,
                                    CHUNK_SIZE,
                                    Sequential,
                                >::verify_bit_inclusion(
                                    &hasher, &proof, &chunk, bit_offset, &root
                                ),
                                "failed to verify bit {bit_offset}",
                            );
                        }
                    }
                    Bitmap::Merkleized(bitmap)
                }

                BitmapOperation::ProofOutOfBounds => {
                    let bitmap = match bitmap {
                        Bitmap::Merkleized(bitmap) => bitmap,
                        Bitmap::Unmerkleized(bitmap) => bitmap.merkleize(&hasher).unwrap(),
                    };
                    assert!(bitmap.proof(&hasher, bit_count).await.is_err());
                    Bitmap::Merkleized(bitmap)
                }

                BitmapOperation::VerifyMutatedProof {
                    bit_offset,
                    mutation,
                } => {
                    let bitmap = match bitmap {
                        Bitmap::Merkleized(bitmap) => bitmap,
                        Bitmap::Unmerkleized(bitmap) => bitmap.merkleize(&hasher).unwrap(),
                    };
                    if bit_count > pruned_bits {
                        let bit_offset = (bit_offset % (bit_count - pruned_bits)) + pruned_bits;
                        if let Ok((mut proof, chunk)) = bitmap.proof(&hasher, bit_offset).await {
                            match mutation {
                                ProofMutation::InactivePeaks => {
                                    proof.inactive_peaks = 1;
                                }
                                ProofMutation::ClearDigests => {
                                    proof.digests.clear();
                                }
                                ProofMutation::ExtraDigest => {
                                    proof.digests.push(hasher.digest(&chunk));
                                }
                                ProofMutation::DropDigest => {
                                    let _ = proof.digests.pop();
                                }
                            }
                            let root = bitmap.root();
                            let valid = TestMerkleizedBitMap::verify_bit_inclusion(
                                &hasher, &proof, &chunk, bit_offset, &root,
                            );
                            if matches!(mutation, ProofMutation::InactivePeaks) {
                                assert!(!valid);
                            }
                        }
                    }
                    Bitmap::Merkleized(bitmap)
                }

                BitmapOperation::DirtyChunks => {
                    let bitmap = match bitmap {
                        Bitmap::Merkleized(bitmap) => bitmap.into_dirty(),
                        Bitmap::Unmerkleized(bitmap) => bitmap,
                    };
                    let _ = bitmap.dirty_chunks();
                    Bitmap::Unmerkleized(bitmap)
                }

                BitmapOperation::RestorePruned => {
                    let mut current = match bitmap {
                        Bitmap::Merkleized(bitmap) => bitmap,
                        Bitmap::Unmerkleized(bitmap) => bitmap.merkleize(&hasher).unwrap(),
                    };
                    if current.pruned_bits() > 0 {
                        current.write_pruned().await.unwrap();
                    }
                    drop(current);

                    let bitmap = MerkleizedBitMap::<_, _, CHUNK_SIZE, Sequential>::init(
                        context.child("bitmap").with_attribute("instance", restarts),
                        PARTITION,
                        Sequential,
                        &hasher,
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
                        Bitmap::Unmerkleized(bitmap) => bitmap.merkleize(&hasher).unwrap(),
                    };
                    let _ = bitmap.write_pruned().await;
                    Bitmap::Merkleized(bitmap)
                }

                BitmapOperation::CorruptPrunedMetadata { len } => {
                    let bitmap = match bitmap {
                        Bitmap::Merkleized(bitmap) => bitmap,
                        Bitmap::Unmerkleized(bitmap) => bitmap.merkleize(&hasher).unwrap(),
                    };
                    bitmap.destroy().await.unwrap();

                    let metadata_cfg = MetadataConfig {
                        partition: PARTITION.into(),
                        codec_config: ((0..).into(), ()),
                    };
                    let mut metadata = Metadata::<_, U64, Vec<u8>>::init(
                        context
                            .child("corrupt_metadata")
                            .with_attribute("instance", restarts),
                        metadata_cfg,
                    )
                    .await
                    .unwrap();
                    let key = U64::new(PRUNED_CHUNKS_PREFIX, 0);
                    match len % 4 {
                        0 => {
                            metadata.put(key, vec![0xFF; usize::from(len % 9)]);
                        }
                        1 => {
                            let invalid_chunks =
                                <mmr::Family as MerkleFamily>::MAX_LEAVES.as_u64() + 1;
                            metadata.put(key, invalid_chunks.to_be_bytes().to_vec());
                        }
                        2 => {
                            metadata.put(key, 1u64.to_be_bytes().to_vec());
                        }
                        _ => {
                            metadata.put(key, 1u64.to_be_bytes().to_vec());
                            metadata.put(U64::new(NODE_PREFIX, 0), vec![0; usize::from(len % 31)]);
                        }
                    }
                    metadata.sync().await.unwrap();
                    drop(metadata);

                    let result = MerkleizedBitMap::<_, _, CHUNK_SIZE, Sequential>::init(
                        context.child("bitmap").with_attribute("instance", restarts),
                        PARTITION,
                        Sequential,
                        &hasher,
                    )
                    .await;
                    assert!(result.is_err());
                    return;
                }

                BitmapOperation::Destroy => {
                    let bitmap = match bitmap {
                        Bitmap::Merkleized(bitmap) => bitmap,
                        Bitmap::Unmerkleized(bitmap) => bitmap.merkleize(&hasher).unwrap(),
                    };
                    bitmap.destroy().await.unwrap();
                    return;
                }
            }
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
