#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_cryptography::{Digest, Sha256, sha256};
use commonware_parallel::Sequential;
use commonware_runtime::{Runner, Supervisor as _, deterministic};
use commonware_storage::{
    Context, MerkleizedBitMap, UnmerkleizedBitMap, merkle::Bagging::ForwardFold,
};
use commonware_utils::bitmap::BitMap;
use libfuzzer_sys::fuzz_target;

const MAX_OPERATIONS: usize = 100;
const CHUNK_SIZE: usize = 32;

/// Bits in one chunk.
const CHUNK_BITS: u64 = BitMap::<CHUNK_SIZE>::CHUNK_SIZE_BITS;

/// The most whole chunks a forged claim moves a bit or a length by.
const MAX_SHIFT_CHUNKS: u64 = 4;

/// The most inactive peaks a forged proof claims.
const MAX_FORGED_INACTIVE_PEAKS: usize = 3;

/// The number of `Forgery` kinds.
const FORGERY_KINDS: u8 = 6;

type Verifier = MerkleizedBitMap<deterministic::Context, sha256::Digest, CHUNK_SIZE, Sequential>;
type BitProof = commonware_storage::mmr::Proof<sha256::Digest>;

enum Bitmap<E: Context, D: Digest, const N: usize> {
    Merkleized(MerkleizedBitMap<E, D, N, Sequential>),
    Unmerkleized(UnmerkleizedBitMap<E, D, N, Sequential>),
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
    ForgeProof { bit_offset: u64, forgery: Forgery },
    AppendChunk { fill: u8 },
}

/// A change to the claim an honest bit proof makes.
#[derive(Debug, Clone)]
enum Forgery {
    /// Move both the claimed length and the bit by whole chunks.
    Relocate { chunks: u64, back: bool },
    /// Move the claimed length by some bits.
    Length { bits: u64, back: bool },
    /// Move the bit by whole chunks.
    Position { chunks: u64, back: bool },
    /// Claim another bit of the same chunk.
    SameChunk { index: u64 },
    /// Flip one bit of the claimed chunk.
    Chunk { index: u64 },
    /// Claim inactive peaks.
    InactivePeaks { peaks: usize },
}

impl<'a> Arbitrary<'a> for Forgery {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(match u.int_in_range(0..=FORGERY_KINDS - 1)? {
            0 => Self::Relocate {
                chunks: u.int_in_range(1..=MAX_SHIFT_CHUNKS)?,
                back: u.arbitrary()?,
            },
            1 => Self::Length {
                bits: u.int_in_range(1..=CHUNK_BITS)?,
                back: u.arbitrary()?,
            },
            2 => Self::Position {
                chunks: u.int_in_range(1..=MAX_SHIFT_CHUNKS)?,
                back: u.arbitrary()?,
            },
            3 => Self::SameChunk {
                index: u.int_in_range(0..=CHUNK_BITS - 1)?,
            },
            4 => Self::Chunk {
                index: u.int_in_range(0..=CHUNK_BITS - 1)?,
            },
            5 => Self::InactivePeaks {
                peaks: u.int_in_range(1..=MAX_FORGED_INACTIVE_PEAKS)?,
            },
            _ => unreachable!(),
        })
    }
}

/// Move `value` by `by`, or `None` when the move leaves the range of `u64`.
fn shift(value: u64, by: u64, back: bool) -> Option<u64> {
    if back {
        value.checked_sub(by)
    } else {
        value.checked_add(by)
    }
}

impl Forgery {
    /// Apply the forgery to an honest `(proof, bit, chunk)` claim. A move out of the range of `u64`
    /// leaves the claim honest.
    fn apply(
        &self,
        proof: &BitProof,
        bit: u64,
        chunk: &[u8; CHUNK_SIZE],
    ) -> (BitProof, u64, [u8; CHUNK_SIZE]) {
        let mut proof = proof.clone();
        let mut bit = bit;
        let mut chunk = *chunk;
        let leaves = *proof.leaves;
        match *self {
            Self::Relocate { chunks, back } => {
                let by = chunks * CHUNK_BITS;
                if let (Some(leaves), Some(moved)) = (shift(leaves, by, back), shift(bit, by, back))
                {
                    proof.leaves = leaves.into();
                    bit = moved;
                }
            }
            Self::Length { bits, back } => {
                if let Some(leaves) = shift(leaves, bits, back) {
                    proof.leaves = leaves.into();
                }
            }
            Self::Position { chunks, back } => {
                if let Some(moved) = shift(bit, chunks * CHUNK_BITS, back) {
                    bit = moved;
                }
            }
            Self::SameChunk { index } => bit = (bit / CHUNK_BITS) * CHUNK_BITS + index,
            Self::Chunk { index } => chunk[(index / 8) as usize] ^= 1 << (index % 8),
            Self::InactivePeaks { peaks } => proof.inactive_peaks = peaks,
        }
        (proof, bit, chunk)
    }
}

/// Whether a claim about a bitmap of `bit_count` bits, `pruned_bits` of them pruned, is true:
/// the real length, no inactive peaks, an existing bit, and the real chunk of that bit. `None`
/// when the bit's chunk is pruned and cannot be read.
fn claim_is_true(
    bitmap: &Verifier,
    bit_count: u64,
    pruned_bits: u64,
    proof: &BitProof,
    bit: u64,
    chunk: &[u8; CHUNK_SIZE],
) -> Option<bool> {
    if proof.inactive_peaks != 0 || *proof.leaves != bit_count || bit >= bit_count {
        return Some(false);
    }
    if bit < pruned_bits {
        return None;
    }
    Some(chunk == bitmap.get_chunk_containing(bit))
}

#[derive(Debug)]
struct FuzzInput {
    operations: Vec<BitmapOperation>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let num_ops = u.int_in_range(1..=MAX_OPERATIONS)?;
        let mut operations = Vec::with_capacity(num_ops);

        for _ in 0..num_ops {
            operations.push(u.arbitrary()?);
        }

        Ok(FuzzInput { operations })
    }
}

fn fuzz(input: FuzzInput) {
    let runner = deterministic::Runner::default();
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
                                    &hasher, &proof, bit_offset, &chunk, &root
                                ),
                                "failed to verify bit {bit_offset}",
                            );
                        }
                    }
                    Bitmap::Merkleized(bitmap)
                }

                BitmapOperation::RestorePruned => {
                    drop(bitmap);
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
                    let bitmap = match bitmap {
                        Bitmap::Merkleized(bitmap) => bitmap,
                        Bitmap::Unmerkleized(bitmap) => bitmap.merkleize(&hasher).unwrap(),
                    };
                    let bitmap = bitmap.write_pruned().await.unwrap();
                    Bitmap::Merkleized(bitmap)
                }

                BitmapOperation::ForgeProof {
                    bit_offset,
                    forgery,
                } => {
                    let bitmap = match bitmap {
                        Bitmap::Merkleized(bitmap) => bitmap,
                        Bitmap::Unmerkleized(bitmap) => bitmap.merkleize(&hasher).unwrap(),
                    };
                    if bit_count > pruned_bits {
                        let bit = (bit_offset % (bit_count - pruned_bits)) + pruned_bits;
                        if let Ok((proof, chunk)) = bitmap.proof(&hasher, bit).await {
                            let root = bitmap.root();
                            assert!(
                                Verifier::verify_bit_inclusion(&hasher, &proof, bit, &chunk, &root),
                                "failed to verify bit {bit}",
                            );
                            let (forged, forged_bit, forged_chunk) =
                                forgery.apply(&proof, bit, &chunk);
                            if let Some(truth) = claim_is_true(
                                &bitmap,
                                bit_count,
                                pruned_bits,
                                &forged,
                                forged_bit,
                                &forged_chunk,
                            ) && Verifier::verify_bit_inclusion(
                                &hasher,
                                &forged,
                                forged_bit,
                                &forged_chunk,
                                &root,
                            ) {
                                assert!(
                                    truth,
                                    "the verifier accepted a false claim: {forgery:?}, \
                                     bit_count {bit_count}, pruned_bits {pruned_bits}, \
                                     leaves {} -> {}, bit {bit} -> {forged_bit}",
                                    *proof.leaves, *forged.leaves,
                                );
                            }
                        }
                    }
                    Bitmap::Merkleized(bitmap)
                }

                BitmapOperation::AppendChunk { fill } => {
                    let mut bitmap = match bitmap {
                        Bitmap::Merkleized(bitmap) => bitmap.into_dirty(),
                        Bitmap::Unmerkleized(bitmap) => bitmap,
                    };
                    for i in 0..CHUNK_BITS {
                        bitmap.push((fill >> (i % 8)) & 1 == 1);
                    }
                    bit_count += CHUNK_BITS;
                    Bitmap::Unmerkleized(bitmap)
                }
            }
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
