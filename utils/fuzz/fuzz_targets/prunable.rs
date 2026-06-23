#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_codec::{Encode, EncodeSize, Read};
use commonware_utils::bitmap::{Prunable, Readable};
use libfuzzer_sys::fuzz_target;

const MAX_OPERATIONS: usize = 1024;

#[derive(Debug, Clone, Copy, Arbitrary)]
enum ChunkSize {
    Size1,
    Size4,
    Size8,
    Size16,
    Size32,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum Operation {
    PushBit(bool),
    PushByte(u8),
    PushChunk(u64),
    PopBit,
    PruneToBit { bit: u64 },
    GetBit(u64),
    Truncate { new_len: u64 },
    Codec,
    ReadableCheck,
    IndexHelpers(u64),
}

#[derive(Debug)]
struct FuzzInput {
    chunk_size: ChunkSize,
    operations: Vec<Operation>,
    arbitrary_bitmap: Prunable<16>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let chunk_size = ChunkSize::arbitrary(u)?;
        let num_ops = u.int_in_range(1..=MAX_OPERATIONS)?;
        let mut operations = Vec::with_capacity(num_ops);
        for _ in 0..num_ops {
            operations.push(Operation::arbitrary(u)?);
        }
        let arbitrary_bitmap = Prunable::<16>::arbitrary(u)?;
        Ok(FuzzInput {
            chunk_size,
            operations,
            arbitrary_bitmap,
        })
    }
}

// An Arbitrary-constructed Prunable must uphold its core invariants and survive a
// codec round-trip that preserves length, pruning, and all unpruned bits.
fn check_arbitrary_bitmap<const N: usize>(prunable: &Prunable<N>) {
    assert!(prunable.pruned_bits() <= prunable.len());
    assert!(prunable.pruned_chunks() <= prunable.chunks_len());

    let encoded = prunable.encode();
    let decoded = Prunable::<N>::read_cfg(&mut encoded.as_ref(), &u64::MAX)
        .expect("valid encode round-trips");
    assert_eq!(decoded.len(), prunable.len());
    assert_eq!(decoded.pruned_chunks(), prunable.pruned_chunks());
    for b in prunable.pruned_bits()..prunable.len() {
        assert_eq!(decoded.get_bit(b), prunable.get_bit(b));
    }
}

fn fuzz_with_chunk_size<const N: usize>(operations: &[Operation]) {
    let mut prunable = Prunable::<N>::new();

    for operation in operations.iter() {
        match operation {
            Operation::PushBit(bit) => {
                prunable.push(*bit);
            }
            Operation::PushByte(byte) => {
                if prunable.len().is_multiple_of(8) {
                    prunable.push_byte(*byte);
                }
            }
            Operation::PushChunk(seed) => {
                if prunable
                    .len()
                    .is_multiple_of(Prunable::<N>::CHUNK_SIZE_BITS)
                {
                    // Create chunk from seed by repeating the seed bytes
                    let seed_bytes = seed.to_le_bytes();
                    let mut chunk = [0u8; N];
                    chunk
                        .iter_mut()
                        .zip(seed_bytes.iter().cycle())
                        .for_each(|(dst, &src)| *dst = src);
                    prunable.push_chunk(&chunk);
                }
            }
            Operation::PopBit => {
                if !prunable.is_empty() && prunable.len() != prunable.pruned_bits() {
                    prunable.pop();
                }
            }
            Operation::PruneToBit { bit } => {
                let len = prunable.len();
                let pruned_bits = prunable.pruned_bits();
                let bit = if len != 0 { bit % len } else { 0 };
                if bit > pruned_bits {
                    prunable.prune_to_bit(bit);
                }
            }
            Operation::GetBit(bit) => {
                if *bit >= prunable.pruned_bits() && *bit < prunable.len() {
                    // Inherent get_bit must agree with the Readable trait oracle, which
                    // recomputes the bit via get_chunk + get_bit_from_chunk.
                    assert_eq!(prunable.get_bit(*bit), Readable::get_bit(&prunable, *bit));
                };
            }
            Operation::Truncate { new_len } => {
                let len = prunable.len();
                let pruned_bits = prunable.pruned_bits();
                if len > pruned_bits {
                    // Pick a valid target in [pruned_bits, len]; truncate panics outside it.
                    let new_len = pruned_bits + (new_len % (len - pruned_bits + 1));
                    let kept: Vec<bool> = (pruned_bits..new_len)
                        .map(|b| prunable.get_bit(b))
                        .collect();
                    prunable.truncate(new_len);
                    assert_eq!(prunable.len(), new_len);
                    assert_eq!(prunable.pruned_bits(), pruned_bits);
                    // Retained bits keep their values after truncation.
                    for (i, expected) in kept.iter().enumerate() {
                        assert_eq!(prunable.get_bit(pruned_bits + i as u64), *expected);
                    }
                }
            }
            Operation::Codec => {
                // write/read_cfg round-trips preserve length, pruning, and all unpruned bits.
                let encoded = prunable.encode();
                assert_eq!(encoded.len(), prunable.encode_size());
                let decoded = Prunable::<N>::read_cfg(&mut encoded.as_ref(), &u64::MAX)
                    .expect("valid encode");
                assert_eq!(decoded.len(), prunable.len());
                assert_eq!(decoded.pruned_chunks(), prunable.pruned_chunks());
                for b in prunable.pruned_bits()..prunable.len() {
                    assert_eq!(decoded.get_bit(b), prunable.get_bit(b));
                }
            }
            Operation::ReadableCheck => {
                // The Readable trait impl must mirror the inherent accessors.
                assert_eq!(
                    Readable::complete_chunks(&prunable),
                    prunable.complete_chunks()
                );
                assert_eq!(Readable::len(&prunable), prunable.len());
                assert_eq!(Readable::pruned_chunks(&prunable), prunable.pruned_chunks());
                if prunable.len() > prunable.pruned_bits() {
                    let (chunk, bits) = Readable::last_chunk(&prunable);
                    let (inherent_chunk, inherent_bits) = prunable.last_chunk();
                    assert_eq!(&chunk, inherent_chunk);
                    assert_eq!(bits, inherent_bits);
                }
            }
            Operation::IndexHelpers(bit) => {
                // Indexing helpers are pure functions of the bit position.
                assert_eq!(Prunable::<N>::chunk_byte_bitmask(*bit), 1u8 << (*bit % 8));
                assert_eq!(
                    Prunable::<N>::chunk_byte_offset(*bit),
                    ((*bit / 8) % N as u64) as usize
                );
            }
        }
    }

    // Default-constructed bitmap is empty and matches new().
    let def = Prunable::<N>::default();
    assert_eq!(def.len(), 0);
    assert!(def.is_empty());
}

fn fuzz(input: FuzzInput) {
    check_arbitrary_bitmap(&input.arbitrary_bitmap);
    match input.chunk_size {
        ChunkSize::Size1 => fuzz_with_chunk_size::<1>(&input.operations),
        ChunkSize::Size4 => fuzz_with_chunk_size::<4>(&input.operations),
        ChunkSize::Size8 => fuzz_with_chunk_size::<8>(&input.operations),
        ChunkSize::Size16 => fuzz_with_chunk_size::<16>(&input.operations),
        ChunkSize::Size32 => fuzz_with_chunk_size::<32>(&input.operations),
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
