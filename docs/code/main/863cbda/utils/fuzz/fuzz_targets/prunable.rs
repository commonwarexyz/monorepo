#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_utils::bitmap::Prunable;
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
}

#[derive(Debug)]
struct FuzzInput {
    chunk_size: ChunkSize,
    operations: Vec<Operation>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let chunk_size = ChunkSize::arbitrary(u)?;
        let num_ops = u.int_in_range(1..=MAX_OPERATIONS)?;
        let mut operations = Vec::with_capacity(num_ops);
        for _ in 0..num_ops {
            operations.push(Operation::arbitrary(u)?);
        }
        Ok(FuzzInput {
            chunk_size,
            operations,
        })
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
                    let _ = prunable.get_bit(*bit);
                };
            }
        }
    }
}

fn fuzz(input: FuzzInput) {
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
