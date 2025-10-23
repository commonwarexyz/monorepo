#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_utils::bitmap::Prunable;
use libfuzzer_sys::fuzz_target;

const MAX_OPERATIONS: usize = 4;

#[derive(Debug, Clone, Copy, Arbitrary)]
enum Operation {
    PushBit(bool),
    PushByte(u8),
    PushChunk([u8; 4]),
    PopBit,
    PruneToBit { bit: u64 },
    GetBit(u64),
}

#[derive(Debug)]
struct FuzzInput {
    operations: Vec<Operation>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let num_ops = u.int_in_range(0..=MAX_OPERATIONS)?;
        let mut operations = Vec::with_capacity(num_ops);
        for _ in 0..num_ops {
            operations.push(Operation::arbitrary(u)?);
        }
        Ok(FuzzInput { operations })
    }
}

fn fuzz(input: FuzzInput) {
    let mut prunable = Prunable::<4>::new();

    for (_, operation) in input.operations.iter().enumerate() {
        match operation {
            Operation::PushBit(bit) => {
                prunable.push(*bit);
            }
            Operation::PushByte(byte) => {
                if prunable.len() % 8 == 0 {
                    prunable.push_byte(*byte);
                }
            }
            Operation::PushChunk(chunk) => {
                if prunable.len() % Prunable::<4>::CHUNK_SIZE_BITS == 0 {
                    prunable.push_chunk(&chunk);
                }
            }
            Operation::PopBit => {
                assert_eq!(prunable.is_empty(), prunable.len() == 0, "pop bit on empty");
                if !prunable.is_empty() {
                    prunable.pop();
                }
            }
            Operation::PruneToBit { bit } => {
                let len = prunable.len();
                let pruned_bites = prunable.pruned_bits();
                let pruned_chunks = prunable.pruned_chunks();
                let bit = if len != 0 { bit % len } else { 0 };
                println!(
                    "Pruning to bit {} len {} pruned bit {} pruned chunks {}",
                    bit, len, pruned_bites, pruned_chunks
                );
                if bit > pruned_bites {
                    prunable.prune_to_bit(bit);
                }
            }
            Operation::GetBit(bit) => {
                let len = prunable.len();
                if len > 0 {
                    let bit = bit % len;
                    let _ = prunable.get_bit(bit);
                };
            }
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
