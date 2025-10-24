#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_utils::bitmap::Prunable;
use libfuzzer_sys::fuzz_target;

const MAX_OPERATIONS: usize = 10;

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
        let num_ops = u.int_in_range(1..=MAX_OPERATIONS)?;
        let mut operations = Vec::with_capacity(num_ops);
        for _ in 0..num_ops {
            operations.push(Operation::arbitrary(u)?);
        }
        Ok(FuzzInput { operations })
    }
}

fn fuzz(input: FuzzInput) {
    let mut prunable = Prunable::<4>::new();

    for operation in input.operations.iter() {
        match operation {
            Operation::PushBit(bit) => {
                prunable.push(*bit);
            }
            Operation::PushByte(byte) => {
                if prunable.len().is_multiple_of(8) {
                    prunable.push_byte(*byte);
                }
            }
            Operation::PushChunk(chunk) => {
                if prunable
                    .len()
                    .is_multiple_of(Prunable::<4>::CHUNK_SIZE_BITS)
                {
                    prunable.push_chunk(chunk);
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

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
