#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_cryptography::lthash::LtHash;
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, Rng, SeedableRng};

#[derive(Debug, Arbitrary)]
enum MutationType {
    AddThenSubtractSameValue,
    AddCombinedThenSubtractIndividual,
    SubtractCombinedThenAddIndividual,
    AddMultipleElementsThenSubtractSum,
    AddSubtractCommutativitySum,
}

#[derive(Debug)]
struct FuzzInput {
    seed: u64,
    initial_value: Vec<u8>,
    mutation_type: MutationType,
    additional_value_a: Vec<u8>,
    additional_value_b: Vec<u8>,
    num_elements: u8,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(FuzzInput {
            seed: u.arbitrary()?,
            initial_value: u.arbitrary()?,
            mutation_type: u.arbitrary()?,
            additional_value_a: u.arbitrary()?,
            additional_value_b: u.arbitrary()?,
            num_elements: u.arbitrary()?,
        })
    }
}

fn generate_random_bytes(rng: &mut StdRng, min_len: usize, max_len: usize) -> Vec<u8> {
    let len = rng.gen_range(min_len..=max_len);
    let mut bytes = vec![0u8; len];
    rng.fill(&mut bytes[..]);
    bytes
}

fn fuzz(input: FuzzInput) {
    let mut rng = StdRng::seed_from_u64(input.seed);

    let mut lthash = LtHash::default();

    lthash.add(&input.initial_value);
    let initial_checksum = lthash.checksum();

    match input.mutation_type {
        MutationType::AddThenSubtractSameValue => {
            let value = generate_random_bytes(&mut rng, 1, 1024);
            lthash.add(&value);
            lthash.subtract(&value);
        }
        MutationType::AddCombinedThenSubtractIndividual => {
            let a = &input.additional_value_a;
            let b = &input.additional_value_b;

            // Create hash(a+b) by combining hash(a) and hash(b)
            let mut hash_a = LtHash::new();
            hash_a.add(a);

            let mut hash_b = LtHash::new();
            hash_b.add(b);

            let mut hash_a_plus_b = LtHash::new();
            hash_a_plus_b.combine(&hash_a);
            hash_a_plus_b.combine(&hash_b);

            // Add H(a+b) then subtract H(a) and H(b)
            lthash.combine(&hash_a_plus_b);

            let mut neg_hash_a = LtHash::new();
            neg_hash_a.subtract(a);
            lthash.combine(&neg_hash_a);

            let mut neg_hash_b = LtHash::new();
            neg_hash_b.subtract(b);
            lthash.combine(&neg_hash_b);
        }
        MutationType::SubtractCombinedThenAddIndividual => {
            let a = &input.additional_value_a;
            let b = &input.additional_value_b;

            // Create hash(a+b) by combining hash(a) and hash(b)
            let mut hash_a = LtHash::new();
            hash_a.add(a);

            let mut hash_b = LtHash::new();
            hash_b.add(b);

            let mut hash_a_plus_b = LtHash::new();
            hash_a_plus_b.combine(&hash_a);
            hash_a_plus_b.combine(&hash_b);

            // Subtract H(a+b) then add H(a) and H(b)
            let mut neg_hash_a_plus_b = LtHash::new();
            neg_hash_a_plus_b.subtract(a);
            neg_hash_a_plus_b.subtract(b);
            lthash.combine(&neg_hash_a_plus_b);

            lthash.combine(&hash_a);
            lthash.combine(&hash_b);
        }
        MutationType::AddMultipleElementsThenSubtractSum => {
            let num_elements = (input.num_elements as usize % 32) + 1;
            let mut elements = Vec::new();
            let mut sum_hash = LtHash::new();

            // Add random elements and collect them
            for _ in 0..num_elements {
                let element = generate_random_bytes(&mut rng, 1, 256);
                lthash.add(&element);
                sum_hash.add(&element);
                elements.push(element);
            }

            // Subtract the sum of all elements
            let mut neg_sum = LtHash::new();
            for element in &elements {
                neg_sum.subtract(element);
            }
            lthash.combine(&neg_sum);
        }
        MutationType::AddSubtractCommutativitySum => {
            // Generate n random values
            let num_elements = (input.num_elements as usize % 128) + 2; // At least 2 elements
            let mut elements = Vec::new();

            for _ in 0..num_elements {
                let element = generate_random_bytes(&mut rng, 1, 256);
                elements.push(element);
            }

            // Add elements in original order
            for element in &elements {
                lthash.add(element);
            }

            // Shuffle elements
            let mut shuffled_elements = elements.clone();
            for i in (1..shuffled_elements.len()).rev() {
                let j = rng.gen_range(0..=i);
                shuffled_elements.swap(i, j);
            }

            // Subtract elements in shuffled order
            for element in &shuffled_elements {
                lthash.subtract(element);
            }
        }
    }

    let final_checksum = lthash.checksum();
    assert_eq!(initial_checksum, final_checksum, "Final check failed");
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
