#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::{
    BatchEntry, BatchVerifier, Signer, Verifier,
    ed25519::{PrivateKey, PublicKey, Signature},
};
use commonware_parallel::{
    Rayon, Sequential, Strategy,
    mocks::{self, Explorer},
};
use commonware_utils::{NZUsize, TestRng};
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;

#[derive(Arbitrary, Debug, Clone)]
enum BatchOperation {
    AddEd25519 {
        private_key_seed: u64,
        namespace: Vec<u8>,
        message: Vec<u8>,
    },
    AddInvalidEd25519 {
        private_key_seed: u64,
        wrong_private_key_seed: u64,
        namespace: Vec<u8>,
        message: Vec<u8>,
    },
    VerifyEd25519,
}

const MAX_OPERATIONS: usize = 32;
const PLANNED_TASKS: usize = 4;

/// A one-worker pool that plans for several tasks, built once. The explorer on it cuts a batch
/// into shards as a multi-core verifier does, and runs them one after another.
static POOL: LazyLock<Rayon> = LazyLock::new(|| mocks::inline(NZUsize!(PLANNED_TASKS)));

type Entry = (Vec<u8>, Vec<u8>, PublicKey, Signature);

fn verify_with(rng: &mut TestRng, batch: &[Entry], strategy: &impl Strategy) -> bool {
    PublicKey::verify_batch(
        rng,
        batch,
        |_, (namespace, message, public_key, signature)| BatchEntry {
            namespace,
            message,
            public_key,
            signature,
        },
        strategy,
    )
}

/// Verifies the batch serially and in the shape the seed picks for each call, which may shard
/// it, and checks that both shapes give the same verdict. The shaped call draws from its own
/// rng, a copy of the serial one, so the serial calls see the same stream as without it.
fn verify_batch(
    rng: &mut TestRng,
    shape_rng: &mut TestRng,
    batch: &[Entry],
    shape_seed: u64,
) -> bool {
    let serial = verify_with(rng, batch, &Sequential);
    let shaped = verify_with(shape_rng, batch, &Explorer::seeded(&POOL, shape_seed));
    assert_eq!(
        serial, shaped,
        "Ed25519 batch verdict depends on the execution shape"
    );
    serial
}

#[derive(Debug)]
struct FuzzInput {
    rng_seed: u64,
    operations: Vec<BatchOperation>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let rng_seed = u.arbitrary()?;
        let num_ops = u.int_in_range(1..=MAX_OPERATIONS)?;
        let operations = (0..num_ops)
            .map(|_| BatchOperation::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(FuzzInput {
            rng_seed,
            operations,
        })
    }
}

fn fuzz(input: FuzzInput) {
    let mut rng = TestRng::new(input.rng_seed);
    let mut shape_rng = TestRng::new(input.rng_seed);
    let shape_seed = input.rng_seed;

    let mut ed25519_batch = Vec::new();
    let mut expected_ed25519_result = None;

    for op in input.operations {
        match op {
            BatchOperation::AddEd25519 {
                private_key_seed,
                namespace,
                message,
            } => {
                let private_key = PrivateKey::from_seed(private_key_seed);
                let public_key = private_key.public_key();
                let signature = private_key.sign(namespace.as_slice(), &message);

                // Verify individual signature is valid
                assert!(public_key.verify(namespace.as_slice(), &message, &signature));

                ed25519_batch.push((namespace, message, public_key, signature));
                expected_ed25519_result = Some(expected_ed25519_result.unwrap_or(true));
            }

            BatchOperation::AddInvalidEd25519 {
                private_key_seed,
                wrong_private_key_seed,
                namespace,
                message,
            } => {
                // Create signature with one key but verify with another
                let private_key = PrivateKey::from_seed(private_key_seed);
                let wrong_private_key = PrivateKey::from_seed(wrong_private_key_seed);
                let wrong_public_key = wrong_private_key.public_key();
                let signature = private_key.sign(namespace.as_slice(), &message);

                // Only add if keys are different (invalid signature)
                if private_key_seed != wrong_private_key_seed {
                    // Verify individual signature is invalid
                    assert!(!wrong_public_key.verify(namespace.as_slice(), &message, &signature));

                    ed25519_batch.push((namespace, message, wrong_public_key, signature));
                    expected_ed25519_result = Some(false);
                }
            }

            BatchOperation::VerifyEd25519 => {
                let result = verify_batch(&mut rng, &mut shape_rng, &ed25519_batch, shape_seed);
                assert_eq!(
                    result,
                    expected_ed25519_result.unwrap_or(false),
                    "Ed25519 batch verification result mismatch",
                );

                // Reset batch and expectation after verification
                ed25519_batch.clear();
                expected_ed25519_result = None;
            }
        }
    }

    // Final verification of any remaining items
    let ed25519_result = verify_batch(&mut rng, &mut shape_rng, &ed25519_batch, shape_seed);
    assert_eq!(
        ed25519_result,
        expected_ed25519_result.unwrap_or(false),
        "Final Ed25519 batch verification failed"
    );
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
