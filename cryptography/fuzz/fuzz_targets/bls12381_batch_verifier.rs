#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::{
    bls12381::{self, Batch as BlsBatch},
    BatchVerifier, PrivateKeyExt, Signer, Verifier,
};
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, SeedableRng};

#[derive(Arbitrary, Debug, Clone)]
enum BatchOperation {
    AddBls12381 {
        private_key_seed: u64,
        namespace: Option<Vec<u8>>,
        message: Vec<u8>,
    },
    AddInvalidBls12381 {
        private_key_seed: u64,
        wrong_private_key_seed: u64,
        namespace: Option<Vec<u8>>,
        message: Vec<u8>,
    },
    VerifyBls12381,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    rng_seed: u64,
    operations: Vec<BatchOperation>,
}

fn fuzz(input: FuzzInput) {
    let mut rng = StdRng::seed_from_u64(input.rng_seed);
    let mut bls12381_batch = BlsBatch::new();
    let mut expected_bls12381_result = true;

    for op in input.operations.into_iter().take(32) {
        match op {
            BatchOperation::AddBls12381 {
                private_key_seed,
                namespace,
                message,
            } => {
                let private_key = bls12381::PrivateKey::from_seed(private_key_seed);
                let public_key = private_key.public_key();
                let signature = private_key.sign(namespace.as_deref(), &message);

                // Verify individual signature is valid
                assert!(public_key.verify(namespace.as_deref(), &message, &signature));

                let added =
                    bls12381_batch.add(namespace.as_deref(), &message, &public_key, &signature);
                assert!(added, "Valid signature should be added to batch");
            }

            BatchOperation::AddInvalidBls12381 {
                private_key_seed,
                wrong_private_key_seed,
                namespace,
                message,
            } => {
                // Create signature with one key but verify with another
                let private_key = bls12381::PrivateKey::from_seed(private_key_seed);
                let wrong_private_key = bls12381::PrivateKey::from_seed(wrong_private_key_seed);
                let wrong_public_key = wrong_private_key.public_key();
                let signature = private_key.sign(namespace.as_deref(), &message);

                // Only add if keys are different (invalid signature)
                if private_key_seed != wrong_private_key_seed {
                    // Verify individual signature is invalid
                    assert!(!wrong_public_key.verify(namespace.as_deref(), &message, &signature));

                    let added = bls12381_batch.add(
                        namespace.as_deref(),
                        &message,
                        &wrong_public_key,
                        &signature,
                    );
                    if added {
                        expected_bls12381_result = false;
                    }
                }
            }

            BatchOperation::VerifyBls12381 => {
                let result = bls12381_batch.verify(&mut rng);
                assert_eq!(
                    result, expected_bls12381_result,
                    "BLS12-381 batch verification result mismatch: expected {expected_bls12381_result}, got {result}",
                );

                // Reset batch and expectation after verification
                bls12381_batch = BlsBatch::new();
                expected_bls12381_result = true;
            }
        }
    }

    // Final verification of any remaining items
    let bls12381_result = bls12381_batch.verify(&mut rng);
    assert_eq!(
        bls12381_result, expected_bls12381_result,
        "Final BLS12-381 batch verification failed"
    );
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
