#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::{
    ed25519::{self, Batch as Ed25519Batch},
    BatchVerifier, PrivateKeyExt, Signer, Verifier,
};
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, SeedableRng};

#[derive(Arbitrary, Debug, Clone)]
enum BatchOperation {
    AddEd25519 {
        private_key_seed: u64,
        namespace: Option<Vec<u8>>,
        message: Vec<u8>,
    },
    AddInvalidEd25519 {
        private_key_seed: u64,
        wrong_private_key_seed: u64,
        namespace: Option<Vec<u8>>,
        message: Vec<u8>,
    },
    VerifyEd25519,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    rng_seed: u64,
    operations: Vec<BatchOperation>,
}

fn fuzz(input: FuzzInput) {
    let mut rng = StdRng::seed_from_u64(input.rng_seed);

    let mut ed25519_batch = Ed25519Batch::new();
    let mut expected_ed25519_result = true;

    for op in input.operations.into_iter().take(32) {
        match op {
            BatchOperation::AddEd25519 {
                private_key_seed,
                namespace,
                message,
            } => {
                let private_key = ed25519::PrivateKey::from_seed(private_key_seed);
                let public_key = private_key.public_key();
                let signature = private_key.sign(namespace.as_deref(), &message);

                // Verify individual signature is valid
                assert!(public_key.verify(namespace.as_deref(), &message, &signature));

                let added =
                    ed25519_batch.add(namespace.as_deref(), &message, &public_key, &signature);
                assert!(added, "Valid signature should be added to batch");
            }

            BatchOperation::AddInvalidEd25519 {
                private_key_seed,
                wrong_private_key_seed,
                namespace,
                message,
            } => {
                // Create signature with one key but verify with another
                let private_key = ed25519::PrivateKey::from_seed(private_key_seed);
                let wrong_private_key = ed25519::PrivateKey::from_seed(wrong_private_key_seed);
                let wrong_public_key = wrong_private_key.public_key();
                let signature = private_key.sign(namespace.as_deref(), &message);

                // Only add if keys are different (invalid signature)
                if private_key_seed != wrong_private_key_seed {
                    // Verify individual signature is invalid
                    assert!(!wrong_public_key.verify(namespace.as_deref(), &message, &signature));

                    let added = ed25519_batch.add(
                        namespace.as_deref(),
                        &message,
                        &wrong_public_key,
                        &signature,
                    );
                    if added {
                        expected_ed25519_result = false;
                    }
                }
            }

            BatchOperation::VerifyEd25519 => {
                let result = ed25519_batch.verify(&mut rng);
                assert_eq!(
                    result, expected_ed25519_result,
                    "Ed25519 batch verification result mismatch: expected {expected_ed25519_result}, got {result}",
                );

                // Reset batch and expectation after verification
                ed25519_batch = Ed25519Batch::new();
                expected_ed25519_result = true;
            }
        }
    }

    // Final verification of any remaining items
    let ed25519_result = ed25519_batch.verify(&mut rng);
    assert_eq!(
        ed25519_result, expected_ed25519_result,
        "Final Ed25519 batch verification failed"
    );
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
