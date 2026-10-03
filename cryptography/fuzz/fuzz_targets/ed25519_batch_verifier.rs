#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::DecodeExt as _;
use commonware_cryptography::{
    BatchVerifier, Signer, Verifier,
    ed25519::{self, Batch as Ed25519Batch},
};
use commonware_cryptography_curve25519::batch;
use commonware_parallel::Sequential;
use commonware_utils::{TestRng, union_unique};
use libfuzzer_sys::fuzz_target;

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
    AddMutatedEd25519 {
        private_key_seed: u64,
        namespace: Vec<u8>,
        message: Vec<u8>,
        position: u8,
        mask: u8,
    },
    VerifyEd25519,
}

const MAX_OPERATIONS: usize = 32;

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

    let mut ed25519_batch = Ed25519Batch::new(0);
    let mut curve_items: Vec<([u8; 32], [u8; 64], Vec<u8>)> = Vec::new();
    let mut expected_ed25519_result = None;

    for op in input.operations {
        match op {
            BatchOperation::AddEd25519 {
                private_key_seed,
                namespace,
                message,
            } => {
                let private_key = ed25519::PrivateKey::from_seed(private_key_seed);
                let public_key = private_key.public_key();
                let signature = private_key.sign(namespace.as_slice(), &message);

                // Verify individual signature is valid
                assert!(public_key.verify(namespace.as_slice(), &message, &signature));

                let added =
                    ed25519_batch.add(namespace.as_slice(), &message, &public_key, &signature);
                assert!(added, "Valid signature should be added to batch");
                curve_items.push((
                    public_key.as_ref().try_into().unwrap(),
                    signature.as_ref().try_into().unwrap(),
                    union_unique(&namespace, &message),
                ));
                expected_ed25519_result = Some(expected_ed25519_result.unwrap_or(true));
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
                let signature = private_key.sign(namespace.as_slice(), &message);

                // Only add if keys are different (invalid signature)
                if private_key_seed != wrong_private_key_seed {
                    // Verify individual signature is invalid
                    assert!(!wrong_public_key.verify(namespace.as_slice(), &message, &signature));

                    let added = ed25519_batch.add(
                        namespace.as_slice(),
                        &message,
                        &wrong_public_key,
                        &signature,
                    );
                    if added {
                        expected_ed25519_result = Some(false);
                    }
                    curve_items.push((
                        wrong_public_key.as_ref().try_into().unwrap(),
                        signature.as_ref().try_into().unwrap(),
                        union_unique(&namespace, &message),
                    ));
                }
            }

            BatchOperation::AddMutatedEd25519 {
                private_key_seed,
                namespace,
                message,
                position,
                mask,
            } => {
                let private_key = ed25519::PrivateKey::from_seed(private_key_seed);
                let public_key = private_key.public_key();
                let mut bytes = private_key.sign(&namespace, &message).as_ref().to_vec();
                bytes[position as usize % 64] ^= mask;
                let signature = ed25519::Signature::decode(bytes).unwrap();
                let valid = public_key.verify(&namespace, &message, &signature);
                expected_ed25519_result = Some(expected_ed25519_result.unwrap_or(true) && valid);
                assert!(ed25519_batch.add(&namespace, &message, &public_key, &signature));
                curve_items.push((
                    public_key.as_ref().try_into().unwrap(),
                    signature.as_ref().try_into().unwrap(),
                    union_unique(&namespace, &message),
                ));
            }

            BatchOperation::VerifyEd25519 => {
                let result = ed25519_batch.verify(&mut rng, &Sequential);
                assert_eq!(verify_curve(&mut rng, &curve_items), result);
                assert_eq!(
                    result,
                    expected_ed25519_result.unwrap_or(false),
                    "Ed25519 batch verification result mismatch",
                );

                // Reset batch and expectation after verification
                ed25519_batch = Ed25519Batch::new(0);
                curve_items.clear();
                expected_ed25519_result = None;
            }
        }
    }

    // Final verification of any remaining items
    let ed25519_result = ed25519_batch.verify(&mut rng, &Sequential);
    assert_eq!(verify_curve(&mut rng, &curve_items), ed25519_result);
    assert_eq!(
        ed25519_result,
        expected_ed25519_result.unwrap_or(false),
        "Final Ed25519 batch verification failed"
    );
}

fn verify_curve(rng: &mut TestRng, items: &[([u8; 32], [u8; 64], Vec<u8>)]) -> bool {
    batch::verify(
        rng,
        items
            .iter()
            .map(|(key, sig, payload)| (*key, *sig, payload.as_slice())),
        &Sequential,
    )
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
