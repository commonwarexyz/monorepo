#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_cryptography::{
    bls12381::{self, Batch},
    BatchVerifier, Signer, Verifier,
};
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, SeedableRng};

mod common;
use common::arbitrary_bytes;

#[derive(Debug)]
enum FuzzOperation {
    AddValid {
        private_key_seed: u64,
        namespace: Vec<u8>,
        message: Vec<u8>,
    },
    AddInvalid {
        private_key_seed: u64,
        wrong_private_key_seed: u64,
        namespace: Vec<u8>,
        message: Vec<u8>,
    },
}

impl<'a> Arbitrary<'a> for FuzzOperation {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, arbitrary::Error> {
        if u.arbitrary()? {
            Ok(FuzzOperation::AddValid {
                private_key_seed: u.arbitrary()?,
                namespace: arbitrary_bytes(u, 0, 50)?,
                message: arbitrary_bytes(u, 0, 100)?,
            })
        } else {
            Ok(FuzzOperation::AddInvalid {
                private_key_seed: u.arbitrary()?,
                wrong_private_key_seed: u.arbitrary()?,
                namespace: arbitrary_bytes(u, 0, 50)?,
                message: arbitrary_bytes(u, 0, 100)?,
            })
        }
    }
}

struct FuzzState {
    batch: Batch,
    expected_result: bool,
}

impl FuzzState {
    fn new() -> Self {
        Self {
            batch: Batch::new(),
            expected_result: true,
        }
    }
}

fn fuzz(state: &mut FuzzState, op: FuzzOperation) {
    match op {
        FuzzOperation::AddValid {
            private_key_seed,
            namespace,
            message,
        } => {
            let private_key = bls12381::PrivateKey::from_seed(private_key_seed);
            let public_key = private_key.public_key();
            let signature = private_key.sign(namespace.as_slice(), &message);

            assert!(public_key.verify(namespace.as_slice(), &message, &signature));

            let added = state
                .batch
                .add(namespace.as_slice(), &message, &public_key, &signature);
            assert!(added, "Valid signature should be added to batch");
        }

        FuzzOperation::AddInvalid {
            private_key_seed,
            wrong_private_key_seed,
            namespace,
            message,
        } => {
            let private_key = bls12381::PrivateKey::from_seed(private_key_seed);
            let wrong_private_key = bls12381::PrivateKey::from_seed(wrong_private_key_seed);
            let wrong_public_key = wrong_private_key.public_key();
            let signature = private_key.sign(namespace.as_slice(), &message);

            if private_key_seed != wrong_private_key_seed {
                assert!(!wrong_public_key.verify(namespace.as_slice(), &message, &signature));

                let added = state.batch.add(
                    namespace.as_slice(),
                    &message,
                    &wrong_public_key,
                    &signature,
                );
                if added {
                    state.expected_result = false;
                }
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    let rng_seed: u64 = u.arbitrary().unwrap_or(0);
    let mut rng = StdRng::seed_from_u64(rng_seed);
    let mut state = FuzzState::new();

    let num_ops = u.int_in_range(1..=32).unwrap_or(1);

    for _ in 0..num_ops {
        match u.arbitrary::<FuzzOperation>() {
            Ok(op) => fuzz(&mut state, op),
            Err(_) => break,
        }
    }

    let result = state.batch.verify(&mut rng);
    assert_eq!(result, state.expected_result, "Batch verification failed");
});
