#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_cryptography::{BatchEntry, BatchVerifier, Signer, Verifier, bls12381};
use commonware_parallel::Sequential;
use commonware_utils::TestRng;
use libfuzzer_sys::fuzz_target;

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
    batch: Vec<(Vec<u8>, Vec<u8>, bls12381::PublicKey, bls12381::Signature)>,
    expected_result: Option<bool>,
}

impl FuzzState {
    fn new() -> Self {
        Self {
            batch: Vec::new(),
            expected_result: None,
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

            state
                .batch
                .push((namespace, message, public_key, signature));
            state.expected_result = Some(state.expected_result.unwrap_or(true));
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

                state
                    .batch
                    .push((namespace, message, wrong_public_key, signature));
                state.expected_result = Some(false);
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    let rng_seed: u64 = u.arbitrary().unwrap_or(0);
    let mut rng = TestRng::new(rng_seed);
    let mut state = FuzzState::new();

    let num_ops = u.int_in_range(1..=32).unwrap_or(1);

    for _ in 0..num_ops {
        match u.arbitrary::<FuzzOperation>() {
            Ok(op) => fuzz(&mut state, op),
            Err(_) => break,
        }
    }

    let result = bls12381::PublicKey::verify_batch(
        &mut rng,
        &state.batch,
        |_, (namespace, message, public_key, signature)| BatchEntry {
            namespace,
            message,
            public_key,
            signature,
        },
        &Sequential,
    );
    assert_eq!(
        result,
        state.expected_result.unwrap_or(false),
        "Batch verification failed"
    );
});
