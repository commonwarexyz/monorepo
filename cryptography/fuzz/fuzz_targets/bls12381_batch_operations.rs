#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_cryptography::{
    bls12381::{
        self,
        primitives::{
            group::{G1, G2},
            ops::batch,
            variant::{MinPk, MinSig},
        },
        Batch as BlsBatch,
    },
    BatchVerifier, Signer, Verifier,
};
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, thread_rng, SeedableRng};

mod common;
use common::{arbitrary_bytes, arbitrary_g1, arbitrary_g2, arbitrary_messages};

#[derive(Debug)]
enum FuzzOperation {
    VerifyMessagesMinPk {
        public_key: G1,
        entries: Vec<(Vec<u8>, Vec<u8>, G2)>,
        concurrency: usize,
    },
    VerifyMessagesMinSig {
        public_key: G2,
        entries: Vec<(Vec<u8>, Vec<u8>, G1)>,
        concurrency: usize,
    },
    AddBls12381 {
        private_key_seed: u64,
        namespace: Vec<u8>,
        message: Vec<u8>,
    },
    AddInvalidBls12381 {
        private_key_seed: u64,
        wrong_private_key_seed: u64,
        namespace: Vec<u8>,
        message: Vec<u8>,
    },
    VerifyBls12381,
}

impl<'a> Arbitrary<'a> for FuzzOperation {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, arbitrary::Error> {
        let choice = u.int_in_range(0..=4)?;

        match choice {
            0 => {
                let messages = arbitrary_messages(u, 0, 20)?;
                let signatures_len = messages.len();
                let mut signatures = Vec::with_capacity(signatures_len);
                for _ in 0..signatures_len {
                    signatures.push(arbitrary_g2(u)?);
                }
                let entries = messages
                    .into_iter()
                    .zip(signatures)
                    .map(|((ns, msg), sig)| (ns, msg, sig))
                    .collect();
                Ok(FuzzOperation::VerifyMessagesMinPk {
                    public_key: arbitrary_g1(u)?,
                    entries,
                    concurrency: u.int_in_range(1..=8)?,
                })
            }
            1 => {
                let messages = arbitrary_messages(u, 0, 20)?;
                let signatures_len = messages.len();
                let mut signatures = Vec::with_capacity(signatures_len);
                for _ in 0..signatures_len {
                    signatures.push(arbitrary_g1(u)?);
                }
                let entries = messages
                    .into_iter()
                    .zip(signatures)
                    .map(|((ns, msg), sig)| (ns, msg, sig))
                    .collect();
                Ok(FuzzOperation::VerifyMessagesMinSig {
                    public_key: arbitrary_g2(u)?,
                    entries,
                    concurrency: u.int_in_range(1..=8)?,
                })
            }
            2 => Ok(FuzzOperation::AddBls12381 {
                private_key_seed: u.arbitrary()?,
                namespace: arbitrary_bytes(u, 0, 50)?,
                message: arbitrary_bytes(u, 0, 100)?,
            }),
            3 => Ok(FuzzOperation::AddInvalidBls12381 {
                private_key_seed: u.arbitrary()?,
                wrong_private_key_seed: u.arbitrary()?,
                namespace: arbitrary_bytes(u, 0, 50)?,
                message: arbitrary_bytes(u, 0, 100)?,
            }),
            4 => Ok(FuzzOperation::VerifyBls12381),
            _ => Ok(FuzzOperation::VerifyBls12381),
        }
    }
}

struct FuzzState {
    bls12381_batch: BlsBatch,
    expected_bls12381_result: bool,
}

impl FuzzState {
    fn new() -> Self {
        Self {
            bls12381_batch: BlsBatch::new(),
            expected_bls12381_result: true,
        }
    }
}

fn fuzz(state: &mut FuzzState, rng: &mut StdRng, op: FuzzOperation) {
    match op {
        FuzzOperation::VerifyMessagesMinPk {
            public_key,
            entries,
            concurrency,
        } => {
            if !entries.is_empty() && concurrency > 0 {
                let entries_refs: Vec<_> = entries
                    .iter()
                    .map(|(ns, msg, sig)| (ns.as_slice(), msg.as_slice(), *sig))
                    .collect();

                let _ = batch::verify_messages::<_, MinPk, _>(
                    &mut thread_rng(),
                    &public_key,
                    &entries_refs,
                    concurrency,
                );
            }
        }

        FuzzOperation::VerifyMessagesMinSig {
            public_key,
            entries,
            concurrency,
        } => {
            if !entries.is_empty() && concurrency > 0 {
                let entries_refs: Vec<_> = entries
                    .iter()
                    .map(|(ns, msg, sig)| (ns.as_slice(), msg.as_slice(), *sig))
                    .collect();

                let _ = batch::verify_messages::<_, MinSig, _>(
                    &mut thread_rng(),
                    &public_key,
                    &entries_refs,
                    concurrency,
                );
            }
        }

        FuzzOperation::AddBls12381 {
            private_key_seed,
            namespace,
            message,
        } => {
            let private_key = bls12381::PrivateKey::from_seed(private_key_seed);
            let public_key = private_key.public_key();
            let signature = private_key.sign(namespace.as_slice(), &message);

            assert!(public_key.verify(namespace.as_slice(), &message, &signature));

            let added =
                state
                    .bls12381_batch
                    .add(namespace.as_slice(), &message, &public_key, &signature);
            assert!(added, "Valid signature should be added to batch");
        }

        FuzzOperation::AddInvalidBls12381 {
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

                let added = state.bls12381_batch.add(
                    namespace.as_slice(),
                    &message,
                    &wrong_public_key,
                    &signature,
                );
                if added {
                    state.expected_bls12381_result = false;
                }
            }
        }

        FuzzOperation::VerifyBls12381 => {
            let batch = std::mem::replace(&mut state.bls12381_batch, BlsBatch::new());
            let result = batch.verify(rng);
            assert_eq!(
                result, state.expected_bls12381_result,
                "BLS12-381 batch verification result mismatch: expected {}, got {}",
                state.expected_bls12381_result, result,
            );

            state.expected_bls12381_result = true;
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
            Ok(op) => fuzz(&mut state, &mut rng, op),
            Err(_) => break,
        }
    }

    let bls12381_result = state.bls12381_batch.verify(&mut rng);
    assert_eq!(
        bls12381_result, state.expected_bls12381_result,
        "Final BLS12-381 batch verification failed"
    );
});
