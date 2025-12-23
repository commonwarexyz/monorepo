#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_cryptography::bls12381::primitives::{
    group::{G1, G2},
    ops::*,
    variant::{MinPk, MinSig},
};
use libfuzzer_sys::fuzz_target;

mod common;
use common::{
    arbitrary_bytes, arbitrary_g1, arbitrary_g2, arbitrary_messages, arbitrary_optional_bytes,
    arbitrary_vec_g1, arbitrary_vec_g2,
};

type Message = (Option<Vec<u8>>, Vec<u8>);

#[derive(Debug)]
enum FuzzOperation {
    PublicKeysMinPk {
        public_keys: Vec<G1>,
    },
    PublicKeysMinSig {
        public_keys: Vec<G2>,
    },
    SignaturesMinPk {
        signatures: Vec<G2>,
    },
    SignaturesMinSig {
        signatures: Vec<G1>,
    },
    AggregateVerifyMultiplePublicKeysMinPk {
        public_keys: Vec<G1>,
        namespace: Option<Vec<u8>>,
        message: Vec<u8>,
        signature: G2,
    },
    AggregateVerifyMultiplePublicKeysMinSig {
        public_keys: Vec<G2>,
        namespace: Option<Vec<u8>>,
        message: Vec<u8>,
        signature: G1,
    },
    AggregateVerifyMultipleMessagesMinPk {
        public_key: G1,
        messages: Vec<(Option<Vec<u8>>, Vec<u8>)>,
        signature: G2,
        concurrency: usize,
    },
    AggregateVerifyMultipleMessagesMinSig {
        public_key: G2,
        messages: Vec<(Option<Vec<u8>>, Vec<u8>)>,
        signature: G1,
        concurrency: usize,
    },
}

impl<'a> Arbitrary<'a> for FuzzOperation {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, arbitrary::Error> {
        let choice = u.int_in_range(0..=7)?;

        match choice {
            0 => Ok(FuzzOperation::PublicKeysMinPk {
                public_keys: arbitrary_vec_g1(u, 0, 20)?,
            }),
            1 => Ok(FuzzOperation::PublicKeysMinSig {
                public_keys: arbitrary_vec_g2(u, 0, 20)?,
            }),
            2 => Ok(FuzzOperation::SignaturesMinPk {
                signatures: arbitrary_vec_g2(u, 0, 20)?,
            }),
            3 => Ok(FuzzOperation::SignaturesMinSig {
                signatures: arbitrary_vec_g1(u, 0, 20)?,
            }),
            4 => Ok(FuzzOperation::AggregateVerifyMultiplePublicKeysMinPk {
                public_keys: arbitrary_vec_g1(u, 0, 20)?,
                namespace: arbitrary_optional_bytes(u, 50)?,
                message: arbitrary_bytes(u, 0, 100)?,
                signature: arbitrary_g2(u)?,
            }),
            5 => Ok(FuzzOperation::AggregateVerifyMultiplePublicKeysMinSig {
                public_keys: arbitrary_vec_g2(u, 0, 20)?,
                namespace: arbitrary_optional_bytes(u, 50)?,
                message: arbitrary_bytes(u, 0, 100)?,
                signature: arbitrary_g1(u)?,
            }),
            6 => Ok(FuzzOperation::AggregateVerifyMultipleMessagesMinPk {
                public_key: arbitrary_g1(u)?,
                messages: arbitrary_messages(u, 0, 20)?,
                signature: arbitrary_g2(u)?,
                concurrency: u.int_in_range(1..=8)?,
            }),
            7 => Ok(FuzzOperation::AggregateVerifyMultipleMessagesMinSig {
                public_key: arbitrary_g2(u)?,
                messages: arbitrary_messages(u, 0, 20)?,
                signature: arbitrary_g1(u)?,
                concurrency: u.int_in_range(1..=8)?,
            }),
            _ => Ok(FuzzOperation::PublicKeysMinPk {
                public_keys: Vec::new(),
            }),
        }
    }
}

fn fuzz(op: FuzzOperation) {
    match op {
        FuzzOperation::PublicKeysMinPk { public_keys } => {
            if !public_keys.is_empty() {
                let _result = aggregate_public_keys::<MinPk, _>(&public_keys);
            }
        }

        FuzzOperation::PublicKeysMinSig { public_keys } => {
            if !public_keys.is_empty() {
                let _result = aggregate_public_keys::<MinSig, _>(&public_keys);
            }
        }

        FuzzOperation::SignaturesMinPk { signatures } => {
            if !signatures.is_empty() {
                let _result = aggregate_signatures::<MinPk, _>(&signatures);
            }
        }

        FuzzOperation::SignaturesMinSig { signatures } => {
            if !signatures.is_empty() {
                let _result = aggregate_signatures::<MinSig, _>(&signatures);
            }
        }

        FuzzOperation::AggregateVerifyMultiplePublicKeysMinPk {
            public_keys,
            namespace,
            message,
            signature,
        } => {
            if !public_keys.is_empty() {
                let _ = aggregate_verify_multiple_public_keys::<MinPk, _>(
                    &public_keys,
                    namespace.as_deref(),
                    &message,
                    &signature,
                );
            }
        }

        FuzzOperation::AggregateVerifyMultiplePublicKeysMinSig {
            public_keys,
            namespace,
            message,
            signature,
        } => {
            if !public_keys.is_empty() {
                let _ = aggregate_verify_multiple_public_keys::<MinSig, _>(
                    &public_keys,
                    namespace.as_deref(),
                    &message,
                    &signature,
                );
            }
        }

        FuzzOperation::AggregateVerifyMultipleMessagesMinPk {
            public_key,
            messages,
            signature,
            concurrency,
        } => {
            if !messages.is_empty() && concurrency > 0 {
                let messages_refs: Vec<(Option<&[u8]>, &[u8])> = messages
                    .iter()
                    .map(|(ns, msg)| (ns.as_deref(), msg.as_slice()))
                    .collect();

                let _ = aggregate_verify_multiple_messages::<MinPk, _>(
                    &public_key,
                    &messages_refs,
                    &signature,
                    concurrency,
                );
            }
        }

        FuzzOperation::AggregateVerifyMultipleMessagesMinSig {
            public_key,
            messages,
            signature,
            concurrency,
        } => {
            if !messages.is_empty() && concurrency > 0 {
                let messages_refs: Vec<(Option<&[u8]>, &[u8])> = messages
                    .iter()
                    .map(|(ns, msg)| (ns.as_deref(), msg.as_slice()))
                    .collect();

                let _ = aggregate_verify_multiple_messages::<MinSig, _>(
                    &public_key,
                    &messages_refs,
                    &signature,
                    concurrency,
                );
            }
        }
    }
}

fuzz_target!(|ops: Vec<FuzzOperation>| {
    for op in ops {
        fuzz(op);
    }
});
