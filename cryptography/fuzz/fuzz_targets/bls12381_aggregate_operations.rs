#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_cryptography::bls12381::primitives::{
    group::{G1, G2},
    ops::aggregate,
    variant::{MinPk, MinSig},
};
use libfuzzer_sys::fuzz_target;

mod common;
use common::{
    arbitrary_bytes, arbitrary_g1, arbitrary_g2, arbitrary_messages, arbitrary_vec_g1,
    arbitrary_vec_g2,
};

#[derive(Debug)]
enum FuzzOperation {
    CombinePublicKeysMinPk {
        public_keys: Vec<G1>,
    },
    CombinePublicKeysMinSig {
        public_keys: Vec<G2>,
    },
    CombineSignaturesMinPk {
        signatures: Vec<G2>,
    },
    CombineSignaturesMinSig {
        signatures: Vec<G1>,
    },
    VerifyPublicKeysMinPk {
        public_keys: Vec<G1>,
        namespace: Vec<u8>,
        message: Vec<u8>,
        signature: G2,
    },
    VerifyPublicKeysMinSig {
        public_keys: Vec<G2>,
        namespace: Vec<u8>,
        message: Vec<u8>,
        signature: G1,
    },
    VerifyMessagesMinPk {
        public_key: G1,
        messages: Vec<(Vec<u8>, Vec<u8>)>,
        signature: G2,
        concurrency: usize,
    },
    VerifyMessagesMinSig {
        public_key: G2,
        messages: Vec<(Vec<u8>, Vec<u8>)>,
        signature: G1,
        concurrency: usize,
    },
}

impl<'a> Arbitrary<'a> for FuzzOperation {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, arbitrary::Error> {
        let choice = u.int_in_range(0..=7)?;

        match choice {
            0 => Ok(FuzzOperation::CombinePublicKeysMinPk {
                public_keys: arbitrary_vec_g1(u, 0, 20)?,
            }),
            1 => Ok(FuzzOperation::CombinePublicKeysMinSig {
                public_keys: arbitrary_vec_g2(u, 0, 20)?,
            }),
            2 => Ok(FuzzOperation::CombineSignaturesMinPk {
                signatures: arbitrary_vec_g2(u, 0, 20)?,
            }),
            3 => Ok(FuzzOperation::CombineSignaturesMinSig {
                signatures: arbitrary_vec_g1(u, 0, 20)?,
            }),
            4 => Ok(FuzzOperation::VerifyPublicKeysMinPk {
                public_keys: arbitrary_vec_g1(u, 0, 20)?,
                namespace: arbitrary_bytes(u, 0, 50)?,
                message: arbitrary_bytes(u, 0, 100)?,
                signature: arbitrary_g2(u)?,
            }),
            5 => Ok(FuzzOperation::VerifyPublicKeysMinSig {
                public_keys: arbitrary_vec_g2(u, 0, 20)?,
                namespace: arbitrary_bytes(u, 0, 50)?,
                message: arbitrary_bytes(u, 0, 100)?,
                signature: arbitrary_g1(u)?,
            }),
            6 => Ok(FuzzOperation::VerifyMessagesMinPk {
                public_key: arbitrary_g1(u)?,
                messages: arbitrary_messages(u, 0, 20)?,
                signature: arbitrary_g2(u)?,
                concurrency: u.int_in_range(1..=8)?,
            }),
            7 => Ok(FuzzOperation::VerifyMessagesMinSig {
                public_key: arbitrary_g2(u)?,
                messages: arbitrary_messages(u, 0, 20)?,
                signature: arbitrary_g1(u)?,
                concurrency: u.int_in_range(1..=8)?,
            }),
            _ => Ok(FuzzOperation::CombinePublicKeysMinPk {
                public_keys: Vec::new(),
            }),
        }
    }
}

fn fuzz(op: FuzzOperation) {
    match op {
        FuzzOperation::CombinePublicKeysMinPk { public_keys } => {
            if !public_keys.is_empty() {
                let _result = aggregate::combine_public_keys::<MinPk, _>(&public_keys);
            }
        }

        FuzzOperation::CombinePublicKeysMinSig { public_keys } => {
            if !public_keys.is_empty() {
                let _result = aggregate::combine_public_keys::<MinSig, _>(&public_keys);
            }
        }

        FuzzOperation::CombineSignaturesMinPk { signatures } => {
            if !signatures.is_empty() {
                let _result = aggregate::combine_signatures::<MinPk, _>(&signatures);
            }
        }

        FuzzOperation::CombineSignaturesMinSig { signatures } => {
            if !signatures.is_empty() {
                let _result = aggregate::combine_signatures::<MinSig, _>(&signatures);
            }
        }

        FuzzOperation::VerifyPublicKeysMinPk {
            public_keys,
            namespace,
            message,
            signature,
        } => {
            if !public_keys.is_empty() {
                let agg_pk = aggregate::combine_public_keys::<MinPk, _>(&public_keys);
                let agg_sig = aggregate::combine_signatures::<MinPk, _>([&signature]);
                let _ =
                    aggregate::verify_public_keys::<MinPk>(&agg_pk, &namespace, &message, &agg_sig);
            }
        }

        FuzzOperation::VerifyPublicKeysMinSig {
            public_keys,
            namespace,
            message,
            signature,
        } => {
            if !public_keys.is_empty() {
                let agg_pk = aggregate::combine_public_keys::<MinSig, _>(&public_keys);
                let agg_sig = aggregate::combine_signatures::<MinSig, _>([&signature]);
                let _ = aggregate::verify_public_keys::<MinSig>(
                    &agg_pk, &namespace, &message, &agg_sig,
                );
            }
        }

        FuzzOperation::VerifyMessagesMinPk {
            public_key,
            messages,
            signature,
            concurrency,
        } => {
            if !messages.is_empty() && concurrency > 0 {
                let messages_refs: Vec<(&[u8], &[u8])> = messages
                    .iter()
                    .map(|(ns, msg)| (ns.as_slice(), msg.as_slice()))
                    .collect();

                let combined_msg = aggregate::combine_messages::<MinPk, _>(&messages_refs, concurrency);
                let agg_sig = aggregate::combine_signatures::<MinPk, _>([&signature]);
                let _ = aggregate::verify_messages::<MinPk>(&public_key, &combined_msg, &agg_sig);
            }
        }

        FuzzOperation::VerifyMessagesMinSig {
            public_key,
            messages,
            signature,
            concurrency,
        } => {
            if !messages.is_empty() && concurrency > 0 {
                let messages_refs: Vec<(&[u8], &[u8])> = messages
                    .iter()
                    .map(|(ns, msg)| (ns.as_slice(), msg.as_slice()))
                    .collect();

                let combined_msg = aggregate::combine_messages::<MinSig, _>(&messages_refs, concurrency);
                let agg_sig = aggregate::combine_signatures::<MinSig, _>([&signature]);
                let _ = aggregate::verify_messages::<MinSig>(&public_key, &combined_msg, &agg_sig);
            }
        }
    }
}

fuzz_target!(|ops: Vec<FuzzOperation>| {
    for op in ops {
        fuzz(op);
    }
});
