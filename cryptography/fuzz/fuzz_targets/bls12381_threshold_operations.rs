#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_cryptography::bls12381::primitives::{
    group::{Share, G1, G2},
    ops::*,
    sharing::Sharing,
    variant::{MinPk, MinSig, PartialSignature},
};
use libfuzzer_sys::fuzz_target;

mod common;
use common::{
    arbitrary_bytes, arbitrary_messages, arbitrary_optional_bytes, arbitrary_partial_sig_g1,
    arbitrary_partial_sig_g2, arbitrary_share, arbitrary_vec_g1, arbitrary_vec_g2,
    arbitrary_vec_indexed_g1, arbitrary_vec_indexed_g2, arbitrary_vec_of_vec_partial_sig_g1,
    arbitrary_vec_of_vec_partial_sig_g2, arbitrary_vec_partial_sig_g1,
    arbitrary_vec_partial_sig_g2,
};

type Message = (Option<Vec<u8>>, Vec<u8>);

enum FuzzOperation {
    PartialSignProofOfPossessionMinPk {
        public: Sharing<MinPk>,
        share: Share,
    },
    PartialSignProofOfPossessionMinSig {
        public: Sharing<MinSig>,
        share: Share,
    },
    PartialVerifyProofOfPossessionMinPk {
        public: Sharing<MinPk>,
        partial: PartialSignature<MinPk>,
    },
    PartialVerifyProofOfPossessionMinSig {
        public: Sharing<MinSig>,
        partial: PartialSignature<MinSig>,
    },
    PartialAggregateSignaturesMinPk {
        partials: Vec<PartialSignature<MinPk>>,
    },
    PartialAggregateSignaturesMinSig {
        partials: Vec<PartialSignature<MinSig>>,
    },
    PartialVerifyMultipleMessagesMinPk {
        public: Sharing<MinPk>,
        index: u32,
        messages: Vec<(Option<Vec<u8>>, Vec<u8>)>,
        partials: Vec<G2>,
    },
    PartialVerifyMultipleMessagesMinSig {
        public: Sharing<MinSig>,
        index: u32,
        messages: Vec<(Option<Vec<u8>>, Vec<u8>)>,
        partials: Vec<G1>,
    },
    PartialVerifyMultiplePublicKeysMinPk {
        public: Sharing<MinPk>,
        namespace: Option<Vec<u8>>,
        message: Vec<u8>,
        partials: Vec<(u32, G2)>,
    },
    PartialVerifyMultiplePublicKeysMinSig {
        public: Sharing<MinSig>,
        namespace: Option<Vec<u8>>,
        message: Vec<u8>,
        partials: Vec<(u32, G1)>,
    },
    ThresholdSignatureRecoverMinPk {
        sharing: Sharing<MinPk>,
        partials: Vec<PartialSignature<MinPk>>,
    },
    ThresholdSignatureRecoverMinSig {
        sharing: Sharing<MinSig>,
        partials: Vec<PartialSignature<MinSig>>,
    },
    ThresholdSignatureRecoverMultipleMinPk {
        sharing: Sharing<MinPk>,
        signature_groups: Vec<Vec<PartialSignature<MinPk>>>,
        concurrency: usize,
    },
    ThresholdSignatureRecoverMultipleMinSig {
        sharing: Sharing<MinSig>,
        signature_groups: Vec<Vec<PartialSignature<MinSig>>>,
        concurrency: usize,
    },
    ThresholdSignatureRecoverPairMinPk {
        sharing: Sharing<MinPk>,
        partials_1: Vec<PartialSignature<MinPk>>,
        partials_2: Vec<PartialSignature<MinPk>>,
    },
    ThresholdSignatureRecoverPairMinSig {
        sharing: Sharing<MinSig>,
        partials_1: Vec<PartialSignature<MinSig>>,
        partials_2: Vec<PartialSignature<MinSig>>,
    },
}

impl<'a> Arbitrary<'a> for FuzzOperation {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, arbitrary::Error> {
        let choice = u.int_in_range(0..=15)?;

        match choice {
            0 => Ok(FuzzOperation::PartialSignProofOfPossessionMinPk {
                public: u.arbitrary()?,
                share: arbitrary_share(u)?,
            }),
            1 => Ok(FuzzOperation::PartialSignProofOfPossessionMinSig {
                public: u.arbitrary()?,
                share: arbitrary_share(u)?,
            }),
            2 => Ok(FuzzOperation::PartialVerifyProofOfPossessionMinPk {
                public: u.arbitrary()?,
                partial: arbitrary_partial_sig_g2(u)?,
            }),
            3 => Ok(FuzzOperation::PartialVerifyProofOfPossessionMinSig {
                public: u.arbitrary()?,
                partial: arbitrary_partial_sig_g1(u)?,
            }),
            4 => Ok(FuzzOperation::PartialAggregateSignaturesMinPk {
                partials: arbitrary_vec_partial_sig_g2(u, 0, 10)?,
            }),
            5 => Ok(FuzzOperation::PartialAggregateSignaturesMinSig {
                partials: arbitrary_vec_partial_sig_g1(u, 0, 10)?,
            }),
            6 => Ok(FuzzOperation::PartialVerifyMultipleMessagesMinPk {
                public: u.arbitrary()?,
                index: u.int_in_range(1..=100)?,
                messages: arbitrary_messages(u, 0, 10)?,
                partials: arbitrary_vec_g2(u, 0, 10)?,
            }),
            7 => Ok(FuzzOperation::PartialVerifyMultipleMessagesMinSig {
                public: u.arbitrary()?,
                index: u.int_in_range(1..=100)?,
                messages: arbitrary_messages(u, 0, 10)?,
                partials: arbitrary_vec_g1(u, 0, 10)?,
            }),
            8 => Ok(FuzzOperation::PartialVerifyMultiplePublicKeysMinPk {
                public: u.arbitrary()?,
                namespace: arbitrary_optional_bytes(u, 50)?,
                message: arbitrary_bytes(u, 0, 100)?,
                partials: arbitrary_vec_indexed_g2(u, 0, 10)?,
            }),
            9 => Ok(FuzzOperation::PartialVerifyMultiplePublicKeysMinSig {
                public: u.arbitrary()?,
                namespace: arbitrary_optional_bytes(u, 50)?,
                message: arbitrary_bytes(u, 0, 100)?,
                partials: arbitrary_vec_indexed_g1(u, 0, 10)?,
            }),
            10 => Ok(FuzzOperation::ThresholdSignatureRecoverMinSig {
                sharing: u.arbitrary()?,
                partials: arbitrary_vec_partial_sig_g1(u, 0, 20)?,
            }),
            11 => Ok(FuzzOperation::ThresholdSignatureRecoverMinPk {
                sharing: u.arbitrary()?,
                partials: arbitrary_vec_partial_sig_g2(u, 0, 20)?,
            }),
            12 => Ok(FuzzOperation::ThresholdSignatureRecoverMultipleMinPk {
                sharing: u.arbitrary()?,
                signature_groups: arbitrary_vec_of_vec_partial_sig_g2(u, 0, 5, 0, 10)?,
                concurrency: u.int_in_range(1..=4)?,
            }),
            13 => Ok(FuzzOperation::ThresholdSignatureRecoverMultipleMinSig {
                sharing: u.arbitrary()?,
                signature_groups: arbitrary_vec_of_vec_partial_sig_g1(u, 0, 5, 0, 10)?,
                concurrency: u.int_in_range(1..=4)?,
            }),
            14 => Ok(FuzzOperation::ThresholdSignatureRecoverPairMinPk {
                sharing: u.arbitrary()?,
                partials_1: arbitrary_vec_partial_sig_g2(u, 0, 10)?,
                partials_2: arbitrary_vec_partial_sig_g2(u, 0, 10)?,
            }),
            15 => Ok(FuzzOperation::ThresholdSignatureRecoverPairMinSig {
                sharing: u.arbitrary()?,
                partials_1: arbitrary_vec_partial_sig_g1(u, 0, 10)?,
                partials_2: arbitrary_vec_partial_sig_g1(u, 0, 10)?,
            }),
            _ => {
                panic!("Unsupported operation type");
            }
        }
    }
}

fn fuzz(op: FuzzOperation) {
    match op {
        FuzzOperation::PartialSignProofOfPossessionMinPk { public, share } => {
            if share.index <= public.required() {
                let _ = partial_sign_proof_of_possession::<MinPk>(&public, &share);
            }
        }

        FuzzOperation::PartialSignProofOfPossessionMinSig { public, share } => {
            if share.index <= public.required() {
                let _ = partial_sign_proof_of_possession::<MinSig>(&public, &share);
            }
        }

        FuzzOperation::PartialVerifyProofOfPossessionMinPk { public, partial } => {
            if partial.index <= public.required() {
                let _ = partial_verify_proof_of_possession::<MinPk>(&public, &partial);
            }
        }

        FuzzOperation::PartialVerifyProofOfPossessionMinSig { public, partial } => {
            if partial.index <= public.required() {
                let _ = partial_verify_proof_of_possession::<MinSig>(&public, &partial);
            }
        }

        FuzzOperation::PartialAggregateSignaturesMinPk { partials } => {
            let _ = partial_aggregate_signatures::<MinPk, _>(&partials);
        }

        FuzzOperation::PartialAggregateSignaturesMinSig { partials } => {
            let _ = partial_aggregate_signatures::<MinSig, _>(&partials);
        }

        FuzzOperation::PartialVerifyMultipleMessagesMinPk {
            public,
            index,
            messages,
            partials,
        } => {
            if index <= public.required() && messages.len() == partials.len() {
                let messages_refs: Vec<(Option<&[u8]>, &[u8])> = messages
                    .iter()
                    .map(|(ns, msg)| (ns.as_deref(), msg.as_slice()))
                    .collect();
                let partials_evals: Vec<PartialSignature<MinPk>> = partials
                    .into_iter()
                    .enumerate()
                    .map(|(i, sig)| PartialSignature {
                        index: index + i as u32,
                        value: sig,
                    })
                    .collect();
                let _ = partial_verify_multiple_messages::<MinPk, _, _>(
                    &public,
                    index,
                    &messages_refs,
                    &partials_evals,
                );
            }
        }

        FuzzOperation::PartialVerifyMultipleMessagesMinSig {
            public,
            index,
            messages,
            partials,
        } => {
            if index <= public.required() && messages.len() == partials.len() {
                let messages_refs: Vec<(Option<&[u8]>, &[u8])> = messages
                    .iter()
                    .map(|(ns, msg)| (ns.as_deref(), msg.as_slice()))
                    .collect();
                let partials_evals: Vec<PartialSignature<MinSig>> = partials
                    .into_iter()
                    .enumerate()
                    .map(|(i, sig)| PartialSignature {
                        index: index + i as u32,
                        value: sig,
                    })
                    .collect();
                let _ = partial_verify_multiple_messages::<MinSig, _, _>(
                    &public,
                    index,
                    &messages_refs,
                    &partials_evals,
                );
            }
        }

        FuzzOperation::PartialVerifyMultiplePublicKeysMinPk {
            public,
            namespace,
            message,
            partials,
        } => {
            if public.required() as usize == partials.len() {
                let partials_evals: Vec<PartialSignature<MinPk>> = partials
                    .into_iter()
                    .map(|(idx, sig)| PartialSignature {
                        index: idx,
                        value: sig,
                    })
                    .collect();
                let _ = partial_verify_multiple_public_keys::<MinPk, _>(
                    &public,
                    namespace.as_deref(),
                    &message,
                    &partials_evals,
                );
            }
        }

        FuzzOperation::PartialVerifyMultiplePublicKeysMinSig {
            public,
            namespace,
            message,
            partials,
        } => {
            if public.required() as usize == partials.len() {
                let partials_evals: Vec<PartialSignature<MinSig>> = partials
                    .into_iter()
                    .map(|(idx, sig)| PartialSignature {
                        index: idx,
                        value: sig,
                    })
                    .collect();
                let _ = partial_verify_multiple_public_keys::<MinSig, _>(
                    &public,
                    namespace.as_deref(),
                    &message,
                    &partials_evals,
                );
            }
        }

        FuzzOperation::ThresholdSignatureRecoverMinPk { sharing, partials } => {
            let _ = threshold_signature_recover::<MinPk, _>(&sharing, &partials);
        }

        FuzzOperation::ThresholdSignatureRecoverMinSig { sharing, partials } => {
            let _ = threshold_signature_recover::<MinSig, _>(&sharing, &partials);
        }

        FuzzOperation::ThresholdSignatureRecoverMultipleMinPk {
            sharing,
            signature_groups,
            concurrency,
        } => {
            if concurrency > 0 && !signature_groups.is_empty() {
                let groups_refs: Vec<Vec<&PartialSignature<MinPk>>> = signature_groups
                    .iter()
                    .map(|group| group.iter().collect())
                    .collect();
                let _ = threshold_signature_recover_multiple::<MinPk, _>(
                    &sharing,
                    groups_refs,
                    concurrency,
                );
            }
        }

        FuzzOperation::ThresholdSignatureRecoverMultipleMinSig {
            sharing,
            signature_groups,
            concurrency,
        } => {
            if concurrency > 0 && !signature_groups.is_empty() {
                let groups_refs: Vec<Vec<&PartialSignature<MinSig>>> = signature_groups
                    .iter()
                    .map(|group| group.iter().collect())
                    .collect();
                let _ = threshold_signature_recover_multiple::<MinSig, _>(
                    &sharing,
                    groups_refs,
                    concurrency,
                );
            }
        }

        FuzzOperation::ThresholdSignatureRecoverPairMinPk {
            sharing,
            partials_1,
            partials_2,
        } => {
            let _ =
                threshold_signature_recover_pair::<MinPk, _>(&sharing, &partials_1, &partials_2);
        }

        FuzzOperation::ThresholdSignatureRecoverPairMinSig {
            sharing,
            partials_1,
            partials_2,
        } => {
            let _ =
                threshold_signature_recover_pair::<MinSig, _>(&sharing, &partials_1, &partials_2);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    let num_ops = u.int_in_range(1..=100).unwrap_or(1);

    for _ in 0..num_ops {
        match u.arbitrary::<FuzzOperation>() {
            Ok(op) => fuzz(op),
            Err(_) => break,
        }
    }
});
