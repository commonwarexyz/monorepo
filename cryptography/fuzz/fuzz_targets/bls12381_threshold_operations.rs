#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_cryptography::bls12381::primitives::{
    group::{Share, G1, G2},
    ops::threshold,
    sharing::Sharing,
    variant::{MinPk, MinSig, PartialSignature},
};
use libfuzzer_sys::fuzz_target;
use rand::thread_rng;

mod common;
use common::{
    arbitrary_bytes, arbitrary_messages, arbitrary_partial_sig_g1, arbitrary_partial_sig_g2,
    arbitrary_share, arbitrary_vec_g1, arbitrary_vec_g2, arbitrary_vec_indexed_g1,
    arbitrary_vec_indexed_g2, arbitrary_vec_of_vec_partial_sig_g1,
    arbitrary_vec_of_vec_partial_sig_g2, arbitrary_vec_partial_sig_g1,
    arbitrary_vec_partial_sig_g2,
};

enum FuzzOperation {
    SignProofOfPossessionMinPk {
        public: Sharing<MinPk>,
        share: Share,
    },
    SignProofOfPossessionMinSig {
        public: Sharing<MinSig>,
        share: Share,
    },
    VerifyProofOfPossessionMinPk {
        public: Sharing<MinPk>,
        partial: PartialSignature<MinPk>,
    },
    VerifyProofOfPossessionMinSig {
        public: Sharing<MinSig>,
        partial: PartialSignature<MinSig>,
    },
    BatchVerifyMessagesMinPk {
        public: Sharing<MinPk>,
        index: u32,
        entries: Vec<(Vec<u8>, Vec<u8>, G2)>,
    },
    BatchVerifyMessagesMinSig {
        public: Sharing<MinSig>,
        index: u32,
        entries: Vec<(Vec<u8>, Vec<u8>, G1)>,
    },
    BatchVerifyPublicKeysMinPk {
        public: Sharing<MinPk>,
        namespace: Vec<u8>,
        message: Vec<u8>,
        partials: Vec<(u32, G2)>,
    },
    BatchVerifyPublicKeysMinSig {
        public: Sharing<MinSig>,
        namespace: Vec<u8>,
        message: Vec<u8>,
        partials: Vec<(u32, G1)>,
    },
    RecoverMinPk {
        sharing: Sharing<MinPk>,
        partials: Vec<PartialSignature<MinPk>>,
    },
    RecoverMinSig {
        sharing: Sharing<MinSig>,
        partials: Vec<PartialSignature<MinSig>>,
    },
    RecoverMultipleMinPk {
        sharing: Sharing<MinPk>,
        signature_groups: Vec<Vec<PartialSignature<MinPk>>>,
        concurrency: usize,
    },
    RecoverMultipleMinSig {
        sharing: Sharing<MinSig>,
        signature_groups: Vec<Vec<PartialSignature<MinSig>>>,
        concurrency: usize,
    },
    RecoverPairMinPk {
        sharing: Sharing<MinPk>,
        partials_1: Vec<PartialSignature<MinPk>>,
        partials_2: Vec<PartialSignature<MinPk>>,
    },
    RecoverPairMinSig {
        sharing: Sharing<MinSig>,
        partials_1: Vec<PartialSignature<MinSig>>,
        partials_2: Vec<PartialSignature<MinSig>>,
    },
}

impl<'a> Arbitrary<'a> for FuzzOperation {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, arbitrary::Error> {
        let choice = u.int_in_range(0..=13)?;

        match choice {
            0 => Ok(FuzzOperation::SignProofOfPossessionMinPk {
                public: u.arbitrary()?,
                share: arbitrary_share(u)?,
            }),
            1 => Ok(FuzzOperation::SignProofOfPossessionMinSig {
                public: u.arbitrary()?,
                share: arbitrary_share(u)?,
            }),
            2 => Ok(FuzzOperation::VerifyProofOfPossessionMinPk {
                public: u.arbitrary()?,
                partial: arbitrary_partial_sig_g2(u)?,
            }),
            3 => Ok(FuzzOperation::VerifyProofOfPossessionMinSig {
                public: u.arbitrary()?,
                partial: arbitrary_partial_sig_g1(u)?,
            }),
            4 => {
                let messages = arbitrary_messages(u, 0, 10)?;
                let partials = arbitrary_vec_g2(u, messages.len(), messages.len())?;
                let entries = messages
                    .into_iter()
                    .zip(partials)
                    .map(|((ns, msg), sig)| (ns, msg, sig))
                    .collect();
                Ok(FuzzOperation::BatchVerifyMessagesMinPk {
                    public: u.arbitrary()?,
                    index: u.int_in_range(1..=100)?,
                    entries,
                })
            }
            5 => {
                let messages = arbitrary_messages(u, 0, 10)?;
                let partials = arbitrary_vec_g1(u, messages.len(), messages.len())?;
                let entries = messages
                    .into_iter()
                    .zip(partials)
                    .map(|((ns, msg), sig)| (ns, msg, sig))
                    .collect();
                Ok(FuzzOperation::BatchVerifyMessagesMinSig {
                    public: u.arbitrary()?,
                    index: u.int_in_range(1..=100)?,
                    entries,
                })
            }
            6 => Ok(FuzzOperation::BatchVerifyPublicKeysMinPk {
                public: u.arbitrary()?,
                namespace: arbitrary_bytes(u, 0, 50)?,
                message: arbitrary_bytes(u, 0, 100)?,
                partials: arbitrary_vec_indexed_g2(u, 0, 10)?,
            }),
            7 => Ok(FuzzOperation::BatchVerifyPublicKeysMinSig {
                public: u.arbitrary()?,
                namespace: arbitrary_bytes(u, 0, 50)?,
                message: arbitrary_bytes(u, 0, 100)?,
                partials: arbitrary_vec_indexed_g1(u, 0, 10)?,
            }),
            8 => Ok(FuzzOperation::RecoverMinSig {
                sharing: u.arbitrary()?,
                partials: arbitrary_vec_partial_sig_g1(u, 0, 20)?,
            }),
            9 => Ok(FuzzOperation::RecoverMinPk {
                sharing: u.arbitrary()?,
                partials: arbitrary_vec_partial_sig_g2(u, 0, 20)?,
            }),
            10 => Ok(FuzzOperation::RecoverMultipleMinPk {
                sharing: u.arbitrary()?,
                signature_groups: arbitrary_vec_of_vec_partial_sig_g2(u, 0, 5, 0, 10)?,
                concurrency: u.int_in_range(1..=4)?,
            }),
            11 => Ok(FuzzOperation::RecoverMultipleMinSig {
                sharing: u.arbitrary()?,
                signature_groups: arbitrary_vec_of_vec_partial_sig_g1(u, 0, 5, 0, 10)?,
                concurrency: u.int_in_range(1..=4)?,
            }),
            12 => Ok(FuzzOperation::RecoverPairMinPk {
                sharing: u.arbitrary()?,
                partials_1: arbitrary_vec_partial_sig_g2(u, 0, 10)?,
                partials_2: arbitrary_vec_partial_sig_g2(u, 0, 10)?,
            }),
            13 => Ok(FuzzOperation::RecoverPairMinSig {
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
        FuzzOperation::SignProofOfPossessionMinPk { public, share } => {
            if share.index <= public.required() {
                let _ = threshold::sign_proof_of_possession::<MinPk>(&public, &share);
            }
        }

        FuzzOperation::SignProofOfPossessionMinSig { public, share } => {
            if share.index <= public.required() {
                let _ = threshold::sign_proof_of_possession::<MinSig>(&public, &share);
            }
        }

        FuzzOperation::VerifyProofOfPossessionMinPk { public, partial } => {
            if partial.index <= public.required() {
                let _ = threshold::verify_proof_of_possession::<MinPk>(&public, &partial);
            }
        }

        FuzzOperation::VerifyProofOfPossessionMinSig { public, partial } => {
            if partial.index <= public.required() {
                let _ = threshold::verify_proof_of_possession::<MinSig>(&public, &partial);
            }
        }

        FuzzOperation::BatchVerifyMessagesMinPk {
            public,
            index,
            entries,
        } => {
            if index <= public.required() && !entries.is_empty() {
                let entries_refs: Vec<(&[u8], &[u8], PartialSignature<MinPk>)> = entries
                    .iter()
                    .enumerate()
                    .map(|(i, (ns, msg, sig))| {
                        (
                            ns.as_slice(),
                            msg.as_slice(),
                            PartialSignature {
                                index: index + i as u32,
                                value: *sig,
                            },
                        )
                    })
                    .collect();
                let _ = threshold::batch_verify_messages::<_, MinPk, _>(
                    &mut thread_rng(),
                    &public,
                    index,
                    &entries_refs,
                    1,
                );
            }
        }

        FuzzOperation::BatchVerifyMessagesMinSig {
            public,
            index,
            entries,
        } => {
            if index <= public.required() && !entries.is_empty() {
                let entries_refs: Vec<(&[u8], &[u8], PartialSignature<MinSig>)> = entries
                    .iter()
                    .enumerate()
                    .map(|(i, (ns, msg, sig))| {
                        (
                            ns.as_slice(),
                            msg.as_slice(),
                            PartialSignature {
                                index: index + i as u32,
                                value: *sig,
                            },
                        )
                    })
                    .collect();
                let _ = threshold::batch_verify_messages::<_, MinSig, _>(
                    &mut thread_rng(),
                    &public,
                    index,
                    &entries_refs,
                    1,
                );
            }
        }

        FuzzOperation::BatchVerifyPublicKeysMinPk {
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
                let _ = threshold::batch_verify_public_keys::<_, MinPk, _>(
                    &mut thread_rng(),
                    &public,
                    &namespace,
                    &message,
                    &partials_evals,
                );
            }
        }

        FuzzOperation::BatchVerifyPublicKeysMinSig {
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
                let _ = threshold::batch_verify_public_keys::<_, MinSig, _>(
                    &mut thread_rng(),
                    &public,
                    &namespace,
                    &message,
                    &partials_evals,
                );
            }
        }

        FuzzOperation::RecoverMinPk { sharing, partials } => {
            let _ = threshold::recover::<MinPk, _>(&sharing, &partials);
        }

        FuzzOperation::RecoverMinSig { sharing, partials } => {
            let _ = threshold::recover::<MinSig, _>(&sharing, &partials);
        }

        FuzzOperation::RecoverMultipleMinPk {
            sharing,
            signature_groups,
            concurrency,
        } => {
            if concurrency > 0 && !signature_groups.is_empty() {
                let groups_refs: Vec<Vec<&PartialSignature<MinPk>>> = signature_groups
                    .iter()
                    .map(|group| group.iter().collect())
                    .collect();
                let _ = threshold::recover_multiple::<MinPk, _>(&sharing, groups_refs, concurrency);
            }
        }

        FuzzOperation::RecoverMultipleMinSig {
            sharing,
            signature_groups,
            concurrency,
        } => {
            if concurrency > 0 && !signature_groups.is_empty() {
                let groups_refs: Vec<Vec<&PartialSignature<MinSig>>> = signature_groups
                    .iter()
                    .map(|group| group.iter().collect())
                    .collect();
                let _ =
                    threshold::recover_multiple::<MinSig, _>(&sharing, groups_refs, concurrency);
            }
        }

        FuzzOperation::RecoverPairMinPk {
            sharing,
            partials_1,
            partials_2,
        } => {
            let _ = threshold::recover_pair::<MinPk, _>(&sharing, &partials_1, &partials_2);
        }

        FuzzOperation::RecoverPairMinSig {
            sharing,
            partials_1,
            partials_2,
        } => {
            let _ = threshold::recover_pair::<MinSig, _>(&sharing, &partials_1, &partials_2);
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
