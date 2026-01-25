#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_codec::{ReadExt, Write};
use commonware_cryptography::bls12381::primitives::{
    group::{Share, G1, G2},
    ops::threshold,
    sharing::Sharing,
    variant::{MinPk, MinSig, PartialSignature},
};
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::{N3f1, Participant};
use libfuzzer_sys::fuzz_target;
use rand::thread_rng;
use std::num::NonZeroUsize;

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
        namespace: Vec<u8>,
    },
    SignProofOfPossessionMinSig {
        public: Sharing<MinSig>,
        share: Share,
        namespace: Vec<u8>,
    },
    VerifyProofOfPossessionMinPk {
        public: Sharing<MinPk>,
        namespace: Vec<u8>,
        partial: PartialSignature<MinPk>,
    },
    VerifyProofOfPossessionMinSig {
        public: Sharing<MinSig>,
        namespace: Vec<u8>,
        partial: PartialSignature<MinSig>,
    },
    BatchVerifySameSignerMinPk {
        public: Sharing<MinPk>,
        index: Participant,
        entries: Vec<(Vec<u8>, Vec<u8>, G2)>,
    },
    BatchVerifySameSignerMinSig {
        public: Sharing<MinSig>,
        index: Participant,
        entries: Vec<(Vec<u8>, Vec<u8>, G1)>,
    },
    BatchVerifySameMessageMinPk {
        public: Sharing<MinPk>,
        namespace: Vec<u8>,
        message: Vec<u8>,
        partials: Vec<(Participant, G2)>,
    },
    BatchVerifySameMessageMinSig {
        public: Sharing<MinSig>,
        namespace: Vec<u8>,
        message: Vec<u8>,
        partials: Vec<(Participant, G1)>,
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
    SignMessageMinPk {
        share: Share,
        namespace: Vec<u8>,
        message: Vec<u8>,
    },
    SignMessageMinSig {
        share: Share,
        namespace: Vec<u8>,
        message: Vec<u8>,
    },
    SerializeShare {
        share: Share,
    },
}

impl<'a> Arbitrary<'a> for FuzzOperation {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, arbitrary::Error> {
        let choice = u.int_in_range(0..=16)?;

        match choice {
            0 => Ok(FuzzOperation::SignProofOfPossessionMinPk {
                public: u.arbitrary()?,
                share: arbitrary_share(u)?,
                namespace: arbitrary_bytes(u, 0, 50)?,
            }),
            1 => Ok(FuzzOperation::SignProofOfPossessionMinSig {
                public: u.arbitrary()?,
                share: arbitrary_share(u)?,
                namespace: arbitrary_bytes(u, 0, 50)?,
            }),
            2 => Ok(FuzzOperation::VerifyProofOfPossessionMinPk {
                public: u.arbitrary()?,
                namespace: arbitrary_bytes(u, 0, 50)?,
                partial: arbitrary_partial_sig_g2(u)?,
            }),
            3 => Ok(FuzzOperation::VerifyProofOfPossessionMinSig {
                public: u.arbitrary()?,
                namespace: arbitrary_bytes(u, 0, 50)?,
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
                Ok(FuzzOperation::BatchVerifySameSignerMinPk {
                    public: u.arbitrary()?,
                    index: Participant::new(u.int_in_range(1..=100)?),
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
                Ok(FuzzOperation::BatchVerifySameSignerMinSig {
                    public: u.arbitrary()?,
                    index: Participant::new(u.int_in_range(1..=100)?),
                    entries,
                })
            }
            6 => Ok(FuzzOperation::BatchVerifySameMessageMinPk {
                public: u.arbitrary()?,
                namespace: arbitrary_bytes(u, 0, 50)?,
                message: arbitrary_bytes(u, 0, 100)?,
                partials: arbitrary_vec_indexed_g2(u, 0, 10)?
                    .into_iter()
                    .map(|(idx, sig)| (Participant::new(idx), sig))
                    .collect(),
            }),
            7 => Ok(FuzzOperation::BatchVerifySameMessageMinSig {
                public: u.arbitrary()?,
                namespace: arbitrary_bytes(u, 0, 50)?,
                message: arbitrary_bytes(u, 0, 100)?,
                partials: arbitrary_vec_indexed_g1(u, 0, 10)?
                    .into_iter()
                    .map(|(idx, sig)| (Participant::new(idx), sig))
                    .collect(),
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
            14 => Ok(FuzzOperation::SignMessageMinPk {
                share: arbitrary_share(u)?,
                namespace: arbitrary_bytes(u, 0, 50)?,
                message: arbitrary_bytes(u, 0, 100)?,
            }),
            15 => Ok(FuzzOperation::SignMessageMinSig {
                share: arbitrary_share(u)?,
                namespace: arbitrary_bytes(u, 0, 50)?,
                message: arbitrary_bytes(u, 0, 100)?,
            }),
            16 => Ok(FuzzOperation::SerializeShare {
                share: arbitrary_share(u)?,
            }),
            _ => {
                panic!("Unsupported operation type");
            }
        }
    }
}

fn fuzz(op: FuzzOperation) {
    match op {
        FuzzOperation::SignProofOfPossessionMinPk {
            public,
            share,
            namespace,
        } => {
            if share.index.get() <= public.required::<N3f1>() {
                let _ = threshold::sign_proof_of_possession::<MinPk>(&public, &share, &namespace);
            }
        }

        FuzzOperation::SignProofOfPossessionMinSig {
            public,
            share,
            namespace,
        } => {
            if share.index.get() <= public.required::<N3f1>() {
                let _ = threshold::sign_proof_of_possession::<MinSig>(&public, &share, &namespace);
            }
        }

        FuzzOperation::VerifyProofOfPossessionMinPk {
            public,
            namespace,
            partial,
        } => {
            if partial.index.get() <= public.required::<N3f1>() {
                let _ =
                    threshold::verify_proof_of_possession::<MinPk>(&public, &namespace, &partial);
            }
        }

        FuzzOperation::VerifyProofOfPossessionMinSig {
            public,
            namespace,
            partial,
        } => {
            if partial.index.get() <= public.required::<N3f1>() {
                let _ =
                    threshold::verify_proof_of_possession::<MinSig>(&public, &namespace, &partial);
            }
        }

        FuzzOperation::BatchVerifySameSignerMinPk {
            public,
            index,
            entries,
        } => {
            if index.get() <= public.required::<N3f1>() && !entries.is_empty() {
                let entries_refs: Vec<(&[u8], &[u8], PartialSignature<MinPk>)> = entries
                    .iter()
                    .enumerate()
                    .map(|(i, (ns, msg, sig))| {
                        (
                            ns.as_slice(),
                            msg.as_slice(),
                            PartialSignature {
                                index: Participant::from_usize(usize::from(index) + i),
                                value: *sig,
                            },
                        )
                    })
                    .collect();
                let _ = threshold::batch_verify_same_signer::<_, MinPk, _>(
                    &mut thread_rng(),
                    &public,
                    index,
                    &entries_refs,
                    &Sequential,
                );
            }
        }

        FuzzOperation::BatchVerifySameSignerMinSig {
            public,
            index,
            entries,
        } => {
            if index.get() <= public.required::<N3f1>() && !entries.is_empty() {
                let entries_refs: Vec<(&[u8], &[u8], PartialSignature<MinSig>)> = entries
                    .iter()
                    .enumerate()
                    .map(|(i, (ns, msg, sig))| {
                        (
                            ns.as_slice(),
                            msg.as_slice(),
                            PartialSignature {
                                index: Participant::from_usize(usize::from(index) + i),
                                value: *sig,
                            },
                        )
                    })
                    .collect();
                let _ = threshold::batch_verify_same_signer::<_, MinSig, _>(
                    &mut thread_rng(),
                    &public,
                    index,
                    &entries_refs,
                    &Sequential,
                );
            }
        }

        FuzzOperation::BatchVerifySameMessageMinPk {
            public,
            namespace,
            message,
            partials,
        } => {
            if public.required::<N3f1>() as usize == partials.len() {
                let partials_evals: Vec<PartialSignature<MinPk>> = partials
                    .into_iter()
                    .map(|(idx, sig)| PartialSignature {
                        index: idx,
                        value: sig,
                    })
                    .collect();
                let _ = threshold::batch_verify_same_message::<_, MinPk, _>(
                    &mut thread_rng(),
                    &public,
                    &namespace,
                    &message,
                    &partials_evals,
                    &Sequential,
                );
            }
        }

        FuzzOperation::BatchVerifySameMessageMinSig {
            public,
            namespace,
            message,
            partials,
        } => {
            if public.required::<N3f1>() as usize == partials.len() {
                let partials_evals: Vec<PartialSignature<MinSig>> = partials
                    .into_iter()
                    .map(|(idx, sig)| PartialSignature {
                        index: idx,
                        value: sig,
                    })
                    .collect();
                let _ = threshold::batch_verify_same_message::<_, MinSig, _>(
                    &mut thread_rng(),
                    &public,
                    &namespace,
                    &message,
                    &partials_evals,
                    &Sequential,
                );
            }
        }

        FuzzOperation::RecoverMinPk { sharing, partials } => {
            let _ = threshold::recover::<MinPk, _, N3f1>(&sharing, &partials, &Sequential);
        }

        FuzzOperation::RecoverMinSig { sharing, partials } => {
            let _ = threshold::recover::<MinSig, _, N3f1>(&sharing, &partials, &Sequential);
        }

        FuzzOperation::RecoverMultipleMinPk {
            sharing,
            signature_groups,
            concurrency,
        } => {
            if !signature_groups.is_empty() {
                let groups_refs: Vec<Vec<&PartialSignature<MinPk>>> = signature_groups
                    .iter()
                    .map(|group| group.iter().collect())
                    .collect();
                let strategy = Rayon::new(NonZeroUsize::new(concurrency).unwrap()).unwrap();
                let _ =
                    threshold::recover_multiple::<MinPk, _, N3f1>(&sharing, groups_refs, &strategy);
            }
        }

        FuzzOperation::RecoverMultipleMinSig {
            sharing,
            signature_groups,
            concurrency,
        } => {
            if !signature_groups.is_empty() {
                let groups_refs: Vec<Vec<&PartialSignature<MinSig>>> = signature_groups
                    .iter()
                    .map(|group| group.iter().collect())
                    .collect();
                let strategy = Rayon::new(NonZeroUsize::new(concurrency).unwrap()).unwrap();
                let _ = threshold::recover_multiple::<MinSig, _, N3f1>(
                    &sharing,
                    groups_refs,
                    &strategy,
                );
            }
        }

        FuzzOperation::RecoverPairMinPk {
            sharing,
            partials_1,
            partials_2,
        } => {
            let _ = threshold::recover_pair::<MinPk, _, N3f1>(
                &sharing,
                &partials_1,
                &partials_2,
                &Sequential,
            );
        }

        FuzzOperation::RecoverPairMinSig {
            sharing,
            partials_1,
            partials_2,
        } => {
            let _ = threshold::recover_pair::<MinSig, _, N3f1>(
                &sharing,
                &partials_1,
                &partials_2,
                &Sequential,
            );
        }

        FuzzOperation::SignMessageMinPk {
            share,
            namespace,
            message,
        } => {
            let _ = threshold::sign_message::<MinPk>(&share, &namespace, &message);
        }

        FuzzOperation::SignMessageMinSig {
            share,
            namespace,
            message,
        } => {
            let _ = threshold::sign_message::<MinSig>(&share, &namespace, &message);
        }

        FuzzOperation::SerializeShare { share } => {
            let mut encoded = Vec::new();
            share.write(&mut encoded);
            if let Ok(decoded) = Share::read(&mut encoded.as_slice()) {
                assert_eq!(share, decoded);
            }
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
