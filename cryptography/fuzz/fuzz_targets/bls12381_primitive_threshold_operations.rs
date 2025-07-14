#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_codec::ReadExt;
use commonware_cryptography::bls12381::primitives::{
    group::{Element, Scalar, Share, G1, G2},
    ops::*,
    poly::{compute_weights, Eval, Weight},
    variant::{MinPk, MinSig},
};
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;

enum FuzzOperation {
    PartialSignProofOfPossessionMinPk {
        public: Poly<G1>,
        share: Share,
    },
    PartialSignProofOfPossessionMinSig {
        public: Poly<G2>,
        share: Share,
    },
    PartialVerifyProofOfPossessionMinPk {
        public: Poly<G1>,
        partial: Eval<G2>,
    },
    PartialVerifyProofOfPossessionMinSig {
        public: Poly<G2>,
        partial: Eval<G1>,
    },
    PartialAggregateSignaturesMinPk {
        partials: Vec<Eval<G2>>,
    },
    PartialAggregateSignaturesMinSig {
        partials: Vec<Eval<G1>>,
    },
    PartialVerifyMultipleMessagesMinPk {
        public: Poly<G1>,
        index: u32,
        messages: Vec<(Option<Vec<u8>>, Vec<u8>)>,
        partials: Vec<G2>,
    },
    PartialVerifyMultipleMessagesMinSig {
        public: Poly<G2>,
        index: u32,
        messages: Vec<(Option<Vec<u8>>, Vec<u8>)>,
        partials: Vec<G1>,
    },
    PartialVerifyMultiplePublicKeysMinPk {
        public: Vec<(u32, G1)>,
        namespace: Option<Vec<u8>>,
        message: Vec<u8>,
        partials: Vec<(u32, G2)>,
    },
    PartialVerifyMultiplePublicKeysMinSig {
        public: Vec<(u32, G2)>,
        namespace: Option<Vec<u8>>,
        message: Vec<u8>,
        partials: Vec<(u32, G1)>,
    },
    PartialVerifyMultiplePublicKeysPrecomputedMinPk {
        pending: Vec<(u32, G1, G2)>,
        namespace: Option<Vec<u8>>,
        message: Vec<u8>,
    },
    PartialVerifyMultiplePublicKeysPrecomputedMinSig {
        pending: Vec<(u32, G2, G1)>,
        namespace: Option<Vec<u8>>,
        message: Vec<u8>,
    },
    MsmInterpolateG1 {
        weights: BTreeMap<u32, Weight>,
        evals: Vec<Eval<G1>>,
    },
    MsmInterpolateG2 {
        weights: BTreeMap<u32, Weight>,
        evals: Vec<Eval<G2>>,
    },
    ThresholdSignatureRecoverMinPk {
        threshold: u32,
        partials: Vec<Eval<G2>>,
    },
    ThresholdSignatureRecoverMinSig {
        threshold: u32,
        partials: Vec<Eval<G1>>,
    },
    ThresholdSignatureRecoverWithWeightsMinPk {
        weights: BTreeMap<u32, Weight>,
        partials: Vec<Eval<G2>>,
    },
    ThresholdSignatureRecoverWithWeightsMinSig {
        weights: BTreeMap<u32, Weight>,
        partials: Vec<Eval<G1>>,
    },
    ThresholdSignatureRecoverMultipleMinPk {
        threshold: u32,
        signature_groups: Vec<Vec<Eval<G2>>>,
        concurrency: usize,
    },
    ThresholdSignatureRecoverMultipleMinSig {
        threshold: u32,
        signature_groups: Vec<Vec<Eval<G1>>>,
        concurrency: usize,
    },
    ThresholdSignatureRecoverPairMinPk {
        threshold: u32,
        partials_1: Vec<Eval<G2>>,
        partials_2: Vec<Eval<G2>>,
    },
    ThresholdSignatureRecoverPairMinSig {
        threshold: u32,
        partials_1: Vec<Eval<G1>>,
        partials_2: Vec<Eval<G1>>,
    },
}

impl<'a> Arbitrary<'a> for FuzzOperation {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, arbitrary::Error> {
        let choice = u.int_in_range(0..=21)?;

        match choice {
            0 => Ok(FuzzOperation::PartialSignProofOfPossessionMinPk {
                public: arbitrary_poly_g1(u)?,
                share: arbitrary_share(u)?,
            }),
            1 => Ok(FuzzOperation::PartialSignProofOfPossessionMinSig {
                public: arbitrary_poly_g2(u)?,
                share: arbitrary_share(u)?,
            }),
            2 => Ok(FuzzOperation::PartialVerifyProofOfPossessionMinPk {
                public: arbitrary_poly_g1(u)?,
                partial: arbitrary_eval_g2(u)?,
            }),
            3 => Ok(FuzzOperation::PartialVerifyProofOfPossessionMinSig {
                public: arbitrary_poly_g2(u)?,
                partial: arbitrary_eval_g1(u)?,
            }),
            4 => Ok(FuzzOperation::PartialAggregateSignaturesMinPk {
                partials: arbitrary_vec_eval_g2(u, 0, 10)?,
            }),
            5 => Ok(FuzzOperation::PartialAggregateSignaturesMinSig {
                partials: arbitrary_vec_eval_g1(u, 0, 10)?,
            }),
            6 => Ok(FuzzOperation::PartialVerifyMultipleMessagesMinPk {
                public: arbitrary_poly_g1(u)?,
                index: u.int_in_range(1..=100)?,
                messages: arbitrary_messages(u, 0, 10)?,
                partials: arbitrary_vec_g2(u, 0, 10)?,
            }),
            7 => Ok(FuzzOperation::PartialVerifyMultipleMessagesMinSig {
                public: arbitrary_poly_g2(u)?,
                index: u.int_in_range(1..=100)?,
                messages: arbitrary_messages(u, 0, 10)?,
                partials: arbitrary_vec_g1(u, 0, 10)?,
            }),
            8 => Ok(FuzzOperation::PartialVerifyMultiplePublicKeysMinPk {
                public: arbitrary_vec_indexed_g1(u, 0, 10)?,
                namespace: arbitrary_optional_bytes(u, 50)?,
                message: arbitrary_bytes(u, 0, 100)?,
                partials: arbitrary_vec_indexed_g2(u, 0, 10)?,
            }),
            9 => Ok(FuzzOperation::PartialVerifyMultiplePublicKeysMinSig {
                public: arbitrary_vec_indexed_g2(u, 0, 10)?,
                namespace: arbitrary_optional_bytes(u, 50)?,
                message: arbitrary_bytes(u, 0, 100)?,
                partials: arbitrary_vec_indexed_g1(u, 0, 10)?,
            }),
            10 => Ok(
                FuzzOperation::PartialVerifyMultiplePublicKeysPrecomputedMinPk {
                    pending: arbitrary_vec_pending_minpk(u, 0, 10)?,
                    namespace: arbitrary_optional_bytes(u, 50)?,
                    message: arbitrary_bytes(u, 0, 100)?,
                },
            ),
            11 => Ok(
                FuzzOperation::PartialVerifyMultiplePublicKeysPrecomputedMinSig {
                    pending: arbitrary_vec_pending_minsig(u, 0, 10)?,
                    namespace: arbitrary_optional_bytes(u, 50)?,
                    message: arbitrary_bytes(u, 0, 100)?,
                },
            ),
            12 => Ok(FuzzOperation::MsmInterpolateG1 {
                weights: arbitrary_weights(u, 0, 10)?,
                evals: arbitrary_vec_eval_g1(u, 0, 10)?,
            }),
            13 => Ok(FuzzOperation::MsmInterpolateG2 {
                weights: arbitrary_weights(u, 0, 10)?,
                evals: arbitrary_vec_eval_g2(u, 0, 10)?,
            }),
            14 => Ok(FuzzOperation::ThresholdSignatureRecoverMinPk {
                threshold: u.int_in_range(1..=10)?,
                partials: arbitrary_vec_eval_g2(u, 0, 20)?,
            }),
            15 => Ok(FuzzOperation::ThresholdSignatureRecoverMinSig {
                threshold: u.int_in_range(1..=10)?,
                partials: arbitrary_vec_eval_g1(u, 0, 20)?,
            }),
            16 => Ok(FuzzOperation::ThresholdSignatureRecoverWithWeightsMinPk {
                weights: arbitrary_weights(u, 0, 10)?,
                partials: arbitrary_vec_eval_g2(u, 0, 20)?,
            }),
            17 => Ok(FuzzOperation::ThresholdSignatureRecoverWithWeightsMinSig {
                weights: arbitrary_weights(u, 0, 10)?,
                partials: arbitrary_vec_eval_g1(u, 0, 20)?,
            }),
            18 => Ok(FuzzOperation::ThresholdSignatureRecoverMultipleMinPk {
                threshold: u.int_in_range(1..=10)?,
                signature_groups: arbitrary_vec_of_vec_eval_g2(u, 0, 5, 0, 10)?,
                concurrency: u.int_in_range(1..=4)?,
            }),
            19 => Ok(FuzzOperation::ThresholdSignatureRecoverMultipleMinSig {
                threshold: u.int_in_range(1..=10)?,
                signature_groups: arbitrary_vec_of_vec_eval_g1(u, 0, 5, 0, 10)?,
                concurrency: u.int_in_range(1..=4)?,
            }),
            20 => Ok(FuzzOperation::ThresholdSignatureRecoverPairMinPk {
                threshold: u.int_in_range(1..=10)?,
                partials_1: arbitrary_vec_eval_g2(u, 0, 10)?,
                partials_2: arbitrary_vec_eval_g2(u, 0, 10)?,
            }),

            21 => Ok(FuzzOperation::ThresholdSignatureRecoverPairMinSig {
                threshold: u.int_in_range(1..=10)?,
                partials_1: arbitrary_vec_eval_g1(u, 0, 10)?,
                partials_2: arbitrary_vec_eval_g1(u, 0, 10)?,
            }),
            _ => {
                panic!("Unsupported operation type");
            }
        }
    }
}

use commonware_cryptography::bls12381::primitives::poly::Poly;

fn arbitrary_scalar(u: &mut Unstructured) -> Result<Scalar, arbitrary::Error> {
    let bytes: [u8; 32] = u.arbitrary()?;
    match Scalar::read(&mut bytes.as_slice()) {
        Ok(s) => Ok(s),
        Err(_) => Ok(Scalar::from_index(u.int_in_range(0..=u32::MAX)?)),
    }
}

fn arbitrary_g1(u: &mut Unstructured) -> Result<G1, arbitrary::Error> {
    let bytes: [u8; 48] = u.arbitrary()?;
    match G1::read(&mut bytes.as_slice()) {
        Ok(point) => Ok(point),
        Err(_) => Ok(if u.arbitrary()? {
            G1::zero()
        } else {
            G1::one()
        }),
    }
}

fn arbitrary_g2(u: &mut Unstructured) -> Result<G2, arbitrary::Error> {
    let bytes: [u8; 96] = u.arbitrary()?;
    match G2::read(&mut bytes.as_slice()) {
        Ok(point) => Ok(point),
        Err(_) => Ok(if u.arbitrary()? {
            G2::zero()
        } else {
            G2::one()
        }),
    }
}

fn arbitrary_share(u: &mut Unstructured) -> Result<Share, arbitrary::Error> {
    Ok(Share {
        index: u.int_in_range(1..=100)?,
        private: arbitrary_scalar(u)?,
    })
}

fn arbitrary_poly_scalar(u: &mut Unstructured) -> Result<Poly<Scalar>, arbitrary::Error> {
    let degree = u.int_in_range(0..=10)?;
    let coeffs = arbitrary_vec_scalar(u, degree as usize + 1, degree as usize + 1)?;
    Ok(Poly::from(coeffs))
}

fn arbitrary_poly_g1(u: &mut Unstructured) -> Result<Poly<G1>, arbitrary::Error> {
    let scalar_poly = arbitrary_poly_scalar(u)?;
    Ok(Poly::<G1>::commit(scalar_poly))
}

fn arbitrary_poly_g2(u: &mut Unstructured) -> Result<Poly<G2>, arbitrary::Error> {
    let scalar_poly = arbitrary_poly_scalar(u)?;
    Ok(Poly::<G2>::commit(scalar_poly))
}

fn arbitrary_eval_g1(u: &mut Unstructured) -> Result<Eval<G1>, arbitrary::Error> {
    Ok(Eval {
        index: u.int_in_range(1..=100)?,
        value: arbitrary_g1(u)?,
    })
}

fn arbitrary_eval_g2(u: &mut Unstructured) -> Result<Eval<G2>, arbitrary::Error> {
    Ok(Eval {
        index: u.int_in_range(1..=100)?,
        value: arbitrary_g2(u)?,
    })
}

fn arbitrary_vec_scalar(
    u: &mut Unstructured,
    min: usize,
    max: usize,
) -> Result<Vec<Scalar>, arbitrary::Error> {
    let len = u.int_in_range(min..=max)?;
    (0..len).map(|_| arbitrary_scalar(u)).collect()
}

fn arbitrary_vec_g1(
    u: &mut Unstructured,
    min: usize,
    max: usize,
) -> Result<Vec<G1>, arbitrary::Error> {
    let len = u.int_in_range(min..=max)?;
    (0..len).map(|_| arbitrary_g1(u)).collect()
}

fn arbitrary_vec_g2(
    u: &mut Unstructured,
    min: usize,
    max: usize,
) -> Result<Vec<G2>, arbitrary::Error> {
    let len = u.int_in_range(min..=max)?;
    (0..len).map(|_| arbitrary_g2(u)).collect()
}

fn arbitrary_vec_eval_g1(
    u: &mut Unstructured,
    min: usize,
    max: usize,
) -> Result<Vec<Eval<G1>>, arbitrary::Error> {
    let len = u.int_in_range(min..=max)?;
    (0..len).map(|_| arbitrary_eval_g1(u)).collect()
}

fn arbitrary_vec_eval_g2(
    u: &mut Unstructured,
    min: usize,
    max: usize,
) -> Result<Vec<Eval<G2>>, arbitrary::Error> {
    let len = u.int_in_range(min..=max)?;
    (0..len).map(|_| arbitrary_eval_g2(u)).collect()
}

fn arbitrary_vec_indexed_g1(
    u: &mut Unstructured,
    min: usize,
    max: usize,
) -> Result<Vec<(u32, G1)>, arbitrary::Error> {
    let len = u.int_in_range(min..=max)?;
    (0..len)
        .map(|_| Ok((u.int_in_range(1..=100)?, arbitrary_g1(u)?)))
        .collect()
}

fn arbitrary_vec_indexed_g2(
    u: &mut Unstructured,
    min: usize,
    max: usize,
) -> Result<Vec<(u32, G2)>, arbitrary::Error> {
    let len = u.int_in_range(min..=max)?;
    (0..len)
        .map(|_| Ok((u.int_in_range(1..=100)?, arbitrary_g2(u)?)))
        .collect()
}

fn arbitrary_vec_pending_minpk(
    u: &mut Unstructured,
    min: usize,
    max: usize,
) -> Result<Vec<(u32, G1, G2)>, arbitrary::Error> {
    let len = u.int_in_range(min..=max)?;
    (0..len)
        .map(|_| Ok((u.int_in_range(1..=100)?, arbitrary_g1(u)?, arbitrary_g2(u)?)))
        .collect()
}

fn arbitrary_vec_pending_minsig(
    u: &mut Unstructured,
    min: usize,
    max: usize,
) -> Result<Vec<(u32, G2, G1)>, arbitrary::Error> {
    let len = u.int_in_range(min..=max)?;
    (0..len)
        .map(|_| Ok((u.int_in_range(1..=100)?, arbitrary_g2(u)?, arbitrary_g1(u)?)))
        .collect()
}

fn arbitrary_messages(
    u: &mut Unstructured,
    min: usize,
    max: usize,
) -> Result<Vec<(Option<Vec<u8>>, Vec<u8>)>, arbitrary::Error> {
    let len = u.int_in_range(min..=max)?;
    (0..len)
        .map(|_| {
            Ok((
                arbitrary_optional_bytes(u, 50)?,
                arbitrary_bytes(u, 0, 100)?,
            ))
        })
        .collect()
}

fn arbitrary_optional_bytes(
    u: &mut Unstructured,
    max: usize,
) -> Result<Option<Vec<u8>>, arbitrary::Error> {
    if u.arbitrary()? {
        Ok(Some(arbitrary_bytes(u, 0, max)?))
    } else {
        Ok(None)
    }
}

fn arbitrary_bytes(
    u: &mut Unstructured,
    min: usize,
    max: usize,
) -> Result<Vec<u8>, arbitrary::Error> {
    let len = u.int_in_range(min..=max)?;
    u.bytes(len).map(|b| b.to_vec())
}

fn arbitrary_weights(
    u: &mut Unstructured,
    min: usize,
    max: usize,
) -> Result<BTreeMap<u32, Weight>, arbitrary::Error> {
    let len = u.int_in_range(min..=max)?;
    if len == 0 {
        return Ok(BTreeMap::new());
    }

    let mut indices = Vec::new();
    for _ in 0..len {
        let index = u.int_in_range(1..=100)?;
        if !indices.contains(&index) {
            indices.push(index);
        }
    }

    if indices.is_empty() {
        return Ok(BTreeMap::new());
    }

    indices.sort();
    compute_weights(indices).or_else(|_| Ok(BTreeMap::new()))
}

fn arbitrary_vec_of_vec_eval_g1(
    u: &mut Unstructured,
    outer_min: usize,
    outer_max: usize,
    inner_min: usize,
    inner_max: usize,
) -> Result<Vec<Vec<Eval<G1>>>, arbitrary::Error> {
    let outer_len = u.int_in_range(outer_min..=outer_max)?;
    (0..outer_len)
        .map(|_| arbitrary_vec_eval_g1(u, inner_min, inner_max))
        .collect()
}

fn arbitrary_vec_of_vec_eval_g2(
    u: &mut Unstructured,
    outer_min: usize,
    outer_max: usize,
    inner_min: usize,
    inner_max: usize,
) -> Result<Vec<Vec<Eval<G2>>>, arbitrary::Error> {
    let outer_len = u.int_in_range(outer_min..=outer_max)?;
    (0..outer_len)
        .map(|_| arbitrary_vec_eval_g2(u, inner_min, inner_max))
        .collect()
}

fn fuzz(op: FuzzOperation) {
    match op {
        FuzzOperation::PartialSignProofOfPossessionMinPk { public, share } => {
            if share.index <= public.degree() + 1 {
                let _ = partial_sign_proof_of_possession::<MinPk>(&public, &share);
            }
        }

        FuzzOperation::PartialSignProofOfPossessionMinSig { public, share } => {
            if share.index <= public.degree() + 1 {
                let _ = partial_sign_proof_of_possession::<MinSig>(&public, &share);
            }
        }

        FuzzOperation::PartialVerifyProofOfPossessionMinPk { public, partial } => {
            if partial.index <= public.degree() + 1 {
                let _ = partial_verify_proof_of_possession::<MinPk>(&public, &partial);
            }
        }

        FuzzOperation::PartialVerifyProofOfPossessionMinSig { public, partial } => {
            if partial.index <= public.degree() + 1 {
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
            if index <= public.degree() + 1 && messages.len() == partials.len() {
                let messages_refs: Vec<(Option<&[u8]>, &[u8])> = messages
                    .iter()
                    .map(|(ns, msg)| (ns.as_deref(), msg.as_slice()))
                    .collect();
                let partials_evals: Vec<Eval<G2>> = partials
                    .into_iter()
                    .enumerate()
                    .map(|(i, sig)| Eval {
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
            if index <= public.degree() + 1 && messages.len() == partials.len() {
                let messages_refs: Vec<(Option<&[u8]>, &[u8])> = messages
                    .iter()
                    .map(|(ns, msg)| (ns.as_deref(), msg.as_slice()))
                    .collect();
                let partials_evals: Vec<Eval<G1>> = partials
                    .into_iter()
                    .enumerate()
                    .map(|(i, sig)| Eval {
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
            if public.len() == partials.len() {
                let public_poly = match public.first() {
                    Some((_idx, _)) => {
                        let degree = public.len() as u32 - 1;
                        let coeffs = vec![
                            arbitrary_g1(&mut Unstructured::new(&[]))
                                .unwrap_or(G1::one());
                            (degree + 1) as usize
                        ];
                        Poly::from(coeffs)
                    }
                    None => return,
                };
                let partials_evals: Vec<Eval<G2>> = partials
                    .into_iter()
                    .map(|(idx, sig)| Eval {
                        index: idx,
                        value: sig,
                    })
                    .collect();
                let _ = partial_verify_multiple_public_keys::<MinPk, _>(
                    &public_poly,
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
            if public.len() == partials.len() {
                let public_poly = match public.first() {
                    Some((_idx, _)) => {
                        let degree = public.len() as u32 - 1;
                        let coeffs = vec![
                            arbitrary_g2(&mut Unstructured::new(&[]))
                                .unwrap_or(G2::one());
                            (degree + 1) as usize
                        ];
                        Poly::from(coeffs)
                    }
                    None => return,
                };
                let partials_evals: Vec<Eval<G1>> = partials
                    .into_iter()
                    .map(|(idx, sig)| Eval {
                        index: idx,
                        value: sig,
                    })
                    .collect();
                let _ = partial_verify_multiple_public_keys::<MinSig, _>(
                    &public_poly,
                    namespace.as_deref(),
                    &message,
                    &partials_evals,
                );
            }
        }

        FuzzOperation::PartialVerifyMultiplePublicKeysPrecomputedMinPk {
            pending,
            namespace,
            message,
        } => {
            let public_keys: Vec<G1> = pending.iter().map(|(_, pk, _)| pk.clone()).collect();
            let partials: Vec<Eval<G2>> = pending
                .iter()
                .map(|(idx, _, sig)| Eval {
                    index: *idx,
                    value: sig.clone(),
                })
                .collect();
            let _ = partial_verify_multiple_public_keys_precomputed::<MinPk, _>(
                &public_keys,
                namespace.as_deref(),
                &message,
                &partials,
            );
        }

        FuzzOperation::PartialVerifyMultiplePublicKeysPrecomputedMinSig {
            pending,
            namespace,
            message,
        } => {
            let public_keys: Vec<G2> = pending.iter().map(|(_, pk, _)| pk.clone()).collect();
            let partials: Vec<Eval<G1>> = pending
                .iter()
                .map(|(idx, _, sig)| Eval {
                    index: *idx,
                    value: sig.clone(),
                })
                .collect();
            let _ = partial_verify_multiple_public_keys_precomputed::<MinSig, _>(
                &public_keys,
                namespace.as_deref(),
                &message,
                &partials,
            );
        }

        FuzzOperation::MsmInterpolateG1 { weights, evals } => {
            let _ = msm_interpolate::<G1, _>(&weights, &evals);
        }

        FuzzOperation::MsmInterpolateG2 { weights, evals } => {
            let _ = msm_interpolate::<G2, _>(&weights, &evals);
        }

        FuzzOperation::ThresholdSignatureRecoverMinPk {
            threshold,
            partials,
        } => {
            if threshold > 0 && threshold <= partials.len() as u32 {
                let _ = threshold_signature_recover::<MinPk, _>(threshold, &partials);
            }
        }

        FuzzOperation::ThresholdSignatureRecoverMinSig {
            threshold,
            partials,
        } => {
            if threshold > 0 && threshold <= partials.len() as u32 {
                let _ = threshold_signature_recover::<MinSig, _>(threshold, &partials);
            }
        }

        FuzzOperation::ThresholdSignatureRecoverWithWeightsMinPk { weights, partials } => {
            let _ = threshold_signature_recover_with_weights::<MinPk, _>(&weights, &partials);
        }

        FuzzOperation::ThresholdSignatureRecoverWithWeightsMinSig { weights, partials } => {
            let _ = threshold_signature_recover_with_weights::<MinSig, _>(&weights, &partials);
        }

        FuzzOperation::ThresholdSignatureRecoverMultipleMinPk {
            threshold,
            signature_groups,
            concurrency,
        } => {
            if threshold > 0 && concurrency > 0 && !signature_groups.is_empty() {
                let groups_refs: Vec<Vec<&Eval<G2>>> = signature_groups
                    .iter()
                    .map(|group| group.iter().collect())
                    .collect();
                let _ = threshold_signature_recover_multiple::<MinPk, _>(
                    threshold,
                    groups_refs,
                    concurrency,
                );
            }
        }

        FuzzOperation::ThresholdSignatureRecoverMultipleMinSig {
            threshold,
            signature_groups,
            concurrency,
        } => {
            if threshold > 0 && concurrency > 0 && !signature_groups.is_empty() {
                let groups_refs: Vec<Vec<&Eval<G1>>> = signature_groups
                    .iter()
                    .map(|group| group.iter().collect())
                    .collect();
                let _ = threshold_signature_recover_multiple::<MinSig, _>(
                    threshold,
                    groups_refs,
                    concurrency,
                );
            }
        }

        FuzzOperation::ThresholdSignatureRecoverPairMinPk {
            threshold,
            partials_1,
            partials_2,
        } => {
            if threshold > 0 {
                let _ = threshold_signature_recover_pair::<MinPk, _>(
                    threshold,
                    &partials_1,
                    &partials_2,
                );
            }
        }

        FuzzOperation::ThresholdSignatureRecoverPairMinSig {
            threshold,
            partials_1,
            partials_2,
        } => {
            if threshold > 0 {
                let _ = threshold_signature_recover_pair::<MinSig, _>(
                    threshold,
                    &partials_1,
                    &partials_2,
                );
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
