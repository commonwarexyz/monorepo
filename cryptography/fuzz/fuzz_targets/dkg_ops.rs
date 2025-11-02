#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_cryptography::bls12381::{
    dkg::ops::{
        construct_public, evaluate_all, generate_shares, recover_public,
        recover_public_with_weights, verify_commitment, verify_share,
    },
    primitives::{
        group::{Element, Share, G1, G2},
        poly::{compute_weights, Poly, Public},
        variant::{MinPk, MinSig},
    },
};
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, SeedableRng};
use std::collections::BTreeMap;

type Message = (Option<Vec<u8>>, Vec<u8>);

#[path = "common/mod.rs"]
mod common;
use common::{arbitrary_g1, arbitrary_g2, arbitrary_poly_g1, arbitrary_poly_g2, arbitrary_share};

const MAX_OPERATIONS: usize = 100;
const MAX_N: u32 = 100;
const MAX_T: u32 = 50;
const MAX_DEALERS: usize = 20;
const MAX_COMMITMENTS: usize = 30;
const MAX_CONCURRENCY: usize = 8;
const MAX_COEFFICIENTS: usize = 32;

enum DkgOperation {
    GenerateSharesMinPk {
        seed: u64,
        share: Option<Share>,
        n: u32,
        t: u32,
    },
    GenerateSharesMinSig {
        seed: u64,
        share: Option<Share>,
        n: u32,
        t: u32,
    },
    EvaluateAllMinPk {
        polynomial: Public<MinPk>,
        n: u32,
    },
    EvaluateAllMinSig {
        polynomial: Public<MinSig>,
        n: u32,
    },
    EvaluateAllEmptyMinPk {
        n: u32,
    },
    EvaluateAllEmptyMinSig {
        n: u32,
    },
    VerifyCommitmentMinPk {
        previous: Option<Public<MinPk>>,
        commitment: Public<MinPk>,
        dealer: u32,
        t: u32,
    },
    VerifyCommitmentMinSig {
        previous: Option<Public<MinSig>>,
        commitment: Public<MinSig>,
        dealer: u32,
        t: u32,
    },
    VerifyCommitmentEmptyMinPk {
        previous: Option<Public<MinPk>>,
        dealer: u32,
        t: u32,
    },
    VerifyCommitmentEmptyMinSig {
        previous: Option<Public<MinSig>>,
        dealer: u32,
        t: u32,
    },
    VerifyShareMinPk {
        commitment: Public<MinPk>,
        recipient: u32,
        share: Share,
    },
    VerifyShareMinSig {
        commitment: Public<MinSig>,
        recipient: u32,
        share: Share,
    },
    ConstructPublicMinPk {
        commitments: Vec<Public<MinPk>>,
        required: u32,
    },
    ConstructPublicMinSig {
        commitments: Vec<Public<MinSig>>,
        required: u32,
    },
    ConstructPublicEmptyMinPk {
        required: u32,
    },
    ConstructPublicEmptyMinSig {
        required: u32,
    },
    RecoverPublicWithWeightsMinPk {
        previous: Public<MinPk>,
        commitments: BTreeMap<u32, Public<MinPk>>,
        weights: BTreeMap<u32, commonware_cryptography::bls12381::primitives::poly::Weight>,
        threshold: u32,
        concurrency: usize,
    },
    RecoverPublicWithWeightsMinSig {
        previous: Public<MinSig>,
        commitments: BTreeMap<u32, Public<MinSig>>,
        weights: BTreeMap<u32, commonware_cryptography::bls12381::primitives::poly::Weight>,
        threshold: u32,
        concurrency: usize,
    },
    RecoverPublicMinPk {
        previous: Public<MinPk>,
        commitments: BTreeMap<u32, Public<MinPk>>,
        threshold: u32,
        concurrency: usize,
    },
    RecoverPublicMinSig {
        previous: Public<MinSig>,
        commitments: BTreeMap<u32, Public<MinSig>>,
        threshold: u32,
        concurrency: usize,
    },
}

struct FuzzInput {
    operations: Vec<DkgOperation>,
}

struct PolyGenerationParams {
    empty_poly_ratio: (u8, u8),
    zero_coeff_ratio: (u8, u8),
    one_coeff_ratio: (u8, u8),
    arbitrary_poly_ratio: (u8, u8),
}

impl<'a> Arbitrary<'a> for PolyGenerationParams {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, arbitrary::Error> {
        Ok(PolyGenerationParams {
            empty_poly_ratio: (u.int_in_range(1..=10)?, u.int_in_range(10..=100)?),
            zero_coeff_ratio: (u.int_in_range(1..=10)?, u.int_in_range(5..=20)?),
            one_coeff_ratio: (u.int_in_range(1..=10)?, u.int_in_range(5..=20)?),
            arbitrary_poly_ratio: (u.int_in_range(1..=10)?, u.int_in_range(10..=100)?),
        })
    }
}

impl std::fmt::Debug for FuzzInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FuzzInput")
            .field("operations_count", &self.operations.len())
            .finish()
    }
}

fn arbitrary_poly_from_bytes_g1(
    u: &mut Unstructured,
    max_coeffs: usize,
    params: &PolyGenerationParams,
) -> Result<Public<MinPk>, arbitrary::Error> {
    let num_coeffs = u.int_in_range(0..=max_coeffs)?;
    if num_coeffs == 0 {
        return Ok(Poly::from(Vec::<G1>::new()));
    }
    let mut coeffs = Vec::new();
    for _ in 0..num_coeffs {
        if u.ratio(params.zero_coeff_ratio.0, params.zero_coeff_ratio.1)? {
            coeffs.push(G1::zero());
        } else if u.ratio(params.one_coeff_ratio.0, params.one_coeff_ratio.1)? {
            coeffs.push(G1::one());
        } else {
            coeffs.push(arbitrary_g1(u)?);
        }
    }
    Ok(Poly::from(coeffs))
}

fn arbitrary_poly_from_bytes_g2(
    u: &mut Unstructured,
    max_coeffs: usize,
    params: &PolyGenerationParams,
) -> Result<Public<MinSig>, arbitrary::Error> {
    let num_coeffs = u.int_in_range(0..=max_coeffs)?;
    if num_coeffs == 0 {
        return Ok(Poly::from(Vec::<G2>::new()));
    }
    let mut coeffs = Vec::new();
    for _ in 0..num_coeffs {
        if u.ratio(params.zero_coeff_ratio.0, params.zero_coeff_ratio.1)? {
            coeffs.push(G2::zero());
        } else if u.ratio(params.one_coeff_ratio.0, params.one_coeff_ratio.1)? {
            coeffs.push(G2::one());
        } else {
            coeffs.push(arbitrary_g2(u)?);
        }
    }
    Ok(Poly::from(coeffs))
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, arbitrary::Error> {
        let poly_generation_params = PolyGenerationParams::arbitrary(u)?;
        let num_ops = u.int_in_range(1..=MAX_OPERATIONS)?;
        let mut operations = Vec::new();

        for _ in 0..num_ops {
            let op = match u.int_in_range(0..=19)? {
                0 => DkgOperation::GenerateSharesMinPk {
                    seed: u.arbitrary()?,
                    share: if u.arbitrary()? {
                        Some(arbitrary_share(u)?)
                    } else {
                        None
                    },
                    n: u.int_in_range(1..=MAX_N)?,
                    t: u.int_in_range(0..=MAX_T)?,
                },
                1 => DkgOperation::GenerateSharesMinSig {
                    seed: u.arbitrary()?,
                    share: if u.arbitrary()? {
                        Some(arbitrary_share(u)?)
                    } else {
                        None
                    },
                    n: u.int_in_range(1..=MAX_N)?,
                    t: u.int_in_range(0..=MAX_T)?,
                },
                2 => DkgOperation::EvaluateAllMinPk {
                    polynomial: if u.ratio(
                        poly_generation_params.arbitrary_poly_ratio.0,
                        poly_generation_params.arbitrary_poly_ratio.1,
                    )? {
                        arbitrary_poly_from_bytes_g1(u, MAX_COEFFICIENTS, &poly_generation_params)?
                    } else {
                        arbitrary_poly_g1(u)?
                    },
                    n: u.int_in_range(0..=MAX_N)?,
                },
                3 => DkgOperation::EvaluateAllMinSig {
                    polynomial: if u.ratio(
                        poly_generation_params.arbitrary_poly_ratio.0,
                        poly_generation_params.arbitrary_poly_ratio.1,
                    )? {
                        arbitrary_poly_from_bytes_g2(u, MAX_COEFFICIENTS, &poly_generation_params)?
                    } else {
                        arbitrary_poly_g2(u)?
                    },
                    n: u.int_in_range(0..=MAX_N)?,
                },
                4 => DkgOperation::EvaluateAllEmptyMinPk {
                    n: u.int_in_range(0..=MAX_N)?,
                },
                5 => DkgOperation::EvaluateAllEmptyMinSig {
                    n: u.int_in_range(0..=MAX_N)?,
                },
                6 => DkgOperation::VerifyCommitmentMinPk {
                    previous: if u.arbitrary()? {
                        Some(
                            if u.ratio(
                                poly_generation_params.arbitrary_poly_ratio.0,
                                poly_generation_params.arbitrary_poly_ratio.1,
                            )? {
                                arbitrary_poly_from_bytes_g1(
                                    u,
                                    MAX_COEFFICIENTS,
                                    &poly_generation_params,
                                )?
                            } else {
                                arbitrary_poly_g1(u)?
                            },
                        )
                    } else {
                        None
                    },
                    commitment: if u.ratio(
                        poly_generation_params.empty_poly_ratio.0,
                        poly_generation_params.empty_poly_ratio.1,
                    )? {
                        Poly::from(Vec::<G1>::new())
                    } else if u.ratio(
                        poly_generation_params.arbitrary_poly_ratio.0,
                        poly_generation_params.arbitrary_poly_ratio.1,
                    )? {
                        arbitrary_poly_from_bytes_g1(u, MAX_COEFFICIENTS, &poly_generation_params)?
                    } else {
                        arbitrary_poly_g1(u)?
                    },
                    dealer: u.int_in_range(0..=MAX_DEALERS as u32)?,
                    t: u.int_in_range(0..=MAX_T)?,
                },
                7 => DkgOperation::VerifyCommitmentMinSig {
                    previous: if u.arbitrary()? {
                        Some(
                            if u.ratio(
                                poly_generation_params.arbitrary_poly_ratio.0,
                                poly_generation_params.arbitrary_poly_ratio.1,
                            )? {
                                arbitrary_poly_from_bytes_g2(
                                    u,
                                    MAX_COEFFICIENTS,
                                    &poly_generation_params,
                                )?
                            } else {
                                arbitrary_poly_g2(u)?
                            },
                        )
                    } else {
                        None
                    },
                    commitment: if u.ratio(
                        poly_generation_params.empty_poly_ratio.0,
                        poly_generation_params.empty_poly_ratio.1,
                    )? {
                        Poly::from(Vec::<G2>::new())
                    } else if u.ratio(
                        poly_generation_params.arbitrary_poly_ratio.0,
                        poly_generation_params.arbitrary_poly_ratio.1,
                    )? {
                        arbitrary_poly_from_bytes_g2(u, MAX_COEFFICIENTS, &poly_generation_params)?
                    } else {
                        arbitrary_poly_g2(u)?
                    },
                    dealer: u.int_in_range(0..=MAX_DEALERS as u32)?,
                    t: u.int_in_range(0..=MAX_T)?,
                },
                8 => DkgOperation::VerifyCommitmentEmptyMinPk {
                    previous: if u.arbitrary()? {
                        Some(arbitrary_poly_from_bytes_g1(
                            u,
                            MAX_COEFFICIENTS,
                            &poly_generation_params,
                        )?)
                    } else {
                        None
                    },
                    dealer: u.int_in_range(0..=MAX_DEALERS as u32)?,
                    t: u.int_in_range(0..=MAX_T)?,
                },
                9 => DkgOperation::VerifyCommitmentEmptyMinSig {
                    previous: if u.arbitrary()? {
                        Some(arbitrary_poly_from_bytes_g2(
                            u,
                            MAX_COEFFICIENTS,
                            &poly_generation_params,
                        )?)
                    } else {
                        None
                    },
                    dealer: u.int_in_range(0..=MAX_DEALERS as u32)?,
                    t: u.int_in_range(0..=MAX_T)?,
                },
                10 => DkgOperation::VerifyShareMinPk {
                    commitment: if u.ratio(
                        poly_generation_params.empty_poly_ratio.0,
                        poly_generation_params.empty_poly_ratio.1,
                    )? {
                        Poly::from(Vec::<G1>::new())
                    } else {
                        arbitrary_poly_from_bytes_g1(u, MAX_COEFFICIENTS, &poly_generation_params)?
                    },
                    recipient: u.int_in_range(0..=MAX_N)?,
                    share: arbitrary_share(u)?,
                },
                11 => DkgOperation::VerifyShareMinSig {
                    commitment: if u.ratio(
                        poly_generation_params.empty_poly_ratio.0,
                        poly_generation_params.empty_poly_ratio.1,
                    )? {
                        Poly::from(Vec::<G2>::new())
                    } else {
                        arbitrary_poly_from_bytes_g2(u, MAX_COEFFICIENTS, &poly_generation_params)?
                    },
                    recipient: u.int_in_range(0..=MAX_N)?,
                    share: arbitrary_share(u)?,
                },
                12 => {
                    let num_commitments = u.int_in_range(0..=MAX_COMMITMENTS)?;
                    let mut commitments = Vec::new();
                    for _ in 0..num_commitments {
                        commitments.push(
                            if u.ratio(
                                poly_generation_params.empty_poly_ratio.0,
                                poly_generation_params.empty_poly_ratio.1,
                            )? {
                                Poly::from(Vec::<G1>::new())
                            } else if u.ratio(
                                poly_generation_params.arbitrary_poly_ratio.0,
                                poly_generation_params.arbitrary_poly_ratio.1,
                            )? {
                                arbitrary_poly_from_bytes_g1(
                                    u,
                                    MAX_COEFFICIENTS,
                                    &poly_generation_params,
                                )?
                            } else {
                                arbitrary_poly_g1(u)?
                            },
                        );
                    }
                    DkgOperation::ConstructPublicMinPk {
                        commitments,
                        required: u.int_in_range(0..=MAX_COMMITMENTS as u32)?,
                    }
                }
                13 => {
                    let num_commitments = u.int_in_range(0..=MAX_COMMITMENTS)?;
                    let mut commitments = Vec::new();
                    for _ in 0..num_commitments {
                        commitments.push(
                            if u.ratio(
                                poly_generation_params.empty_poly_ratio.0,
                                poly_generation_params.empty_poly_ratio.1,
                            )? {
                                Poly::from(Vec::<G2>::new())
                            } else if u.ratio(
                                poly_generation_params.arbitrary_poly_ratio.0,
                                poly_generation_params.arbitrary_poly_ratio.1,
                            )? {
                                arbitrary_poly_from_bytes_g2(
                                    u,
                                    MAX_COEFFICIENTS,
                                    &poly_generation_params,
                                )?
                            } else {
                                arbitrary_poly_g2(u)?
                            },
                        );
                    }
                    DkgOperation::ConstructPublicMinSig {
                        commitments,
                        required: u.int_in_range(0..=MAX_COMMITMENTS as u32)?,
                    }
                }
                14 => DkgOperation::ConstructPublicEmptyMinPk {
                    required: u.int_in_range(0..=MAX_COMMITMENTS as u32)?,
                },
                15 => DkgOperation::ConstructPublicEmptyMinSig {
                    required: u.int_in_range(0..=MAX_COMMITMENTS as u32)?,
                },
                16 => {
                    let num_commitments = u.int_in_range(0..=MAX_COMMITMENTS)?;
                    let mut commitments = BTreeMap::new();
                    let mut indices = Vec::new();
                    for _ in 0..num_commitments {
                        let dealer = u.int_in_range(0..=MAX_DEALERS as u32)?;
                        commitments.insert(
                            dealer,
                            if u.ratio(
                                poly_generation_params.empty_poly_ratio.0,
                                poly_generation_params.empty_poly_ratio.1,
                            )? {
                                Poly::from(Vec::<G1>::new())
                            } else if u.ratio(
                                poly_generation_params.arbitrary_poly_ratio.0,
                                poly_generation_params.arbitrary_poly_ratio.1,
                            )? {
                                arbitrary_poly_from_bytes_g1(
                                    u,
                                    MAX_COEFFICIENTS,
                                    &poly_generation_params,
                                )?
                            } else {
                                arbitrary_poly_g1(u)?
                            },
                        );
                        indices.push(dealer);
                    }
                    let weights = if !indices.is_empty() {
                        compute_weights(indices).unwrap_or_default()
                    } else {
                        BTreeMap::new()
                    };
                    DkgOperation::RecoverPublicWithWeightsMinPk {
                        previous: if u.ratio(
                            poly_generation_params.empty_poly_ratio.0,
                            poly_generation_params.empty_poly_ratio.1,
                        )? {
                            Poly::from(Vec::<G1>::new())
                        } else {
                            arbitrary_poly_from_bytes_g1(
                                u,
                                MAX_COEFFICIENTS,
                                &poly_generation_params,
                            )?
                        },
                        commitments,
                        weights,
                        threshold: u.int_in_range(0..=MAX_T)?,
                        concurrency: u.int_in_range(1..=MAX_CONCURRENCY)?,
                    }
                }
                17 => {
                    let num_commitments = u.int_in_range(0..=MAX_COMMITMENTS)?;
                    let mut commitments = BTreeMap::new();
                    let mut indices = Vec::new();
                    for _ in 0..num_commitments {
                        let dealer = u.int_in_range(0..=MAX_DEALERS as u32)?;
                        commitments.insert(
                            dealer,
                            if u.ratio(
                                poly_generation_params.empty_poly_ratio.0,
                                poly_generation_params.empty_poly_ratio.1,
                            )? {
                                Poly::from(Vec::<G2>::new())
                            } else if u.ratio(
                                poly_generation_params.arbitrary_poly_ratio.0,
                                poly_generation_params.arbitrary_poly_ratio.1,
                            )? {
                                arbitrary_poly_from_bytes_g2(
                                    u,
                                    MAX_COEFFICIENTS,
                                    &poly_generation_params,
                                )?
                            } else {
                                arbitrary_poly_g2(u)?
                            },
                        );
                        indices.push(dealer);
                    }
                    let weights = if !indices.is_empty() {
                        compute_weights(indices).unwrap_or_default()
                    } else {
                        BTreeMap::new()
                    };
                    DkgOperation::RecoverPublicWithWeightsMinSig {
                        previous: if u.ratio(
                            poly_generation_params.empty_poly_ratio.0,
                            poly_generation_params.empty_poly_ratio.1,
                        )? {
                            Poly::from(Vec::<G2>::new())
                        } else {
                            arbitrary_poly_from_bytes_g2(
                                u,
                                MAX_COEFFICIENTS,
                                &poly_generation_params,
                            )?
                        },
                        commitments,
                        weights,
                        threshold: u.int_in_range(0..=MAX_T)?,
                        concurrency: u.int_in_range(1..=MAX_CONCURRENCY)?,
                    }
                }
                18 => {
                    let num_commitments = u.int_in_range(0..=MAX_COMMITMENTS)?;
                    let mut commitments = BTreeMap::new();
                    for _ in 0..num_commitments {
                        let dealer = u.int_in_range(0..=MAX_DEALERS as u32)?;
                        commitments.insert(
                            dealer,
                            if u.ratio(
                                poly_generation_params.empty_poly_ratio.0,
                                poly_generation_params.empty_poly_ratio.1,
                            )? {
                                Poly::from(Vec::<G1>::new())
                            } else {
                                arbitrary_poly_from_bytes_g1(
                                    u,
                                    MAX_COEFFICIENTS,
                                    &poly_generation_params,
                                )?
                            },
                        );
                    }
                    DkgOperation::RecoverPublicMinPk {
                        previous: arbitrary_poly_from_bytes_g1(
                            u,
                            MAX_COEFFICIENTS,
                            &poly_generation_params,
                        )?,
                        commitments,
                        threshold: u.int_in_range(0..=MAX_T)?,
                        concurrency: u.int_in_range(1..=MAX_CONCURRENCY)?,
                    }
                }
                19 => {
                    let num_commitments = u.int_in_range(0..=MAX_COMMITMENTS)?;
                    let mut commitments = BTreeMap::new();
                    for _ in 0..num_commitments {
                        let dealer = u.int_in_range(0..=MAX_DEALERS as u32)?;
                        commitments.insert(
                            dealer,
                            if u.ratio(
                                poly_generation_params.empty_poly_ratio.0,
                                poly_generation_params.empty_poly_ratio.1,
                            )? {
                                Poly::from(Vec::<G2>::new())
                            } else {
                                arbitrary_poly_from_bytes_g2(
                                    u,
                                    MAX_COEFFICIENTS,
                                    &poly_generation_params,
                                )?
                            },
                        );
                    }
                    DkgOperation::RecoverPublicMinSig {
                        previous: arbitrary_poly_from_bytes_g2(
                            u,
                            MAX_COEFFICIENTS,
                            &poly_generation_params,
                        )?,
                        commitments,
                        threshold: u.int_in_range(0..=MAX_T)?,
                        concurrency: u.int_in_range(1..=MAX_CONCURRENCY)?,
                    }
                }
                _ => unreachable!(),
            };
            operations.push(op);
        }

        Ok(FuzzInput { operations })
    }
}

fn fuzz(input: FuzzInput) {
    for op in input.operations {
        match op {
            DkgOperation::GenerateSharesMinPk { seed, share, n, t } => {
                if t > 0 && t <= n {
                    let mut rng = StdRng::seed_from_u64(seed);
                    let (commitment, shares) = generate_shares::<_, MinPk>(&mut rng, share, n, t);
                    assert_eq!(shares.len(), n as usize);
                    if t > 0 {
                        assert_eq!(commitment.degree(), t - 1);
                    }
                    for (i, share) in shares.iter().enumerate() {
                        assert_eq!(share.index, i as u32);
                    }
                }
            }
            DkgOperation::GenerateSharesMinSig { seed, share, n, t } => {
                if t > 0 && t <= n {
                    let mut rng = StdRng::seed_from_u64(seed);
                    let (commitment, shares) = generate_shares::<_, MinSig>(&mut rng, share, n, t);
                    assert_eq!(shares.len(), n as usize);
                    if t > 0 {
                        assert_eq!(commitment.degree(), t - 1);
                    }
                    for (i, share) in shares.iter().enumerate() {
                        assert_eq!(share.index, i as u32);
                    }
                }
            }
            DkgOperation::EvaluateAllMinPk { polynomial, n } => {
                let evals = evaluate_all::<MinPk>(&polynomial, n);
                assert_eq!(evals.len(), n as usize);
            }
            DkgOperation::EvaluateAllMinSig { polynomial, n } => {
                let evals = evaluate_all::<MinSig>(&polynomial, n);
                assert_eq!(evals.len(), n as usize);
            }
            DkgOperation::EvaluateAllEmptyMinPk { n } => {
                let empty_poly = Poly::<G1>::from(Vec::new());
                let evals = evaluate_all::<MinPk>(&empty_poly, n);
                assert_eq!(evals.len(), n as usize);
            }
            DkgOperation::EvaluateAllEmptyMinSig { n } => {
                let empty_poly = Poly::<G2>::from(Vec::new());
                let evals = evaluate_all::<MinSig>(&empty_poly, n);
                assert_eq!(evals.len(), n as usize);
            }
            DkgOperation::VerifyCommitmentMinPk {
                previous,
                commitment,
                dealer,
                t,
            } => {
                let _ = verify_commitment::<MinPk>(previous.as_ref(), &commitment, dealer, t);
            }
            DkgOperation::VerifyCommitmentMinSig {
                previous,
                commitment,
                dealer,
                t,
            } => {
                let _ = verify_commitment::<MinSig>(previous.as_ref(), &commitment, dealer, t);
            }
            DkgOperation::VerifyCommitmentEmptyMinPk {
                previous,
                dealer,
                t,
            } => {
                let empty_commitment = Poly::<G1>::from(Vec::new());
                let _ = verify_commitment::<MinPk>(previous.as_ref(), &empty_commitment, dealer, t);
            }
            DkgOperation::VerifyCommitmentEmptyMinSig {
                previous,
                dealer,
                t,
            } => {
                let empty_commitment = Poly::<G2>::from(Vec::new());
                let _ =
                    verify_commitment::<MinSig>(previous.as_ref(), &empty_commitment, dealer, t);
            }
            DkgOperation::VerifyShareMinPk {
                commitment,
                recipient,
                share,
            } => {
                let _ = verify_share::<MinPk>(&commitment, recipient, &share);
            }
            DkgOperation::VerifyShareMinSig {
                commitment,
                recipient,
                share,
            } => {
                let _ = verify_share::<MinSig>(&commitment, recipient, &share);
            }
            DkgOperation::ConstructPublicMinPk {
                commitments,
                required,
            } => {
                let _ = construct_public::<MinPk>(commitments.iter(), required);
            }
            DkgOperation::ConstructPublicMinSig {
                commitments,
                required,
            } => {
                let _ = construct_public::<MinSig>(commitments.iter(), required);
            }
            DkgOperation::ConstructPublicEmptyMinPk { required } => {
                let empty: Vec<Public<MinPk>> = vec![];
                let _ = construct_public::<MinPk>(empty.iter(), required);
            }
            DkgOperation::ConstructPublicEmptyMinSig { required } => {
                let empty: Vec<Public<MinSig>> = vec![];
                let _ = construct_public::<MinSig>(empty.iter(), required);
            }
            DkgOperation::RecoverPublicWithWeightsMinPk {
                previous,
                commitments,
                weights,
                threshold,
                concurrency,
            } => {
                if threshold > 0 && concurrency > 0 {
                    let _ = recover_public_with_weights::<MinPk>(
                        &previous,
                        &commitments,
                        &weights,
                        threshold,
                        concurrency,
                    );
                }
            }
            DkgOperation::RecoverPublicWithWeightsMinSig {
                previous,
                commitments,
                weights,
                threshold,
                concurrency,
            } => {
                if threshold > 0 && concurrency > 0 {
                    let _ = recover_public_with_weights::<MinSig>(
                        &previous,
                        &commitments,
                        &weights,
                        threshold,
                        concurrency,
                    );
                }
            }
            DkgOperation::RecoverPublicMinPk {
                previous,
                commitments,
                threshold,
                concurrency,
            } => {
                if threshold > 0 && concurrency > 0 {
                    let _ =
                        recover_public::<MinPk>(&previous, &commitments, threshold, concurrency);
                }
            }
            DkgOperation::RecoverPublicMinSig {
                previous,
                commitments,
                threshold,
                concurrency,
            } => {
                if threshold > 0 && concurrency > 0 {
                    let _ =
                        recover_public::<MinSig>(&previous, &commitments, threshold, concurrency);
                }
            }
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
