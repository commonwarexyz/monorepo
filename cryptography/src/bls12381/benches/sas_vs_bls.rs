//! PS-SAS against BLS batch verification over identical keys, messages, and claim shapes.
//!
//! Workloads:
//!
//! - `certificate`: one atomic aggregate claim over `q` signers, where signer `i` signs message
//!   `i % distinct` (a quorum certificate with `distinct` different votes).
//! - `votes`: `q` independent single-signer claims over `distinct` messages in one period (votes
//!   arriving individually).
//! - `blocks`: `q` independent single-signer claims over `q` messages spread across `periods`
//!   periods (producer blocks at different heights). BLS ignores periods.
//! - `sign`: one signature, with and without a cached PS period base.

use commonware_cryptography::bls12381::primitives::{
    group::{FixedBase, Private},
    ops::{self, batch, sas},
    variant::{MinPk, MinSig, Variant},
};
use commonware_math::algebra::{Additive, CryptoGroup};
use commonware_parallel::Sequential;
use commonware_utils::{TestRng, test_rng};
use criterion::{Criterion, criterion_group, criterion_main};
use rand::RngExt as _;
use std::hint::black_box;

const NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_SAS_VS_BLS_BENCH";

/// Signers per batch: quorums of committees with 31, 46, 101, and 251 members (`n - f`, `n = 5f + 1`).
const QUORUMS: [usize; 4] = [25, 37, 81, 201];

/// Bytes per message, roughly a Multimmit vote body.
const MESSAGE_LEN: usize = 150;

/// Committee size `n = 5f + 1` whose quorum `n - f` is `quorum`.
const fn committee_size(quorum: usize) -> usize {
    quorum + (quorum - 1) / 4
}

/// The seed of the batch-verification randomness, fixed per benchmark.
const RNG_SEED: u64 = 1;

/// Keys for both schemes and a pool of messages and periods.
///
/// The first `size` keys sign. The PS table covers the whole committee of `size + f` keys
/// (`size = n - f`, `n = 5f + 1`), as a verifier's would.
struct Committee<V: Variant<Public: FixedBase>> {
    bls: Vec<(Private, V::Public)>,
    ps: Vec<(sas::PrivateKey, sas::PublicKey<V>)>,
    table: sas::KeyTable<V>,
    messages: Vec<Vec<u8>>,
    periods: Vec<Vec<u8>>,
}

impl<V: Variant<Public: FixedBase>> Committee<V> {
    fn new(size: usize) -> Self {
        let mut rng = test_rng();
        let bls = (0..size).map(|_| ops::keypair::<_, V>(&mut rng)).collect();
        let ps: Vec<_> = (0..committee_size(size))
            .map(|_| sas::keypair::<_, V>(&mut rng))
            .collect();
        let publics: Vec<_> = ps.iter().map(|(_, public)| *public).collect();
        let table = sas::KeyTable::new(&publics);
        let messages = (0..size)
            .map(|_| {
                let mut message = vec![0u8; MESSAGE_LEN];
                rng.fill(message.as_mut_slice());
                message
            })
            .collect();
        let periods = (0..size)
            .map(|height| format!("height-{height}").into_bytes())
            .collect();
        Self {
            bls,
            ps,
            table,
            messages,
            periods,
        }
    }

    /// Message signed by `signer` under `spread`.
    fn message(&self, signer: usize, spread: Spread) -> &[u8] {
        match spread {
            Spread::Even(distinct) => &self.messages[signer % distinct],
            Spread::Bloc(percent) => {
                let shared = self.messages.len() - self.messages.len() * percent / 100;
                if signer < shared {
                    &self.messages[0]
                } else {
                    &self.messages[signer]
                }
            }
        }
    }

    fn bls_signature(&self, signer: usize, message: &[u8]) -> V::Signature {
        ops::sign_message::<V>(&self.bls[signer].0, NAMESPACE, message)
    }

    fn ps_signature(&self, signer: usize, period: &[u8], message: &[u8]) -> V::Signature {
        sas::sign_message::<V>(&self.ps[signer].0, period, NAMESPACE, message)
    }

    /// One BLS claim per `(signer, message)`.
    fn bls_claims<'a>(&self, signed: &[(usize, &'a [u8])]) -> Vec<batch::Claim<'a, V>> {
        signed
            .iter()
            .map(|&(signer, message)| batch::Claim {
                signature: self.bls_signature(signer, message),
                terms: vec![batch::Term {
                    public: self.bls[signer].1,
                    namespace: NAMESPACE,
                    message,
                }],
            })
            .collect()
    }

    /// One PS claim per `(signer, period, message)`.
    fn ps_claims<'a>(&self, signed: &[(usize, &'a [u8], &'a [u8])]) -> Vec<sas::Claim<'a, V>> {
        signed
            .iter()
            .map(|&(signer, period, message)| sas::Claim {
                period,
                signature: self.ps_signature(signer, period, message),
                terms: vec![sas::Term {
                    public: self.ps[signer].1,
                    namespace: NAMESPACE,
                    message,
                }],
            })
            .collect()
    }
}

fn bench_bls<V: Variant<Public: FixedBase>>(
    c: &mut Criterion,
    name: &str,
    claims: &[batch::Claim<'_, V>],
    invalid: usize,
) {
    let mut rng = TestRng::new(RNG_SEED);
    c.bench_function(name, |b| {
        b.iter(|| {
            let failed = batch::verify_claims(&mut rng, claims, &Sequential);
            assert_eq!(failed.len(), invalid);
            black_box(failed)
        })
    });
}

fn bench_ps<V: Variant<Public: FixedBase>>(
    c: &mut Criterion,
    name: &str,
    claims: &[sas::Claim<'_, V>],
    table: Option<&sas::KeyTable<V>>,
    invalid: usize,
) {
    let mut rng = TestRng::new(RNG_SEED);
    c.bench_function(name, |b| {
        b.iter(|| {
            let failed = match table {
                Some(table) => sas::verify_claims_with_table(&mut rng, claims, table, &Sequential),
                None => sas::verify_claims(&mut rng, claims, &Sequential),
            };
            assert_eq!(failed.len(), invalid);
            black_box(failed)
        })
    });
}

/// Benchmarks one workload for both schemes, corrupting the last `invalid` claims of each.
///
/// Verification runs sequentially.
fn compare<V: Variant<Public: FixedBase>>(
    c: &mut Criterion,
    label: &str,
    mut bls: Vec<batch::Claim<'_, V>>,
    mut ps: Vec<sas::Claim<'_, V>>,
    table: &sas::KeyTable<V>,
    invalid: usize,
) {
    for claim in bls.iter_mut().rev().take(invalid) {
        claim.signature += &V::Signature::generator();
    }
    for claim in ps.iter_mut().rev().take(invalid) {
        claim.signature += &V::Signature::generator();
    }
    bench_bls(
        c,
        &format!("{}/{label} scheme=bls invalid={invalid}", module_path!()),
        &bls,
        invalid,
    );
    bench_ps(
        c,
        &format!("{}/{label} scheme=ps invalid={invalid}", module_path!()),
        &ps,
        None,
        invalid,
    );
    bench_ps(
        c,
        &format!(
            "{}/{label} scheme=ps-table invalid={invalid}",
            module_path!()
        ),
        &ps,
        Some(table),
        invalid,
    );
}

/// How signers spread across messages.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Spread {
    /// Signer `i` signs message `i % distinct`, so groups are equal-sized.
    Even(usize),
    /// `percent` of signers each sign their own message and the rest share one.
    Bloc(usize),
}

impl Spread {
    fn label(self) -> String {
        match self {
            Self::Even(distinct) => format!("distinct={distinct}"),
            Self::Bloc(percent) => format!("distinct={percent}pct"),
        }
    }
}

/// Message spreads to measure for a quorum of `q`.
fn divergences(q: usize) -> Vec<Spread> {
    let mut distinct: Vec<_> = [1, 5, 20, q].into_iter().filter(|&d| d <= q).collect();
    distinct.dedup();
    let mut spreads: Vec<_> = distinct.into_iter().map(Spread::Even).collect();
    spreads.insert(spreads.len() - 1, Spread::Bloc(70));
    spreads
}

fn register<V: Variant<Public: FixedBase>>(c: &mut Criterion, variant: &str) {
    for q in QUORUMS {
        let committee = Committee::<V>::new(q);
        let period: &[u8] = &committee.periods[0];

        // One aggregate claim over the whole quorum.
        for spread in divergences(q) {
            let mut bls_signature = V::Signature::zero();
            let mut ps_signature = V::Signature::zero();
            let mut bls_terms = Vec::with_capacity(q);
            let mut ps_terms = Vec::with_capacity(q);
            for signer in 0..q {
                let message = committee.message(signer, spread);
                bls_signature += &committee.bls_signature(signer, message);
                ps_signature += &committee.ps_signature(signer, period, message);
                bls_terms.push(batch::Term {
                    public: committee.bls[signer].1,
                    namespace: NAMESPACE,
                    message,
                });
                ps_terms.push(sas::Term {
                    public: committee.ps[signer].1,
                    namespace: NAMESPACE,
                    message,
                });
            }
            compare(
                c,
                &format!(
                    "workload=certificate variant={variant} q={q} {}",
                    spread.label()
                ),
                vec![batch::Claim {
                    signature: bls_signature,
                    terms: bls_terms,
                }],
                vec![sas::Claim {
                    period,
                    signature: ps_signature,
                    terms: ps_terms,
                }],
                &committee.table,
                0,
            );
        }

        // Independent votes in one period.
        for spread in divergences(q) {
            let signed: Vec<_> = (0..q)
                .map(|signer| (signer, committee.message(signer, spread)))
                .collect();
            let ps_signed: Vec<_> = signed
                .iter()
                .map(|&(signer, message)| (signer, period, message))
                .collect();
            let invalids: &[usize] = if spread == Spread::Even(q) {
                &[0, 1]
            } else {
                &[0]
            };
            for &invalid in invalids {
                compare(
                    c,
                    &format!("workload=votes variant={variant} q={q} {}", spread.label()),
                    committee.bls_claims(&signed),
                    committee.ps_claims(&ps_signed),
                    &committee.table,
                    invalid,
                );
            }
        }

        // Independent blocks, each over its own message, spread across periods.
        let mut spreads: Vec<_> = [1, 2, 4, q].into_iter().filter(|&p| p <= q).collect();
        spreads.dedup();
        for periods in spreads {
            let signed: Vec<_> = (0..q)
                .map(|signer| (signer, committee.message(signer, Spread::Even(q))))
                .collect();
            let ps_signed: Vec<_> = signed
                .iter()
                .map(|&(signer, message)| {
                    let period: &[u8] = &committee.periods[signer % periods];
                    (signer, period, message)
                })
                .collect();
            let invalids: &[usize] = if periods == 4 { &[0, 1] } else { &[0] };
            for &invalid in invalids {
                compare(
                    c,
                    &format!("workload=blocks variant={variant} q={q} periods={periods}"),
                    committee.bls_claims(&signed),
                    committee.ps_claims(&ps_signed),
                    &committee.table,
                    invalid,
                );
            }
        }
    }
}

/// Signing cost: BLS, PS with the period base hashed per signature, and PS with it cached.
fn register_sign<V: Variant<Public: FixedBase>>(c: &mut Criterion, variant: &str) {
    let committee = Committee::<V>::new(1);
    let message: &[u8] = &committee.messages[0];
    let period: &[u8] = &committee.periods[0];
    let base = sas::period_base::<V>(period);
    let (bls, _) = &committee.bls[0];
    let (ps, _) = &committee.ps[0];
    c.bench_function(
        &format!(
            "{}/workload=sign variant={variant} scheme=bls",
            module_path!()
        ),
        |b| b.iter(|| black_box(ops::sign_message::<V>(bls, NAMESPACE, message))),
    );
    c.bench_function(
        &format!(
            "{}/workload=sign variant={variant} scheme=ps base=hashed",
            module_path!()
        ),
        |b| b.iter(|| black_box(sas::sign_message::<V>(ps, period, NAMESPACE, message))),
    );
    c.bench_function(
        &format!(
            "{}/workload=sign variant={variant} scheme=ps base=cached",
            module_path!()
        ),
        |b| {
            b.iter(|| {
                black_box(sas::sign_with_base::<V>(
                    ps, &base, period, NAMESPACE, message,
                ))
            })
        },
    );
}

/// One-time cost of a committee's [`sas::KeyTable`].
fn register_precompute<V: Variant<Public: FixedBase>>(c: &mut Criterion, variant: &str) {
    for q in QUORUMS {
        let committee = Committee::<V>::new(q);
        let publics: Vec<_> = committee.ps.iter().map(|(_, public)| *public).collect();
        c.bench_function(
            &format!(
                "{}/workload=precompute variant={variant} n={} scheme=ps-table",
                module_path!(),
                publics.len()
            ),
            |b| b.iter(|| black_box(sas::KeyTable::new(&publics))),
        );
    }
}

fn bench_sas_vs_bls(c: &mut Criterion) {
    register_sign::<MinPk>(c, "minpk");
    register_sign::<MinSig>(c, "minsig");
    register_precompute::<MinPk>(c, "minpk");
    register_precompute::<MinSig>(c, "minsig");
    register::<MinPk>(c, "minpk");
    register::<MinSig>(c, "minsig");
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .warm_up_time(std::time::Duration::from_millis(200))
        .measurement_time(std::time::Duration::from_secs(1));
    targets = bench_sas_vs_bls
}

criterion_main!(benches);
