//! Synchronized aggregate (PS-SAS) against BLS batch verification over identical keys, messages,
//! and claim shapes.
//!
//! Workloads:
//!
//! - `certificate`: one aggregate claim over `q` signers, where signer `i` signs one of `distinct`
//!   messages (a quorum certificate over that many different votes).
//! - `votes`: `q` single-signer claims over `distinct` messages in one period.
//! - `blocks`: `q` single-signer claims, each over its own message, spread across `periods`
//!   periods. BLS ignores periods.
//! - `sign`: one signature, with the PS period base hashed or cached.
//! - `precompute`: building a committee's [`sas::KeyTable`].

use commonware_cryptography::bls12381::primitives::{
    group::Private,
    ops::{self, batch, sas},
    variant::{MinPk, MinSig, Variant},
};
use commonware_math::algebra::Additive;
use commonware_parallel::Sequential;
use commonware_utils::{TestRng, test_rng};
use criterion::{Criterion, criterion_group};
use rand::RngExt as _;
use std::hint::black_box;

const NAMESPACE: &[u8] = b"namespace";

/// Signers per batch: the `n - f` quorums of committees of 31, 101, and 251 (`n = 5f + 1`).
const QUORUMS: [usize; 3] = [25, 81, 201];

/// Bytes per message.
const MESSAGE_LEN: usize = 150;

/// Returns the committee size `n = 5f + 1` whose quorum `n - f` is `quorum`.
const fn committee_size(quorum: usize) -> usize {
    quorum + (quorum - 1) / 4
}

/// How signers spread across messages.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Spread {
    /// Every signer signs the same message.
    Same,
    /// Thirty percent of signers share one message and the rest each sign their own.
    Mostly,
    /// Every signer signs its own message.
    Distinct,
}

impl Spread {
    const ALL: [Self; 3] = [Self::Same, Self::Mostly, Self::Distinct];

    const fn label(self) -> &'static str {
        match self {
            Self::Same => "same",
            Self::Mostly => "mixed",
            Self::Distinct => "distinct",
        }
    }
}

/// Keys for both schemes, the PS table of the whole committee, and a pool of messages and periods.
struct Committee<V: Variant> {
    bls: Vec<(Private, V::Public)>,
    ps: Vec<(sas::PrivateKey, sas::PublicKey<V>)>,
    table: sas::KeyTable<V>,
    messages: Vec<Vec<u8>>,
    periods: Vec<Vec<u8>>,
}

impl<V: Variant> Committee<V> {
    /// Creates a committee whose first `quorum` members sign.
    fn new(quorum: usize) -> Self {
        let mut rng = test_rng();
        let bls = (0..quorum)
            .map(|_| ops::keypair::<_, V>(&mut rng))
            .collect();
        let ps: Vec<_> = (0..committee_size(quorum))
            .map(|_| sas::keypair::<_, V>(&mut rng))
            .collect();
        let publics: Vec<_> = ps.iter().map(|(_, public)| *public).collect();
        let messages = (0..quorum)
            .map(|_| {
                let mut message = vec![0u8; MESSAGE_LEN];
                rng.fill(message.as_mut_slice());
                message
            })
            .collect();
        let periods = (0..quorum)
            .map(|height| format!("height-{height}").into_bytes())
            .collect();
        Self {
            bls,
            ps,
            table: sas::KeyTable::new(&publics),
            messages,
            periods,
        }
    }

    /// Returns the message `signer` signs under `spread`.
    fn message(&self, signer: usize, spread: Spread) -> &[u8] {
        let shared = self.messages.len() * 3 / 10;
        match spread {
            Spread::Same => &self.messages[0],
            Spread::Mostly if signer < shared => &self.messages[0],
            Spread::Mostly | Spread::Distinct => &self.messages[signer],
        }
    }

    /// Returns one BLS claim per `(signer, message)`.
    fn bls_claims<'a>(&self, signed: &[(usize, &'a [u8])]) -> Vec<batch::Claim<'a, V>> {
        signed
            .iter()
            .map(|&(signer, message)| batch::Claim {
                signature: ops::sign_message::<V>(&self.bls[signer].0, NAMESPACE, message),
                terms: vec![batch::Term {
                    public: self.bls[signer].1,
                    namespace: NAMESPACE,
                    message,
                }],
            })
            .collect()
    }

    /// Returns one PS claim per `(signer, period, message)`.
    fn ps_claims<'a>(&self, signed: &[(usize, &'a [u8], &'a [u8])]) -> Vec<sas::Claim<'a, V>> {
        signed
            .iter()
            .map(|&(signer, period, message)| sas::Claim {
                period,
                signature: sas::sign_message::<V>(&self.ps[signer].0, period, NAMESPACE, message),
                terms: vec![sas::Term {
                    public: self.ps[signer].1,
                    namespace: NAMESPACE,
                    message,
                }],
            })
            .collect()
    }
}

/// Benchmarks one workload under BLS, PS, and PS with the committee table.
fn compare<V: Variant>(
    c: &mut Criterion,
    label: &str,
    bls: &[batch::Claim<'_, V>],
    ps: &[sas::Claim<'_, V>],
    table: &sas::KeyTable<V>,
) {
    c.bench_function(&format!("{}/{label} scheme=bls", module_path!()), |b| {
        let mut rng = TestRng::new(1);
        b.iter(|| assert!(batch::verify_claims(&mut rng, bls, &Sequential).is_empty()))
    });
    c.bench_function(&format!("{}/{label} scheme=ps", module_path!()), |b| {
        let mut rng = TestRng::new(1);
        b.iter(|| assert!(sas::verify_claims(&mut rng, ps, &Sequential).is_empty()))
    });
    c.bench_function(
        &format!("{}/{label} scheme=ps_table", module_path!()),
        |b| {
            let mut rng = TestRng::new(1);
            b.iter(|| {
                assert!(sas::verify_claims_with_table(&mut rng, ps, table, &Sequential).is_empty())
            })
        },
    );
}

fn register<V: Variant>(c: &mut Criterion, variant: &str) {
    for q in QUORUMS {
        let committee = Committee::<V>::new(q);
        let period: &[u8] = &committee.periods[0];

        for spread in Spread::ALL {
            // One aggregate claim over the whole quorum.
            let mut bls_signature = V::Signature::zero();
            let mut ps_signature = V::Signature::zero();
            let mut bls_terms = Vec::with_capacity(q);
            let mut ps_terms = Vec::with_capacity(q);
            for signer in 0..q {
                let message = committee.message(signer, spread);
                let mut claims = committee.bls_claims(&[(signer, message)]);
                bls_signature += &claims[0].signature;
                bls_terms.append(&mut claims[0].terms);
                let mut claims = committee.ps_claims(&[(signer, period, message)]);
                ps_signature += &claims[0].signature;
                ps_terms.append(&mut claims[0].terms);
            }
            compare(
                c,
                &format!(
                    "workload=cert variant={variant} q={q} messages={}",
                    spread.label()
                ),
                &[batch::Claim {
                    signature: bls_signature,
                    terms: bls_terms,
                }],
                &[sas::Claim {
                    period,
                    signature: ps_signature,
                    terms: ps_terms,
                }],
                &committee.table,
            );

            // Independent votes in one period.
            let signed: Vec<_> = (0..q)
                .map(|signer| (signer, committee.message(signer, spread)))
                .collect();
            let ps_signed: Vec<_> = signed
                .iter()
                .map(|&(signer, message)| (signer, period, message))
                .collect();
            compare(
                c,
                &format!(
                    "workload=votes variant={variant} q={q} messages={}",
                    spread.label()
                ),
                &committee.bls_claims(&signed),
                &committee.ps_claims(&ps_signed),
                &committee.table,
            );
        }

        // Independent blocks, each over its own message, in one period or one period each.
        for periods in [1, q] {
            let signed: Vec<_> = (0..q)
                .map(|signer| (signer, committee.message(signer, Spread::Distinct)))
                .collect();
            let ps_signed: Vec<_> = signed
                .iter()
                .map(|&(signer, message)| {
                    let period: &[u8] = &committee.periods[signer % periods];
                    (signer, period, message)
                })
                .collect();
            compare(
                c,
                &format!("workload=blocks variant={variant} q={q} periods={periods}"),
                &committee.bls_claims(&signed),
                &committee.ps_claims(&ps_signed),
                &committee.table,
            );
        }
    }
}

/// Benchmarks signing under BLS and PS, with the PS period base hashed or cached.
fn register_sign<V: Variant>(c: &mut Criterion, variant: &str) {
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

/// Benchmarks building a committee's [`sas::KeyTable`].
fn register_precompute<V: Variant>(c: &mut Criterion, variant: &str) {
    for q in QUORUMS {
        let committee = Committee::<V>::new(q);
        let publics: Vec<_> = committee.ps.iter().map(|(_, public)| *public).collect();
        c.bench_function(
            &format!(
                "{}/workload=precompute variant={variant} n={}",
                module_path!(),
                publics.len()
            ),
            |b| b.iter(|| black_box(sas::KeyTable::new(&publics))),
        );
    }
}

fn bench_sas_verify_claims(c: &mut Criterion) {
    register_sign::<MinPk>(c, "min_pk");
    register_sign::<MinSig>(c, "min_sig");
    register_precompute::<MinPk>(c, "min_pk");
    register_precompute::<MinSig>(c, "min_sig");
    register::<MinPk>(c, "min_pk");
    register::<MinSig>(c, "min_sig");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_sas_verify_claims
}
