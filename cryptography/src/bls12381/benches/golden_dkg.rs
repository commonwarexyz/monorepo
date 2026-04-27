use commonware_codec::EncodeSize as _;
use commonware_cryptography::bls12381::golden_dkg::{
    self, DealerLog, Info, PrivateKey, PublicKey, Setup, SignedDealerLog,
};
use commonware_math::algebra::Random;
use commonware_parallel::Sequential;
use commonware_utils::{ordered::Set, N3f1, TryCollect};
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{rngs::StdRng, SeedableRng};
use rand_core::CryptoRngCore;
use std::{collections::BTreeMap, hint::black_box, num::NonZeroU32, sync::LazyLock};

// One dealer is enough: Golden DKG cost scales with the number of receivers,
// not the number of dealers.
cfg_if::cfg_if! {
    if #[cfg(full_bench)] {
        const RECEIVERS: &[u32] = &[5, 10, 15, 20, 25];
        const MAX_RECEIVERS: u32 = 25;
    } else {
        const RECEIVERS: &[u32] = &[5, 10, 25];
        const MAX_RECEIVERS: u32 = 25;
    }
}

/// Cached eVRF setup, sized for the largest configuration we benchmark.
/// Building it is expensive, so we share one across all benches.
static SETUP: LazyLock<Setup> =
    LazyLock::new(|| Setup::new(NonZeroU32::new(MAX_RECEIVERS).unwrap()));

/// A Golden DKG scenario with one dealer and `n` receivers.
struct Bench {
    info: Info,
    me: PrivateKey,
}

impl Bench {
    fn new(rng: &mut impl CryptoRngCore, n: u32) -> Self {
        let me = PrivateKey::random(&mut *rng);
        let dealers: Set<PublicKey> = std::iter::once(me.public()).try_collect().unwrap();
        let players: Set<PublicKey> = (0..n)
            .map(|_| PrivateKey::random(&mut *rng).public())
            .try_collect()
            .unwrap();
        let info = Info::new(0, None, dealers, players);
        Self { info, me }
    }

    fn deal(&self, rng: &mut impl CryptoRngCore) -> SignedDealerLog {
        golden_dkg::deal::<N3f1>(rng, &SETUP, &self.info, &self.me, None, &Sequential)
            .expect("honest deal should succeed")
    }
}

/// Time for a dealer to produce a [`SignedDealerLog`] addressed to `n` receivers.
fn bench_golden_dkg_deal(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0);
    for &n in RECEIVERS {
        let bench = Bench::new(&mut rng, n);
        c.bench_function(&format!("{}::deal/n={}", module_path!(), n), |b| {
            b.iter_batched(
                || {
                    (
                        bench.info.clone(),
                        bench.me.clone(),
                        StdRng::seed_from_u64(0),
                    )
                },
                |(info, me, mut rng)| {
                    black_box(
                        golden_dkg::deal::<N3f1>(&mut rng, &SETUP, &info, &me, None, &Sequential)
                            .unwrap(),
                    );
                },
                BatchSize::SmallInput,
            );
        });
    }
}

/// Time for a receiver to verify one dealer's [`SignedDealerLog`].
///
/// `golden_dkg::observe` performs the full verification a real receiver does
/// (signature check, eVRF batch check, and the per-dealing linear check).
fn bench_golden_dkg_verify(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0);
    for &n in RECEIVERS {
        let bench = Bench::new(&mut rng, n);
        let signed = bench.deal(&mut rng);
        let (pk, log) = signed.identify().expect("honest log should identify");
        let mut logs = BTreeMap::<PublicKey, DealerLog>::new();
        logs.insert(pk, log);
        c.bench_function(&format!("{}::verify/n={}", module_path!(), n), |b| {
            b.iter_batched(
                || (bench.info.clone(), logs.clone(), StdRng::seed_from_u64(0)),
                |(info, logs, mut rng)| {
                    black_box(
                        golden_dkg::observe::<N3f1>(&mut rng, &SETUP, &info, logs, &Sequential)
                            .unwrap(),
                    );
                },
                BatchSize::SmallInput,
            );
        });
    }
}

/// Encoded size of one dealer's [`SignedDealerLog`] addressed to `n` receivers.
///
/// Reported via stdout (no measured timing) in the same style as
/// `coding/src/benches/bench_size.rs`.
fn bench_golden_dkg_dealing_size(_c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0);
    for &n in RECEIVERS {
        let bench = Bench::new(&mut rng, n);
        let signed = bench.deal(&mut rng);
        println!(
            "{}::dealing_size/n={}: {} B",
            module_path!(),
            n,
            signed.encode_size(),
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets =
        bench_golden_dkg_deal,
        bench_golden_dkg_verify,
        bench_golden_dkg_dealing_size,
}
