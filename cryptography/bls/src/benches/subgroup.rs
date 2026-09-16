use commonware_cryptography_bls::bls12381::group::{G1, G2};
use commonware_utils::TestRng;
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

const CORPUS_SIZE: usize = 1_024;
const RNG_SEED: u64 = 0x5b67_726f_7570;

// COMMONWARE_SUBGROUP_LARGE=1 selects the opt-in 100k/1M workloads.
// Use a filter such as "group=g1 points=100000" for one group and size.
// Include the space after the count: Criterion's regex also matches numeric prefixes.
pub(super) fn large_workloads() -> bool {
    match std::env::var("COMMONWARE_SUBGROUP_LARGE") {
        Err(std::env::VarError::NotPresent) => false,
        Ok(value) if value == "1" => true,
        _ => panic!("COMMONWARE_SUBGROUP_LARGE must be unset or 1"),
    }
}

fn consume<T>(decoded: Option<Vec<T>>) {
    let decoded = decoded.expect("valid subgroup fixture");
    black_box(&decoded);
    drop(decoded);
}

macro_rules! bench_group {
    ($c:ident, $group:ident, $scheme:path, $label:literal, $size:literal) => {{
        let counts: &[usize] = if large_workloads() {
            &[100_000, 1_000_000]
        } else {
            &[1, 8, 64, 512, 4_096]
        };

        for &count in counts {
            let make_fixtures = || {
                let distinct = count.min(CORPUS_SIZE);
                let generator = $group::generator();
                let mut point = generator;
                let mut corpus = Vec::with_capacity(distinct);
                for _ in 0..distinct {
                    corpus.push(point.to_bytes());
                    point = point.add(&generator);
                }
                let encoded: Vec<[u8; $size]> = (0..count).map(|i| corpus[i % distinct]).collect();

                // Validate the distinct corpus outside timing. Large workloads recycle it to
                // bound setup work while retaining the requested decoded vector length.
                let corpus = &encoded[..distinct];
                let individual: Vec<_> = corpus
                    .iter()
                    .map(|bytes| $group::from_bytes(bytes).expect("valid subgroup fixture"))
                    .collect();
                let mut rng = TestRng::new(RNG_SEED);
                assert_eq!(
                    $group::batch_from_bytes(&mut rng, corpus).expect("valid subgroup fixture"),
                    individual
                );
                encoded
            };
            let mut fixtures = None;

            $c.bench_function(
                &format!(
                    "{}/group={} points={count} impl=native_batch",
                    module_path!(),
                    $label
                ),
                |b| {
                    let encoded = fixtures.get_or_insert_with(make_fixtures);
                    let mut rng = TestRng::new(RNG_SEED);
                    b.iter(|| {
                        consume($group::batch_from_bytes(
                            black_box(&mut rng),
                            black_box(encoded.as_slice()),
                        ));
                    });
                },
            );
            $c.bench_function(
                &format!(
                    "{}/group={} points={count} impl=native_individual",
                    module_path!(),
                    $label
                ),
                |b| {
                    let encoded = fixtures.get_or_insert_with(make_fixtures);
                    b.iter(|| {
                        let decoded = black_box(encoded.as_slice())
                            .iter()
                            .map($group::from_bytes)
                            .collect();
                        consume(decoded);
                    });
                },
            );
            $c.bench_function(
                &format!(
                    "{}/group={} points={count} impl=blst_individual",
                    module_path!(),
                    $label
                ),
                |b| {
                    let encoded = fixtures.get_or_insert_with(make_fixtures);
                    b.iter(|| {
                        let decoded = black_box(encoded.as_slice())
                            .iter()
                            .map(|bytes| {
                                <$scheme>::from_bytes(bytes)
                                    .ok()
                                    .filter(|point| point.subgroup_check())
                            })
                            .collect();
                        consume(decoded);
                    });
                },
            );
        }
    }};
}

fn bench(c: &mut Criterion) {
    bench_group!(c, G1, blst::min_sig::Signature, "g1", 48);
    bench_group!(c, G2, blst::min_pk::Signature, "g2", 96);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench,
}
