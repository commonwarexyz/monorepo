//! Complete wire-to-validated-G1 timings, including fresh subgroup challenges.

use super::*;
use commonware_utils::TestRng;
use criterion::{BatchSize, Criterion, SamplingMode, Throughput};
use std::{hint::black_box, path::Path, time::Duration};

#[derive(Clone, Copy, Debug)]
enum Method {
    StandardIndividual,
    StandardBatch,
    Pair,
    TripleSerial,
    TripleBatch,
}

impl Method {
    fn name(self) -> &'static str {
        match self {
            Self::StandardIndividual => "standard_individual",
            Self::StandardBatch => "standard_batch",
            Self::Pair => "pair_roots4",
            Self::TripleSerial => "triple_roots1",
            Self::TripleBatch => "triple_roots4",
        }
    }

    fn format(self) -> Format {
        match self {
            Self::StandardIndividual | Self::StandardBatch => Format::Standard,
            Self::Pair => Format::Pair,
            Self::TripleSerial | Self::TripleBatch => Format::Triple,
        }
    }

    fn receive(self, bytes: &[u8], rng: &mut impl CryptoRng) -> Option<Vec<G1>> {
        let (standard, tail) = bytes.as_chunks::<48>();
        if !tail.is_empty() {
            return None;
        }
        match self {
            Self::StandardIndividual => standard.iter().map(G1::from_bytes).collect(),
            Self::StandardBatch => G1::batch_from_bytes(rng, standard),
            Self::TripleSerial => with_backend(Receive::<_, 1> {
                bytes,
                format: self.format(),
                rng,
            }),
            Self::Pair | Self::TripleBatch => with_backend(Receive::<_, 4> {
                bytes,
                format: self.format(),
                rng,
            }),
        }
    }
}

#[test]
#[ignore = "manual Criterion wire-to-validated-G1 benchmark"]
fn measure_wire_to_points() {
    #[cfg(target_arch = "x86_64")]
    let avx512 =
        std::is_x86_feature_detected!("avx512f") && std::is_x86_feature_detected!("avx512ifma");
    #[cfg(not(target_arch = "x86_64"))]
    let avx512 = false;
    if std::env::var_os("COMMONWARE_REQUIRE_AVX512").is_some() {
        assert!(avx512, "this benchmark requires AVX-512F and AVX-512 IFMA");
    }
    eprintln!(
        "Vroom backend: {}",
        if avx512 { "avx512-ifma" } else { "portable" }
    );
    // Set COMMONWARE_DECODE_COUNTS=1000,6000,100000 for the full workload.
    // Methods can be selected with COMMONWARE_DECODE_METHODS=standard_batch,triple_roots4.
    let counts =
        std::env::var("COMMONWARE_DECODE_COUNTS").unwrap_or_else(|_| "1000,6000,100000".into());
    let methods = std::env::var("COMMONWARE_DECODE_METHODS").ok();
    let selected = |name: &str| {
        methods
            .as_ref()
            .is_none_or(|methods| methods.split(',').any(|method| method == name))
    };
    let output = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/criterion");
    let mut criterion = Criterion::default()
        .without_plots()
        .output_directory(&output)
        .sample_size(10)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3));
    let mut group = criterion.benchmark_group(module_path!());
    group.sampling_mode(SamplingMode::Flat);
    for n in counts
        .split(',')
        .map(|count| count.parse::<usize>().expect("point count"))
    {
        assert!(n > 0);
        // All methods use the same random, distinct nonidentity points. blst is
        // only a fixture oracle here; native timed paths contain no blst calls.
        let points = tests::fixtures(n);
        let expected = tests::public_points(&points);
        let standard = tests::encode(&points, Format::Standard);
        let pair = tests::encode(&points, Format::Pair);
        let triple = tests::encode(&points, Format::Triple);
        assert_eq!(standard.len(), 48 * n);
        assert_eq!(pair.len(), standard.len());
        assert_eq!(triple.len(), standard.len());
        group.throughput(Throughput::Elements(n as u64));
        for method in [
            Method::StandardIndividual,
            Method::StandardBatch,
            Method::Pair,
            Method::TripleSerial,
            Method::TripleBatch,
        ] {
            if !selected(method.name()) {
                continue;
            }
            let bytes = match method.format() {
                Format::Standard => &standard,
                Format::Pair => &pair,
                Format::Triple => &triple,
            };
            assert_eq!(
                method.receive(bytes, &mut TestRng::new(0)).unwrap(),
                expected
            );
            let mut seed = 0u64;
            group.bench_function(format!("method={} n={n}", method.name()), |b| {
                b.iter_batched(
                    || (),
                    |()| {
                        seed = seed.wrapping_add(1);
                        let mut rng = TestRng::new(seed);
                        black_box(method.receive(black_box(bytes), &mut rng).unwrap())
                    },
                    BatchSize::PerIteration,
                );
            });
        }
        if selected("blst_individual") {
            group.bench_function(format!("method=blst_individual n={n}"), |b| {
                b.iter_batched(
                    || (),
                    |()| {
                        black_box(
                            standard
                                .chunks_exact(48)
                                .map(|bytes| {
                                    let point =
                                        blst::min_pk::PublicKey::from_bytes(black_box(bytes))
                                            .unwrap();
                                    point.validate().unwrap();
                                    point
                                })
                                .collect::<Vec<_>>(),
                        )
                    },
                    BatchSize::PerIteration,
                );
            });
        }
    }
    group.finish();
    criterion.final_summary();
}
