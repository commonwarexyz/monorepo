use commonware_cryptography::reed_solomon::{DecodePlan, Decoder, Encoder};
use commonware_utils::test_rng;
use criterion::{Criterion, criterion_group};
use rand::Rng as _;
use std::hint::black_box;

// Run stripes serially to measure their total work without parallel scheduling noise.
// The coding crate's decode benchmarks measure end-to-end parallel reconstruction.
fn bench_decode_stripes(c: &mut Criterion) {
    let mut rng = test_rng();
    let shard_bytes = 64 * 1024;
    for (originals, recoveries) in [(17, 33), (33, 17)] {
        let mut data = vec![vec![0u8; shard_bytes]; originals];
        let mut encoder = Encoder::new(originals, recoveries, shard_bytes).unwrap();
        for shard in &mut data {
            rng.fill_bytes(shard);
            encoder.add_original_shard(shard).unwrap();
        }
        let encoded = encoder.encode().unwrap();
        let recovery: Vec<_> = encoded.recovery_iter().collect();
        let original_received = originals / 2;
        let recovery_received = originals - original_received;

        for stripes in [1, 8] {
            let stripe_bytes = shard_bytes / stripes;
            let mut decoders: Vec<_> = (0..stripes)
                .map(|_| Decoder::new(originals, recoveries, stripe_bytes).unwrap())
                .collect();
            for shared in [false, true] {
                let plan = if shared { "shared" } else { "per_stripe" };
                c.bench_function(
                    &format!(
                        "{}/k={originals} m={recoveries} shard_bytes={shard_bytes} stripes={stripes} plan={plan}",
                        module_path!(),
                    ),
                    |b| {
                        b.iter(|| {
                            // Include preparation once per reconstruction, not once per benchmark.
                            let plan = shared.then(|| {
                                DecodePlan::new(
                                    originals,
                                    recoveries,
                                    0..original_received,
                                    0..recovery_received,
                                )
                                .unwrap()
                            });
                            for (stripe, decoder) in decoders.iter_mut().enumerate() {
                                let start = stripe * stripe_bytes;
                                let end = start + stripe_bytes;
                                for (i, shard) in data.iter().take(original_received).enumerate() {
                                    decoder.add_original_shard(i, &shard[start..end]).unwrap();
                                }
                                for (i, shard) in recovery.iter().take(recovery_received).enumerate() {
                                    decoder.add_recovery_shard(i, &shard[start..end]).unwrap();
                                }
                                let decoded = match &plan {
                                    Some(plan) => decoder.decode_with_recovery_plan(plan),
                                    None => decoder.decode_with_recovery(),
                                }
                                .unwrap();
                                black_box(decoded);
                            }
                        });
                    },
                );
            }
        }
    }
}

criterion_group!(benches, bench_decode_stripes);
