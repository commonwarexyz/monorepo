use super::utils::{Policy, get_random_kvs, init, policies};
use commonware_runtime::{
    Supervisor as _,
    benchmarks::{context, tokio},
};
use commonware_utils::test_rng;
use criterion::{Criterion, criterion_group};
use std::time::{Duration, Instant};

fn bench_restart(c: &mut Criterion) {
    let mut rng = test_rng();
    for &num_keys in &[100, 1_000, 10_000, 100_000] {
        let initial_kvs = get_random_kvs(num_keys);
        for policy in policies(&mut rng) {
            let runner = tokio::Runner::default();
            c.bench_function(
                &format!(
                    "{}/keys={} read_options={}",
                    module_path!(),
                    num_keys,
                    policy.label()
                ),
                |b| {
                    b.to_async(&runner).iter_custom(|iters| {
                        let initial_kvs = initial_kvs.clone();
                        async move {
                            let ctx = context::get::<commonware_runtime::tokio::Context>();
                            let mut total = Duration::ZERO;
                            for _ in 0..iters {
                                // Use a fresh dataset and cache-bypassing setup writes so both
                                // measured arms begin from the same page-cache state.
                                let (mut metadata, _) =
                                    init(ctx.child("setup"), Policy::DontCache, Policy::DontCache)
                                        .await;
                                for (key, value) in &initial_kvs {
                                    metadata.put(key.clone(), value.clone());
                                }
                                metadata = metadata.sync().await.unwrap();
                                metadata.sync().await.unwrap();

                                let start = Instant::now();
                                let (metadata, _) =
                                    init(ctx.child("measured"), policy, Policy::Default).await;
                                total += start.elapsed();

                                metadata.destroy().await.unwrap();
                            }
                            total
                        }
                    });
                },
            );
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_restart
}
