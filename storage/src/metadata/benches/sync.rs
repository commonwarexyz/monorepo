use super::utils::{Key, Policy, Val, get_modified_kvs, get_random_kvs, init, policies};
use commonware_runtime::{
    Supervisor as _,
    benchmarks::{context, tokio},
};
use commonware_utils::test_rng;
use criterion::{Criterion, criterion_group};
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
enum Shape {
    Overwrite,
    Grow,
    Shrink,
}

impl Shape {
    const fn label(self) -> &'static str {
        match self {
            Self::Overwrite => "overwrite",
            Self::Grow => "grow",
            Self::Shrink => "shrink",
        }
    }

    fn mutations(self, initial_kvs: &[(Key, Val)], modified: usize) -> Vec<(Key, Val)> {
        let mut mutations = get_modified_kvs(initial_kvs, modified);
        if let Some((_, value)) = mutations.first_mut() {
            match self {
                Self::Overwrite => {}
                Self::Grow => value.resize(200, 0),
                Self::Shrink => value.truncate(50),
            }
        }
        mutations
    }
}

const fn shapes(modified: usize) -> &'static [Shape] {
    if modified == 0 {
        &[Shape::Overwrite]
    } else {
        &[Shape::Overwrite, Shape::Grow, Shape::Shrink]
    }
}

fn bench_sync(c: &mut Criterion) {
    let runner = tokio::Runner::default();
    let mut rng = test_rng();
    for &num_keys in &[100, 1_000, 10_000] {
        for &modified in &[0, 1, 5, 25, 50, 75, 100] {
            let initial_kvs = get_random_kvs(num_keys);

            for &shape in shapes(modified) {
                let modified_kvs = shape.mutations(&initial_kvs, modified);
                for policy in policies(&mut rng) {
                    let label = format!(
                        "{}/keys={} modified={} shape={} write_options={}",
                        module_path!(),
                        num_keys,
                        modified,
                        shape.label(),
                        policy.label()
                    );

                    c.bench_function(&label, |b| {
                        b.to_async(&runner).iter_custom(|iters| {
                            let initial_kvs = initial_kvs.clone();
                            let modified_kvs = modified_kvs.clone();
                            async move {
                                let ctx = context::get::<commonware_runtime::tokio::Context>();
                                let mut total = Duration::ZERO;
                                for _ in 0..iters {
                                    // Build a fresh store with cache-bypassing writes, then switch
                                    // only the measured sync to the selected policy.
                                    let (mut metadata, control) = init(
                                        ctx.child("storage"),
                                        Policy::DontCache,
                                        Policy::DontCache,
                                    )
                                    .await;
                                    for (key, value) in &initial_kvs {
                                        metadata.put(key.clone(), value.clone());
                                    }
                                    metadata = metadata.sync().await.unwrap();
                                    metadata = metadata.sync().await.unwrap();

                                    control.set_write(matches!(policy, Policy::DontCache));
                                    for (key, value) in &modified_kvs {
                                        metadata.put(key.clone(), value.clone());
                                    }

                                    let start = Instant::now();
                                    metadata = metadata.sync().await.unwrap();
                                    total += start.elapsed();

                                    metadata.destroy().await.unwrap();
                                }
                                total
                            }
                        });
                    });
                }
            }
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_sync
}
