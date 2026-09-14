use super::fixtures::{accounts, new_state, selected_active_profiles};
use commonware_runtime::Runner as _;
use criterion::{Criterion, criterion_group};
use std::{hint::black_box, time::Instant};

fn bench_initialize(c: &mut Criterion) {
    let mut sizes = selected_active_profiles()
        .into_iter()
        .map(|(_, p)| p.live_accounts)
        .collect::<Vec<_>>();
    sizes.sort_unstable();
    sizes.dedup();
    for live in sizes {
        let accounts = accounts(live);
        c.bench_function(&format!("{}/live_accounts={live}", module_path!()), |b| {
            b.iter_custom(|iterations| {
                (0..iterations)
                    .map(|_| {
                        super::fixtures::runner().start(|runtime| async {
                            let start = Instant::now();
                            let state = new_state(runtime, &accounts).await;
                            let elapsed = start.elapsed();
                            assert_eq!(state.live_accounts(), live as u64);
                            black_box(state);
                            elapsed
                        })
                    })
                    .sum()
            });
        });
    }
}
criterion_group! {name = benches; config = Criterion::default().sample_size(10); targets = bench_initialize,}
