//! Extraction and ordering over one view's final votes and the headers they name.
//!
//! - `tips`: a V-QC's tips, the highest window block `n - 3f` recorded votes endorse per chain.
//! - `final_tips`: the pool's final tip `b*`, the highest window block `n - f` validators endorse.
//! - `settled`: whether each chain can still gain a block in the view.
//! - `det`: `Det(G)` of the final votes.
//! - `validate`: V-QC admission, rebuilding its resolution paths and its tips-history commitment.
//! - `horiz` and `sweep`: the horizontal order over resolved tips and over the pool's sweep.
//!
//! Ancestry is read from the scenario's mock header store, a map walk per height, so the
//! extraction figures include that lookup cost rather than the production header store's.

use super::common::scenarios;
use commonware_cryptography::bls12381::primitives::variant::MinPk;
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

fn bench_algebra(c: &mut Criterion) {
    for (participants, shape, view) in scenarios::<MinPk>() {
        let mut bench = |function: &str, run: &dyn Fn()| {
            c.bench_function(
                &format!(
                    "{}::{function}/n={participants} votes={shape}",
                    module_path!()
                ),
                |b| b.iter(run),
            );
        };
        bench("tips", &|| {
            black_box(view.tips());
        });
        bench("final_tips", &|| {
            black_box(view.final_tips());
        });
        bench("settled", &|| {
            black_box(view.settled());
        });
        bench("det", &|| {
            black_box(view.det());
        });
        bench("validate", &|| {
            black_box(view.validate());
        });
        bench("horiz", &|| {
            black_box(view.horiz());
        });
        bench("sweep", &|| {
            black_box(view.sweep());
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_algebra
}
