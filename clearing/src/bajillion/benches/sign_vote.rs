use super::admission_fixtures::{Validators, certificate_fixture};
use commonware_utils::Participant;
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

fn bench_sign_vote(c: &mut Criterion) {
    let fixture = certificate_fixture();
    let signer = Validators::new().signer(Participant::new(0));
    c.bench_function(&format!("{}/n=100", module_path!()), |b| {
        b.iter(|| black_box(signer.sign(black_box(&fixture.header)).expect("sign vote")));
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_sign_vote,
}
