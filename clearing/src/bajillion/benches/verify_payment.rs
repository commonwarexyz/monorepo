use super::fixtures::payment_fixture;
use commonware_cryptography::Sha256;
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

fn bench_verify_payment(c: &mut Criterion) {
    let fixture = payment_fixture();
    c.bench_function(
        &format!("{}/backend=curve25519 hash=sha256", module_path!()),
        |b| {
            b.iter(|| {
                black_box(&fixture.payment)
                    .verify_linked::<Sha256>(black_box(&fixture.context))
                    .expect("benchmark payment is valid");
            });
        },
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_verify_payment,
}
