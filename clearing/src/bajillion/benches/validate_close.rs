use super::fixtures::{active_close_fixture, profile_key, selected_active_profiles};
use commonware_clearing::bajillion::transition::validate_close;
use commonware_cryptography::Sha256;
use commonware_cryptography_curve25519::signing::BatchVerifier as PaymentBatchVerifier;
use commonware_utils::TestRng;
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

fn bench_validate_close(c: &mut Criterion) {
    for (_, profile) in selected_active_profiles() {
        let fixture = active_close_fixture(profile);
        c.bench_function(
            &format!(
                "{}/{} E={}",
                module_path!(),
                profile_key(profile),
                profile.edges(),
            ),
            |b| {
                let mut rng = TestRng::new(0);
                b.iter(|| {
                    black_box(validate_close::<Sha256, _, _, PaymentBatchVerifier, _>(
                        black_box(&fixture.context),
                        black_box(&fixture.operator_bls),
                        black_box(&fixture.deposits),
                        black_box(&fixture.withdrawals),
                        black_box(fixture.prepared.close()),
                        black_box(&mut rng),
                    ))
                    .expect("benchmark close is valid")
                });
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_validate_close,
}
