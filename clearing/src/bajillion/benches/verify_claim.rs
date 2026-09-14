use super::{
    fixtures::{active_close_fixture, profile_key, runner, selected_active_profiles},
    sizes::withdrawal_claim_fixture,
};
use commonware_clearing::bajillion::boundary::WithdrawalAction;
use commonware_cryptography::Sha256;
use commonware_runtime::Runner as _;
use criterion::{Criterion, criterion_group};
use std::{hint::black_box, num::NonZeroU64};

fn bench_verify_claim(c: &mut Criterion) {
    for (_, profile) in selected_active_profiles() {
        let (claims, root, opening) = runner().start(|runtime| async move {
            let fixture = active_close_fixture(runtime, profile).await;
            let mut claims = Vec::new();
            for total in [
                1,
                u32::try_from(profile.live_accounts).expect("output count fits"),
            ] {
                for (label, action) in [
                    ("amount", WithdrawalAction::Amount(NonZeroU64::MIN)),
                    ("close", WithdrawalAction::Close),
                ] {
                    claims.push((
                        label,
                        total,
                        withdrawal_claim_fixture(&fixture, total, action),
                    ));
                }
            }
            let account = fixture.accounts[profile.live_accounts / 2].0.clone();
            let (state, _) = fixture
                .prepared
                .apply(fixture.state)
                .await
                .expect("close applies");
            let opening = state.opening(account).await.expect("current balance opens");
            assert_eq!(
                opening
                    .verify::<Sha256>(&state.root())
                    .expect("opening verifies"),
                opening.balance
            );
            (claims, state.root(), opening)
        });
        for (action, total, fixture) in claims {
            c.bench_function(
                &format!(
                    "{}::withdrawal/{} W={total} action={action}",
                    module_path!(),
                    profile_key(profile)
                ),
                |b| {
                    b.iter(|| {
                        black_box(
                            black_box(&fixture.claim)
                                .verify::<Sha256>(black_box(&fixture.root))
                                .expect("withdrawal claim verifies"),
                        )
                    })
                },
            );
        }
        c.bench_function(
            &format!(
                "{}::current_opening/{} context=successor",
                module_path!(),
                profile_key(profile)
            ),
            |b| {
                b.iter(|| {
                    black_box(
                        black_box(&opening)
                            .verify::<Sha256>(black_box(&root))
                            .expect("current opening verifies"),
                    )
                })
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = bench_verify_claim,
}
