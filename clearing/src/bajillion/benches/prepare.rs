use super::{
    fixtures::{active_close_fixture, profile_key, selected_active_profiles},
    raw,
};
use commonware_clearing::bajillion::transition::prepare_dealing;
use commonware_cryptography::Sha256;
use commonware_runtime::Runner as _;
use criterion::{Criterion, criterion_group};
use std::{
    hint::black_box,
    time::{Duration, Instant},
};

fn bench_prepare(c: &mut Criterion) {
    for (_, profile) in selected_active_profiles() {
        let (context, deposits, withdrawals, terminals, expected) = super::fixtures::runner()
            .start(|runtime| async move {
                let fixture = active_close_fixture(runtime, profile).await;
                (
                    fixture.context,
                    fixture.deposits,
                    fixture.withdrawals,
                    fixture.terminals,
                    fixture.prepared.encoded().clone(),
                )
            });
        c.bench_function(
            &format!(
                "{}/{} E={}",
                module_path!(),
                profile_key(profile),
                profile.edges()
            ),
            |b| {
                b.iter_custom(|iterations| {
                    let mut elapsed = Duration::ZERO;
                    for _ in 0..iterations {
                        let terminals = terminals.clone();
                        let start = Instant::now();
                        let prepared = prepare_dealing::<Sha256, _, _>(
                            context.epoch_context(),
                            &deposits,
                            &withdrawals,
                            terminals,
                        )
                        .expect("prepare dealing");
                        elapsed += start.elapsed();
                        assert_eq!(prepared.encoded(), &expected);
                        black_box(prepared);
                    }
                    elapsed
                });
            },
        );
    }
}
criterion_group! {name = benches; config = Criterion::default().sample_size(10); targets = bench_prepare,}

pub(crate) fn samples() {
    let profiles = selected_active_profiles();
    let [(_, profile)] = profiles.as_slice() else {
        panic!("prepare-samples requires exactly one selected profile");
    };
    let profile = *profile;
    let samples = raw::samples();
    let (context, deposits, withdrawals, terminals, expected) =
        super::fixtures::runner().start(|runtime| async move {
            let fixture = active_close_fixture(runtime, profile).await;
            (
                fixture.context,
                fixture.deposits,
                fixture.withdrawals,
                fixture.terminals,
                fixture.prepared.encoded().clone(),
            )
        });
    let name = format!(
        "{}/{} E={}",
        module_path!(),
        profile_key(profile),
        profile.edges()
    );
    println!(
        "{{\"record\":\"raw_metadata\",\"kind\":\"prepare\",\"name\":\"{name}\",\"boundary\":\"detached_inputs_to_prepared_dealing_return\",\"samples\":{samples},\"iterations_per_sample\":1,\"n\":{},\"a\":{},\"b\":{},\"k\":{},\"edges\":{},\"expected_bytes\":{}}}",
        profile.live_accounts,
        profile.senders,
        profile.credited_accounts,
        profile.out_degree,
        profile.edges(),
        expected.len(),
    );
    for sample in 0..samples {
        let terminals = terminals.clone();
        let start = Instant::now();
        let prepared = prepare_dealing::<Sha256, _, _>(
            context.epoch_context(),
            &deposits,
            &withdrawals,
            terminals,
        )
        .expect("prepare dealing");
        let elapsed = start.elapsed();
        assert_eq!(prepared.encoded(), &expected);
        black_box(prepared);
        println!(
            "{{\"record\":\"raw_sample\",\"kind\":\"prepare\",\"name\":\"{name}\",\"sample\":{sample},\"iterations\":1,\"total_ns\":{},\"verified\":true}}",
            elapsed.as_nanos(),
        );
    }
}
