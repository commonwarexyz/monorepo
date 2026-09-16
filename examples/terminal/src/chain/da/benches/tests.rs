use super::{super::durability::controlled, *};
use commonware_macros::select;
use commonware_runtime::{
    deterministic,
    mocks::{
        DelayedSyncContext, PendingSyncs, drive_pending_syncs, next_pending_sync,
        release_pending_syncs,
    },
};
use commonware_utils::channel::fallible::OneshotExt as _;
use std::{
    future::{Future as _, poll_fn},
    num::NonZeroU64,
    task::Poll,
};

fn options(withdrawals: usize) -> Options {
    Options {
        storage_directory: PathBuf::new(),
        accounts: 32,
        senders: 16,
        recipients: 8,
        out_degree: 2,
        withdrawals,
        history: 3,
        samples: 2,
        warmup: 0,
        runtime_workers: 2,
        workers: NonZeroUsize::MIN,
        benchmark_limits: false,
    }
}

#[test]
fn sparse_activity_batch_commits_without_serial_rollover_waits() {
    let options = Options {
        accounts: 1024,
        senders: 1024,
        recipients: 512,
        out_degree: 1,
        history: 0,
        ..options(0)
    };
    let scheme = signer();
    let (options, scheme) = (&options, &scheme);
    let ((deployment, expected_head, expected_operations), crash) =
        deterministic::Runner::default().start_and_recover(|mut context| async move {
            let strategy = context.strategy(options.workers);
            let page_cache = crate::protocol::fixture_page_cache(&context);
            let (deployment, input) = setup(
                context.child("baseline"),
                options,
                scheme,
                &strategy,
                page_cache.clone(),
            )
            .await
            .unwrap();
            assert_eq!(input.row_count, 1024);
            assert_eq!(input.activity_append_operations, 2048);
            let gates = std::array::from_fn(|_| PendingSyncs::default());
            gates[0].unblock();
            gates[2].unblock();
            let activity = &gates[1];
            let replica = drive_pending_syncs(
                activity,
                controlled(&context, PREFIX, &deployment, &gates, page_cache),
            )
            .await;
            let (_, prepared) = seal::<Sha256, _, _, _, _, BatchVerifier, _>(
                scheme,
                &replica,
                &input.context,
                &deployment.operator_ack,
                &input.deposits,
                &input.withdrawals,
                input.encoded_dealing.clone(),
                &mut context,
                &strategy,
            )
            .await
            .unwrap();
            let expected_operations = prepared.replica().logs().activity_operations().1.to_vec();
            let entered = activity.entered();
            let mut apply = Box::pin(replica.apply(prepared.into_parts().1));
            let replica = poll_fn(|cx| {
                let result = apply.as_mut().poll(cx);
                assert_eq!(
                    activity.entered(),
                    entered,
                    "activity apply waited for an intermediate rollover sync"
                );
                result
            })
            .await
            .unwrap();

            // The batch fits one data section. Its durability work can complete in one round,
            // even though flushing its Merkle nodes starts an optional rollover sync.
            let mut rounds = 0;
            let mut commit = Box::pin(replica.commit());
            let replica = poll_fn(|cx| match commit.as_mut().poll(cx) {
                Poll::Ready(result) => Poll::Ready(result),
                Poll::Pending => {
                    if activity.entered() > activity.completions() {
                        rounds += 1;
                        assert_eq!(rounds, 1, "activity commit serialized rollover syncs");
                        release_pending_syncs(activity);
                    }
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            })
            .await
            .unwrap();
            assert_eq!(rounds, 1, "activity commit skipped its durability gate");
            assert_eq!(replica.head(), input.expected_head);
            (deployment, input.expected_head, expected_operations)
        });
    deterministic::Runner::from(crash).start(|context| async move {
        let replica = NativeReplica::open(
            context.child("reopened"),
            config(
                deployment.digest(),
                crate::protocol::fixture_page_cache(&context),
                context.strategy(options.workers),
            ),
        )
        .await
        .unwrap();
        assert_eq!(replica.head(), expected_head);
        let (_, operations) = replica
            .logs()
            .activity_opening(
                &expected_head.logs.activity,
                1,
                NonZeroU64::new(expected_operations.len() as u64).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(operations, expected_operations);
    });
}

#[test]
fn measured_ack_advances_and_reopens_every_owner() {
    for withdrawals in [0, 32] {
        let options = options(withdrawals);
        let scheme = signer();
        let (options, scheme) = (&options, &scheme);
        let ((deployment, input, sample), crash) = deterministic::Runner::default()
            .start_and_recover(|mut context| async move {
                let strategy = context.strategy(options.workers);
                let page_cache = crate::protocol::fixture_page_cache(&context);
                let (deployment, input) = setup(
                    context.child("baseline"),
                    options,
                    scheme,
                    &strategy,
                    page_cache.clone(),
                )
                .await
                .unwrap();
                let mut lane = open(
                    context.child("measurement"),
                    deployment.clone(),
                    page_cache,
                    strategy.clone(),
                )
                .await
                .unwrap();
                let sample = measure(&mut context, &mut lane, &input, scheme, &strategy)
                    .await
                    .unwrap();
                assert!(sample.rows > 0 && sample.mutations > 0);
                assert_eq!(sample.deletions, withdrawals);
                assert_eq!(
                    input.expected_head.state.live_accounts(),
                    (options.accounts - withdrawals) as u64
                );
                assert!(
                    measure(&mut context, &mut lane, &input, scheme, &strategy)
                        .await
                        .is_err(),
                    "a saved-candidate retry became a counted sample"
                );
                (deployment, input, sample)
            });
        deterministic::Runner::from(crash).start(|context| async move {
            let strategy = context.strategy(options.workers);
            let page_cache = crate::protocol::fixture_page_cache(&context);
            let lane = open(context, deployment, page_cache, strategy)
                .await
                .unwrap();
            verify_reopened(&lane, &input, &sample, scheme).unwrap();
        });
    }
}

#[test]
fn measured_ack_waits_for_private_durability() {
    let options = options(32);
    let scheme = signer();
    let (options, scheme) = (&options, &scheme);
    let ((deployment, input, sample), crash) = deterministic::Runner::default()
        .start_and_recover(|context| async move {
            let strategy = context.strategy(options.workers);
            let page_cache = crate::protocol::fixture_page_cache(&context);
            let (deployment, input) = setup(
                context.child("baseline"),
                options,
                scheme,
                &strategy,
                page_cache.clone(),
            )
            .await
            .unwrap();
            let public = PendingSyncs::default();
            public.unblock();
            let private = PendingSyncs::default();
            private.unblock();
            let mut controlled = DelayedSyncContext {
                inner: context.child("measured"),
                pending: public,
            };
            let state = NativeReplica::open(
                controlled.child("replica"),
                config(deployment.digest(), page_cache.clone(), strategy.clone()),
            )
            .await
            .unwrap();
            let checkpoint = checkpoint::Store::open(DelayedSyncContext {
                inner: context.child("private"), pending: private.clone(),
            }, PREFIX, deployment.digest(), page_cache).await.unwrap();
            let mut lane = Lane { deployment: deployment.clone(), pending: None, state: Some(state), checkpoint: Some(checkpoint) };
            private.arm();
            let gate = next_pending_sync(&private);
            let mut sample = Box::pin(measure(&mut controlled, &mut lane, &input, scheme, &strategy));
            let polling = Instant::now();
            select! {
                _ = gate.blocked => {},
                _ = &mut sample => panic!("ACK benchmark timer returned before its private Commit was durable"),
            }

            // The reported wall interval includes a private durability wait longer than all
            // work before that wait. This detects stopping the clock before publication.
            let hold = polling.elapsed() + Duration::from_millis(10);
            let blocked = Instant::now();
            std::thread::sleep(hold);
            let held = blocked.elapsed();
            gate.release.send_lossy(Ok(()));
            private.unblock();
            let sample = sample.await.unwrap();
            assert!(sample.elapsed >= held, "ACK timer excluded its private durability wait");
            (deployment, input, sample)
        });
    deterministic::Runner::from(crash).start(|context| async move {
        let strategy = context.strategy(options.workers);
        let page_cache = crate::protocol::fixture_page_cache(&context);
        let lane = open(context, deployment, page_cache, strategy)
            .await
            .unwrap();
        verify_reopened(&lane, &input, &sample, scheme).unwrap();
    });
}
