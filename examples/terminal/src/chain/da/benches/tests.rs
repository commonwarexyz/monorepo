use super::*;
use commonware_macros::select;
use commonware_runtime::{
    deterministic,
    mocks::{DelayedSyncContext, PendingSyncs, next_pending_sync},
};
use commonware_utils::channel::fallible::OneshotExt as _;

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
fn measured_ack_advances_and_reopens_every_owner() {
    for withdrawals in [0, 32] {
        let options = options(withdrawals);
        let scheme = signer();
        let (options, scheme) = (&options, &scheme);
        let ((deployment, input, sample), crash) = deterministic::Runner::default()
            .start_and_recover(|mut context| async move {
                let strategy = context.strategy(options.workers);
                let (deployment, input) =
                    setup(context.child("baseline"), options, scheme, &strategy)
                        .await
                        .unwrap();
                let mut lane = open(
                    context.child("measurement"),
                    deployment.clone(),
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
            let lane = open(context, deployment, strategy).await.unwrap();
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
            let (deployment, input) = setup(context.child("baseline"), options, scheme, &strategy).await.unwrap();
            let public = PendingSyncs::default();
            public.unblock();
            let private = PendingSyncs::default();
            private.unblock();
            let mut controlled = DelayedSyncContext {
                inner: context.child("measured"),
                pending: public,
            };
            let state = NativeReplica::open(controlled.child("replica"), config(&controlled, deployment.digest(), strategy.clone())).await.unwrap();
            let checkpoint = checkpoint::Store::open(DelayedSyncContext {
                inner: context.child("private"), pending: private.clone(),
            }, PREFIX, deployment.digest()).await.unwrap();
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
        let lane = open(context, deployment, strategy).await.unwrap();
        verify_reopened(&lane, &input, &sample, scheme).unwrap();
    });
}
