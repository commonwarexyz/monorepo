//! Causal retirement coverage for native work left pending by commit-only publication.

use super::*;
use crate::{
    chain::{
        native::RegistryEntry,
        types::Database,
        validator::{PAGE_CACHE_SIZE, PAGE_SIZE, db_config},
    },
    protocol::{clearing_private, committee, genesis_balances},
};
use commonware_cryptography::Signer as _;
use commonware_glue::stateful::db::DatabaseSet;
use commonware_runtime::{
    buffer::paged::CacheRef,
    mocks::{DeferredSync, release_next_pending_syncs},
};

type DelayedContext = DelayedSyncContext<deterministic::Context>;

async fn delayed_sealer(
    context: &deterministic::Context,
    prefix: &str,
    deployment: &Deployment,
) -> Sealer<DelayedContext> {
    let strategy = context.strategy(NZUsize!(1));
    let pending = PendingSyncs::default();
    pending.unblock();
    let context = DelayedSyncContext {
        inner: context.child("retirement_sealer"),
        pending,
    };
    let db = <Database<DelayedContext> as DatabaseSet<_>>::init(
        context.child("settlement"),
        db_config(
            &format!("{prefix}-settlement"),
            CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
        ),
    )
    .await;
    Sealer::new(
        context.child("sealer"),
        Config {
            strategy,
            scheme: bls12381::Scheme::signer(committee().unwrap(), clearing_private(0).unwrap())
                .unwrap(),
            registry: RegistryView::new(vec![RegistryEntry {
                deployment: deployment.clone(),
                network_key: ed25519::PrivateKey::from_seed(88).public_key(),
                max_dealing_bytes: 4 * 1024 * 1024,
            }]),
            db,
            partition: prefix.into(),
            validators: Vec::new(),
            fetch_timeout: Duration::from_secs(1),
            retain_history: false,
        },
    )
    .0
}

async fn replacement(
    context: &deterministic::Context,
    prefix: &str,
    deployment: &Deployment,
    prepared: PreparedReplica<Key, Digest, Rayon>,
) -> NativeReplica<DelayedContext> {
    let pending = PendingSyncs::default();
    let config = replica_config(
        &format!("{prefix}-replica-{}-1", deployment.digest()),
        context,
        context.strategy(NZUsize!(1)),
    );
    let replica = drive_pending_syncs(
        &pending,
        Box::pin(tests::init_config(
            DelayedSyncContext {
                inner: context.child("replacement"),
                pending: pending.clone(),
            },
            config,
            genesis_balances(deployment).unwrap(),
        )),
    )
    .await
    .unwrap()
    .apply(prepared)
    .await
    .unwrap();
    drive_pending_syncs(&pending, replica.sync()).await.unwrap()
}

#[test]
fn imported_retirement_waits_for_commit_optional_rollover_io() {
    for fail in [false, true] {
        let prefix = if fail {
            "retirement_error"
        } else {
            "retirement_success"
        };
        let ((deployment, offset_partition), crash) = deterministic::Runner::default()
            .start_and_recover(move |context| async move {
                let fixture = Fixture::new(&context, prefix, 126).await;
                let deployment = fixture.lane.deployment.clone();
                let (ballot, _, old_prepared) = fixture
                    .prepare(
                        0,
                        126,
                        Floors {
                            activity: 0,
                            payouts: 0,
                        },
                    )
                    .await;
                let (_, _, replacement_prepared) = fixture
                    .prepare(
                        0,
                        126,
                        Floors {
                            activity: 0,
                            payouts: 0,
                        },
                    )
                    .await;
                drop(fixture);

                let gates = std::array::from_fn(|_| PendingSyncs::default());
                let checkpoint_gate = PendingSyncs::default();
                checkpoint_gate.unblock();
                let mut lane = controlled_lane(
                    &context,
                    prefix,
                    &deployment,
                    &gates,
                    checkpoint_gate,
                )
                .await;
                gates[0].unblock();
                gates[1].unblock();

                let replacement = replacement(
                    &context,
                    prefix,
                    &deployment,
                    replacement_prepared.into_parts().1,
                )
                .await;
                let mut checkpoint = lane.manifest().canonical.checkpoint.clone();
                checkpoint.generation = 1;
                checkpoint.next = 1;
                checkpoint.batch = Some(ballot.header.batch_id::<Sha256>().into_digest());
                checkpoint.head = replacement.head();
                let transfer = sync::Transfer::capture(&replacement, checkpoint)
                    .await
                    .unwrap();

                let payout_gate = &gates[2];
                let starts = payout_gate.starts();
                let entered = payout_gate.entered();
                let completions = payout_gate.completions();
                // At the exact variable-journal boundary, the offsets fixed journal seals first,
                // followed by the authoritative data journal. Commit then syncs the new data tail
                // and joins only the latter two completions.
                let mut publication = Box::pin(persist_candidate(
                    &mut lane,
                    old_prepared.into_parts().1,
                    ballot.clone(),
                ));
                loop {
                    if payout_gate.starts() >= starts + 3 {
                        break;
                    }
                    select! {
                        _ = &mut publication => panic!("candidate published before its data syncs"),
                        _ = commonware_runtime::reschedule() => {},
                    }
                }
                assert_eq!(payout_gate.starts(), starts + 3);
                assert_eq!(payout_gate.entered(), entered + 2);
                assert_eq!(payout_gate.completions(), completions);
                assert_eq!(payout_gate.lock().len(), 3);
                let optional = next_pending_sync(payout_gate);
                assert_eq!(payout_gate.lock().len(), 2);
                release_next_pending_syncs(payout_gate, 2);
                publication.await.unwrap();
                assert_eq!(payout_gate.starts(), starts + 3);
                assert_eq!(payout_gate.entered(), entered + 2);
                assert_eq!(payout_gate.completions(), completions + 2);
                assert_eq!(lane.state.as_ref().unwrap().head(), replacement.head());
                assert_eq!(
                    lane.state
                        .as_ref()
                        .unwrap()
                        .logs()
                        .head()
                        .payouts
                        .operations,
                    128
                );
                assert_eq!(
                    lane.manifest().candidate.as_ref().unwrap().checkpoint.head,
                    replacement.head()
                );
                assert_eq!(
                    lane.manifest().decision.as_ref().unwrap().encode(),
                    ballot.encode()
                );
                lane.checkpoint = Some(lane.checkpoint.take().unwrap().stage(1).await.unwrap());

                let old_config = replica_config(
                    &format!("{prefix}-replica-{}-0", deployment.digest()),
                    &context,
                    context.strategy(NZUsize!(1)),
                );
                let offset_partition =
                    format!("{}_offsets-blobs", old_config.logs.payouts.log.partition);
                assert!(!context.scan(&offset_partition).await.unwrap().is_empty());

                let mut sealer = delayed_sealer(&context, prefix, &deployment).await;
                let operator = ed25519::PrivateKey::from_seed(88).public_key();
                let validator = ed25519::PrivateKey::from_seed(100).public_key();
                let (_, (mut sender, _)) =
                    tests::network(&context, &operator, &validator, true, true).await;
                let mut lanes = vec![lane];
                let mut imports = Imports::new();
                let imported = sync::Imported {
                    replica: replacement,
                    transfer,
                };
                let DeferredSync {
                    release,
                    blocked: mut optional_blocked,
                } = optional;
                let mut retirement = Box::pin(sealer.imported(
                    &mut lanes,
                    &mut imports,
                    (0, 0, Ok(Some(imported))),
                    &mut sender,
                ));
                select! {
                    _ = &mut optional_blocked => {},
                    result = &mut retirement => panic!("retirement bypassed pending offset sync: {result:?}"),
                }

                let checkpoint = checkpoint::Store::open(
                    context.child("pending_marker"),
                    prefix,
                    deployment.digest(),
                )
                .await
                .unwrap();
                assert_eq!(checkpoint.get().unwrap().garbage, Some(0));
                assert_eq!(
                    checkpoint.get().unwrap().canonical.checkpoint.generation,
                    1
                );
                assert!(checkpoint.stage(2).await.is_err());
                assert!(!context.scan(&offset_partition).await.unwrap().is_empty());

                release.send_lossy(if fail {
                    Err(commonware_runtime::Error::Closed)
                } else {
                    Ok(())
                });
                let result = retirement.await;
                if fail {
                    assert!(result.is_err());
                    assert_eq!(payout_gate.completions(), completions + 2);
                    assert_eq!(lanes[0].manifest().garbage, Some(0));
                    assert!(!context.scan(&offset_partition).await.unwrap().is_empty());
                } else {
                    result.unwrap();
                    assert_eq!(payout_gate.completions(), completions + 3);
                    assert!(lanes[0].manifest().garbage.is_none());
                    assert!(matches!(
                        context.scan(&offset_partition).await,
                        Err(commonware_runtime::Error::PartitionMissing(_))
                    ));
                }
                drop(lanes);
                drop(sealer);
                (deployment, offset_partition)
            });

        deterministic::Runner::from(crash).start(|context| async move {
            if fail {
                let (sealer, _) = tests::sealer(&context, prefix, &deployment).await;
                let mut lanes = Vec::new();
                sealer.lane(&mut lanes, &deployment).await.unwrap();
                assert!(lanes[0].manifest().garbage.is_none());
                assert_eq!(lanes[0].manifest().canonical.checkpoint.generation, 1);
            } else {
                let lane = reopen(&context, prefix, &deployment).await;
                assert!(lane.manifest().garbage.is_none());
                assert_eq!(lane.manifest().canonical.checkpoint.generation, 1);
            }
            assert!(matches!(
                context.scan(&offset_partition).await,
                Err(commonware_runtime::Error::PartitionMissing(_))
            ));
        });
    }
}
