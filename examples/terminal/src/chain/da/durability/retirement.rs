//! Causal retirement coverage for native work left pending by commit-only publication.

use super::*;
use crate::{
    chain::{native::RegistryEntry, types::Database, validator::db_config},
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
    page_cache: CacheRef,
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
        db_config(&format!("{prefix}-settlement"), page_cache.clone()),
    )
    .await;
    Sealer::new(
        context.child("sealer"),
        Config {
            strategy,
            page_cache,
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
    prepared: Vec<PreparedReplica<Key, Digest, Rayon>>,
    page_cache: CacheRef,
) -> NativeReplica<DelayedContext> {
    let pending = PendingSyncs::default();
    let config = replica_config(
        &format!("{prefix}-replica-{}-1", deployment.digest()),
        page_cache,
        context.strategy(NZUsize!(1)),
    );
    let mut replica = drive_pending_syncs(
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
    .unwrap();
    for prepared in prepared {
        replica = drive_pending_syncs(&pending, replica.apply(prepared))
            .await
            .unwrap();
    }
    drive_pending_syncs(&pending, replica.sync()).await.unwrap()
}

#[test]
fn imported_retirement_waits_for_commit_optional_merkle_rollover_io() {
    for fail in [false, true] {
        let prefix = if fail {
            "retirement_error"
        } else {
            "retirement_success"
        };
        let ((deployment, merkle_partition), crash) = deterministic::Runner::default()
            .start_and_recover(move |context| async move {
                let mut fixture = Fixture::new(&context, prefix, 511).await;
                let deployment = fixture.lane.deployment.clone();
                let mut replacement_prepared = Vec::new();
                for outgoing in [510, 510] {
                    let (history_ballot, _, old_history) = fixture
                        .prepare(
                            outgoing,
                            0,
                            Floors {
                                activity: 0,
                                payouts: 0,
                            },
                        )
                        .await;
                    let (_, _, replacement_history) = fixture
                        .prepare(
                            outgoing,
                            0,
                            Floors {
                                activity: 0,
                                payouts: 0,
                            },
                        )
                        .await;
                    replacement_prepared.push(replacement_history.into_parts().1);
                    fixture.candidate(history_ballot, old_history).await;
                    fixture.promote().await;
                }
                let (ballot, _, old_prepared) = fixture
                    .prepare(
                        1,
                        0,
                        Floors {
                            activity: 0,
                            payouts: 0,
                        },
                    )
                    .await;
                let (_, _, replacement_candidate) = fixture
                    .prepare(
                        1,
                        0,
                        Floors {
                            activity: 0,
                            payouts: 0,
                        },
                    )
                    .await;
                replacement_prepared.push(replacement_candidate.into_parts().1);
                let page_cache = fixture.page_cache.clone();
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
                    page_cache.clone(),
                )
                .await;
                gates[0].unblock();
                gates[2].unblock();

                let replacement = replacement(
                    &context,
                    prefix,
                    &deployment,
                    replacement_prepared,
                    page_cache.clone(),
                )
                .await;
                let mut checkpoint = lane.manifest().canonical.checkpoint.clone();
                checkpoint.generation = 1;
                checkpoint.next = ballot.epoch.checked_add(1).unwrap();
                checkpoint.batch = Some(ballot.header.batch_id::<Sha256>().into_digest());
                checkpoint.head = replacement.head();
                let transfer = sync::Transfer::capture(&replacement, checkpoint)
                    .await
                    .unwrap();

                let activity_gate = &gates[1];
                let starts = activity_gate.starts();
                let entered = activity_gate.entered();
                let completions = activity_gate.completions();
                // Two valid 511-row, 510-entry closes leave 2,045 activity leaves. The final
                // two-row, one-entry close reaches 2,049 leaves and exactly 4,096 MMR nodes.
                // Commit starts the authoritative data-tail sync first, then flushing those nodes
                // starts an optional Merkle rollover that publication does not join.
                let mut publication = Box::pin(persist_candidate(
                    &mut lane,
                    old_prepared.into_parts().1,
                    ballot.clone(),
                ));
                loop {
                    if activity_gate.starts() >= starts + 2 {
                        break;
                    }
                    select! {
                        _ = &mut publication => panic!("candidate published before its data syncs"),
                        _ = commonware_runtime::reschedule() => {},
                    }
                }
                assert_eq!(activity_gate.starts(), starts + 2);
                assert_eq!(activity_gate.entered(), entered + 1);
                assert_eq!(activity_gate.completions(), completions);
                assert_eq!(activity_gate.lock().len(), 2);
                release_next_pending_syncs(activity_gate, 1);
                publication.await.unwrap();
                assert_eq!(activity_gate.starts(), starts + 2);
                assert_eq!(activity_gate.entered(), entered + 1);
                assert_eq!(activity_gate.completions(), completions + 1);
                assert_eq!(activity_gate.lock().len(), 1);
                let optional = next_pending_sync(activity_gate);
                assert_eq!(lane.state.as_ref().unwrap().head(), replacement.head());
                assert_eq!(
                    lane.state
                        .as_ref()
                        .unwrap()
                        .logs()
                        .head()
                        .activity
                        .operations,
                    2049
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
                    page_cache.clone(),
                    context.strategy(NZUsize!(1)),
                );
                let merkle_partition =
                    format!("{}-blobs", old_config.logs.activity.merkle.journal_partition);
                assert!(!context.scan(&merkle_partition).await.unwrap().is_empty());

                let mut sealer =
                    delayed_sealer(&context, prefix, &deployment, page_cache.clone()).await;
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
                    result = &mut retirement => panic!("retirement bypassed pending Merkle sync: {result:?}"),
                }

                let checkpoint = checkpoint::Store::open(
                    context.child("pending_marker"),
                    prefix,
                    deployment.digest(),
                    page_cache,
                )
                .await
                .unwrap();
                assert_eq!(checkpoint.get().unwrap().garbage, Some(0));
                assert_eq!(
                    checkpoint.get().unwrap().canonical.checkpoint.generation,
                    1
                );
                assert!(checkpoint.stage(2).await.is_err());
                assert!(!context.scan(&merkle_partition).await.unwrap().is_empty());

                release.send_lossy(if fail {
                    Err(commonware_runtime::Error::Closed)
                } else {
                    Ok(())
                });
                let result = retirement.await;
                if fail {
                    assert!(result.is_err());
                    assert_eq!(activity_gate.completions(), completions + 1);
                    assert_eq!(lanes[0].manifest().garbage, Some(0));
                    assert!(!context.scan(&merkle_partition).await.unwrap().is_empty());
                } else {
                    result.unwrap();
                    assert_eq!(activity_gate.completions(), completions + 2);
                    assert!(lanes[0].manifest().garbage.is_none());
                    assert!(matches!(
                        context.scan(&merkle_partition).await,
                        Err(commonware_runtime::Error::PartitionMissing(_))
                    ));
                }
                drop(lanes);
                drop(sealer);
                (deployment, merkle_partition)
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
                context.scan(&merkle_partition).await,
                Err(commonware_runtime::Error::PartitionMissing(_))
            ));
        });
    }
}
