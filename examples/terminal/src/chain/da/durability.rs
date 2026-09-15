//! Causal native checkpoint, rollback, and peer-transfer tests.

use super::{tests::Fixture, *};
use commonware_clearing::bajillion::{logs, qmdb, replica::Replica};
use commonware_runtime::{
    Clock as _, Listener as _, Runner as _, Supervisor as _, deterministic,
    mocks::{DelayedSyncContext, PendingSyncs, drive_pending_syncs, next_pending_sync},
};
use std::{future::Future, net::SocketAddr};

async fn drive<T>(gates: &[PendingSyncs; 3], future: impl Future<Output = T>) -> T {
    drive_pending_syncs(
        &gates[0],
        Box::pin(drive_pending_syncs(
            &gates[1],
            Box::pin(drive_pending_syncs(&gates[2], Box::pin(future))),
        )),
    )
    .await
}
async fn controlled(
    context: &deterministic::Context,
    prefix: &str,
    deployment: &Deployment,
    gates: &[PendingSyncs; 3],
) -> NativeReplica<DelayedSyncContext<deterministic::Context>> {
    let config = replica_config(
        &format!("{prefix}-replica-{}-0", deployment.digest()),
        context,
        Sequential,
    );
    let state = qmdb::State::open(
        DelayedSyncContext {
            inner: context.child("controlled_state"),
            pending: gates[0].clone(),
        },
        config.state,
    )
    .await
    .unwrap();
    let activity_cfg = config.logs.activity.log.codec_config;
    let payout_cfg = config.logs.payouts.log.codec_config;
    let activity = logs::ActivityDb::init(
        DelayedSyncContext {
            inner: context.child("controlled_activity"),
            pending: gates[1].clone(),
        },
        config.logs.activity,
    )
    .await
    .unwrap();
    let payouts = logs::PayoutDb::init(
        DelayedSyncContext {
            inner: context.child("controlled_payouts"),
            pending: gates[2].clone(),
        },
        config.logs.payouts,
    )
    .await
    .unwrap();
    Replica::from_parts(
        state,
        logs::Logs::from_parts(activity, payouts, activity_cfg, payout_cfg),
    )
}
pub(super) async fn reopen(
    context: &deterministic::Context,
    prefix: &str,
    deployment: &Deployment,
) -> Lane<deterministic::Context> {
    let checkpoints =
        checkpoint::Store::open(context.child("checkpoint"), prefix, deployment.digest())
            .await
            .unwrap();
    let generation = checkpoints.get().unwrap().canonical.checkpoint.generation;
    let replica = NativeReplica::open(
        context.child("replica"),
        replica_config(
            &format!("{prefix}-replica-{}-{generation}", deployment.digest()),
            context,
            Sequential,
        ),
    )
    .await
    .unwrap();
    let (replica, checkpoints) = recover(replica, deployment, checkpoints).await.unwrap();
    Lane {
        deployment: deployment.clone(),
        fetching: false,
        pending: None,
        state: Some(replica),
        checkpoint: Some(checkpoints),
    }
}
async fn controlled_lane(
    context: &deterministic::Context,
    prefix: &str,
    deployment: &Deployment,
    gates: &[PendingSyncs; 3],
    checkpoint_gate: PendingSyncs,
) -> Lane<DelayedSyncContext<deterministic::Context>> {
    let state = drive(gates, controlled(context, prefix, deployment, gates)).await;
    let checkpoints = checkpoint::Store::open(
        DelayedSyncContext {
            inner: context.child("controlled_checkpoint"),
            pending: checkpoint_gate,
        },
        prefix,
        deployment.digest(),
    )
    .await
    .unwrap();
    Lane {
        deployment: deployment.clone(),
        fetching: false,
        pending: None,
        state: Some(state),
        checkpoint: Some(checkpoints),
    }
}

#[test]
fn candidate_publication_waits_for_the_private_ack_commit() {
    for fail in [false, true] {
        let ((deployment, parent, candidate, decision), crash) =
            deterministic::Runner::default().start_and_recover(move |context| async move {
                let fixture = Fixture::new(&context, "ack_barrier", 8).await;
                let deployment = fixture.lane.deployment.clone();
                let parent = fixture.lane.state.as_ref().unwrap().head();
                let (ballot, _, prepared) = fixture
                    .prepare(3, 3, Floors { activity: 0, payouts: 0 })
                    .await;
                let decision = ballot.encode();
                let candidate = prepared.close().roots;
                drop(fixture);
                let gates = std::array::from_fn(|_| PendingSyncs::default());
                let metadata = PendingSyncs::default();
                metadata.unblock();
                let mut lane = controlled_lane(
                    &context, "ack_barrier", &deployment, &gates, metadata.clone(),
                ).await;
                for gate in &gates { gate.unblock(); }
                metadata.arm();
                let gate = next_pending_sync(&metadata);
                let mut publish = Box::pin(persist_candidate(&mut lane, prepared.into_parts().1, ballot));
                select! {
                    _ = gate.blocked => {},
                    _ = &mut publish => panic!("candidate published before its private ACK Commit was durable"),
                }
                if fail {
                    gate.release.send_lossy(Err(commonware_runtime::Error::Closed));
                    assert!(publish.await.is_err());
                } else {
                    gate.release.send_lossy(Ok(()));
                    metadata.unblock();
                    publish.await.unwrap();
                    assert_eq!(lane.manifest().decision.as_ref().unwrap().encode(), decision);
                }
                (deployment, parent, candidate, decision)
            });
        deterministic::Runner::from(crash).start(|context| async move {
            // Public data reaches its own durability barriers before the private control
            // Commit. Inspect the raw stores before application recovery can rewind them.
            let replica = NativeReplica::open(
                context.child("raw_ack_candidate"),
                replica_config(
                    &format!("ack_barrier-replica-{}-0", deployment.digest()),
                    &context,
                    Sequential,
                ),
            )
            .await
            .unwrap();
            assert_eq!(replica.state().root(), candidate.successor);
            assert_ne!(replica.head(), parent);
            assert_eq!(*replica.logs().head(), candidate.logs());
            drop(replica);
            let lane = reopen(&context, "ack_barrier", &deployment).await;
            let manifest = lane.manifest();
            assert_eq!(
                lane.state.as_ref().unwrap().head(),
                manifest.complete().checkpoint.head
            );
            if !fail {
                assert_eq!(manifest.decision.as_ref().unwrap().encode(), decision);
                assert!(manifest.candidate.is_some());
            }
        });
    }
}

#[test]
fn incomplete_candidate_rewinds_all_three_without_a_body_journal() {
    for role in 0..4 {
        let ((deployment, target), crash) = deterministic::Runner::default().start_and_recover(move |context| async move {
            let fixture = Fixture::new(&context, "candidate_cut", 8).await;
            let deployment = fixture.lane.deployment.clone();
            let target = fixture.lane.state.as_ref().unwrap().head();
            let (ballot, _, prepared) = fixture.prepare(3, 3, Floors { activity: 0, payouts: 0 }).await;
            drop(fixture);
            let gates = std::array::from_fn(|_| PendingSyncs::default());
            let metadata = PendingSyncs::default();
            metadata.unblock();
            let mut lane = controlled_lane(&context, "candidate_cut", &deployment, &gates, metadata.clone()).await;
            for (index, gate) in gates.iter().enumerate() { if index == role { gate.arm(); } else { gate.unblock(); } }
            if role == 3 { metadata.arm(); }
            let gate = next_pending_sync(if role == 3 { &metadata } else { &gates[role] });
            let mut publish = Box::pin(persist_candidate(&mut lane, prepared.into_parts().1, ballot));
            select! { _ = gate.blocked => {}, _ = &mut publish => panic!("candidate became publishable before every durability barrier"), }
            drop(publish);
            drop(lane);
            drop(gate.release);
            (deployment, target)
        });
        deterministic::Runner::from(crash).start(|context| async move {
            let lane = reopen(&context, "candidate_cut", &deployment).await;
            // If the metadata write reached its barrier, recovery may select that coherent
            // candidate. Otherwise the previous common checkpoint owns all three rollbacks.
            let selected = lane.manifest().complete().checkpoint.head;
            assert_eq!(lane.state.as_ref().unwrap().head(), selected);
            if role < 3 {
                assert_eq!(selected, target);
                assert!(lane.manifest().decision.is_none());
            }
            assert!(!context.encode().contains("archive_"));
        });
    }
}

#[test]
fn durable_components_ahead_of_the_manifest_rewind_without_replay() {
    for durable in 1..8 {
        let ((deployment, parent, candidate), crash) = deterministic::Runner::default()
            .start_and_recover(move |context| async move {
                let mut fixture = Fixture::new(&context, "ahead", 8).await;
                let (ballot, _, prepared) = fixture
                    .prepare(
                        1,
                        1,
                        Floors {
                            activity: 0,
                            payouts: 0,
                        },
                    )
                    .await;
                fixture.candidate(ballot, prepared).await;
                fixture.promote().await;
                let deployment = fixture.lane.deployment.clone();
                let parent = fixture.lane.state.as_ref().unwrap().head();
                let (_, _, prepared) = fixture
                    .prepare(
                        3,
                        3,
                        Floors {
                            activity: 0,
                            payouts: 0,
                        },
                    )
                    .await;
                let replica = fixture
                    .lane
                    .state
                    .unwrap()
                    .apply(prepared.into_parts().1)
                    .await
                    .unwrap();
                let candidate = replica.head();
                let (state, logs) = replica.into_parts();
                let (activity, payouts) = logs.into_parts();
                if durable & 1 != 0 {
                    drop(state.sync().await.unwrap());
                } else {
                    drop(state);
                }
                if durable & 2 != 0 {
                    drop(activity.sync().await.unwrap());
                } else {
                    drop(activity);
                }
                if durable & 4 != 0 {
                    drop(payouts.sync().await.unwrap());
                } else {
                    drop(payouts);
                }
                (deployment, parent, candidate)
            });
        let ((deployment, parent), crash) =
            deterministic::Runner::from(crash).start_and_recover(move |context| async move {
                let replica = NativeReplica::open(
                    context.child("raw_ahead"),
                    replica_config(
                        &format!("ahead-replica-{}-0", deployment.digest()),
                        &context,
                        Sequential,
                    ),
                )
                .await
                .unwrap();
                let observed = replica.head();
                if durable & 1 != 0 {
                    assert_eq!(observed.state, candidate.state);
                    assert_ne!(observed.state, parent.state);
                }
                if durable & 2 != 0 {
                    assert_eq!(observed.logs.activity, candidate.logs.activity);
                    assert_ne!(observed.logs.activity, parent.logs.activity);
                }
                if durable & 4 != 0 {
                    assert_eq!(observed.logs.payouts, candidate.logs.payouts);
                    assert_ne!(observed.logs.payouts, parent.logs.payouts);
                }
                let checkpoints = checkpoint::Store::open(
                    context.child("checkpoint"),
                    "ahead",
                    deployment.digest(),
                )
                .await
                .unwrap();
                assert_eq!(
                    checkpoints.get().unwrap().complete().checkpoint.head,
                    parent
                );
                let (replica, checkpoints) =
                    recover(replica, &deployment, checkpoints).await.unwrap();
                assert_eq!(replica.head(), parent);
                assert!(checkpoints.get().unwrap().decision.is_none());
                assert_eq!(
                    tests::metric(&context, "raw_ahead_state_balances_apply_batch_calls_total"),
                    0
                );
                (deployment, parent)
            });
        deterministic::Runner::from(crash).start(|context| async move {
            assert_eq!(
                reopen(&context, "ahead", &deployment)
                    .await
                    .state
                    .unwrap()
                    .head(),
                parent
            );
        });
    }
}

#[test]
fn completed_candidate_survives_restart_and_promotion_without_reapplication() {
    let ((deployment, target, decision), crash) = deterministic::Runner::default()
        .start_and_recover(|context| async move {
            let mut fixture = Fixture::new(&context, "candidate", 8).await;
            let (ballot, _, prepared) = fixture
                .prepare(
                    3,
                    3,
                    Floors {
                        activity: 0,
                        payouts: 0,
                    },
                )
                .await;
            fixture.candidate(ballot.clone(), prepared).await;
            let target = fixture.lane.state.as_ref().unwrap().head();
            assert_eq!(fixture.lane.next(), 0);
            (fixture.lane.deployment.clone(), target, ballot)
        });
    let ((deployment, target), crash) =
        deterministic::Runner::from(crash).start_and_recover(|context| async move {
            let mut lane = reopen(&context, "candidate", &deployment).await;
            assert_eq!(lane.state.as_ref().unwrap().head(), target);
            assert_eq!(
                lane.manifest().decision.as_ref().unwrap().encode(),
                decision.encode()
            );
            assert_eq!(
                tests::metric(&context, "replica_state_balances_apply_batch_calls_total"),
                0
            );
            let mut manifest = lane.manifest().as_ref().clone();
            manifest.canonical = manifest.candidate.take().unwrap();
            manifest.decision = None;
            lane.checkpoint = Some(lane.checkpoint.take().unwrap().put(manifest).await.unwrap());
            (deployment, target)
        });
    deterministic::Runner::from(crash).start(|context| async move {
        let lane = reopen(&context, "candidate", &deployment).await;
        assert_eq!(lane.next(), 1);
        assert_eq!(lane.state.as_ref().unwrap().head(), target);
        assert!(lane.manifest().decision.is_none());
        assert_eq!(
            tests::metric(&context, "replica_state_balances_apply_batch_calls_total"),
            0
        );
    });
}

#[test]
fn candidate_disposal_selects_parent_before_each_native_rewind() {
    for role in 0..3 {
        let ((deployment, parent, decision), crash) = deterministic::Runner::default().start_and_recover(move |context| async move {
            let mut fixture = Fixture::new(&context, "discard", 8).await;
            let parent = fixture.lane.state.as_ref().unwrap().head();
            let (decision, _, prepared) = fixture.prepare(3, 3, Floors { activity: 0, payouts: 0 }).await;
            fixture.candidate(decision.clone(), prepared).await;
            let deployment = fixture.lane.deployment.clone();
            drop(fixture);
            let gates = std::array::from_fn(|_| PendingSyncs::default());
            let metadata = PendingSyncs::default(); metadata.unblock();
            let mut lane = controlled_lane(&context, "discard", &deployment, &gates, metadata).await;
            for (index, gate) in gates.iter().enumerate() { if index == role { gate.arm(); } else { gate.unblock(); } }
            let gate = next_pending_sync(&gates[role]);
            let mut rollback = Box::pin(discard(&mut lane));
            select! { _ = gate.blocked => {}, _ = &mut rollback => panic!("disposal returned before rewind durability"), }
            drop(rollback);
            assert_eq!(lane.manifest().complete().checkpoint.head, parent);
            assert!(lane.manifest().candidate.is_none());
            assert_eq!(lane.manifest().decision.as_ref().unwrap().encode(), decision.encode());
            drop(lane); drop(gate.release);
            (deployment, parent, decision)
        });
        deterministic::Runner::from(crash).start(|context| async move {
            let lane = reopen(&context, "discard", &deployment).await;
            assert_eq!(lane.state.as_ref().unwrap().head(), parent);
            assert!(lane.manifest().candidate.is_none());
            assert_eq!(
                lane.manifest().decision.as_ref().unwrap().encode(),
                decision.encode()
            );
        });
    }
}

#[test]
fn rewind_cannot_publish_volatile_alignment_before_all_native_syncs() {
    for role in 0..3 {
        let ((deployment, target), crash) = deterministic::Runner::default().start_and_recover(move |context| async move {
            let fixture = Fixture::new(&context, "rewind_barrier", 8).await;
            let deployment = fixture.lane.deployment.clone();
            let target = fixture.lane.state.as_ref().unwrap().head();
            let (_, _, prepared) = fixture.prepare(3, 3, Floors { activity: 0, payouts: 0 }).await;
            drop(fixture.lane.state.unwrap().apply(prepared.into_parts().1).await.unwrap().sync().await.unwrap());
            let gates = std::array::from_fn(|_| PendingSyncs::default());
            let replica = drive(&gates, controlled(&context, "rewind_barrier", &deployment, &gates)).await;
            let (state, logs) = replica.into_parts();
            // Every native head can match while its rewind is still volatile. The aggregate
            // call must complete all durability barriers even on these native no-op paths.
            let state = drive(&gates, state.rewind(&target.state)).await.unwrap();
            let logs = drive(&gates, logs.rewind(&target.logs)).await.unwrap();
            let replica = Replica::from_parts(state, logs);
            assert_eq!(replica.head(), target);
            for (index, gate) in gates.iter().enumerate() { if index == role { gate.arm(); } else { gate.unblock(); } }
            let gate = next_pending_sync(&gates[role]);
            let mut rewind = Box::pin(replica.rewind(&target));
            select! { _ = gate.blocked => {}, _ = &mut rewind => panic!("volatile alignment returned before its durability barrier"), }
            assert!(gates[role].calls() > 0);
            assert_eq!(tests::metric(&context, "controlled_state_balances_apply_batch_calls_total"), 0);
            gate.release.send_lossy(Ok(())); gates[role].unblock();
            assert_eq!(rewind.await.unwrap().head(), target);
            (deployment, target)
        });
        deterministic::Runner::from(crash).start(|context| async move {
            let replica = NativeReplica::open(
                context.child("raw_reopen"),
                replica_config(
                    &format!("rewind_barrier-replica-{}-0", deployment.digest()),
                    &context,
                    Sequential,
                ),
            )
            .await
            .unwrap();
            assert_eq!(replica.head(), target);
        });
    }
}

async fn serve_source(
    context: &deterministic::Context,
    address: SocketAddr,
    lanes: Vec<Lane<deterministic::Context>>,
    mut gate: Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>,
) -> Handle<()> {
    let mut listener = context.bind(address).await.unwrap();
    context.child("native_source").spawn(move |_| async move {
        loop {
            let (_, mut sink, mut stream) = listener.accept().await.unwrap();
            let request = rpc::recv_request(&mut stream).await.unwrap();
            if let Some((entered, released)) = gate.take() {
                entered.send_lossy(());
                released.await.unwrap();
            }
            assert_eq!(
                request.method,
                sync::METHOD_NATIVE,
                "catch-up must use only native QMDB Source"
            );
            let response = sync::serve(&lanes, sync::NativeRequest::decode(request.body).unwrap())
                .await
                .unwrap();
            rpc::send_response(
                &mut sink,
                &rpc::Response::Success {
                    body: response.encode(),
                },
            )
            .await
            .unwrap();
        }
    })
}

#[test]
fn native_source_serves_admitted_parent_while_every_donor_has_an_unadmitted_child() {
    use crate::chain::state::{AdmittedRootsResponse, StatusRecord, admitted_key};
    use commonware_glue::stateful::db::{DatabaseSet as _, Unmerkleized as _};
    deterministic::Runner::default().start(|context| async move {
        let mut donor = Fixture::new(&context, "donor", 8).await;
        let (parent, _, prepared) = donor
            .prepare(
                3,
                3,
                Floors {
                    activity: 0,
                    payouts: 0,
                },
            )
            .await;
        donor.candidate(parent.clone(), prepared).await;
        donor.promote().await;
        let canonical = donor.lane.manifest().canonical.clone();
        let (child, _, prepared) = donor
            .prepare(
                2,
                2,
                Floors {
                    activity: 0,
                    payouts: 0,
                },
            )
            .await;
        donor.candidate(child.clone(), prepared).await;
        assert!(donor.lane.manifest().candidate.is_some());
        let deployment = donor.lane.deployment.clone();
        let address = "127.0.0.1:22500".parse().unwrap();
        let (entered, blocked) = oneshot::channel();
        let (release, released) = oneshot::channel();
        let server = serve_source(&context, address, vec![donor.lane], Some((entered, released))).await;
        let fresh = Fixture::new(&context, "fresh", 8).await;
        let (owner, _) = tests::sealer(&context, "snapshot", &deployment).await;
        let status = StatusRecord { deployment: *deployment.digest(), height: 20, timestamp: 20, state_root: parent.roots.successor, last_finalized: Some(0), custody: 0, claimable: 0, hard_faulted: false };
        let admitted = AdmittedRootsResponse::new(parent.header.batch_id::<Sha256>(), parent.roots, parent.context.predecessor_logs().activity.operations, true);
        let batch = owner.db.new_batches().await.write(status_key(deployment.digest()), Some(Record::Status(status.clone()))).write(admitted_key(deployment.digest(), 0), Some(Record::Admitted(admitted))).merkleize().await.unwrap();
        owner.db.apply(batch).await;
        let authority = sync::capture(&owner.db, deployment.digest()).await.unwrap();
        assert_eq!(authority.first, 0);
        assert_eq!(authority.next(), 1);
        let mut importing = Box::pin(sync::download(
            context.child("import"),
            authority,
            deployment.clone(),
            replica_config("parent-import", &context, Sequential),
            fresh.lane.manifest().canonical.checkpoint.clone(),
            1,
            false,
            address,
            Duration::from_secs(1),
        ));
        select! { _ = blocked => {}, _ = &mut importing => panic!("import must await its native donor"), }
        let admitted = AdmittedRootsResponse::new(child.header.batch_id::<Sha256>(), child.roots, child.context.predecessor_logs().activity.operations, true);
        let batch = owner.db.new_batches().await.write(admitted_key(deployment.digest(), 0), None).write(admitted_key(deployment.digest(), 1), Some(Record::Admitted(admitted))).write(status_key(deployment.digest()), Some(Record::Status(StatusRecord { last_finalized: Some(1), state_root: child.roots.successor, ..status }))).merkleize().await.unwrap();
        owner.db.apply(batch).await;
        assert_eq!(sync::capture(&owner.db, deployment.digest()).await.unwrap().first, 1);
        release.send_lossy(());
        let imported = importing.await.unwrap().unwrap();
        assert_eq!(imported.replica.head(), canonical.checkpoint.head);
        assert_eq!(
            imported.transfer.checkpoint.batch,
            canonical.checkpoint.batch
        );
        let mut forged = canonical;
        forged.ops_root = Digest::from([0u8; 32]);
        assert!(forged.check(&deployment).is_err());
        server.abort();
    });
}

#[test]
fn failed_source_preserves_other_lanes_and_imports_the_admitted_competing_candidate() {
    use crate::chain::{
        query::{Evidence, EvidenceLookup},
        state::{AdmittedRootsResponse, StatusRecord, admitted_key},
    };
    use commonware_cryptography::{Hasher as _, Signer as _};
    use commonware_glue::stateful::db::{DatabaseSet as _, Unmerkleized as _};
    let ((deployment, expected), crash) = deterministic::Runner::default().start_and_recover(|context| async move {
        let mut donor = Fixture::new(&context, "winner", 8).await;
        let (winner, _, prepared) = donor.prepare(3, 3, Floors { activity: 0, payouts: 0 }).await;
        donor.candidate(winner.clone(), prepared).await;
        let expected = donor.lane.state.as_ref().unwrap().head();
        let deployment = donor.lane.deployment.clone();
        let good_address: SocketAddr = "127.0.0.1:22602".parse().unwrap();
        let bad_address: SocketAddr = "127.0.0.1:22601".parse().unwrap();
        let server = serve_source(&context, good_address, vec![donor.lane], None).await;
        let mut loser = Fixture::new(&context, "loser", 8).await;
        let (losing, _, prepared) = loser.prepare(2, 2, Floors { activity: 0, payouts: 0 }).await;
        assert_ne!(losing.header, winner.header);
        loser.candidate(losing, prepared).await;
        assert_eq!(loser.lane.manifest().complete().checkpoint.next, 1);
        assert_eq!(loser.lane.next(), 0);
        drop(loser);
        let (entered, blocked) = oneshot::channel();
        let (release, resumed) = oneshot::channel();
        let mut listener = context.bind(bad_address).await.unwrap();
        let failed = context.child("failed_source").spawn(move |context| async move {
            let mut gate = Some((entered, resumed));
            loop {
                let (_, mut sink, mut stream) = listener.accept().await.unwrap();
                let request = rpc::recv_request(&mut stream).await.unwrap();
                let query = sync::NativeRequest::decode(request.body.clone()).unwrap();
                let response = if matches!(query.query, sync::Query::State(_)) {
                    if let Some((entered, resumed)) = gate.take() { entered.send_lossy(()); resumed.await.unwrap(); }
                    rpc::Response::Success { body: sync::NativeResponse::Unavailable.encode() }
                } else { rpc::call(&context, good_address, &request).await.unwrap() };
                let _ = rpc::send_response(&mut sink, &response).await;
            }
        });
        let (mut sealer, mailbox) = tests::sealer(&context, "loser", &deployment).await;
        let mut other = Deployment::new(Sha256::hash(&[b"independent-native-lane"]), deployment.operator.clone(), deployment.operator_ack, deployment.accounts.clone());
        other.generate(context.child("other_genesis")).await.unwrap();
        let mut entries = sealer.registry.entries();
        entries.push(crate::chain::native::RegistryEntry { deployment: other.clone(), network_key: ed25519::PrivateKey::from_seed(89).public_key(), max_dealing_bytes: 4 * 1024 * 1024 });
        sealer.registry = RegistryView::new(entries);
        let committee = crate::protocol::committee().unwrap();
        sealer.scheme = (0..committee.members().len()).map(|index| bls12381::Scheme::signer(committee.clone(), crate::protocol::clearing_private(index).unwrap()).unwrap()).find(|scheme| scheme.me().unwrap().get() == 1).unwrap();
        let mut members = committee.members().to_vec();
        members.swap(0, 1);
        sealer.validators = members.into_iter().enumerate().map(|(index, clearing)| ValidatorEntry { clearing, query: match index { 0 => bad_address, 1 => good_address, _ => "127.0.0.1:22600".parse().unwrap() } }).collect();
        assert_eq!(sealer.validators[0].clearing, committee.members()[1]);
        assert_eq!(sealer.validators[sealer.scheme.me().unwrap().get() as usize].query, good_address);
        let admitted = AdmittedRootsResponse::new(winner.header.batch_id::<Sha256>(), winner.roots, winner.context.predecessor_logs().activity.operations, false);
        let batch = sealer.db.new_batches().await.write(admitted_key(deployment.digest(), 0), Some(Record::Admitted(admitted))).merkleize().await.unwrap();
        sealer.db.apply(batch).await;
        let db = sealer.db.clone();
        let operator = ed25519::PrivateKey::from_seed(88).public_key();
        let validator = ed25519::PrivateKey::from_seed(100).public_key();
        let (_, channel) = tests::network(&context, &operator, &validator, true, true).await;
        let actor = sealer.start(channel);
        let response = mailbox.native(sync::NativeRequest { deployment: *deployment.digest(), query: sync::Query::Checkpoint { max_next: 0 } }).await.unwrap();
        assert!(matches!(response, sync::NativeResponse::Checkpoint(transfer) if transfer.checkpoint.next == 0));
        select! { _ = blocked => {}, _ = context.sleep(Duration::from_secs(2)) => panic!("failed native source never started"), }
        let batch = db.new_batches().await.write(status_key(deployment.digest()), Some(Record::Status(StatusRecord { deployment: *deployment.digest(), height: 1000, timestamp: 1000, state_root: deployment.genesis().root(), last_finalized: None, custody: 0, claimable: 0, hard_faulted: true }))).merkleize().await.unwrap();
        db.apply(batch).await;
        let response = select! {
            response = mailbox.native(sync::NativeRequest { deployment: *other.digest(), query: sync::Query::Checkpoint { max_next: 0 } }) => response.unwrap(),
            _ = context.sleep(Duration::from_millis(10)) => panic!("one source blocked the unrelated lane"),
        };
        assert!(matches!(response, sync::NativeResponse::Checkpoint(_)));
        release.send_lossy(());
        let recovered = async {
            loop {
                if let sync::NativeResponse::Checkpoint(transfer) = mailbox.native(sync::NativeRequest { deployment: *deployment.digest(), query: sync::Query::Checkpoint { max_next: 1 } }).await.unwrap()
                    && transfer.checkpoint.head == expected { break; }
                context.sleep(Duration::from_millis(1)).await;
            }
        };
        select! { _ = recovered => {}, _ = context.sleep(Duration::from_secs(5)) => panic!("healthy source could not replace same-epoch losing candidate"), }
        let account = deployment.accounts[0].key.clone();
        let EvidenceResponse::Served(Evidence::State(lookup)) = mailbox.serve(EvidenceRequest::new(*deployment.digest(), EvidenceLookup::State { root: deployment.genesis().root(), operations: deployment.genesis().operations(), account: account.clone() })).await.unwrap() else { panic!("faulted import lost its finalized recovery proof"); };
        assert_eq!(lookup.resolve::<Sha256>(&deployment.genesis().root(), &qmdb::account_key(&account).unwrap()).unwrap().unwrap().get(), 4096);
        actor.abort(); server.abort(); failed.abort();
        (deployment, expected)
    });
    deterministic::Runner::from(crash).start(|context| async move {
        let lane = reopen(&context, "loser", &deployment).await;
        assert_eq!(lane.state.as_ref().unwrap().head(), expected);
        assert_eq!(lane.next(), 1);
        assert!(lane.manifest().decision.is_none());
        assert!(lane.manifest().candidate.is_none());
        assert_eq!(lane.manifest().canonical.checkpoint.generation, 1);
    });
}

#[test]
fn physical_prune_and_recorded_prune_intent_preserve_native_transfer_and_old_holder_claims() {
    for cut_before_prune in [false, true] {
        let (
            (deployment, old_index, old_output, old_request, frozen, latest, retained, authority),
            crash,
        ) = deterministic::Runner::default().start_and_recover(move |context| async move {
            let mut hot = Fixture::new(&context, "hot", 70).await;
            let mut holder = Fixture::new(&context, "holder", 70).await;
            let mut heads = Vec::new();
            let mut ballots = Vec::new();
            let mut old = None;
            for epoch in 0..132 {
                let floors = if epoch >= 4 {
                    let head: commonware_clearing::bajillion::replica::ReplicaHead<Digest> =
                        heads[if epoch >= 129 { 128 } else { epoch - 4 }];
                    Floors {
                        activity: head.logs.activity.operations - 1,
                        payouts: head.logs.payouts.operations - 1,
                    }
                } else {
                    Floors {
                        activity: 0,
                        payouts: 0,
                    }
                };
                let (ballot, requests, prepared) = hot.prepare(0, 70, floors).await;
                let (other, _, replica) = holder.prepare(0, 70, floors).await;
                assert_eq!(ballot.header, other.header);
                if epoch == 0 {
                    let index = ballot.context.predecessor_logs().payouts.operations;
                    let output = prepared.close().withdrawal_evidence().0[0].clone();
                    old = Some((index, output, requests.requests()[0].clone()));
                }
                hot.candidate(ballot.clone(), prepared).await;
                hot.promote().await;
                holder.candidate(other, replica).await;
                holder.promote().await;
                heads.push(hot.lane.state.as_ref().unwrap().head());
                ballots.push(ballot);
            }
            let latest = heads[131];
            let frozen = heads[128];
            let authority = sync::Authorities {
                first: 128,
                finalized: Some(128),
                entries: ballots
                    .iter()
                    .skip(128)
                    .enumerate()
                    .map(|(index, ballot)| {
                        crate::chain::state::AdmittedRootsResponse::new(
                            ballot.header.batch_id::<Sha256>(),
                            ballot.roots,
                            ballot.context.predecessor_logs().activity.operations,
                            index == 0,
                        )
                    })
                    .collect(),
            };
            let logs = hot.lane.state.as_ref().unwrap().logs();
            let source = commonware_clearing::bajillion::custody::Epoch::load(logs, 128)
                .await
                .unwrap()
                .source_proof(logs, &frozen.logs)
                .await
                .unwrap()
                .verify::<Sha256, Key>(&frozen.logs)
                .unwrap();
            let retained = authority
                .retention(&hot.lane.manifest().canonical.checkpoint, &source)
                .unwrap();
            assert_eq!(
                retained.activity,
                ballots[128].context.predecessor_logs().activity.operations
            );
            assert_eq!(
                retained.payouts,
                ballots[128].context.predecessor_logs().payouts.operations
            );
            assert!(retained.payouts < latest.logs.payouts.floor);
            assert!(retained.state > 4096 && retained.activity > 128 && retained.payouts > 128);
            if cut_before_prune {
                let mut manifest = hot.lane.manifest().as_ref().clone();
                manifest.canonical.checkpoint.retained = retained;
                hot.lane.checkpoint = Some(
                    hot.lane
                        .checkpoint
                        .take()
                        .unwrap()
                        .put(manifest)
                        .await
                        .unwrap(),
                );
            } else {
                Sealer::<deterministic::Context>::prune(&mut hot.lane, retained)
                    .await
                    .unwrap();
            }
            let (old_index, old_output, old_request) = old.unwrap();
            (
                hot.lane.deployment.clone(),
                old_index,
                old_output,
                old_request,
                frozen,
                latest,
                retained,
                authority,
            )
        });
        let ((deployment, frozen, latest, account), crash) = deterministic::Runner::from(crash)
            .start_and_recover(|context| async move {
                let hot = reopen(&context, "hot", &deployment).await;
                let holder = reopen(&context, "holder", &deployment).await;
                let replica = hot.state.as_ref().unwrap();
                assert_eq!(replica.head(), latest);
                assert_eq!(hot.manifest().canonical.checkpoint.retained, retained);
                assert!(replica.state().retained_start() > 0);
                assert!(replica.logs().retained_starts().activity > old_index);
                assert!(replica.logs().retained_starts().payouts > old_index);
                assert!(
                    payout(replica, &frozen.logs.payouts, old_index)
                        .await
                        .is_err()
                );
                let claim = payout(
                    holder.state.as_ref().unwrap(),
                    &frozen.logs.payouts,
                    old_index,
                )
                .await
                .unwrap();
                assert_eq!(claim.output(), &old_output);
                claim.verify::<Sha256>(&frozen.logs.payouts).unwrap();
                let retained_source = commonware_clearing::bajillion::custody::Epoch::load(
                    holder.state.as_ref().unwrap().logs(),
                    0,
                )
                .await
                .unwrap();
                let source_proof = retained_source
                    .source_proof(holder.state.as_ref().unwrap().logs(), &frozen.logs)
                    .await
                    .unwrap();
                let source = source_proof.verify::<Sha256, Key>(&frozen.logs).unwrap();
                source
                    .verify_withdrawal::<Sha256>(&old_request, &claim)
                    .unwrap();
                assert!(
                    commonware_clearing::bajillion::custody::Epoch::load(replica.logs(), 0)
                        .await
                        .is_err()
                );
                let protected =
                    commonware_clearing::bajillion::custody::Epoch::load(replica.logs(), 128)
                        .await
                        .unwrap();
                let protected_proof = protected
                    .source_proof(replica.logs(), &frozen.logs)
                    .await
                    .unwrap();
                let protected_source = protected_proof.verify::<Sha256, Key>(&frozen.logs).unwrap();
                let account = protected_source.withdrawals().requests()[0]
                    .account()
                    .clone();
                retained_current_proofs(replica, frozen.state, latest.state, &account).await;
                assert!(matches!(
                    protected
                        .account_lookup(replica.logs(), &frozen.logs, &account)
                        .await
                        .unwrap(),
                    commonware_clearing::bajillion::challenge::AccountLookup::Present(_)
                ));
                let address = "127.0.0.1:22700".parse().unwrap();
                let server = serve_source(&context, address, vec![hot], None).await;
                let fresh = Fixture::new(&context, "pruned_import_base", 70).await;
                let imported = Box::pin(sync::download(
                    context.child("pruned_import"),
                    authority,
                    deployment.clone(),
                    replica_config("fresh-after-prune", &context, Sequential),
                    fresh.lane.manifest().canonical.checkpoint.clone(),
                    1,
                    false,
                    address,
                    Duration::from_secs(1),
                ))
                .await
                .unwrap()
                .unwrap();
                assert_eq!(imported.transfer.checkpoint.retained, retained);
                let imported = imported.replica;
                assert_eq!(imported.head(), latest);
                assert!(imported.logs().retained_starts().activity > 0);
                retained_current_proofs(&imported, frozen.state, latest.state, &account).await;
                let source =
                    commonware_clearing::bajillion::custody::Epoch::load(imported.logs(), 128)
                        .await
                        .unwrap();
                source
                    .withdrawal_claim(imported.logs(), &frozen.logs, &account)
                    .await
                    .unwrap();

                server.abort();
                (deployment, frozen, latest, account)
            });
        deterministic::Runner::from(crash).start(|context| async move {
            let imported = NativeReplica::open(
                context.child("imported_reopen"),
                replica_config("fresh-after-prune", &context, Sequential),
            )
            .await
            .unwrap();
            assert_eq!(imported.head(), latest);
            assert_ne!(frozen, latest);
            assert!(imported.state().retained_start() > 0);
            retained_current_proofs(&imported, frozen.state, latest.state, &account).await;
            let source = commonware_clearing::bajillion::custody::Epoch::load(imported.logs(), 128)
                .await
                .unwrap();
            source
                .withdrawal_claim(imported.logs(), &frozen.logs, &account)
                .await
                .unwrap();
            assert_eq!(source.context().deployment(), deployment.digest());
        });
    }
}

async fn retained_current_proofs(
    replica: &NativeReplica<deterministic::Context>,
    finalized: qmdb::StateHead<Digest>,
    pending: qmdb::StateHead<Digest>,
    account: &Key,
) {
    let account_key = qmdb::account_key(account).unwrap();
    let absent = qmdb::account_key(
        &crate::protocol::Wallet::from_seed("outside-retained-state", 0).public_key(),
    )
    .unwrap();
    for (head, epochs) in [(finalized, 129), (pending, 132)] {
        let present = replica
            .state()
            .lookup_at(head.root(), head.operations(), &account_key)
            .await
            .unwrap();
        assert_eq!(
            present
                .resolve::<Sha256>(&head.root(), &account_key)
                .unwrap()
                .unwrap()
                .get(),
            4096 - epochs * 7
        );
        let missing = replica
            .state()
            .lookup_at(head.root(), head.operations(), &absent)
            .await
            .unwrap();
        assert!(
            missing
                .resolve::<Sha256>(&head.root(), &absent)
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn finality_prunes_an_idle_lane_while_another_lane_keeps_the_mailbox_ready() {
    use crate::chain::state::{AdmittedRootsResponse, StatusRecord, admitted_key, status_key};
    use commonware_cryptography::{Hasher as _, Signer as _};
    use commonware_glue::stateful::db::{DatabaseSet as _, Unmerkleized as _};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let ((deployment, expected), crash) =
        deterministic::Runner::default().start_and_recover(|context| async move {
            let mut fixture = Fixture::new(&context, "maintenance", 70).await;
            let mut ballots: Vec<Ballot> = Vec::new();
            for epoch in 0..12 {
                let floors = if epoch >= 4 {
                    let roots = ballots[epoch - 4].roots;
                    Floors {
                        activity: roots.change.operations - 1,
                        payouts: roots.withdrawal_outputs.operations - 1,
                    }
                } else {
                    Floors {
                        activity: 0,
                        payouts: 0,
                    }
                };
                let (ballot, _, prepared) = fixture.prepare(0, 70, floors).await;
                fixture.candidate(ballot.clone(), prepared).await;
                fixture.promote().await;
                ballots.push(ballot);
            }
            let deployment = fixture.lane.deployment.clone();
            let expected = fixture.lane.state.as_ref().unwrap().head();
            drop(fixture);
            let (mut sealer, mailbox) = tests::sealer(&context, "maintenance", &deployment).await;
            let mut other = Deployment::new(
                Sha256::hash(&[b"busy-maintenance-lane"]),
                deployment.operator.clone(),
                deployment.operator_ack,
                deployment.accounts.clone(),
            );
            other.generate(context.child("busy_genesis")).await.unwrap();
            let mut entries = sealer.registry.entries();
            entries.push(crate::chain::native::RegistryEntry {
                deployment: other.clone(),
                network_key: ed25519::PrivateKey::from_seed(89).public_key(),
                max_dealing_bytes: 4 * 1024 * 1024,
            });
            sealer.registry = RegistryView::new(entries);
            let db = sealer.db.clone();
            let operator = ed25519::PrivateKey::from_seed(88).public_key();
            let validator = ed25519::PrivateKey::from_seed(100).public_key();
            let (_, channel) = tests::network(&context, &operator, &validator, true, true).await;
            let actor = sealer.start(channel);
            let count = Arc::new(AtomicUsize::new(0));
            let counted = count.clone();
            let busy = context.child("busy_requests").spawn(move |_| async move {
                loop {
                    mailbox
                        .native(sync::NativeRequest {
                            deployment: *other.digest(),
                            query: sync::Query::Checkpoint { max_next: 0 },
                        })
                        .await
                        .unwrap();
                    counted.fetch_add(1, Ordering::SeqCst);
                }
            });
            context.sleep(Duration::from_millis(5)).await;
            let mut batch = db.new_batches().await;
            for (epoch, ballot) in ballots.iter().enumerate().skip(8) {
                let admitted = AdmittedRootsResponse::new(
                    ballot.header.batch_id::<Sha256>(),
                    ballot.roots,
                    ballot.context.predecessor_logs().activity.operations,
                    epoch == 8,
                );
                batch = batch.write(
                    admitted_key(deployment.digest(), epoch as u64),
                    Some(Record::Admitted(admitted)),
                );
            }
            batch = batch.write(
                status_key(deployment.digest()),
                Some(Record::Status(StatusRecord {
                    height: 300,
                    timestamp: 300,
                    deployment: *deployment.digest(),
                    state_root: ballots[8].roots.successor,
                    last_finalized: Some(8),
                    custody: 0,
                    claimable: 0,
                    hard_faulted: false,
                })),
            );
            db.apply(batch.merkleize().await.unwrap()).await;
            let before = count.load(Ordering::SeqCst);
            context.sleep(Duration::from_millis(250)).await;
            assert!(
                count.load(Ordering::SeqCst) > before,
                "unrelated lane must remain ready throughout maintenance"
            );
            actor.abort();
            busy.abort();
            (deployment, expected)
        });
    deterministic::Runner::from(crash).start(|context| async move {
        let lane = reopen(&context, "maintenance", &deployment).await;
        assert_eq!(lane.state.as_ref().unwrap().head(), expected);
        assert_eq!(lane.manifest().canonical.checkpoint.retained.epoch, 8);
        assert!(
            lane.state
                .as_ref()
                .unwrap()
                .logs()
                .retained_starts()
                .activity
                >= 128
        );
        assert!(
            lane.state
                .as_ref()
                .unwrap()
                .logs()
                .retained_starts()
                .payouts
                >= 128
        );
    });
}
