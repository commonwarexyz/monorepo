//! Deterministic fixtures for the native checkpoint owner.

use super::*;
use crate::{
    chain::tx::{RegisterEpochRequest, SettlementTx},
    protocol::{
        Account, MAX_GENESIS_ACCOUNTS, Protocol, Wallet, clearing_private, committee, deployments,
    },
};
use commonware_clearing::bajillion::{
    boundary::{DepositBatch, SignedWithdrawal, WithdrawalAction, WithdrawalBatch},
    payment::{SendAuthorization, VectorSendBody},
    transition::{PreparedClose, Terminal, prepare_close_with_strategy},
    vector::{OutEntry, OutVector},
};
use commonware_consensus::types::Height;
use commonware_cryptography::Signer as _;
use commonware_glue::stateful::db::{DatabaseSet as _, Unmerkleized as _};
use commonware_p2p::simulated::{Config as NetConfig, Link, Network as SimulatedNetwork};
use commonware_runtime::{Clock as _, Metrics as _, Runner as _, Supervisor as _, deterministic};
use commonware_utils::{NZUsize, probability};
use std::num::NonZeroU64;

pub(crate) async fn init_config<E: StorageContext + Spawner>(
    context: E,
    config: commonware_clearing::bajillion::replica::Config,
    genesis: Vec<(commonware_clearing::bajillion::qmdb::AccountKey, NonZeroU64)>,
) -> Result<NativeReplica<E>> {
    let replica = NativeReplica::open(context, config).await?;
    let (state, logs) = replica.into_parts();
    let prepared = state
        .prepare(
            state.head(),
            genesis
                .into_iter()
                .map(|(key, value)| (key, Some(value)))
                .collect(),
        )
        .await?;
    Ok(Replica::from_parts(state.apply(prepared).await?, logs))
}

pub(super) struct Fixture {
    pub(super) lane: Lane<deterministic::Context>,
    wallets: Vec<Wallet>,
}
impl Fixture {
    pub(super) async fn new(context: &deterministic::Context, prefix: &str, active: usize) -> Self {
        let mut wallets = (0..2 * active + 1)
            .map(|i| Wallet::from_seed("proof-owner", 90_000 + i as u64))
            .collect::<Vec<_>>();
        wallets.sort_unstable_by_key(Wallet::public_key);
        assert!(wallets.len() <= MAX_GENESIS_ACCOUNTS);
        let template = deployments().remove(0);
        let deployment = Deployment::new(
            *template.digest(),
            template.operator,
            template.operator_ack,
            wallets
                .iter()
                .map(|wallet| Account {
                    key: wallet.public_key(),
                    balance: 4096,
                })
                .collect(),
        );
        let state = Box::pin(init_config(
            context.child("fixture"),
            replica_config(
                &format!("{prefix}-replica-{}-0", deployment.digest()),
                context,
                Sequential,
            ),
            genesis_balances(&deployment).unwrap(),
        ))
        .await
        .unwrap();
        let state = Box::pin(state.commit()).await.unwrap();
        let deployment = Deployment::configured(
            *deployment.digest(),
            deployment.operator,
            deployment.operator_ack,
            deployment.accounts,
            state.state().root(),
            state.state().head().operations(),
        )
        .unwrap();
        let checkpoints =
            checkpoint::Store::open(context.child("checkpoint"), prefix, deployment.digest())
                .await
                .unwrap();
        let (state, checkpoints) = recover(state, &deployment, checkpoints).await.unwrap();
        Self {
            lane: Lane {
                deployment,
                fetching: false,
                pending: None,
                state: Some(state),
                checkpoint: Some(checkpoints),
            },
            wallets,
        }
    }
    pub(super) fn active(&self, position: usize) -> &Wallet {
        &self.wallets[2 * position + 1]
    }
    pub(super) async fn prepare(
        &self,
        outgoing: usize,
        withdrawals: usize,
        floors: Floors,
    ) -> (
        Ballot,
        WithdrawalBatch<Key, Digest>,
        PreparedClose<Key, Digest>,
    ) {
        let replica = self.lane.state.as_ref().unwrap();
        let epoch = self.lane.next();
        let protocol = Protocol::new(NZUsize!(1)).unwrap();
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::new(
            (0..withdrawals)
                .map(|position| {
                    SignedWithdrawal::sign(
                        *self.lane.deployment.digest(),
                        replica.state().root().digest,
                        Bytes::from(vec![position as u8; 16]),
                        WithdrawalAction::Amount(NonZeroU64::new(7).unwrap()),
                        100 + epoch * 20,
                        self.active(position).signer(),
                    )
                })
                .collect(),
        )
        .unwrap();
        let context = protocol
            .registration_at(
                epoch,
                deposits.clone(),
                withdrawals.clone(),
                replica.state().liability(),
                11 + epoch * 20,
                12 + epoch * 20,
            )
            .unwrap()
            .context
            .bind::<Sha256, _, _>(replica, &deposits, &withdrawals, floors)
            .unwrap();
        let terminals = if outgoing == 0 {
            Vec::new()
        } else {
            let payer = self.active(0);
            let vector = OutVector::new(
                epoch,
                payer.public_key(),
                (1..=outgoing)
                    .map(|position| OutEntry {
                        recipient: self.active(position).public_key(),
                        cumulative: 1,
                        count: 1,
                    })
                    .collect(),
            )
            .unwrap();
            let body = VectorSendBody::new(
                context.payment(),
                payer.public_key(),
                outgoing as u64,
                outgoing as u64,
                vector.root::<Sha256, Digest>().unwrap(),
            );
            vec![Terminal {
                operator_signature: protocol.sign_ack_aggregate(&body),
                authorization: SendAuthorization::sign(body, payer.signer()),
                vector,
            }]
        };
        let prepared = Box::pin(prepare_close_with_strategy::<Sha256, _, _, _, _>(
            replica,
            &context,
            &deposits,
            &withdrawals,
            terminals,
            &Sequential,
        ))
        .await
        .unwrap();
        let close = prepared.close();
        let scheme =
            bls12381::Scheme::signer(committee().unwrap(), clearing_private(0).unwrap()).unwrap();
        let ballot = Ballot {
            deployment: *self.lane.deployment.digest(),
            epoch,
            proposal: *close.roots.proposal.digest(),
            context,
            header: close.header,
            roots: close.roots,
            withdrawal_total: close.withdrawal_total,
            vote: scheme.sign(&close.header).unwrap(),
        };
        (ballot, withdrawals, prepared)
    }
    pub(super) async fn candidate(&mut self, ballot: Ballot, prepared: PreparedClose<Key, Digest>) {
        persist_candidate(&mut self.lane, prepared.into_parts().1, ballot)
            .await
            .unwrap();
    }
    pub(super) async fn promote(&mut self) {
        let mut manifest = self.lane.manifest().as_ref().clone();
        manifest.canonical = manifest.candidate.take().unwrap();
        manifest.decision = None;
        self.lane.checkpoint = Some(
            self.lane
                .checkpoint
                .take()
                .unwrap()
                .put(manifest)
                .await
                .unwrap(),
        );
    }
}

pub(super) fn metric(context: &deterministic::Context, name: &str) -> u64 {
    let metrics = context.encode();
    metrics
        .lines()
        .find_map(|line| {
            line.strip_prefix(name)
                .filter(|suffix| suffix.starts_with(' '))
                .and_then(|suffix| suffix.trim().parse().ok())
        })
        .unwrap_or_else(|| panic!("missing metric {name}: {metrics}"))
}

#[test]
fn vote_decision_codecs_bind_registration_and_proposal() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = Fixture::new(&context, "decision", 4).await;
        let (ballot, _, _) = fixture
            .prepare(
                1,
                1,
                Floors {
                    activity: 0,
                    payouts: 0,
                },
            )
            .await;
        ballot.check().unwrap();
        assert_eq!(
            Ballot::decode(ballot.encode()).unwrap().encode(),
            ballot.encode()
        );
        let mut wrong = ballot.clone();
        wrong.epoch += 1;
        assert!(wrong.check().is_err());
        wrong = ballot;
        wrong.proposal = Digest::from([0u8; 32]);
        assert!(wrong.check().is_err());
    });
}

struct VoteCase {
    deployment: Deployment,
    initial: Sealer<deterministic::Context>,
    registered: CloseContext<Key, Digest>,
    expected: Header<Digest>,
    dealing: Dealing,
    alternate: Dealing,
}

#[commonware_macros::boxed]
async fn vote_case(context: &deterministic::Context, prefix: &str) -> VoteCase {
    let mut deployment = deployments().remove(0);
    deployment.generate(context.child("genesis")).await.unwrap();
    let protocol = Protocol::new(NZUsize!(1)).unwrap();
    let state = init_config(
        context.child("operator"),
        replica_config(&format!("{prefix}-operator"), context, Sequential),
        genesis_balances(&deployment).unwrap(),
    )
    .await
    .unwrap();
    let deposits = DepositBatch::empty();
    let withdrawals = WithdrawalBatch::empty();
    let deposit_root = deposits.root::<Sha256>().unwrap();
    let liability = state.state().liability();
    let registration = SettlementTx::RegisterEpoch(RegisterEpochRequest {
        deployment: *deployment.digest(),
        epoch: 0,
        predecessor_liability: liability,
        deposits_root: deposit_root,
        withdrawals: withdrawals.clone(),
        openings: Vec::new(),
        fee: 4096,
        signature: protocol.sign_chain_registration(
            0,
            liability,
            &deposit_root,
            &withdrawals,
            4096,
        ),
    });
    let (initial, _) = sealer(context, prefix, &deployment).await;
    let db = initial.db.clone();
    let batch = crate::chain::state::execute(
        db.new_batches().await,
        Height::new(1),
        1,
        &crate::protocol::Timing::DEFAULT,
        &crate::chain::harness::native(vec![deployment.clone()]),
        &[registration],
    )
    .await
    .unwrap();
    db.apply(batch).await;
    let registered = {
        let guard = db.read().await;
        let Some(Record::Machine(bytes)) =
            guard.get(&machine_key(deployment.digest())).await.unwrap()
        else {
            panic!("registered machine");
        };
        Machine::decode(bytes)
            .unwrap()
            .registered()
            .unwrap()
            .context
            .clone()
    };
    let prepared = Box::pin(prepare_close_with_strategy::<Sha256, _, _, _, _>(
        &state,
        &registered,
        &deposits,
        &withdrawals,
        Vec::new(),
        &Sequential,
    ))
    .await
    .unwrap();
    let expected = prepared.close().header;
    let dealing = Dealing {
        deployment: *deployment.digest(),
        epoch: 0,
        context: registered.epoch_context().clone(),
        bytes: prepared.encoded().clone(),
    };
    let wallets = crate::protocol::wallets();
    let vector = OutVector::new(
        0,
        wallets[0].public_key(),
        vec![OutEntry {
            recipient: wallets[1].public_key(),
            cumulative: 1,
            count: 1,
        }],
    )
    .unwrap();
    let body = VectorSendBody::new(
        registered.payment(),
        wallets[0].public_key(),
        1,
        1,
        vector.root::<Sha256, Digest>().unwrap(),
    );
    let alternate = Box::pin(prepare_close_with_strategy::<Sha256, _, _, _, _>(
        &state,
        &registered,
        &deposits,
        &withdrawals,
        vec![Terminal {
            operator_signature: protocol.sign_ack_aggregate(&body),
            authorization: SendAuthorization::sign(body, wallets[0].signer()),
            vector,
        }],
        &Sequential,
    ))
    .await
    .unwrap();
    assert_ne!(alternate.close().header, expected);
    let alternate = Dealing {
        bytes: alternate.encoded().clone(),
        ..dealing.clone()
    };
    VoteCase {
        deployment,
        initial,
        registered,
        expected,
        dealing,
        alternate,
    }
}

#[test]
fn saved_vote_reissues_after_restart_and_admission_promotes_without_apply() {
    use crate::chain::{
        query::{Evidence, EvidenceLookup},
        state::{AdmittedRootsResponse, admitted_key},
    };
    deterministic::Runner::default().start(|context| async move {
        let VoteCase { deployment, initial, registered, expected, dealing, alternate } = vote_case(&context, "saved-vote").await;
        let db = initial.db.clone();
        let wire = Message::Dealing(Box::new(dealing.clone())).encode();
        let operator = ed25519::PrivateKey::from_seed(88).public_key();
        let validator = ed25519::PrivateKey::from_seed(91).public_key();
        let mut decision = None;
        for restart in 0..2 {
            let run = context.child(if restart == 0 { "vote_initial" } else { "vote_restart" });
            let ((mut sender, mut receiver), channel) = network(&run, &operator, &validator, true, true).await;
            let (actor, mailbox) = Sealer::new(run.child("owner"), Config { scheme: initial.scheme.clone(), registry: initial.registry.clone(), db: db.clone(), partition: "saved-vote".into(), validators: Vec::new(), fetch_timeout: Duration::from_secs(1), retain_history: false });
            let handle = actor.start(channel);
            let mut other = dealing.clone();
            other.bytes = if restart == 0 { Bytes::from_static(&[0]) } else { alternate.bytes.clone() };
            assert_ne!(other.id(), dealing.id());
            sender.send(Recipients::One(validator.clone()), Message::Dealing(Box::new(other)).encode(), true);
            select! { vote = receiver.recv() => panic!("another proposal received a vote: {vote:?}"), _ = run.sleep(Duration::from_millis(10)) => {}, }
            sender.send(Recipients::One(validator.clone()), wire.clone(), true);
            let (_, bytes) = select! { message = receiver.recv() => message.unwrap(), _ = run.sleep(Duration::from_secs(1)) => panic!("saved candidate vote was not returned"), };
            let Message::Vote(ballot) = Message::decode(bytes).unwrap() else { panic!("vote"); };
            assert_eq!(ballot.header, expected);
            assert_eq!(ballot.proposal, dealing.id());
            assert_eq!(ballot.context, registered);
            sender.send(Recipients::One(validator.clone()), Message::Dealing(Box::new(alternate.clone())).encode(), true);
            select! { vote = receiver.recv() => panic!("decided epoch signed another valid proposal: {vote:?}"), _ = run.sleep(Duration::from_millis(10)) => {}, }
            if let Some(saved) = &decision { assert_eq!(&ballot.encode(), saved); } else { decision = Some(ballot.encode()); }
            assert!(matches!(mailbox.serve(EvidenceRequest::new(*deployment.digest(), EvidenceLookup::CloseEvidence { epoch: 0, batch_id: expected.batch_id::<Sha256>() })).await.unwrap(), EvidenceResponse::Served(Evidence::Close { header, .. }) if header == expected));
            if restart == 1 {
                assert_eq!(metric(&run, "vote_restart_owner_replica_state_balances_apply_batch_calls_total"), 0);
                let admitted = AdmittedRootsResponse::new(expected.batch_id::<Sha256>(), ballot.roots, registered.predecessor_logs().activity.operations, false);
                let batch = db.new_batches().await.write(admitted_key(deployment.digest(), 0), Some(Record::Admitted(admitted))).merkleize().await.unwrap();
                db.apply(batch).await;
                mailbox.native(sync::NativeRequest { deployment: *deployment.digest(), query: sync::Query::Checkpoint { max_next: 1 } }).await.unwrap();
                assert_eq!(metric(&run, "vote_restart_owner_replica_state_balances_apply_batch_calls_total"), 0);
            }
            handle.abort();
            let _ = handle.await;
        }
        let saved = checkpoint::Store::open(context.child("inspect"), "saved-vote", deployment.digest()).await.unwrap();
        assert_eq!(saved.get().unwrap().canonical.checkpoint.next, 1);
        assert!(saved.get().unwrap().candidate.is_none());
        assert!(saved.get().unwrap().decision.is_none());
    });
}

#[test]
fn discarded_vote_survives_private_pruning_and_crash_before_another_valid_proposal() {
    let ((deployment, alternate, saved, parent), crash) =
        deterministic::Runner::default().start_and_recover(|context| async move {
            let VoteCase { deployment, initial, expected, dealing, alternate, .. } = vote_case(&context, "discarded-vote").await;
            assert!(initial.db.finalize().await.durable().await);
            let operator = ed25519::PrivateKey::from_seed(88).public_key();
            let validator = ed25519::PrivateKey::from_seed(91).public_key();
            let ((mut sender, mut receiver), channel) = network(&context, &operator, &validator, true, true).await;
            let (actor, _mailbox) = Sealer::new(context.child("initial_owner"), Config {
                scheme: initial.scheme.clone(), registry: initial.registry.clone(), db: initial.db.clone(),
                partition: "discarded-vote".into(), validators: Vec::new(), fetch_timeout: Duration::from_secs(1), retain_history: false,
            });
            let handle = actor.start(channel);
            sender.send(Recipients::One(validator), Message::Dealing(Box::new(dealing)).encode(), true);
            let (_, bytes) = select! {
                message = receiver.recv() => message.unwrap(),
                _ = context.sleep(Duration::from_secs(1)) => panic!("initial candidate vote was not returned"),
            };
            let Message::Vote(ballot) = Message::decode(bytes).unwrap() else { panic!("vote"); };
            assert_eq!(ballot.header, expected);
            handle.abort();
            let _ = handle.await;
            let mut lane = durability::reopen(&context, "discarded-vote", &deployment).await;

            // Isolate disposal's signer-memory contract while the registration remains valid.
            // Expiry would independently reject the alternative and hide a lost decision.
            let parent = lane.manifest().canonical.checkpoint.head;
            Box::pin(discard(&mut lane)).await.unwrap();
            assert_eq!(lane.state.as_ref().unwrap().head(), parent);
            assert!(lane.manifest().candidate.is_none());
            let mut control = lane.checkpoint.take().unwrap();
            for generation in 1..33 {
                control = control.stage(generation).await.unwrap();
                control = control.retired().await.unwrap();
            }
            assert_eq!(control.get().unwrap().decision.as_ref().unwrap().encode(), ballot.encode());
            (deployment, alternate, ballot.encode(), parent)
        });
    deterministic::Runner::from(crash).start(|context| async move {
        let (initial, _) = sealer(&context, "discarded-vote", &deployment).await;
        let lane = durability::reopen(&context, "discarded-vote", &deployment).await;
        assert_eq!(lane.state.as_ref().unwrap().head(), parent);
        assert!(lane.manifest().candidate.is_none());
        assert_eq!(lane.manifest().decision.as_ref().unwrap().encode(), saved);
        let (machine, height) = {
            let db = initial.db.read().await;
            let Some(Record::Machine(bytes)) = db.get(&machine_key(deployment.digest())).await.unwrap() else { panic!("registered machine"); };
            let Some(Record::Status(status)) = db.get(&status_key(deployment.digest())).await.unwrap() else { panic!("status"); };
            assert!(!status.hard_faulted);
            (Machine::decode(bytes).unwrap(), status.height)
        };
        let registered = machine.registered().unwrap();
        assert!(height <= registered.context.admission_deadline());
        assert_eq!(registered.context.epoch_context(), &alternate.context);
        let mut validation_context = context.child("alternate_validation");
        let (_, prepared) = seal::<Sha256, _, _, _, _, PaymentBatchVerifier, _>(
            &initial.scheme, lane.state.as_ref().unwrap(), registered.context,
            &deployment.operator_ack, registered.deposits, registered.withdrawals,
            alternate.bytes.clone(), &mut validation_context, &Sequential,
        ).await.unwrap();
        assert_ne!(prepared.close().header, lane.manifest().decision.as_ref().unwrap().header);
        drop(prepared);
        drop(lane);
        let operator = ed25519::PrivateKey::from_seed(88).public_key();
        let validator = ed25519::PrivateKey::from_seed(91).public_key();
        let ((mut sender, mut receiver), channel) = network(&context, &operator, &validator, true, true).await;
        let (actor, mailbox) = Sealer::new(context.child("restarted_owner"), Config {
            scheme: initial.scheme.clone(), registry: initial.registry.clone(), db: initial.db.clone(),
            partition: "discarded-vote".into(), validators: Vec::new(), fetch_timeout: Duration::from_secs(1), retain_history: false,
        });
        let handle = actor.start(channel);
        mailbox.native(sync::NativeRequest { deployment: *deployment.digest(), query: sync::Query::Checkpoint { max_next: 0 } }).await.unwrap();
        sender.send(Recipients::One(validator), Message::Dealing(Box::new(alternate)).encode(), true);
        select! {
            message = receiver.recv() => panic!("discarded epoch signed a different valid proposal: {message:?}"),
            _ = context.sleep(Duration::from_millis(20)) => {},
        }
        assert_eq!(metric(&context, "restarted_owner_replica_state_balances_apply_batch_calls_total"), 0);
        handle.abort();
        let _ = handle.await;
        let control = checkpoint::Store::open(context.child("inspect"), "discarded-vote", deployment.digest()).await.unwrap();
        assert_eq!(control.get().unwrap().decision.as_ref().unwrap().encode(), saved);
        assert!(control.get().unwrap().candidate.is_none());
    });
}

/// One two-peer simulated network: the operator's DA channel endpoints
/// and the validator's, with links per `to_validator`/`to_operator`.
pub(crate) async fn network(
    context: &deterministic::Context,
    operator: &ed25519::PublicKey,
    validator: &ed25519::PublicKey,
    to_validator: bool,
    to_operator: bool,
) -> (
    (
        impl Sender<PublicKey = ed25519::PublicKey>,
        impl Receiver<PublicKey = ed25519::PublicKey>,
    ),
    (
        impl Sender<PublicKey = ed25519::PublicKey>,
        impl Receiver<PublicKey = ed25519::PublicKey>,
    ),
) {
    let (net, oracle) = SimulatedNetwork::new_with_peers(
        context.child("network"),
        NetConfig {
            max_size: 4 * 1024 * 1024,
            max_peers_per_set: NZUsize!(2),
            disconnect_on_block: true,
            tracked_peer_sets: NZUsize!(1),
        },
        [operator.clone(), validator.clone()],
    )
    .await;
    net.start();
    let quota = commonware_runtime::Quota::per_second(commonware_utils::NZU32!(128));
    let operator_chan = oracle
        .control(operator.clone())
        .register(0, quota)
        .await
        .unwrap();
    let validator_chan = oracle
        .control(validator.clone())
        .register(0, quota)
        .await
        .unwrap();
    let link = Link {
        latency: Duration::from_millis(1),
        jitter: Duration::from_millis(0),
        success_rate: probability!(1.0),
    };
    if to_validator {
        oracle
            .add_link(operator.clone(), validator.clone(), link.clone())
            .await
            .unwrap();
    }
    if to_operator {
        oracle
            .add_link(validator.clone(), operator.clone(), link)
            .await
            .unwrap();
    }
    (operator_chan, validator_chan)
}

pub(super) async fn sealer(
    context: &deterministic::Context,
    prefix: &str,
    deployment: &Deployment,
) -> (Sealer<deterministic::Context>, Mailbox) {
    use crate::chain::{
        native::RegistryEntry,
        validator::{PAGE_CACHE_SIZE, PAGE_SIZE, db_config},
    };
    use commonware_glue::stateful::db::DatabaseSet;
    use commonware_runtime::buffer::paged::CacheRef;
    let db = <Database<deterministic::Context> as DatabaseSet<_>>::init(
        context.child("settlement"),
        db_config(
            &format!("{prefix}-settlement"),
            CacheRef::from_pooler(context, PAGE_SIZE, PAGE_CACHE_SIZE),
        ),
    )
    .await;
    Sealer::new(
        context.child("sealer"),
        Config {
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
}
