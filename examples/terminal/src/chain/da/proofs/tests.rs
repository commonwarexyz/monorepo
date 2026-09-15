//! Focused tests for the durable, individually addressable proof archive.

use super::*;
use crate::{
    chain::{
        da::{self, Config, Lane, Mailbox, Sealer},
        native::RegistryEntry,
        query::EvidenceRequest,
        registry::RegistryView,
        tx::{AdmitRequest, RegisterEpochRequest, SettlementTx},
        types::Database,
        validator::db_config,
    },
    protocol::{
        Account, Deployment, MAX_GENESIS_ACCOUNTS, Protocol, Timing, Wallet, clearing_private,
        committee, deployments, genesis_balances, state_config,
    },
};
use bytes::Bytes;
use commonware_clearing::bajillion::{
    admission::bls12381,
    boundary::{DepositBatch, WithdrawalAction, WithdrawalBatch},
    payment::{SendAuthorization, VectorSendBody},
    qmdb::State,
    transition::{PreparedClose, Terminal, prepare_close_with_strategy},
    vector::OutVector,
};
use commonware_codec::DecodeExt as _;
use commonware_consensus::types::Height;
use commonware_cryptography::{Signer as _, ed25519};
use commonware_glue::stateful::db::DatabaseSet;
use commonware_macros::select;
use commonware_runtime::{
    Metrics as _, Runner as _, Supervisor as _,
    deterministic::{self, FaultConfig, PartialWriteMode, WriteConfig},
    mocks::{DelayedSyncContext, PendingSyncs, drive_pending_syncs, next_pending_sync},
};
use commonware_utils::{NZUsize, probability};
use std::{num::NonZeroU64, time::Duration};

const FUNDING: u64 = 4096;

struct Fixture {
    deployment: Deployment,
    wallets: Vec<Wallet>,
    state: State<deterministic::Context, Sha256>,
}

impl Fixture {
    async fn new(context: &deterministic::Context, prefix: &str, active: usize) -> Self {
        // Unused even positions provide deterministic gaps before, between, and after all leaves.
        let mut wallets = (0..2 * active + 1)
            .map(|i| Wallet::from_seed("proof-owner", 90_000 + i as u64))
            .collect::<Vec<_>>();
        assert!(wallets.len() <= MAX_GENESIS_ACCOUNTS);
        wallets.sort_unstable_by_key(Wallet::public_key);
        let template = deployments().remove(0);
        let accounts = wallets
            .iter()
            .map(|wallet| Account {
                key: wallet.public_key(),
                balance: FUNDING,
            })
            .collect();
        let deployment = Deployment::new(
            *template.digest(),
            template.operator,
            template.operator_ack,
            accounts,
        );
        let state = State::<_, Sha256>::init(
            context.child("fixture"),
            state_config(
                &format!("{prefix}-balances-{}", deployment.digest()),
                context,
                Sequential,
            ),
            genesis_balances(&deployment).unwrap(),
        )
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
        let deployment = Deployment::configured(
            *deployment.digest(),
            deployment.operator,
            deployment.operator_ack,
            deployment.accounts,
            state.root(),
            state.head().operations(),
        )
        .unwrap();
        Self {
            deployment,
            wallets,
            state,
        }
    }

    fn active(&self, position: usize) -> &Wallet {
        &self.wallets[2 * position + 1]
    }

    async fn prepare(
        &self,
        epoch: u64,
        outgoing: usize,
        withdrawals: usize,
    ) -> (Sealed, PreparedClose<Key, Digest>) {
        let protocol = Protocol::new(NZUsize!(1)).unwrap();
        let deposits = DepositBatch::empty();
        let requests = (0..withdrawals)
            .map(|position| {
                let owner = if outgoing > 0 && position == 2 {
                    outgoing + 1
                } else {
                    position
                };
                let amount = if outgoing > 0 && position == 0 {
                    FUNDING
                } else {
                    7
                };
                SignedWithdrawal::sign(
                    *self.deployment.digest(),
                    self.state.root().digest,
                    Bytes::from(vec![position as u8; MAX_DESTINATION_BYTES]),
                    WithdrawalAction::Amount(NonZeroU64::new(amount).unwrap()),
                    100,
                    self.active(owner).signer(),
                )
            })
            .collect();
        let withdrawals = WithdrawalBatch::new(requests).unwrap();
        let context = protocol
            .registration_at(
                epoch,
                deposits.clone(),
                withdrawals.clone(),
                self.state.liability(),
                11 + epoch * 20,
                12 + epoch * 20,
            )
            .unwrap()
            .context
            .bind::<Sha256, _, _>(&self.state, &deposits, &withdrawals)
            .unwrap();
        let terminals = if outgoing == 0 {
            Vec::new()
        } else {
            let payer = self.active(0);
            let entries = (1..=outgoing)
                .map(|position| OutEntry {
                    recipient: self.active(position).public_key(),
                    cumulative: 1,
                    count: 1,
                })
                .collect();
            let vector = OutVector::new(epoch, payer.public_key(), entries).unwrap();
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
        let prepared = prepare_close_with_strategy::<Sha256, _, _, _, _>(
            &self.state,
            &context,
            &deposits,
            &withdrawals,
            terminals,
            &Sequential,
        )
        .await
        .unwrap();
        let sealed = Sealer::<deterministic::Context>::record(
            context,
            deposits,
            withdrawals,
            prepared.encoded().clone(),
            &prepared,
        );
        (sealed, prepared)
    }

    async fn advance(self, prepared: PreparedClose<Key, Digest>) -> Self {
        Self {
            state: self
                .state
                .apply(prepared.into_parts().1)
                .await
                .unwrap()
                .commit()
                .await
                .unwrap(),
            ..self
        }
    }

    fn lookups(&self, sealed: &Sealed) -> Vec<EvidenceLookup> {
        let batch = sealed.header.batch_id::<Sha256>().into_digest();
        let mut lookups = Vec::new();
        for wallet in &self.wallets {
            let account = wallet.public_key();
            lookups.extend([
                EvidenceLookup::Account {
                    batch,
                    account: account.clone(),
                },
                EvidenceLookup::Change {
                    batch,
                    account: account.clone(),
                },
                EvidenceLookup::WithdrawalOutput {
                    batch,
                    account: account.clone(),
                },
                EvidenceLookup::CommittedEntry {
                    batch,
                    payer: self.active(0).public_key(),
                    recipient: account.clone(),
                },
                EvidenceLookup::CommittedEntry {
                    batch,
                    payer: self.wallets[0].public_key(),
                    recipient: account,
                },
            ]);
        }
        lookups
    }
}

fn metric(context: &deterministic::Context, name: &str) -> u64 {
    context
        .encode()
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next()? == name).then(|| fields.next().unwrap().parse().unwrap())
        })
        .unwrap_or_else(|| panic!("missing metric {name}"))
}

fn crash_config() -> deterministic::Config {
    deterministic::Config::default()
        .with_timeout(Some(Duration::from_secs(30)))
        .with_storage_fault_config(FaultConfig::default().write(WriteConfig {
            failure_rate: probability!(0.0),
            retention_rate: probability!(1.0),
            mode: PartialWriteMode::Prefix,
        }))
}

async fn records<E: StorageContext>(store: &Store<E>) -> Vec<Bytes> {
    let Some(last) = store.archive.last_index() else {
        return Vec::new();
    };
    let mut records = Vec::new();
    for index in 0..=last {
        records.push(
            store
                .archive
                .get(Identifier::Index(index))
                .await
                .unwrap()
                .expect("proof exports occupy one contiguous ordinal prefix")
                .encode(),
        );
    }
    records
}

fn expected(
    sealed: &Sealed,
    close: &Close<Key, Digest>,
    lookups: Vec<EvidenceLookup>,
) -> Vec<(EvidenceLookup, Bytes)> {
    lookups
        .into_iter()
        .map(|lookup| {
            let body = da::answer(&sealed.context, &sealed.withdrawals, close, &lookup).unwrap();
            (lookup, body.encode())
        })
        .collect()
}

async fn check_answers<E: StorageContext>(
    store: &Store<E>,
    sealed: &Sealed,
    answers: &[(EvidenceLookup, Bytes)],
) {
    let descriptor = store
        .descriptor(&sealed.header.batch_id::<Sha256>().into_digest())
        .await
        .unwrap()
        .unwrap();
    store.check(sealed).await.unwrap();
    for (lookup, bytes) in answers {
        assert_eq!(
            store.answer(&descriptor, lookup).await.unwrap().encode(),
            *bytes,
            "{lookup:?}"
        );
    }
}

async fn check_served(
    context: &deterministic::Context,
    sealer: &Sealer<deterministic::Context>,
    lanes: &[Lane<deterministic::Context>],
    deployment: &Deployment,
    answers: &[(EvidenceLookup, Bytes)],
) {
    let canonical_gets = metric(context, "sealer_archive_gets_total");
    let vote_gets = metric(context, "sealer_votes_gets_total");
    for (lookup, bytes) in answers {
        assert_eq!(
            sealer
                .serve(
                    lanes,
                    EvidenceRequest::new(*deployment.digest(), lookup.clone())
                )
                .await
                .unwrap()
                .encode(),
            *bytes,
            "{lookup:?}"
        );
    }
    assert_eq!(metric(context, "sealer_archive_gets_total"), canonical_gets);
    assert_eq!(metric(context, "sealer_votes_gets_total"), vote_gets);
}

async fn open_lane(
    context: &deterministic::Context,
    prefix: &str,
    deployment: &Deployment,
) -> (
    Sealer<deterministic::Context>,
    Mailbox,
    Vec<Lane<deterministic::Context>>,
) {
    let cache = CacheRef::from_pooler(context, PAGE_SIZE, PAGE_CACHE_SIZE);
    let db = <Database<deterministic::Context> as DatabaseSet<_>>::init(
        context.child("settlement"),
        db_config(&format!("{prefix}-settlement"), cache),
    )
    .await;
    let (sealer, mailbox) = Sealer::new(
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
        },
    );
    let mut lanes = Vec::new();
    assert_eq!(sealer.lane(&mut lanes, deployment).await.unwrap(), 0);
    (sealer, mailbox, lanes)
}

#[test]
fn indexed_answers_match_complete_close_across_vector_shapes() {
    for (outgoing, withdrawals) in [(0, 0), (0, 1), (0, 3), (1, 3), (3, 3), (5, 3)] {
        let ((deployment, sealed, answers, count), checkpoint) = deterministic::Runner::default()
            .start_and_recover(|context| async move {
                let fixture =
                    Fixture::new(&context, "parity", (outgoing + 2).max(withdrawals)).await;
                let (sealed, prepared) = fixture.prepare(0, outgoing, withdrawals).await;
                let outputs = prepared.close().withdrawal_evidence().0;
                assert_eq!(outputs.len(), withdrawals);
                if outgoing > 0 {
                    assert!(outputs.iter().any(|output| output.amount() == 0));
                    assert!(outputs.iter().any(|output| output.amount() > 0));
                }
                let answers = expected(&sealed, prepared.close(), fixture.lookups(&sealed));
                let store = Store::open(
                    context.child("proofs"),
                    "parity",
                    *fixture.deployment.digest(),
                )
                .await
                .unwrap()
                .retain(&sealed, prepared.close())
                .await
                .unwrap();
                let count = records(&store).await.len();
                check_answers(&store, &sealed, &answers).await;
                (fixture.deployment, sealed, answers, count)
            });
        deterministic::Runner::from(checkpoint).start(|context| async move {
            let store = Store::open(context.child("proofs"), "parity", *deployment.digest())
                .await
                .unwrap();
            assert_eq!(records(&store).await.len(), count);
            check_answers(&store, &sealed, &answers).await;
        });
    }
}

#[test]
fn cancelled_export_rolls_back_ordinals_and_retry_is_idempotent() {
    for committed_prefix in [false, true] {
        let ((deployment, sealed, close, prefix_bytes, answers), checkpoint) =
            deterministic::Runner::new(crash_config()).start_and_recover(|context| async move {
                let mut fixture = Fixture::new(&context, "cancel", 10).await;
                let mut proofs = Store::open(context.child("proofs"), "cancel", *fixture.deployment.digest())
                    .await.unwrap();
                let mut canonical = da::store(context.child("canonical"), "cancel-canonical", fixture.deployment.digest()).await;
                if committed_prefix {
                    let (sealed, prepared) = fixture.prepare(0, 3, 0).await;
                    proofs = proofs.retain(&sealed, prepared.close()).await.unwrap();
                    canonical = canonical.put_sync(0, sealed.header.batch_id::<Sha256>().into_digest(), &sealed)
                        .await.unwrap();
                    fixture = fixture.advance(prepared).await;
                }
                let prefix_bytes = records(&proofs).await;
                drop(proofs);
                let (sealed, prepared) = fixture.prepare(u64::from(committed_prefix), 7, 0).await;
                let answers = expected(&sealed, prepared.close(), fixture.lookups(&sealed));
                let pending = PendingSyncs::default();
                let proofs = drive_pending_syncs(&pending, Store::open(
                    DelayedSyncContext { inner: context.child("partial"), pending: pending.clone() },
                    "cancel", *fixture.deployment.digest(),
                )).await.unwrap();
                let writes = metric(&context, "runtime_storage_write_bytes_total");
                pending.arm();
                let gate = next_pending_sync(&pending);
                let mut export = Box::pin(proofs.retain(&sealed, prepared.close()));
                select! {
                    result = &mut export => panic!("export completed before the durability gate: {:?}", result.err()),
                    blocked = gate.blocked => blocked.unwrap(),
                }
                assert!(pending.calls() > 0);
                assert!(metric(&context, "runtime_storage_write_bytes_total") > writes);
                assert_eq!(metric(&context, "partial_syncs_total"), 1);
                assert!(metric(&context, "partial_freezer_puts_total") > 0);
                drop(export);
                drop(gate.release);
                drop(canonical);
                (fixture.deployment, sealed, prepared.into_parts().0, prefix_bytes, answers)
            });
        let ((deployment, sealed, answers, final_bytes), checkpoint) =
            deterministic::Runner::from(checkpoint).start_and_recover(|context| async move {
                let (sealer, _mailbox, mut lanes) =
                    open_lane(&context, "cancel", &deployment).await;
                let lane = &mut lanes[0];
                let mut proofs = lane.proofs.take().unwrap();
                assert_eq!(records(&proofs).await, prefix_bytes);
                let batch = sealed.header.batch_id::<Sha256>().into_digest();
                assert!(proofs.descriptor(&batch).await.unwrap().is_none());
                assert!(
                    !lane
                        .store
                        .as_ref()
                        .unwrap()
                        .has(Identifier::Key(&batch))
                        .await
                        .unwrap()
                );
                assert_eq!(
                    lane.state.as_ref().unwrap().root(),
                    *sealed.context.predecessor_root()
                );
                assert_eq!(
                    lane.state.as_ref().unwrap().head().operations(),
                    sealed.predecessor_operations
                );
                proofs = proofs.retain(&sealed, &close).await.unwrap();
                let final_bytes = records(&proofs).await;
                assert!(final_bytes.len() > prefix_bytes.len());
                assert_eq!(&final_bytes[..prefix_bytes.len()], prefix_bytes.as_slice());
                let puts = metric(&context, "sealer_proofs_freezer_puts_total");
                let syncs = metric(&context, "sealer_proofs_syncs_total");
                let last = proofs.archive.last_index();
                proofs = proofs.retain(&sealed, &close).await.unwrap();
                assert_eq!(proofs.archive.last_index(), last);
                assert_eq!(metric(&context, "sealer_proofs_freezer_puts_total"), puts);
                assert_eq!(metric(&context, "sealer_proofs_syncs_total"), syncs);
                assert_eq!(records(&proofs).await, final_bytes);
                check_answers(&proofs, &sealed, &answers).await;
                let canonical = lane
                    .store
                    .take()
                    .unwrap()
                    .put_sync(sealed.context.payment().epoch(), batch, &sealed)
                    .await
                    .unwrap();
                let state = lane.state.take().unwrap();
                let (state, next) = da::recover(state, &deployment, &canonical, &proofs)
                    .await
                    .unwrap();
                assert_eq!(next, sealed.context.payment().epoch() + 1);
                assert_eq!(state.root(), sealed.roots.successor);
                assert_eq!(state.head().operations(), sealed.operations);
                drop((state, canonical, proofs, lanes, sealer));
                (deployment, sealed, answers, final_bytes)
            });
        deterministic::Runner::from(checkpoint).start(|context| async move {
            let (sealer, _mailbox, lanes) = open_lane(&context, "cancel", &deployment).await;
            assert_eq!(
                records(lanes[0].proofs.as_ref().unwrap()).await,
                final_bytes
            );
            assert_eq!(
                lanes[0].state.as_ref().unwrap().root(),
                sealed.roots.successor
            );
            assert_eq!(
                lanes[0].state.as_ref().unwrap().head().operations(),
                sealed.operations
            );
            assert_eq!(
                metric(&context, "sealer_balances_balances_apply_batch_calls_total"),
                0
            );
            check_served(&context, &sealer, &lanes, &deployment, &answers).await;
        });
    }
}

#[test]
fn synced_index_requires_canonical_authority_after_each_restart() {
    let ((deployment, sealed, close, answers, indexed), checkpoint) =
        deterministic::Runner::default().start_and_recover(|context| async move {
            let fixture = Fixture::new(&context, "gate", 6).await;
            let (sealed, prepared) = fixture.prepare(0, 3, 3).await;
            let answers = expected(&sealed, prepared.close(), fixture.lookups(&sealed));
            let proofs = Store::open(
                context.child("proofs"),
                "gate",
                *fixture.deployment.digest(),
            )
            .await
            .unwrap()
            .retain(&sealed, prepared.close())
            .await
            .unwrap();
            let indexed = records(&proofs).await;
            (
                fixture.deployment,
                sealed,
                prepared.into_parts().0,
                answers,
                indexed,
            )
        });
    let ((deployment, sealed, close, answers, indexed), checkpoint) =
        deterministic::Runner::from(checkpoint).start_and_recover(|context| async move {
            let (sealer, _mailbox, lanes) = open_lane(&context, "gate", &deployment).await;
            assert_eq!(records(lanes[0].proofs.as_ref().unwrap()).await, indexed);
            let batch = sealed.header.batch_id::<Sha256>().into_digest();
            assert!(
                lanes[0]
                    .proofs
                    .as_ref()
                    .unwrap()
                    .descriptor(&batch)
                    .await
                    .unwrap()
                    .is_some()
            );
            let mut lookups = answers
                .iter()
                .map(|(lookup, _)| lookup.clone())
                .collect::<Vec<_>>();
            lookups.extend([
                EvidenceLookup::PredecessorState {
                    batch,
                    account: deployment.accounts[0].key.clone(),
                },
                EvidenceLookup::SuccessorState {
                    batch,
                    account: deployment.accounts[0].key.clone(),
                },
            ]);
            let reads = metric(&context, "sealer_proofs_gets_total");
            for lookup in lookups {
                assert_eq!(
                    sealer
                        .serve(&lanes, EvidenceRequest::new(*deployment.digest(), lookup))
                        .await
                        .unwrap(),
                    EvidenceResponse::Unsealed
                );
            }
            assert_eq!(metric(&context, "sealer_proofs_gets_total"), reads);
            (deployment, sealed, close, answers, indexed)
        });
    let ((deployment, answers, indexed), checkpoint) = deterministic::Runner::from(checkpoint)
        .start_and_recover(|context| async move {
            let (sealer, _mailbox, mut lanes) = open_lane(&context, "gate", &deployment).await;
            let request = EvidenceRequest::new(*deployment.digest(), answers[0].0.clone());
            assert_eq!(
                sealer.serve(&lanes, request.clone()).await.unwrap(),
                EvidenceResponse::Unsealed
            );
            let lane = &mut lanes[0];
            let proofs = lane
                .proofs
                .take()
                .unwrap()
                .retain(&sealed, &close)
                .await
                .unwrap();
            assert_eq!(metric(&context, "sealer_proofs_freezer_puts_total"), 0);
            assert_eq!(metric(&context, "sealer_proofs_syncs_total"), 0);
            assert_eq!(records(&proofs).await, indexed);
            let canonical = lane
                .store
                .take()
                .unwrap()
                .put_sync(0, sealed.header.batch_id::<Sha256>().into_digest(), &sealed)
                .await
                .unwrap();
            let (state, next) =
                da::recover(lane.state.take().unwrap(), &deployment, &canonical, &proofs)
                    .await
                    .unwrap();
            assert_eq!(next, 1);
            lane.store = Some(canonical);
            lane.state = Some(state);
            lane.proofs = Some(proofs);
            lane.next = next;
            check_served(&context, &sealer, &lanes, &deployment, &answers).await;
            (deployment, answers, indexed)
        });
    deterministic::Runner::from(checkpoint).start(|context| async move {
        let (sealer, _mailbox, lanes) = open_lane(&context, "gate", &deployment).await;
        assert_eq!(records(lanes[0].proofs.as_ref().unwrap()).await, indexed);
        assert_eq!(
            metric(&context, "sealer_balances_balances_apply_batch_calls_total"),
            0
        );
        check_served(&context, &sealer, &lanes, &deployment, &answers).await;
    });
}

#[test]
fn reconcile_cannot_publish_canonical_when_proof_export_fails() {
    let ((deployment, sealed, answers), checkpoint) = deterministic::Runner::new(crash_config())
        .start_and_recover(|context| async move {
            let fixture = Fixture::new(&context, "barrier", 6).await;
            let (sealed, prepared) = fixture.prepare(0, 3, 0).await;
            let answers = expected(&sealed, prepared.close(), fixture.lookups(&sealed));
            let Fixture {
                deployment, state, ..
            } = fixture;
            drop(state);
            let (mut sealer, _mailbox, mut lanes) =
                open_lane(&context, "barrier", &deployment).await;
            let protocol = Protocol::new(NZUsize!(1)).unwrap();
            let deposits_root = sealed.deposits.root::<Sha256>().unwrap();
            let liability = sealed.context.predecessor_liability();
            let certificate = sealer
                .scheme
                .assemble_exact((1..=sealer.scheme.committee().quorum()).map(|index| {
                    bls12381::Scheme::signer(committee().unwrap(), clearing_private(index).unwrap())
                        .unwrap()
                        .sign(&sealed.header)
                        .unwrap()
                }))
                .unwrap();
            let update = crate::chain::state::execute(
                sealer.db.new_batches().await,
                Height::new(1),
                1,
                &Timing::DEFAULT,
                &crate::chain::harness::native(vec![deployment.clone()]),
                &[
                    SettlementTx::RegisterEpoch(RegisterEpochRequest {
                        deployment: *deployment.digest(),
                        epoch: 0,
                        predecessor_liability: liability,
                        deposits_root,
                        withdrawals: sealed.withdrawals.clone(),
                        openings: Vec::new(),
                        fee: 4096,
                        signature: protocol.sign_chain_registration(
                            0,
                            liability,
                            &deposits_root,
                            &sealed.withdrawals,
                            4096,
                        ),
                    }),
                    SettlementTx::Admit(AdmitRequest {
                        deployment: *deployment.digest(),
                        epoch: 0,
                        header: sealed.header,
                        roots: sealed.roots,
                        withdrawal_total: sealed.withdrawal_total,
                        certificate,
                    }),
                ],
            )
            .await
            .unwrap();
            sealer.db.apply(update).await;
            assert!(sealer.db.finalize().await.durable().await);
            lanes[0].votes = Some(
                lanes[0]
                    .votes
                    .take()
                    .unwrap()
                    .put_sync(0, sealed.header.batch_id::<Sha256>().into_digest(), &sealed)
                    .await
                    .unwrap(),
            );

            // Only sync operations fail. A consumed proof archive identifies the export as the
            // failing operation; that owner is discarded without observing or reusing its contents.
            context.storage_fault_config().write().sync_rate = Some(probability!(1.0));
            assert!(sealer.reconcile(&mut lanes, 0, None).await.is_err());
            assert!(
                lanes[0].proofs.is_none(),
                "the injected failure must occur inside proof export"
            );
            drop((lanes, sealer));
            context.storage_fault_config().write().sync_rate = None;
            (deployment, sealed, answers)
        });
    let ((deployment, sealed, answers, indexed), checkpoint) =
        deterministic::Runner::from(checkpoint).start_and_recover(|context| async move {
            let (mut sealer, _mailbox, mut lanes) =
                open_lane(&context, "barrier", &deployment).await;
            let batch = sealed.header.batch_id::<Sha256>().into_digest();
            {
                let db = sealer.db.read().await;
                let Some(crate::chain::state::Record::Admitted(admitted)) = db
                    .get(&crate::chain::state::admitted_key(deployment.digest(), 0))
                    .await
                    .unwrap()
                else {
                    panic!("the admitted close must survive the proof-export crash");
                };
                assert_eq!(admitted.batch_id, sealed.header.batch_id::<Sha256>());
                assert_eq!(admitted.roots, sealed.roots);
            }
            assert!(records(lanes[0].proofs.as_ref().unwrap()).await.is_empty());
            assert!(lanes[0].store.as_ref().unwrap().last_index().is_none());
            assert!(
                lanes[0]
                    .votes
                    .as_ref()
                    .unwrap()
                    .has(Identifier::Key(&batch))
                    .await
                    .unwrap()
            );
            assert_eq!(
                lanes[0].state.as_ref().unwrap().root(),
                *sealed.context.predecessor_root()
            );
            assert_eq!(
                lanes[0].state.as_ref().unwrap().head().operations(),
                sealed.predecessor_operations
            );
            assert_eq!(
                sealer
                    .serve(
                        &lanes,
                        EvidenceRequest::new(*deployment.digest(), answers[0].0.clone())
                    )
                    .await
                    .unwrap(),
                EvidenceResponse::Unsealed
            );
            assert!(
                sealer
                    .reconcile(&mut lanes, 0, None)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert_eq!(lanes[0].next, 1);
            assert_eq!(
                lanes[0].state.as_ref().unwrap().root(),
                sealed.roots.successor
            );
            assert_eq!(
                lanes[0].state.as_ref().unwrap().head().operations(),
                sealed.operations
            );
            let indexed = records(lanes[0].proofs.as_ref().unwrap()).await;
            assert!(!indexed.is_empty());
            check_served(&context, &sealer, &lanes, &deployment, &answers).await;
            (deployment, sealed, answers, indexed)
        });
    deterministic::Runner::from(checkpoint).start(|context| async move {
        let (sealer, _mailbox, lanes) = open_lane(&context, "barrier", &deployment).await;
        assert_eq!(lanes[0].next, 1);
        assert_eq!(
            lanes[0].state.as_ref().unwrap().root(),
            sealed.roots.successor
        );
        assert_eq!(records(lanes[0].proofs.as_ref().unwrap()).await, indexed);
        assert_eq!(
            metric(&context, "sealer_balances_balances_apply_batch_calls_total"),
            0
        );
        check_served(&context, &sealer, &lanes, &deployment, &answers).await;
    });
}

fn height(len: usize) -> u64 {
    if len < 2 {
        0
    } else {
        u64::from(usize::BITS - (len - 1).leading_zeros())
    }
}

#[test]
fn historical_serving_reads_only_logarithmic_individual_records() {
    for outgoing in [31, 509] {
        let ((deployment, answers, limits), checkpoint) = deterministic::Runner::default()
            .start_and_recover(|context| async move {
                let fixture = Fixture::new(&context, "reads", outgoing + 2).await;
                let (sealed, prepared) = fixture.prepare(0, outgoing, 3).await;
                let count = prepared.close().change_evidence().0.len();
                assert_eq!(count, outgoing + 2);
                let batch = sealed.header.batch_id::<Sha256>().into_digest();
                let mut lookups = Vec::new();
                let mut limits = Vec::new();
                for index in [
                    0,
                    1,
                    2,
                    3,
                    2 * outgoing,
                    2 * outgoing + 1,
                    2 * outgoing + 3,
                    2 * outgoing + 4,
                ] {
                    let account = fixture.wallets[index].public_key();
                    lookups.push(EvidenceLookup::Account {
                        batch,
                        account: account.clone(),
                    });
                    limits.push(4 + 3 * height(count + 1));
                    lookups.push(EvidenceLookup::CommittedEntry {
                        batch,
                        payer: fixture.active(0).public_key(),
                        recipient: account.clone(),
                    });
                    limits.push(7 + 3 * height(count + 1) + 3 * height(outgoing + 1));
                    lookups.push(EvidenceLookup::WithdrawalOutput { batch, account });
                    limits.push(2 + 3 * height(4));
                }
                let answers = expected(&sealed, prepared.close(), lookups);
                let proofs = Store::open(
                    context.child("proofs"),
                    "reads",
                    *fixture.deployment.digest(),
                )
                .await
                .unwrap()
                .retain(&sealed, prepared.close())
                .await
                .unwrap();
                let values = records(&proofs).await;
                assert!(
                    values
                        .iter()
                        .all(|value| value.len() <= PAGE_SIZE.get() as usize)
                );
                let canonical = da::store(
                    context.child("canonical"),
                    "reads-canonical",
                    fixture.deployment.digest(),
                )
                .await
                .put_sync(0, batch, &sealed)
                .await
                .unwrap();
                let fixture = fixture.advance(prepared).await;
                drop((canonical, proofs));
                (fixture.deployment, answers, limits)
            });
        deterministic::Runner::from(checkpoint).start(|context| async move {
            let (sealer, _mailbox, lanes) = open_lane(&context, "reads", &deployment).await;
            assert_eq!(
                metric(&context, "sealer_balances_balances_apply_batch_calls_total"),
                0
            );
            let full_reads = metric(&context, "sealer_archive_gets_total");
            let vote_reads = metric(&context, "sealer_votes_gets_total");
            assert!(
                full_reads > 0,
                "recovery must have read and validated its canonical anchor"
            );
            for ((lookup, bytes), limit) in answers.into_iter().zip(limits) {
                let gets = metric(&context, "sealer_proofs_gets_total");
                let read_bytes = metric(&context, "runtime_storage_read_bytes_total");
                let response = sealer
                    .serve(
                        &lanes,
                        EvidenceRequest::new(*deployment.digest(), lookup.clone()),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.encode(), bytes, "{lookup:?}");
                let gets = metric(&context, "sealer_proofs_gets_total") - gets;
                let read_bytes = metric(&context, "runtime_storage_read_bytes_total") - read_bytes;
                assert!(
                    gets > 0 && gets <= limit,
                    "{lookup:?}: {gets} record gets, limit {limit}"
                );
                assert!(
                    read_bytes > 0,
                    "the query must perform physical archive reads"
                );
                assert!(
                    read_bytes <= (8 + 4 * gets) * u64::from(PAGE_SIZE.get()),
                    "{lookup:?}: {read_bytes} bytes for {gets} bounded records"
                );
                assert_eq!(metric(&context, "sealer_archive_gets_total"), full_reads);
                assert_eq!(metric(&context, "sealer_votes_gets_total"), vote_reads);
            }
        });
    }
}

#[test]
fn span_codec_checks_the_complete_extent_without_allocation() {
    for len in [0, 1, 2, 3, 31, u32::MAX] {
        let extent = u64::from(len) + node_count(len);
        for leaves in [0, u64::MAX - extent] {
            let span = Span { leaves, len };
            assert_eq!(span.encode().len(), u64::SIZE + u32::SIZE);
            let decoded = Span::decode(span.encode()).unwrap();
            assert_eq!(decoded, span);
            assert_eq!(decoded.nodes(), leaves + u64::from(len));
            assert_eq!(decoded.end(), leaves + extent);
            let mut next = leaves;
            assert_eq!(Span::reserve(&mut next, len as usize).unwrap(), span);
            assert_eq!(next, span.end());
        }
        if extent > 0 {
            let overflow = Span {
                leaves: u64::MAX - extent + 1,
                len,
            };
            assert!(Span::decode(overflow.encode()).is_err());
            let mut next = overflow.leaves;
            assert!(Span::reserve(&mut next, len as usize).is_err());
            assert_eq!(next, overflow.leaves);
        }
    }
    if usize::BITS > u32::BITS {
        let mut next = 0;
        assert!(Span::reserve(&mut next, usize::MAX).is_err());
        assert_eq!(next, 0);
    }
    for bytes in [Bytes::new(), Bytes::from(vec![0; Span::SIZE - 1])] {
        assert!(Span::decode(bytes).is_err());
    }
}

#[test]
fn descriptor_codec_bounds_counts_and_the_second_withdrawal_tree() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = Fixture::new(&context, "descriptor", 6).await;
        let (sealed, prepared) = fixture.prepare(0, 3, 3).await;
        let store = Store::open(
            context.child("proofs"),
            "descriptor",
            *fixture.deployment.digest(),
        )
        .await
        .unwrap()
        .retain(&sealed, prepared.close())
        .await
        .unwrap();
        let batch = sealed.header.batch_id::<Sha256>().into_digest();
        let descriptor = store.descriptor(&batch).await.unwrap().unwrap();
        assert_eq!(Descriptor::decode(descriptor.encode()).unwrap(), descriptor);
        for len in [0, MAX_ACTIVITY_ROWS as u32] {
            let mut value = descriptor.clone();
            value.changes = Span { leaves: 0, len };
            assert!(Descriptor::decode(value.encode()).is_ok());
        }
        for len in [0, MAX_WITHDRAWALS as u32] {
            let mut value = descriptor.clone();
            value.withdrawals = Span { leaves: 0, len };
            assert!(Descriptor::decode(value.encode()).is_ok());
        }
        let mut invalid = descriptor.clone();
        invalid.changes.len = MAX_ACTIVITY_ROWS as u32 + 1;
        assert!(Descriptor::decode(invalid.encode()).is_err());
        invalid = descriptor.clone();
        invalid.withdrawals.len = MAX_WITHDRAWALS as u32 + 1;
        assert!(Descriptor::decode(invalid.encode()).is_err());
        invalid = descriptor.clone();
        invalid.withdrawals = Span {
            leaves: u64::MAX - 3 - node_count(3),
            len: 3,
        };
        assert!(Span::decode(invalid.withdrawals.encode()).is_ok());
        assert!(Descriptor::decode(invalid.encode()).is_err());
        let Some(Record::Change(mut change)) = store
            .archive
            .get(Identifier::Index(descriptor.changes.leaves))
            .await
            .unwrap()
        else {
            panic!("fixture has change records");
        };
        for len in [0, MAX_ACCEPTED_PAYMENTS as u32] {
            change.entries = Span { leaves: 0, len };
            assert!(Change::decode(change.encode()).is_ok());
        }
        change.entries.len = MAX_ACCEPTED_PAYMENTS as u32 + 1;
        assert!(Change::decode(change.encode()).is_err());
        let mut wrong_position = sealed.clone();
        wrong_position.operations += 1;
        assert!(store.check(&wrong_position).await.is_err());
        let wrong_lookup = EvidenceLookup::Account {
            batch: Sha256::hash(&[b"other batch"]),
            account: fixture.active(0).public_key(),
        };
        assert!(store.answer(&descriptor, &wrong_lookup).await.is_err());
        assert!(
            store
                .retain(&wrong_position, prepared.close())
                .await
                .is_err()
        );
    });
}

#[test]
fn canonical_without_a_proof_descriptor_is_incompatible_at_restart() {
    for native_committed in [false, true] {
        let (deployment, checkpoint) =
            deterministic::Runner::default().start_and_recover(|context| async move {
                let mut fixture = Fixture::new(&context, "old-storage", 6).await;
                let (sealed, prepared) = fixture.prepare(0, 3, 0).await;
                let canonical = da::store(
                    context.child("canonical"),
                    "old-storage-canonical",
                    fixture.deployment.digest(),
                )
                .await
                .put_sync(0, sealed.header.batch_id::<Sha256>().into_digest(), &sealed)
                .await
                .unwrap();
                if native_committed {
                    fixture = fixture.advance(prepared).await;
                }
                drop(canonical);
                fixture.deployment
            });
        deterministic::Runner::from(checkpoint).start(|context| async move {
            let state = State::<_, Sha256>::open(
                context.child("balances"),
                state_config(
                    &format!("old-storage-balances-{}", deployment.digest()),
                    &context,
                    Sequential,
                ),
            )
            .await
            .unwrap();
            let canonical = da::store(
                context.child("canonical"),
                "old-storage-canonical",
                deployment.digest(),
            )
            .await;
            let proofs = Store::open(context.child("proofs"), "old-storage", *deployment.digest())
                .await
                .unwrap();
            let writes = metric(&context, "runtime_storage_write_bytes_total");
            let error = da::recover(state, &deployment, &canonical, &proofs)
                .await
                .err()
                .expect("canonical history requires its published proof descriptor");
            assert!(error.to_string().contains("incompatible validator storage"));
            assert_eq!(
                metric(&context, "runtime_storage_write_bytes_total"),
                writes
            );
            assert!(proofs.archive.last_index().is_none());
        });
    }
}
