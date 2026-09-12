use super::{fixture::ReadFixture, *};
use crate::chain::ingress::{Provider as _, Submission};
use commonware_consensus::Reporter as _;
use commonware_p2p::Receiver;
use commonware_runtime::IoBuf;
use commonware_utils::{Acknowledgement as _, acknowledgement::Exact, channel::mpsc};
use futures::FutureExt as _;

#[derive(Debug)]
struct NetworkInput(mpsc::Receiver<(ed25519::PublicKey, IoBuf)>);

impl Receiver for NetworkInput {
    type Error = Infallible;
    type PublicKey = ed25519::PublicKey;

    async fn recv(&mut self) -> Result<(Self::PublicKey, IoBuf), Self::Error> {
        match self.0.recv().await {
            Some(message) => Ok(message),
            None => std::future::pending().await,
        }
    }
}

struct QualifiedFixture {
    native: NativeGenesis,
    db: Database<deterministic::Context>,
    finalized: Finalized,
    honest: SettlementTx,
    challenge: SettlementTx,
}

impl QualifiedFixture {
    async fn new(context: &deterministic::Context) -> Self {
        let native = native_for(two_deployments());
        let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
        let fixture = close_fixture(
            native.chain_id(),
            &protocol,
            0,
            genesis_cache(),
            b"qualification",
            11,
            12,
        );
        let challenge = SettlementTx::Challenge(ChallengeRequest {
            deployment: deployment(),
            batch_id: fixture.result.finalized.batch_id,
            evidence: ack_fork(&fixture.result, &protocol, (2, 3)).encode(),
        });
        let honest = SettlementTx::Deposit(signed_deposit(
            native.chain_id(),
            deployment(),
            DepositEvent {
                id: Sha256::hash(&[b"qualified-honest-deposit"]),
                account: wallets()[0].public_key(),
                amount: 1,
            },
        ));
        let initial = [fixture.deposit_tx, fixture.register_tx, fixture.admit_tx];
        let db = open(context.child("canonical"), "canonical").await;
        let (root, _) = seal_native(&db, 1, &native, &initial).await;
        let finalized = Finalized::default();
        finalized.record(1, Digest::EMPTY, root, 1);

        // Independent real execution proves both honest effects; ingress's own
        // canonical database still has neither effect consumed.
        for (label, tx) in [("proof_deposit", &honest), ("proof_challenge", &challenge)] {
            let proof = open(context.child(label), label).await;
            seal_native(&proof, 1, &native, &initial).await;
            seal_native(&proof, 2, &native, std::slice::from_ref(tx)).await;
            match tx {
                SettlementTx::Deposit(request) => assert!(
                    read(&proof, &deposit_key(&deployment(), &request.event.id))
                        .await
                        .is_some()
                ),
                SettlementTx::Challenge(_) => assert!(matches!(
                    read(&proof, &fault_key(&deployment())).await,
                    Some(Record::Fault(FaultRecord::Faulted(
                        HardFaultReasonResponse::ProvenChallenge {
                            kind: ChallengeKind::AckFork,
                            ..
                        }
                    )))
                )),
                _ => unreachable!(),
            }
        }
        Self {
            native,
            db,
            finalized,
            honest,
            challenge,
        }
    }

    fn actor(
        &self,
        context: &deterministic::Context,
        capacity: usize,
        bytes: usize,
    ) -> (ingress::Actor<deterministic::Context>, ingress::Mailbox) {
        ingress::Actor::new(
            context.child("ingress"),
            ingress::Config {
                mailbox_size: NZUsize!(32),
                capacity: NonZeroUsize::new(capacity).unwrap(),
                bytes: NonZeroUsize::new(bytes).unwrap(),
                lease: 2,
                retention: 8,
            },
            RegistryView::new(self.native.deployments.clone()),
        )
    }

    fn start(
        &self,
        context: &deterministic::Context,
        capacity: usize,
        bytes: usize,
    ) -> ingress::Mailbox {
        let (actor, mailbox) = self.actor(context, capacity, bytes);
        actor.start(
            commonware_p2p::utils::mocks::inert_channel::<ed25519::PublicKey>([]),
            self.db.clone(),
            self.finalized.clone(),
            self.native.clone(),
            Timing::DEFAULT,
            Set::from_iter_dedup([]),
        );
        mailbox
    }

    fn deposit(&self, seed: u64) -> SettlementTx {
        SettlementTx::Deposit(signed_deposit(
            self.native.chain_id(),
            deployment(),
            DepositEvent {
                id: Sha256::hash(&[b"qualification-deposit", &seed.to_be_bytes()]),
                account: wallets()[0].public_key(),
                amount: 1,
            },
        ))
    }
}

async fn submit(mailbox: &ingress::Mailbox, tx: &SettlementTx) -> Submission {
    mailbox.submit_raw(tx.encode().into()).await.unwrap()
}

async fn report(mailbox: &ingress::Mailbox, height: u64, transactions: Vec<SettlementTx>) {
    let mut block = Block::genesis(
        ed25519::PrivateKey::from_seed(0).public_key(),
        Digest::EMPTY,
        0,
        initial_sync_target::<deterministic::Context>(),
    );
    block.height = Height::new(height);
    block.transactions = transactions;
    let (ack, waiter) = Exact::handle();
    let mut reporter = mailbox.clone();
    reporter.report(marshal::Update::Block(Arc::new(block), ack));
    waiter.await.unwrap();
}

async fn foreign_flood(context: deterministic::Context, committee_relay: bool, public: bool) {
    let fixture = QualifiedFixture::new(&context).await;
    let peer = if committee_relay {
        ed25519::PrivateKey::from_seed(71).public_key()
    } else {
        fixture.native.deployments[1].network_key.clone()
    };
    let committee = Set::from_iter_dedup(if committee_relay {
        vec![peer.clone()]
    } else {
        vec![]
    });
    let (mut actor, mailbox) = fixture.actor(&context, 2, MAX_BLOCK_BYTES);
    let (completed, mut completion) = mpsc::channel(1);
    actor.observe_completion(completed);
    let (network, receiver) = mpsc::channel(1);
    let (sender, _) = commonware_p2p::utils::mocks::inert_channel::<ed25519::PublicKey>([]);
    actor.start(
        (sender, NetworkInput(receiver)),
        fixture.db.clone(),
        fixture.finalized.clone(),
        fixture.native.clone(),
        Timing::DEFAULT,
        committee,
    );
    for seed in 0..8 {
        let mut forged = fixture.deposit(seed);
        let SettlementTx::Deposit(request) = &mut forged else {
            unreachable!()
        };
        request.event.amount += 1;
        assert!(!request.verify(&fixture.native.chain_id()));
        for tx in [
            forged,
            SettlementTx::Challenge(ChallengeRequest {
                deployment: deployment(),
                batch_id: BatchId::new(Sha256::hash(&[b"bogus-challenge", &seed.to_be_bytes()])),
                evidence: Bytes::new(),
            }),
        ] {
            if public {
                let _ = submit(&mailbox, &tx).await;
            } else {
                network
                    .send((peer.clone(), tx.encode().into()))
                    .await
                    .unwrap();
            }
            completion
                .recv()
                .await
                .expect("adversarial worker actually completed");
        }
    }
    assert_eq!(
        submit(&mailbox, &fixture.honest).await,
        Submission::Accepted,
        "invalid foreign work consumed honest ordinary reservation"
    );
    assert_eq!(
        submit(&mailbox, &fixture.challenge).await,
        Submission::Accepted,
        "invalid foreign work consumed honest recovery reservation"
    );
    let mut provider = mailbox;
    let proposed = provider.drain(MAX_BLOCK_TXS, MAX_BLOCK_BYTES).await;
    assert!(proposed.contains(&fixture.honest));
    assert!(proposed.contains(&fixture.challenge));
    seal_native(&fixture.db, 2, &fixture.native, &proposed).await;
    let SettlementTx::Deposit(deposit) = fixture.honest else {
        unreachable!()
    };
    assert!(
        read(&fixture.db, &deposit_key(&deployment(), &deposit.event.id))
            .await
            .is_some()
    );
    assert!(matches!(
        read(&fixture.db, &fault_key(&deployment())).await,
        Some(Record::Fault(FaultRecord::Faulted(_)))
    ));
}

#[test]
fn registered_foreign_flood_preserves_honest_reservations() {
    deterministic::Runner::default().start(|context| foreign_flood(context, false, false));
}

#[test]
fn committee_relay_flood_preserves_honest_reservations() {
    deterministic::Runner::default().start(|context| foreign_flood(context, true, false));
}

#[test]
fn public_flood_preserves_honest_reservations() {
    deterministic::Runner::default().start(|context| foreign_flood(context, false, true));
}

#[test]
fn qualified_leases_bytes_retention_and_fitting_drains() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = QualifiedFixture::new(&context).await;
        let txs = [
            fixture.deposit(0),
            fixture.deposit(1),
            fixture.deposit(2),
            fixture.deposit(3),
        ];
        let size = txs[0].encode_size();
        let mailbox = fixture.start(&context, 8, 3 * size);
        for tx in &txs[..3] {
            assert_eq!(submit(&mailbox, tx).await, Submission::Accepted);
        }
        assert_eq!(submit(&mailbox, &txs[3]).await, Submission::Full);
        let mut provider = mailbox.clone();
        assert_eq!(provider.drain(8, 2 * size).await, txs[..2]);
        assert_eq!(
            submit(&mailbox, &txs[3]).await,
            Submission::Full,
            "leases keep their byte reservation"
        );
        assert_eq!(submit(&mailbox, &txs[0]).await, Submission::Duplicate);
        assert_eq!(provider.drain(8, size).await, vec![txs[2].clone()]);
        for height in [3, 5, 7] {
            report(&mailbox, height, vec![]).await;
            assert_eq!(provider.drain(8, 3 * size).await, txs[..3]);
        }
        report(&mailbox, 9, vec![]).await;
        assert!(provider.drain(8, MAX_BLOCK_BYTES).await.is_empty());
        assert_eq!(submit(&mailbox, &txs[3]).await, Submission::Accepted);
        assert_eq!(provider.drain(8, size).await, vec![txs[3].clone()]);
    });
}

#[test]
fn qualified_proof_variants_share_one_action_and_small_work_fits() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = QualifiedFixture::new(&context).await;
        let mailbox = fixture.start(&context, 8, MAX_BLOCK_BYTES);
        assert_eq!(
            submit(&mailbox, &fixture.challenge).await,
            Submission::Accepted
        );
        let mut alternative = fixture.challenge.clone();
        let SettlementTx::Challenge(request) = &mut alternative else {
            unreachable!()
        };
        let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
        let close = close_fixture(
            fixture.native.chain_id(),
            &protocol,
            0,
            genesis_cache(),
            b"qualification",
            11,
            12,
        );
        request.evidence = ack_fork(&close.result, &protocol, (4, 5)).encode();
        assert_ne!(alternative, fixture.challenge);
        assert!(matches!(
            super::super::state::preflight(
                &fixture.db,
                &fixture.finalized,
                &fixture.native,
                &Timing::DEFAULT,
                &alternative
            )
            .await
            .unwrap(),
            super::super::state::Preflight::Eligible { .. }
        ));
        assert_eq!(submit(&mailbox, &alternative).await, Submission::Full);
        assert_eq!(
            submit(&mailbox, &fixture.honest).await,
            Submission::Accepted
        );
        let mut provider = mailbox;
        assert_eq!(
            provider.drain(8, fixture.honest.encode_size()).await,
            vec![fixture.honest]
        );
        assert_eq!(
            provider.drain(8, MAX_BLOCK_BYTES).await,
            vec![fixture.challenge]
        );
    });
}

#[test]
fn canceled_rpc_waiters_keep_running_work_charged_and_control_live() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = QualifiedFixture::new(&context).await;
        let (mut actor, mailbox) = fixture.actor(&context, 8, MAX_BLOCK_BYTES);
        let (completed, mut completion) = mpsc::channel(8);
        actor.observe_completion(completed);
        actor.start(
            commonware_p2p::utils::mocks::inert_channel::<ed25519::PublicKey>([]),
            fixture.db.clone(),
            fixture.finalized.clone(),
            fixture.native.clone(),
            Timing::DEFAULT,
            Set::from_iter_dedup([]),
        );
        let (slot, db) = fixture.db.write().await;
        let mut submissions = Vec::new();
        for seed in 0..4 {
            let mut submission =
                Box::pin(mailbox.submit_raw(fixture.deposit(seed).encode().into()));
            assert!(futures::poll!(&mut submission).is_pending());
            submissions.push(submission);
        }
        let mut provider = mailbox.clone();
        assert!(provider.drain(8, MAX_BLOCK_BYTES).await.is_empty());
        context.sleep(Duration::from_millis(1)).await;
        assert!(
            completion.recv().now_or_never().is_none(),
            "storage blocks actual worker completion"
        );
        drop(submissions);
        assert_eq!(
            submit(&mailbox, &fixture.deposit(4)).await,
            Submission::Full,
            "lost RPC waiters must not release queued or running raw reservations"
        );
        report(&mailbox, 2, vec![]).await;
        assert!(provider.drain(8, MAX_BLOCK_BYTES).await.is_empty());
        slot.put(db);
        for _ in 0..4 {
            completion.recv().await.unwrap();
        }
        let proposed = provider.drain(8, MAX_BLOCK_BYTES).await;
        assert_eq!(proposed.len(), 4);
        assert_eq!(
            submit(&mailbox, &fixture.deposit(4)).await,
            Submission::Accepted
        );
        seal_native(&fixture.db, 2, &fixture.native, &proposed).await;
        for tx in proposed {
            let SettlementTx::Deposit(request) = tx else {
                unreachable!()
            };
            assert!(
                read(&fixture.db, &deposit_key(&deployment(), &request.event.id))
                    .await
                    .is_some()
            );
        }
    });
}

#[test]
fn query_rejects_excess_partial_frames_and_recovers_after_read_timeout() {
    deterministic::Runner::default().start(|context| async move {
        let mut fixture = ReadFixture::new(&context).await;
        fixture.seal(&context, true).await;
        let mut partial = Vec::new();
        for _ in 0..query::MAX_CONNECTIONS {
            let (mut sink, stream) = context.dial(fixture.address).await.unwrap();
            commonware_runtime::Sink::send(
                &mut sink,
                commonware_codec::varint::UInt(4_u32 * 1024 * 1024).encode(),
            )
            .await
            .unwrap();
            commonware_runtime::Sink::send(&mut sink, Bytes::from(vec![0; 1024]))
                .await
                .unwrap();
            partial.push((sink, stream));
        }
        context.sleep(Duration::from_millis(1)).await;
        let refused = rpc::invoke(
            &context,
            fixture.address,
            "query",
            query::METHOD_READ,
            req(Lookup::Status).encode(),
        )
        .await;
        assert!(
            refused.is_err(),
            "excess connection is dropped before request buffering"
        );
        context.sleep(query::REQUEST_READ_TIMEOUT).await;
        for (_, mut stream) in partial {
            assert!(
                rpc::recv_response(&mut stream).await.is_err(),
                "partial request slot expires"
            );
        }
        let response = rpc::invoke(
            &context,
            fixture.address,
            "query",
            query::METHOD_READ,
            req(Lookup::Status).encode(),
        )
        .await
        .unwrap();
        assert!(matches!(
            ReadResponse::decode(response).unwrap(),
            ReadResponse::Certified(_)
        ));
    });
}

#[test]
fn cross_target_claims_share_the_source_reservation() {
    deterministic::Runner::default().start(|context| async move {
        let native = native_for(two_deployments());
        let db = open(context.child("claims"), "claims").await;
        let finalized = Finalized::default();
        let (register, admit, claim) = withdrawal_fixture();
        seal_native(&db, 1, &native, &[register, admit]).await;
        let (root, _) = seal_native(&db, 13, &native, &[]).await;
        finalized.record(13, Digest::EMPTY, root, 13);
        let wallet = wallets()
            .into_iter()
            .find(|wallet| wallet.public_key().encode() == *claim.claim.output().destination())
            .unwrap();
        let compound = |target| {
            SettlementTx::ClaimDeposit(ClaimDepositRequest {
                claim: FinalizedClaim::Withdrawal(claim.clone()),
                deposit: DepositRequest::sign(
                    native.chain_id(),
                    target,
                    DepositEvent {
                        id: Sha256::hash(&[b"ingress-compound"]),
                        account: wallet.public_key(),
                        amount: 7,
                    },
                    wallet.signer(),
                ),
            })
        };
        let target = *native.deployments[1].deployment.digest();
        let (actor, mailbox) = ingress::Actor::<_, Exact>::new(
            context.child("ingress"),
            ingress::Config {
                mailbox_size: NZUsize!(16),
                capacity: NZUsize!(4),
                bytes: NZUsize!(MAX_BLOCK_BYTES),
                lease: 2,
                retention: 8,
            },
            RegistryView::new(native.deployments.clone()),
        );
        actor.start(
            commonware_p2p::utils::mocks::inert_channel::<ed25519::PublicKey>([]),
            db.clone(),
            finalized.clone(),
            native.clone(),
            Timing::DEFAULT,
            Set::from_iter_dedup([]),
        );
        let winner = compound(target);
        assert_eq!(submit(&mailbox, &winner).await, Submission::Accepted);
        assert_eq!(submit(&mailbox, &winner).await, Submission::Duplicate);
        for competing in [compound(deployment()), SettlementTx::ClaimWithdrawal(claim)] {
            assert!(matches!(
                super::super::state::preflight(
                    &db,
                    &finalized,
                    &native,
                    &Timing::DEFAULT,
                    &competing
                )
                .await
                .unwrap(),
                super::super::state::Preflight::Eligible { .. }
            ));
            assert_eq!(submit(&mailbox, &competing).await, Submission::Full);
        }
        let mut provider = mailbox;
        let proposed = provider.drain(4, MAX_BLOCK_BYTES).await;
        assert_eq!(proposed, vec![winner]);
        seal_native(&db, 14, &native, &proposed).await;
        assert_eq!(status(&db).await.claimable, 0);
        assert!(matches!(
            read(
                &db,
                &deposit_key(&target, &Sha256::hash(&[b"ingress-compound"]))
            )
            .await,
            Some(Record::Deposit(_))
        ));
    });
}

#[test]
fn raw_bytes_include_the_running_job_and_preserve_other_classes() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = QualifiedFixture::new(&context).await;
        let mailbox = fixture.start(&context, 8, MAX_BLOCK_BYTES);
        let (slot, db) = fixture.db.write().await;
        let mut first = Box::pin(mailbox.submit_raw(fixture.challenge.encode().into()));
        assert!(futures::poll!(&mut first).is_pending());
        let mut provider = mailbox.clone();
        assert!(provider.drain(8, MAX_BLOCK_BYTES).await.is_empty());
        context.sleep(Duration::from_millis(1)).await;
        let mut maximal = vec![0; MAX_TX_BYTES];
        maximal[0] = 6;
        let mut remaining = vec![0; MAX_TX_BYTES - fixture.challenge.encode_size()];
        remaining[0] = 6;
        let mut second = Box::pin(mailbox.submit_raw(Bytes::from(maximal).into()));
        let mut third = Box::pin(mailbox.submit_raw(Bytes::from(remaining).into()));
        assert!(futures::poll!(&mut second).is_pending());
        assert!(futures::poll!(&mut third).is_pending());
        assert!(provider.drain(8, MAX_BLOCK_BYTES).await.is_empty());
        assert_eq!(submit(&mailbox, &fixture.challenge).await, Submission::Full);
        let mut ordinary = Box::pin(mailbox.submit_raw(fixture.honest.encode().into()));
        assert!(futures::poll!(&mut ordinary).is_pending());
        assert!(provider.drain(8, MAX_BLOCK_BYTES).await.is_empty());
        slot.put(db);
        assert_eq!(first.await.unwrap(), Submission::Accepted);
        assert_eq!(second.await.unwrap(), Submission::Full);
        assert_eq!(third.await.unwrap(), Submission::Full);
        assert_eq!(ordinary.await.unwrap(), Submission::Accepted);
        assert_eq!(
            submit(&mailbox, &fixture.challenge).await,
            Submission::Duplicate
        );
        let proposed = provider.drain(8, MAX_BLOCK_BYTES).await;
        assert!(proposed.contains(&fixture.honest));
        assert!(proposed.contains(&fixture.challenge));
    });
}

#[test]
fn mailbox_overflow_drops_raw_bodies_and_preserves_proposal_control() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = QualifiedFixture::new(&context).await;
        let (actor, mailbox) = fixture.actor(&context, 8, MAX_BLOCK_BYTES);
        let (slot, db) = fixture.db.write().await;
        let transactions = (0..64)
            .map(|seed| fixture.deposit(seed))
            .collect::<Vec<_>>();
        let mut submissions = Box::pin(futures::future::join_all(
            transactions.iter().map(|tx| submit(&mailbox, tx)),
        ));
        assert!(futures::poll!(&mut submissions).is_pending());
        let mut provider = mailbox.clone();
        let mut control = Box::pin(provider.drain(8, MAX_BLOCK_BYTES));
        assert!(futures::poll!(&mut control).is_pending());
        actor.start(
            commonware_p2p::utils::mocks::inert_channel::<ed25519::PublicKey>([]),
            fixture.db.clone(),
            fixture.finalized.clone(),
            fixture.native.clone(),
            Timing::DEFAULT,
            Set::from_iter_dedup([]),
        );
        assert!(
            control.await.is_empty(),
            "proposal control survives a full submission mailbox while storage waits"
        );
        slot.put(db);
        let results = submissions.await;
        assert!(
            results
                .iter()
                .filter(|result| **result == Submission::Full)
                .count()
                >= 32
        );
        let expected = transactions
            .into_iter()
            .zip(results)
            .filter_map(|(tx, result)| (result == Submission::Accepted).then_some(tx))
            .collect::<Vec<_>>();
        assert!(!expected.is_empty());
        assert_eq!(provider.drain(8, MAX_BLOCK_BYTES).await, expected);
    });
}

#[derive(Debug)]
struct ReadyFlood {
    peer: ed25519::PublicKey,
    bytes: Bytes,
    remaining: usize,
    exhausted: Option<commonware_utils::channel::oneshot::Sender<()>>,
}

impl Receiver for ReadyFlood {
    type Error = Infallible;
    type PublicKey = ed25519::PublicKey;

    async fn recv(&mut self) -> Result<(Self::PublicKey, IoBuf), Self::Error> {
        if self.remaining > 0 {
            self.remaining -= 1;
            return Ok((self.peer.clone(), self.bytes.clone().into()));
        }
        if let Some(exhausted) = self.exhausted.take() {
            let _ = exhausted.send(());
        }
        std::future::pending().await
    }
}

#[test]
fn continuously_ready_network_yields_to_qualification_and_proposals() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = QualifiedFixture::new(&context).await;
        let (actor, mailbox) = fixture.actor(&context, 8, MAX_BLOCK_BYTES);
        let mut submitted = Box::pin(mailbox.submit_raw(fixture.honest.encode().into()));
        assert!(futures::poll!(&mut submitted).is_pending());
        let (exhausted, mut exhaustion) = commonware_utils::channel::oneshot::channel();
        let receiver = ReadyFlood {
            peer: fixture.native.deployments[1].network_key.clone(),
            bytes: SettlementTx::Challenge(ChallengeRequest {
                deployment: deployment(),
                batch_id: BatchId::new(Digest::EMPTY),
                evidence: Bytes::new(),
            })
            .encode(),
            remaining: 10_000,
            exhausted: Some(exhausted),
        };
        let (sender, _) = commonware_p2p::utils::mocks::inert_channel::<ed25519::PublicKey>([]);
        actor.start(
            (sender, receiver),
            fixture.db.clone(),
            fixture.finalized.clone(),
            fixture.native.clone(),
            Timing::DEFAULT,
            Set::from_iter_dedup([]),
        );
        assert_eq!(submitted.await.unwrap(), Submission::Accepted);
        let mut provider = mailbox;
        let proposed = provider.drain(8, MAX_BLOCK_BYTES).await;
        assert_eq!(proposed, vec![fixture.honest]);
        assert!(
            matches!(
                exhaustion.try_recv(),
                Err(commonware_utils::channel::oneshot::error::TryRecvError::Empty)
            ),
            "qualification/proposal must finish while the network remains ready"
        );
        seal_native(&fixture.db, 2, &fixture.native, &proposed).await;
        let SettlementTx::Deposit(request) = &proposed[0] else {
            unreachable!()
        };
        assert!(
            read(&fixture.db, &deposit_key(&deployment(), &request.event.id))
                .await
                .is_some()
        );
    });
}

#[test]
fn stopped_ingress_is_an_error_instead_of_a_capacity_advisory() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = QualifiedFixture::new(&context).await;
        let (actor, mailbox) = fixture.actor(&context, 8, MAX_BLOCK_BYTES);
        drop(actor);
        assert!(
            mailbox
                .submit_raw(fixture.honest.encode().into())
                .await
                .is_err()
        );
    });
}
