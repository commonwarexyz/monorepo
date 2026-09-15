use super::*;
use commonware_clearing::bajillion::{
    custody::Epoch as SourceEpoch,
    logs::{LogHead, PayoutOperation},
    transition::WithdrawalClaim,
};
use std::{collections::BTreeMap, net::SocketAddr};

#[derive(Clone)]
struct ProofProvider {
    transactions: Vec<SettlementTx>,
    proofs: Arc<BTreeMap<(u64, u64), WithdrawalClaim<Digest>>>,
    requested: Arc<Mutex<Vec<(u64, u64)>>>,
}

impl ingress::Provider for ProofProvider {
    async fn drain(&mut self, _: usize, _: usize) -> Vec<SettlementTx> {
        std::mem::take(&mut self.transactions)
    }

    async fn payout_proof(
        &mut self,
        scoped: Digest,
        head: LogHead<Digest>,
        index: u64,
    ) -> Option<WithdrawalClaim<Digest>> {
        assert_eq!(scoped, deployment());
        self.requested.lock().push((head.operations, index));
        self.proofs.get(&(head.operations, index)).cloned()
    }
}

async fn verify_proposal_custodian_rotation(
    context: &deterministic::Context,
    head: LogHead<Digest>,
    expected: WithdrawalClaim<Digest>,
    stale: WithdrawalClaim<Digest>,
) {
    let index = expected.position();
    let addresses = [19_895, 19_896].map(|port| SocketAddr::from(([127, 0, 0, 1], port)));
    let mut servers = Vec::new();
    for (address, claim) in addresses.into_iter().zip([stale, expected.clone()]) {
        let mut listener = context.bind(address).await.unwrap();
        servers.push(context.child("proof_source").spawn(move |_| async move {
            let (_, mut sink, mut stream) = listener.accept().await.unwrap();
            let request = rpc::recv_request(&mut stream).await.unwrap();
            assert_eq!(request.method, query::METHOD_EVIDENCE);
            assert_eq!(
                query::EvidenceRequest::decode(request.body).unwrap(),
                query::EvidenceRequest::new(deployment(), EvidenceLookup::Payout { head, index }),
            );
            rpc::send_response(
                &mut sink,
                &rpc::Response::Success {
                    body: EvidenceResponse::Served(Evidence::Payout(claim)).encode(),
                },
            )
            .await
            .unwrap();
        }));
    }
    let (_actor, mailbox) = ingress::Actor::new(
        context.child("proof_ingress"),
        ingress::Config {
            mailbox_size: NZUsize!(8),
            capacity: NZUsize!(8),
            bytes: NZUsize!(4096),
            lease: 1,
            retention: 4,
        },
        RegistryView::new(Vec::new()),
    );
    let mut provider =
        ingress::WitnessProvider::new(context.child("provider"), mailbox, addresses.to_vec());
    let actual = ingress::Provider::payout_proof(&mut provider, deployment(), head, index).await;
    assert_eq!(actual, Some(expected));
    for server in servers {
        server.await.unwrap();
    }
}

#[test]
fn proposals_refresh_claims_while_every_block_finalizes_and_consume_zero_outputs() {
    deterministic::Runner::default().start(|context| async move {
        let db = open(context.child("ledger"), "flat-payout-proposals").await;
        let native = native();
        let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
        let genesis = genesis_cache();
        let mut replica = replay_state(
            context.child("replica"),
            crate::protocol::state_config(
                "flat-payout-replica",
                &context,
                protocol.strategy().clone(),
            ),
            &genesis.history,
        )
        .await;
        let wallets = wallets();
        let requests = wallets
            .iter()
            .enumerate()
            .map(|(index, wallet)| {
                SignedWithdrawal::sign(
                    deployment(),
                    genesis.root().digest,
                    wallet.public_key().encode(),
                    WithdrawalAction::Amount(
                        NonZeroU64::new(if index == 0 { 100 } else { 1 }).unwrap(),
                    ),
                    100,
                    wallet.signer(),
                )
            })
            .collect();
        let withdrawals = WithdrawalBatch::new(requests).unwrap();
        let mut results = Vec::new();
        for epoch in 0..4 {
            let boundary = if epoch == 0 {
                withdrawals.clone()
            } else {
                WithdrawalBatch::empty()
            };
            let deposits = DepositBatch::empty();
            let root = deposits.root::<Sha256>().unwrap();
            let liability = replica.state().liability();
            let registration = protocol
                .registration_at(
                    epoch,
                    deposits,
                    boundary.clone(),
                    liability,
                    epoch + 11,
                    epoch + 12,
                )
                .unwrap();
            let terminals = if epoch == 0 {
                let payer = &wallets[0];
                let vector = OutVector::new(
                    0,
                    payer.public_key(),
                    vec![OutEntry {
                        recipient: wallets[1].public_key(),
                        cumulative: 1,
                        count: 1,
                    }],
                )
                .unwrap();
                let body = VectorSendBody::new(
                    registration.context.payment(),
                    payer.public_key(),
                    1,
                    1,
                    vector.root::<Sha256, Digest>().unwrap(),
                );
                vec![Terminal {
                    operator_signature: protocol.sign_ack_aggregate(&body),
                    authorization: SendAuthorization::sign(body, payer.signer()),
                    vector,
                }]
            } else {
                Vec::new()
            };
            let register = SettlementTx::RegisterEpoch(RegisterEpochRequest {
                deployment: deployment(),
                epoch,
                predecessor_liability: liability,
                deposits_root: root,
                withdrawals: boundary.clone(),
                openings: boundary
                    .requests()
                    .iter()
                    .map(|request| genesis.opening(request.account()).unwrap())
                    .collect(),
                fee: 4096,
                signature: protocol
                    .sign_chain_registration(epoch, liability, &root, &boundary, 4096),
            });
            let (result, prepared) = protocol
                .complete(
                    protocol.prepare(registration, terminals).unwrap(),
                    &replica,
                    &mut TestRng::new(epoch),
                )
                .await
                .unwrap();
            replica = replica.apply(prepared).await.unwrap();
            seal_native(
                &db,
                epoch + 1,
                &native,
                &[register, SettlementTx::Admit(AdmitRequest::from(&result))],
            )
            .await;
            assert!(matches!(
                read(&db, &admitted_key(&deployment(), epoch)).await,
                Some(Record::Admitted(_))
            ));
            results.push(result);
        }
        for height in 5..=13 {
            seal_native(&db, height, &native, &[]).await;
        }
        assert_eq!(status(&db).await.last_finalized, Some(0));
        assert_eq!(status(&db).await.claimable, 3);
        let first_tip = crate::protocol::PayoutTip {
            heads: results[0].roots.logs(),
            finalized: Some(0),
        };
        let source_epoch = SourceEpoch::<Key, Digest>::load(replica.logs(), 0)
            .await
            .unwrap();
        let first_source = source_epoch
            .source_proof(replica.logs(), &first_tip.heads)
            .await
            .unwrap();
        let source = first_source
            .verify::<Sha256, Key>(&first_tip.heads)
            .unwrap();
        assert_eq!(source.context(), &results[0].context);
        assert_eq!(source.withdrawals(), &withdrawals);
        assert_eq!(first_tip.encode().len(), 105);
        assert_eq!(
            crate::protocol::PayoutTip::decode(first_tip.encode()).unwrap(),
            first_tip
        );
        let wire = Evidence::Source(first_source.clone());
        assert_eq!(Evidence::decode(wire.encode()).unwrap(), wire);
        let lookup = EvidenceLookup::Source {
            epoch: 0,
            heads: first_tip.heads,
        };
        assert_eq!(EvidenceLookup::decode(lookup.encode()).unwrap(), lookup);
        let pending = SourceEpoch::<Key, Digest>::load(replica.logs(), 1)
            .await
            .unwrap();
        let pending_proof = pending
            .source_proof(replica.logs(), &results[3].roots.logs())
            .await
            .unwrap();
        assert!(
            pending_proof
                .verify::<Sha256, Key>(&first_tip.heads)
                .is_err()
        );
        assert!(
            pending
                .source_proof(replica.logs(), &first_tip.heads)
                .await
                .is_err()
        );
        let claims = &results[0].withdrawal_claims;
        assert_eq!(claims.len(), 4);
        assert_eq!(
            claims
                .iter()
                .filter(|claim| claim.output().amount() == 0)
                .count(),
            1
        );
        let start = results[0].context.predecessor_logs().payouts.operations;
        assert_eq!(
            claims
                .iter()
                .map(WithdrawalClaim::position)
                .collect::<Vec<_>>(),
            (start..start + 4).collect::<Vec<_>>()
        );

        let mut proofs = BTreeMap::new();
        for result in &results {
            for claim in claims {
                let (opening, operations) = replica
                    .logs()
                    .payout_opening(
                        &result.roots.withdrawal_outputs,
                        claim.position(),
                        NonZeroU64::MIN,
                    )
                    .await
                    .unwrap();
                let [PayoutOperation::Append(output)] = operations.as_slice() else {
                    panic!("output position is an append");
                };
                let refreshed = WithdrawalClaim::new(output.clone(), opening);
                assert!(
                    refreshed
                        .verify::<Sha256>(&result.roots.withdrawal_outputs)
                        .is_ok()
                );
                proofs.insert(
                    (result.roots.withdrawal_outputs.operations, claim.position()),
                    refreshed,
                );
            }
        }
        verify_proposal_custodian_rotation(
            &context,
            results[3].roots.withdrawal_outputs,
            proofs[&(results[3].roots.withdrawal_outputs.operations, start)].clone(),
            claims[0].clone(),
        )
        .await;
        let (gap, operations) = replica
            .logs()
            .payout_opening(
                &results[3].roots.withdrawal_outputs,
                start + 4,
                NonZeroU64::MIN,
            )
            .await
            .unwrap();
        assert!(matches!(
            operations.as_slice(),
            [PayoutOperation::Commit(..)]
        ));
        assert!(
            WithdrawalClaim::new(claims[0].output().clone(), gap)
                .verify::<Sha256>(&results[3].roots.withdrawal_outputs)
                .is_err()
        );
        let mut parent = Block::genesis(
            ed25519::PrivateKey::from_seed(0).public_key(),
            native.chain_id(),
            13,
            initial_sync_target::<deterministic::Context>(),
        );
        parent.height = Height::new(13);
        parent.state_root = db.read().await.root();
        let mut app: App<Scheme, ProofProvider> = App::new(
            parent.clone(),
            Timing::DEFAULT,
            native.clone(),
            Finalized::default(),
        );
        let requested = Arc::new(Mutex::new(Vec::new()));
        let proofs = Arc::new(proofs);
        let mut initial = Vec::new();
        for wallet in &wallets {
            initial.push(
                native_balance(&db, &native, &wallet.public_key())
                    .await
                    .unwrap(),
            );
        }
        let mut paid = BTreeMap::<Key, u64>::new();
        let mut consumed = std::collections::BTreeSet::new();
        let zero = claims
            .iter()
            .position(|claim| claim.output().amount() == 0)
            .unwrap();
        let positive = (0..claims.len())
            .filter(|index| *index != zero)
            .collect::<Vec<_>>();
        for (offset, positions) in [
            vec![positive[1], positive[1]],
            vec![positive[2]],
            vec![positive[0]],
        ]
        .into_iter()
        .enumerate()
        {
            let epoch = offset + 1;
            let height = 14 + offset as u64;
            let index = claims[positions[0]].position();
            let mut hint = None;
            for candidate in start..=index {
                if let Some(Record::Unclaimed(end)) =
                    read(&db, &unclaimed_key(&deployment(), candidate)).await
                    && index < end
                {
                    hint = Some(candidate);
                }
            }
            let hint = hint.unwrap();
            let transactions = positions
                .iter()
                .map(|position| {
                    SettlementTx::ClaimWithdrawal(WithdrawalClaimRequest {
                        deployment: deployment(),
                        start: hint,
                        claim: claims[*position].clone(),
                    })
                })
                .collect::<Vec<_>>();
            let block_context = Context {
                round: Round::new(Epoch::zero(), View::new(height)),
                leader: parent.context.leader.clone(),
                parent: (parent.context.round.view(), parent.digest()),
            };
            let provider = ProofProvider {
                transactions: transactions.clone(),
                proofs: proofs.clone(),
                requested: requested.clone(),
            };
            if offset == 0 {
                let unavailable = ProofProvider {
                    proofs: Arc::new(BTreeMap::new()),
                    ..provider.clone()
                };
                let skipped = app
                    .propose(
                        (context.child("unavailable_proof"), block_context.clone()),
                        marshal::ancestry::from_iter([Arc::new(parent.clone())]),
                        db.new_batches().await,
                        Input {
                            upstream: (),
                            provider: unavailable,
                        },
                    )
                    .await
                    .unwrap();
                assert!(skipped.block.transactions.is_empty());
                drop(skipped);
                assert_eq!(status(&db).await.claimable, 3);
            }
            let proposed = app
                .propose(
                    (context.child("propose"), block_context.clone()),
                    marshal::ancestry::from_iter([Arc::new(parent.clone())]),
                    db.new_batches().await,
                    Input {
                        upstream: (),
                        provider,
                    },
                )
                .await
                .unwrap();
            assert_eq!(proposed.block.transactions.len(), positions.len());
            for (tx, original) in proposed.block.transactions.iter().zip(&transactions) {
                let (SettlementTx::ClaimWithdrawal(tx), SettlementTx::ClaimWithdrawal(original)) =
                    (tx, original)
                else {
                    unreachable!()
                };
                assert_eq!(tx.claim.position(), original.claim.position());
                assert_eq!(tx.claim.output(), original.claim.output());
                assert_ne!(tx.claim.encode(), original.claim.encode());
                assert!(
                    tx.claim
                        .verify::<Sha256>(&results[epoch].roots.withdrawal_outputs)
                        .is_ok()
                );
            }
            let verified = app
                .verify(
                    (context.child("verify"), block_context),
                    marshal::ancestry::from_iter([
                        Arc::new(proposed.block.clone()),
                        Arc::new(parent.clone()),
                    ]),
                    db.new_batches().await,
                )
                .await
                .unwrap();
            assert_eq!(verified.root(), proposed.merkleized.root());
            drop(verified);
            parent = proposed.block;
            db.apply(proposed.merkleized).await;
            assert_eq!(status(&db).await.last_finalized, Some(epoch as u64));
            for retired in 0..epoch as u64 {
                assert_eq!(read(&db, &admitted_key(&deployment(), retired)).await, None);
                assert_eq!(read(&db, &anchor_key(&deployment(), retired)).await, None);
            }
            for retained in epoch as u64..4 {
                assert!(matches!(
                    read(&db, &admitted_key(&deployment(), retained)).await,
                    Some(Record::Admitted(_))
                ));
            }
            let Some(Record::PayoutHead(tip)) = read(&db, &payout_head_key(&deployment())).await
            else {
                panic!("current payout tip");
            };
            assert_eq!(tip.finalized, Some(epoch as u64));
            let old = source_epoch
                .source_proof(replica.logs(), &tip.heads)
                .await
                .unwrap();
            let source = old.verify::<Sha256, Key>(&tip.heads).unwrap();
            assert_eq!(source.context(), &results[0].context);
            assert_eq!(source.activity_range().head, tip.heads.activity);
            let wire = Evidence::Source(old.clone());
            assert_eq!(Evidence::decode(wire.encode()).unwrap(), wire);
            let mut wrong = old.clone();
            let mut corrupted = wrong.metadata.to_vec();
            corrupted[0] ^= 1;
            wrong.metadata = Bytes::from(corrupted);
            assert!(wrong.verify::<Sha256, Key>(&tip.heads).is_err());
            let mut wrong = tip.heads;
            wrong.activity.operations += 1;
            assert!(old.verify::<Sha256, Key>(&wrong).is_err());
            for position in positions {
                if !consumed.insert(position) {
                    continue;
                }
                let output = claims[position].output();
                *paid
                    .entry(Key::decode(output.destination().clone()).unwrap())
                    .or_default() += output.amount();
            }
            for (index, wallet) in wallets.iter().enumerate() {
                assert_eq!(
                    native_balance(&db, &native, &wallet.public_key())
                        .await
                        .unwrap(),
                    initial[index] + paid.get(&wallet.public_key()).copied().unwrap_or(0)
                );
            }
        }
        assert_eq!(status(&db).await.claimable, 0);
        let zero_index = claims[zero].position();
        assert_eq!(
            read(&db, &unclaimed_key(&deployment(), zero_index)).await,
            Some(Record::Unclaimed(zero_index + 1))
        );
        assert_eq!(requested.lock().len(), 6);

        let deadline = 50;
        let pending = SignedWithdrawal::sign(
            deployment(),
            replica.state().root().digest,
            wallets[0].public_key().encode(),
            WithdrawalAction::Amount(NonZeroU64::MIN),
            deadline,
            wallets[0].signer(),
        );
        seal_native(
            &db,
            17,
            &native,
            &[SettlementTx::QueueWithdrawal(QueueWithdrawalRequest {
                request: pending.clone(),
                opening: replica
                    .state()
                    .opening(wallets[0].public_key())
                    .await
                    .unwrap(),
            })],
        )
        .await;
        assert_eq!(
            read(
                &db,
                &withdrawal_key(&deployment(), &wallets[0].public_key())
            )
            .await,
            Some(Record::Withdrawal(pending))
        );
        for height in 18..=deadline {
            seal_native(&db, height, &native, &[]).await;
        }
        assert!(status(&db).await.hard_faulted);
        assert_eq!(status(&db).await.last_finalized, Some(3));
        let mut recovery = vec![SettlementTx::BeginHardFaultSettlement(
            BeginHardFaultSettlementRequest {
                deployment: deployment(),
            },
        )];
        for wallet in &wallets {
            recovery.push(SettlementTx::ClaimHardFault(ClaimHardFaultRequest {
                deployment: deployment(),
                opening: replica.state().opening(wallet.public_key()).await.unwrap(),
            }));
        }
        seal_native(&db, deadline + 1, &native, &recovery).await;
        assert_eq!(status(&db).await.custody, 0);
        assert_eq!(status(&db).await.claimable, 0);
        assert_eq!(
            read(&db, &unclaimed_key(&deployment(), zero_index)).await,
            Some(Record::Unclaimed(zero_index + 1))
        );
        let mut recovered = Vec::new();
        for wallet in &wallets {
            recovered.push(
                native_balance(&db, &native, &wallet.public_key())
                    .await
                    .unwrap(),
            );
        }
        let zero_claim = SettlementTx::ClaimWithdrawal(WithdrawalClaimRequest {
            deployment: deployment(),
            start: zero_index,
            claim: proofs[&(results[3].roots.withdrawal_outputs.operations, zero_index)].clone(),
        });
        seal_native(
            &db,
            deadline + 2,
            &native,
            &[zero_claim.clone(), zero_claim],
        )
        .await;
        assert_eq!(status(&db).await.claimable, 0);
        assert_eq!(
            read(&db, &unclaimed_key(&deployment(), zero_index)).await,
            None
        );
        let old = SettlementTx::ClaimWithdrawal(WithdrawalClaimRequest {
            deployment: deployment(),
            start,
            claim: claims[zero].clone(),
        });
        let alternate = SettlementTx::ClaimWithdrawal(WithdrawalClaimRequest {
            deployment: deployment(),
            start: zero_index,
            claim: proofs[&(results[3].roots.withdrawal_outputs.operations, zero_index)].clone(),
        });
        seal_native(&db, deadline + 3, &native, &[old, alternate]).await;
        for (index, wallet) in wallets.iter().enumerate() {
            assert_eq!(
                native_balance(&db, &native, &wallet.public_key())
                    .await
                    .unwrap(),
                recovered[index]
            );
        }
        assert!(db.finalize().await.durable().await);
        drop(db);
        let db = open(context.child("reopen"), "flat-payout-proposals").await;
        for index in start..start + 4 {
            assert_eq!(read(&db, &unclaimed_key(&deployment(), index)).await, None);
        }
    });
}

#[test]
fn certified_payout_status_rejects_preissuance_splices_and_tracks_split_ranges() {
    deterministic::Runner::default().start(|context| async move {
        let mut rng = test_rng();
        let SchemeFixture {
            participants,
            schemes,
            ..
        } = scheme_mocks::fixture(&mut rng, NAMESPACE, 4);
        let db = open(context.child("ledger"), "flat-payout-status").await;
        let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
        let state = genesis_cache();
        let withdrawals = WithdrawalBatch::new(
            wallets()
                .into_iter()
                .take(3)
                .map(|wallet| {
                    SignedWithdrawal::sign(
                        deployment(),
                        state.root().digest,
                        wallet.public_key().encode(),
                        WithdrawalAction::Amount(NonZeroU64::MIN),
                        100,
                        wallet.signer(),
                    )
                })
                .collect(),
        )
        .unwrap();
        let deposits = DepositBatch::empty();
        let deposits_root = deposits.root::<Sha256>().unwrap();
        let registration = protocol
            .registration_at(0, deposits, withdrawals.clone(), 400, 11, 12)
            .unwrap();
        let result = protocol
            .fixture_complete(
                &accounts(),
                &[],
                protocol.prepare(registration, Vec::new()).unwrap(),
                41,
            )
            .unwrap();
        let start = result.context.predecessor_logs().payouts.operations;
        let index = start + 2;
        let request = req(Lookup::Unclaimed { index });
        let register = SettlementTx::RegisterEpoch(RegisterEpochRequest {
            deployment: deployment(),
            epoch: 0,
            predecessor_liability: 400,
            deposits_root,
            withdrawals: withdrawals.clone(),
            openings: withdrawals
                .requests()
                .iter()
                .map(|request| state.opening(request.account()).unwrap())
                .collect(),
            fee: 4096,
            signature: protocol.sign_chain_registration(0, 400, &deposits_root, &withdrawals, 4096),
        });
        let (before, _) = certified_read(
            &db,
            &schemes,
            participants[0].clone(),
            1,
            vec![register, SettlementTx::Admit(AdmitRequest::from(&result))],
            &request,
        )
        .await;
        let before_verified = light::verify_read::<deterministic::Context, Scheme>(
            &mut rng,
            &schemes[0],
            &request,
            &before,
        )
        .unwrap();
        assert!(before_verified.unclaimed.is_none());
        assert!(
            result.withdrawal_claims[2]
                .verify::<Sha256>(&before_verified.payout_tip.unwrap().heads.payouts)
                .is_err()
        );
        let (issued, _) = certified_read(
            &db,
            &schemes,
            participants[0].clone(),
            13,
            Vec::new(),
            &request,
        )
        .await;
        let issued_verified = light::verify_read::<deterministic::Context, Scheme>(
            &mut rng,
            &schemes[0],
            &request,
            &issued,
        )
        .unwrap();
        assert_eq!(
            issued_verified.unclaimed,
            Some(
                commonware_clearing::bajillion::settlement::UnclaimedInterval {
                    start,
                    end: start + 3
                }
            )
        );
        assert!(
            result.withdrawal_claims[2]
                .verify::<Sha256>(&issued_verified.payout_tip.unwrap().heads.payouts)
                .is_ok()
        );
        let mut splice = before.clone();
        splice.payout = issued.payout.clone();
        assert!(matches!(
            light::verify_read::<deterministic::Context, Scheme>(
                &mut rng,
                &schemes[0],
                &request,
                &splice
            ),
            Err(light::Error::Proof)
        ));
        let mut splice = issued.clone();
        splice.proof = before.proof;
        assert!(matches!(
            light::verify_read::<deterministic::Context, Scheme>(
                &mut rng,
                &schemes[0],
                &request,
                &splice
            ),
            Err(light::Error::Proof)
        ));
        let first = SettlementTx::ClaimWithdrawal(WithdrawalClaimRequest {
            deployment: deployment(),
            start,
            claim: result.withdrawal_claims[1].clone(),
        });
        let (split, _) = certified_read(
            &db,
            &schemes,
            participants[0].clone(),
            14,
            vec![
                first.clone(),
                SettlementTx::ClaimWithdrawal(WithdrawalClaimRequest {
                    deployment: deployment(),
                    start,
                    claim: result.withdrawal_claims[0].clone(),
                }),
                first,
            ],
            &request,
        )
        .await;
        assert_eq!(read(&db, &unclaimed_key(&deployment(), start)).await, None);
        let verified = light::verify_read::<deterministic::Context, Scheme>(
            &mut rng,
            &schemes[0],
            &request,
            &split,
        )
        .unwrap();
        assert_eq!(
            verified.unclaimed,
            Some(
                commonware_clearing::bajillion::settlement::UnclaimedInterval {
                    start: start + 2,
                    end: start + 3
                }
            )
        );
        let mut stale_hint_proof = split.clone();
        stale_hint_proof.proof = query::ReadProof::Absent {
            proof: db
                .read()
                .await
                .exclusion_proof(&unclaimed_key(&deployment(), start))
                .await
                .unwrap(),
        };
        assert!(matches!(
            light::verify_read::<deterministic::Context, Scheme>(
                &mut rng,
                &schemes[0],
                &request,
                &stale_hint_proof
            ),
            Err(light::Error::Proof)
        ));
        let stale = WithdrawalClaimRequest {
            deployment: deployment(),
            start,
            claim: result.withdrawal_claims[2].clone(),
        };
        let reserve = status(&db).await.claimable;
        seal_native(
            &db,
            15,
            &native(),
            &[SettlementTx::ClaimWithdrawal(stale.clone())],
        )
        .await;
        assert_eq!(status(&db).await.claimable, reserve);
        seal_native(
            &db,
            16,
            &native(),
            &[SettlementTx::ClaimWithdrawal(WithdrawalClaimRequest {
                start: start + 2,
                ..stale
            })],
        )
        .await;
        assert_eq!(status(&db).await.claimable, reserve - 1);
        assert_eq!(
            read(&db, &unclaimed_key(&deployment(), start + 2)).await,
            None
        );
    });
}

#[test]
fn fault_reads_bind_the_finalized_prefix_to_the_same_block() {
    deterministic::Runner::default().start(|context| async move {
        let mut rng = test_rng();
        let SchemeFixture {
            participants,
            schemes,
            ..
        } = scheme_mocks::fixture(&mut rng, NAMESPACE, 4);
        let db = open(context.child("ledger"), "fault-finalized-prefix").await;
        let fixture = epoch_fixture();
        let request = req(Lookup::Fault);
        let (before, _) = certified_read(
            &db,
            &schemes,
            participants[0].clone(),
            1,
            vec![fixture.deposit_tx, fixture.register_tx, fixture.admit_tx],
            &request,
        )
        .await;
        let (after, _) = certified_read(
            &db,
            &schemes,
            participants[0].clone(),
            13,
            Vec::new(),
            &request,
        )
        .await;
        for (response, finalized) in [(&before, None), (&after, Some(0))] {
            let verified = light::verify_read::<deterministic::Context, Scheme>(
                &mut rng,
                &schemes[0],
                &request,
                response,
            )
            .unwrap();
            assert_eq!(verified.record, None);
            assert_eq!(verified.payout_tip.unwrap().finalized, finalized);
        }
        let mut absent = after.clone();
        absent.payout = None;
        let mut stale = after.clone();
        stale.payout = before.payout.clone();
        let mut premature = before;
        premature.payout = after.payout;
        for response in [absent, stale, premature] {
            assert!(matches!(
                light::verify_read::<deterministic::Context, Scheme>(
                    &mut rng,
                    &schemes[0],
                    &request,
                    &response,
                ),
                Err(light::Error::Proof)
            ));
        }
    });
}

#[test]
fn retired_epoch_reads_keep_their_captured_tip_and_reject_preissuance_absence() {
    deterministic::Runner::default().start(|context| async move {
        let mut rng = test_rng();
        let SchemeFixture {
            participants,
            schemes,
            ..
        } = scheme_mocks::fixture(&mut rng, NAMESPACE, 4);
        let db = open(context.child("ledger"), "retired-epoch-reads").await;
        let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
        let first = close_fixture(
            native().chain_id(),
            &protocol,
            0,
            genesis_cache(),
            b"retired-first",
            11,
            12,
        );
        let second = close_fixture(
            native().chain_id(),
            &protocol,
            1,
            first.successor.clone(),
            b"retired-second",
            12,
            13,
        );
        let future_request = req(Lookup::Admitted { epoch: 1 });
        let (preissuance, _) = certified_read(
            &db,
            &schemes,
            participants[0].clone(),
            1,
            vec![
                first.deposit_tx.clone(),
                first.register_tx.clone(),
                first.admit_tx.clone(),
            ],
            &future_request,
        )
        .await;
        assert!(
            light::verify_read::<deterministic::Context, Scheme>(
                &mut rng,
                &schemes[0],
                &future_request,
                &preissuance
            )
            .unwrap()
            .record
            .is_none()
        );
        seal(
            &db,
            2,
            &[
                second.deposit_tx.clone(),
                second.register_tx.clone(),
                second.admit_tx.clone(),
            ],
        )
        .await;
        let historical_request = req(Lookup::Admitted { epoch: 0 });
        let (captured, _) = certified_read(
            &db,
            &schemes,
            participants[0].clone(),
            13,
            Vec::new(),
            &historical_request,
        )
        .await;
        let (latest, _) = certified_read(
            &db,
            &schemes,
            participants[0].clone(),
            14,
            Vec::new(),
            &future_request,
        )
        .await;
        commonware_runtime::reschedule().await;
        assert_eq!(read(&db, &admitted_key(&deployment(), 0)).await, None);
        assert_eq!(read(&db, &anchor_key(&deployment(), 0)).await, None);
        let historical = light::verify_read::<deterministic::Context, Scheme>(
            &mut rng,
            &schemes[0],
            &historical_request,
            &captured,
        )
        .unwrap();
        assert!(
            matches!(historical.record, Some(Record::Admitted(admitted)) if admitted.finalized)
        );
        assert_eq!(historical.payout_tip.unwrap().finalized, Some(0));
        let current = light::verify_read::<deterministic::Context, Scheme>(
            &mut rng,
            &schemes[0],
            &future_request,
            &latest,
        )
        .unwrap();
        let tip = current.payout_tip.unwrap();
        assert_eq!(tip.finalized, Some(1));
        let mut splice = preissuance.clone();
        splice.payout = latest.payout.clone();
        assert!(matches!(
            light::verify_read::<deterministic::Context, Scheme>(
                &mut rng,
                &schemes[0],
                &future_request,
                &splice
            ),
            Err(light::Error::Proof)
        ));
        let mut splice = latest;
        splice.proof = preissuance.proof;
        assert!(matches!(
            light::verify_read::<deterministic::Context, Scheme>(
                &mut rng,
                &schemes[0],
                &future_request,
                &splice
            ),
            Err(light::Error::Proof)
        ));
        let replica = replay_state(
            context.child("retained_replica"),
            crate::protocol::state_config(
                "retired-epoch-replica",
                &context,
                protocol.strategy().clone(),
            ),
            &second.successor.history,
        )
        .await;
        let epoch = SourceEpoch::<Key, Digest>::load(replica.logs(), 0)
            .await
            .unwrap();
        let proof = epoch
            .source_proof(replica.logs(), &tip.heads)
            .await
            .unwrap();
        let source = proof.verify::<Sha256, Key>(&tip.heads).unwrap();
        assert_eq!(source.context(), &first.result.context);
        assert_eq!(source.activity_range().head, tip.heads.activity);
        assert_eq!(
            source.activity_range().start,
            first.result.context.predecessor_logs().activity.operations
        );
    });
}
