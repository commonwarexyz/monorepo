use super::*;
use commonware_clearing::bajillion::{
    logs::{LogHead, PayoutOperation},
    settlement::ClaimedRange,
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

async fn claimed_record_count(db: &Database<deterministic::Context>, end: u64) -> usize {
    let mut records = 0;
    for index in 1..end {
        records += usize::from(matches!(
            read(db, &claimed_key(&deployment(), index)).await,
            Some(Record::Claimed(_))
        ));
    }
    records
}

async fn unpaid_append_count(
    db: &Database<deterministic::Context>,
    claims: &[WithdrawalClaim<Digest>],
) -> usize {
    let mut unpaid = 0;
    for claim in claims {
        unpaid += usize::from(claimed(db, claim.position()).await.is_none());
    }
    unpaid
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
                crate::protocol::fixture_page_cache(&context),
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
        let mut first_claims = Vec::new();
        let mut liability = genesis.liability();
        for epoch in 0..4 {
            let boundary = if epoch == 0 {
                withdrawals.clone()
            } else {
                WithdrawalBatch::empty()
            };
            let deposits = DepositBatch::empty();
            let root = deposits.root::<Sha256>().unwrap();
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
            if epoch == 0 {
                let start = result.context.predecessor_logs().payouts.operations;
                for position in start..start + 4 {
                    let output = replica.logs().payout_at(position).await.unwrap();
                    let (opening, _) = replica
                        .logs()
                        .payout_opening(&result.roots.withdrawal_outputs, position, NonZeroU64::MIN)
                        .await
                        .unwrap();
                    first_claims.push(WithdrawalClaim::new(output, opening));
                }
            }
            seal_native(
                &db,
                epoch + 1,
                &native,
                &[register, SettlementTx::Admit(AdmitRequest::from(&result))],
            )
            .await;
            liability = liability.checked_sub(result.withdrawal_total).unwrap();
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
            payouts: results[0].roots.withdrawal_outputs,
            finalized: Some(0),
        };
        assert_eq!(first_tip.encode().len(), 57);
        assert_eq!(
            crate::protocol::PayoutTip::decode(first_tip.encode()).unwrap(),
            first_tip
        );
        let claims = &first_claims;
        assert_eq!(claims.len(), 4);
        assert_eq!(
            claims
                .iter()
                .filter(|claim| claim.output().amount() == 0)
                .count(),
            1
        );
        let start = results[0].context.predecessor_logs().payouts.operations;
        let first_commit = start + claims.len() as u64;
        assert_eq!(
            claimed(&db, first_commit).await,
            Some(ClaimedRange {
                start: first_commit,
                end: first_commit + 1,
            })
        );
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
            let observed = claims[positions[0]].position();
            let transactions = positions
                .iter()
                .map(|position| {
                    SettlementTx::ClaimWithdrawal(WithdrawalClaimRequest {
                        deployment: deployment(),
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
            assert!(claimed(&db, observed).await.is_none());
            parent = proposed.block;
            db.apply(proposed.merkleized).await;
            assert!(claimed(&db, observed).await.is_some());
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
        let settled_end = results[3].roots.withdrawal_outputs.operations;
        assert_eq!(claimed(&db, zero_index).await, None);
        assert!(zero_index > start && zero_index + 1 < settled_end);
        let left = claimed(&db, zero_index - 1).await.unwrap();
        let right = claimed(&db, zero_index + 1).await.unwrap();
        assert_eq!(
            left,
            ClaimedRange {
                start,
                end: zero_index
            }
        );
        assert_eq!(
            right,
            ClaimedRange {
                start: zero_index + 1,
                end: settled_end,
            }
        );
        assert_eq!(read(&db, &claimed_key(&deployment(), 0)).await, None);
        assert_eq!(
            read(&db, &claimed_key(&deployment(), left.start)).await,
            Some(Record::Claimed(left.end))
        );
        assert_eq!(
            read(&db, &claimed_key(&deployment(), right.start)).await,
            Some(Record::Claimed(right.end))
        );
        for result in &results {
            assert_eq!(
                claimed(&db, result.roots.withdrawal_outputs.operations - 1).await,
                Some(right)
            );
        }
        let unpaid = unpaid_append_count(&db, claims).await;
        let range_records = claimed_record_count(&db, settled_end).await;
        assert_eq!((unpaid, range_records), (1, 2));
        assert_eq!(range_records, unpaid + 1);
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
        assert_eq!(claimed(&db, zero_index - 1).await, Some(left));
        assert_eq!(claimed(&db, zero_index + 1).await, Some(right));
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
            claimed(&db, zero_index).await,
            Some(ClaimedRange {
                start,
                end: settled_end,
            })
        );
        assert_eq!(
            read(&db, &claimed_key(&deployment(), right.start)).await,
            None
        );
        let unpaid = unpaid_append_count(&db, claims).await;
        let range_records = claimed_record_count(&db, settled_end).await;
        assert_eq!((unpaid, range_records), (0, 1));
        assert_eq!(range_records, unpaid + 1);
        let old = SettlementTx::ClaimWithdrawal(WithdrawalClaimRequest {
            deployment: deployment(),
            claim: claims[zero].clone(),
        });
        let alternate = SettlementTx::ClaimWithdrawal(WithdrawalClaimRequest {
            deployment: deployment(),
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
            assert_eq!(
                claimed(&db, index).await,
                Some(ClaimedRange {
                    start,
                    end: settled_end,
                })
            );
        }
        assert_eq!(
            read(&db, &claimed_key(&deployment(), start + 1)).await,
            None
        );
        assert_eq!(claimed_record_count(&db, settled_end).await, 1);
    });
}

#[test]
fn certified_payout_status_rejects_preissuance_splices_and_tracks_claimed_merges() {
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
        let balances = replay_state(
            context.child("payout_status_validator"),
            crate::protocol::state_config(
                "payout_status_validator",
                crate::protocol::fixture_page_cache(&context),
                protocol.strategy().clone(),
            ),
            &state.history,
        )
        .await;
        let (result, candidate) = protocol
            .complete(
                protocol.prepare(registration, Vec::new()).unwrap(),
                &balances,
                &mut TestRng::new(41),
            )
            .await
            .unwrap();
        let start = result.context.predecessor_logs().payouts.operations;
        let balances = balances.apply(candidate).await.unwrap();
        let mut claims = Vec::new();
        for position in start..start + 3 {
            let output = balances.logs().payout_at(position).await.unwrap();
            let (opening, _) = balances
                .logs()
                .payout_opening(&result.roots.withdrawal_outputs, position, NonZeroU64::MIN)
                .await
                .unwrap();
            claims.push(WithdrawalClaim::new(output, opening));
        }
        let index = start + 1;
        let request = req(Lookup::Claimed { index });
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
        assert!(before_verified.claimed.is_none());
        assert!(
            claims[1]
                .verify::<Sha256>(&before_verified.payout_tip.unwrap().payouts)
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
        assert!(issued_verified.claimed.is_none());
        assert!(
            claims[1]
                .verify::<Sha256>(&issued_verified.payout_tip.unwrap().payouts)
                .is_ok()
        );
        assert_eq!(
            claimed(&db, start + 3).await,
            Some(ClaimedRange {
                start: start + 3,
                end: start + 4,
            })
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
            claim: claims[1].clone(),
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
                    claim: claims[0].clone(),
                }),
                first,
            ],
            &request,
        )
        .await;
        let verified = light::verify_read::<deterministic::Context, Scheme>(
            &mut rng,
            &schemes[0],
            &request,
            &split,
        )
        .unwrap();
        assert_eq!(
            verified.claimed,
            Some(ClaimedRange {
                start,
                end: start + 2,
            })
        );
        assert_eq!(
            read(&db, &claimed_key(&deployment(), start)).await,
            Some(Record::Claimed(start + 2))
        );
        let unpaid = unpaid_append_count(&db, &claims).await;
        let range_records = claimed_record_count(&db, start + 4).await;
        assert_eq!((unpaid, range_records), (1, 2));
        assert_eq!(range_records, unpaid + 1);
        assert!(db.finalize().await.durable().await);
        drop(db);
        let db = open(context.child("fragmented_reopen"), "flat-payout-status").await;
        assert_eq!(
            claimed(&db, index).await,
            Some(ClaimedRange {
                start,
                end: start + 2,
            })
        );
        assert_eq!(claimed(&db, start + 2).await, None);
        assert_eq!(
            claimed(&db, start + 3).await,
            Some(ClaimedRange {
                start: start + 3,
                end: start + 4,
            })
        );
        let unpaid = unpaid_append_count(&db, &claims).await;
        let range_records = claimed_record_count(&db, start + 4).await;
        assert_eq!((unpaid, range_records), (1, 2));
        assert_eq!(range_records, unpaid + 1);
        let last = WithdrawalClaimRequest {
            deployment: deployment(),
            claim: claims[2].clone(),
        };
        let reserve = status(&db).await.claimable;
        let exact_request = req(Lookup::Claimed { index: start });
        let (merged, _) = certified_read(
            &db,
            &schemes,
            participants[0].clone(),
            15,
            vec![
                SettlementTx::ClaimWithdrawal(last.clone()),
                SettlementTx::ClaimWithdrawal(last),
            ],
            &exact_request,
        )
        .await;
        assert_eq!(status(&db).await.claimable, reserve - 1);
        let merged = light::verify_read::<deterministic::Context, Scheme>(
            &mut rng,
            &schemes[0],
            &exact_request,
            &merged,
        )
        .unwrap();
        assert_eq!(
            merged.claimed,
            Some(ClaimedRange {
                start,
                end: start + 4,
            })
        );
        assert_eq!(claimed(&db, start + 2).await, merged.claimed);
        assert_eq!(
            read(&db, &claimed_key(&deployment(), start + 3)).await,
            None
        );
        let unpaid = unpaid_append_count(&db, &claims).await;
        let range_records = claimed_record_count(&db, start + 4).await;
        assert_eq!((unpaid, range_records), (0, 1));
        assert_eq!(range_records, unpaid + 1);
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
    });
}
