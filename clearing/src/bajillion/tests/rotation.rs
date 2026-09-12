//! Committee rotation through independently reconstructed, certified QMDB history.

use super::*;
use crate::bajillion::{
    admission::{Committee, bls12381, seal},
    qmdb::account_key,
    transition::Terminal,
};
use bytes::Bytes;
use commonware_cryptography::bls12381::primitives::variant::MinSig;
use core::num::NonZeroU64;

const OUTGOING: [u64; 4] = [1_001, 1_002, 1_003, 1_004];
const INCOMING: [u64; 4] = [1_002, 1_004, 1_005, 1_006];
const GROWN: [u64; 7] = [1_001, 1_002, 1_003, 1_004, 1_005, 1_006, 1_007];
const SHRUNK: [u64; 4] = [1_002, 1_004, 1_006, 1_008];

fn committee(seeds: &[u64]) -> (Committee, Vec<bls12381::Scheme>) {
    let keys = seeds
        .iter()
        .map(|seed| BlsPrivate::new(Scalar::from(*seed)))
        .collect::<Vec<_>>();
    let committee = Committee::new(keys.iter().map(compute_public::<MinSig>).collect()).unwrap();
    let mut schemes = keys
        .into_iter()
        .map(|key| bls12381::Scheme::signer(committee.clone(), key).unwrap())
        .collect::<Vec<_>>();
    schemes.sort_by_key(|scheme| scheme.me().unwrap());
    (committee, schemes)
}

struct Epoch {
    context: CloseContext<VerifyingKey, ShaDigest>,
    deposits: DepositBatch<VerifyingKey>,
    withdrawals: WithdrawalBatch<VerifyingKey, ShaDigest>,
    prepared: PreparedClose<VerifyingKey, ShaDigest>,
}

/// Each epoch creates one account and transfers from three existing accounts. The first
/// epoch also closes one account, so handoff must preserve both membership and absence.
async fn prepare_epoch(
    state: &TestState,
    fixture: &Fixture,
    epoch: u64,
    committee: &Committee,
) -> Epoch {
    let deployment = *fixture.context.deployment();
    let fresh = SigningKey::from_seed(40_000 + epoch).public_key();
    let deposits = DepositBatch::new(vec![DepositRecord::new(fresh, 50).unwrap()]).unwrap();
    let withdrawals = WithdrawalBatch::new(if epoch == EPOCH {
        vec![SignedWithdrawal::sign(
            deployment,
            state.root().digest,
            Bytes::from_static(b"rotation-withdrawal"),
            WithdrawalAction::Close,
            99,
            &fixture.accounts.last().unwrap().1,
        )]
    } else {
        Vec::new()
    })
    .unwrap();
    let context = EpochContext::new::<Sha256>(
        deployment,
        epoch,
        fixture.operator.public_key(),
        &deposits,
        &withdrawals,
        state.liability(),
        98,
        99,
        CloseLimits::protocol_maximum(),
        committee.commitment::<Sha256>(),
    )
    .unwrap()
    .bind::<Sha256, _, _>(state, &deposits, &withdrawals)
    .await
    .unwrap();
    let terminals = fixture.accounts[..3]
        .iter()
        .map(|(payer, private)| {
            let vector = OutVector::new(
                epoch,
                payer.clone(),
                vec![OutEntry {
                    recipient: fixture.accounts[3].0.clone(),
                    cumulative: 1,
                    count: 1,
                }],
            )
            .unwrap();
            let ack = VectorAck::sign_by_authorities(
                VectorSendBody::new(
                    context.payment(),
                    payer.clone(),
                    0,
                    1,
                    vector.root::<Sha256, ShaDigest>().unwrap(),
                ),
                private,
                &fixture.operator,
            );
            Terminal {
                authorization: SendAuthorization::from_raw_unchecked(
                    ack.body().clone(),
                    ack.payer_signature().clone(),
                ),
                vector,
                operator_signature: bls_ack(&fixture.operator_bls_private, ack.body()),
            }
        })
        .collect();
    let prepared = prepare_close_with_strategy::<Sha256, _, _, _, _>(
        state,
        &context,
        &deposits,
        &withdrawals,
        terminals,
        &Sequential,
    )
    .await
    .unwrap();
    Epoch {
        context,
        deposits,
        withdrawals,
        prepared,
    }
}

#[commonware_macros::boxed]
async fn rotate(context: deterministic::Context, outgoing: &[u64], incoming: &[u64]) {
    let fixture = fixture(context.child("operator"), 12, 3, 4, 1).await;
    let (committee_out, schemes_out) = committee(outgoing);
    let (committee_in, schemes_in) = committee(incoming);
    assert_ne!(
        committee_out.commitment::<Sha256>(),
        committee_in.commitment::<Sha256>()
    );
    let first = prepare_epoch(&fixture.state, &fixture, EPOCH, &committee_out).await;
    let first_close = first.prepared.close();
    let genesis = vec![fixture.genesis.clone()];
    let mut rng = TestRng::new(41);
    let mut votes = Vec::new();
    let mut outgoing_replicas = Vec::new();
    for (index, scheme) in schemes_out.iter().enumerate() {
        let replica = replay_state(
            context.child("outgoing"),
            &format!("outgoing-{index}"),
            &genesis,
        )
        .await
        .unwrap();
        let (vote, prepared) = seal::<Sha256, _, _, _, _, AckBatchVerifier, _>(
            scheme,
            &replica,
            &first.context,
            &fixture.operator_bls,
            &first.deposits,
            &first.withdrawals,
            first.prepared.encoded().clone(),
            &mut rng,
            &Sequential,
        )
        .await
        .unwrap();
        assert!(scheme.verify_vote(&first_close.header, &vote));
        assert_eq!(
            prepared.state().mutations(),
            first.prepared.state().mutations()
        );
        let (replica, _) = prepared.apply::<_, Sha256>(replica).await.unwrap();
        outgoing_replicas.push(replica.commit().await.unwrap());
        votes.push(vote);
    }
    let quorum_out = committee_out.quorum();
    assert!(
        schemes_out[0]
            .assemble_exact(votes[..quorum_out - 1].to_vec())
            .is_err()
    );
    assert!(schemes_out[0].assemble_exact(votes.clone()).is_err());
    let certificate_out = schemes_out[0]
        .assemble_exact(votes.into_iter().take(quorum_out))
        .unwrap();
    let verifier_out = bls12381::Scheme::verifier(committee_out);
    let verifier_in = bls12381::Scheme::verifier(committee_in.clone());
    assert_eq!(certificate_out.signers.count(), quorum_out);
    assert!(verifier_out.verify_exact(&first_close.header, &certificate_out));
    assert!(!verifier_in.verify_exact(&first_close.header, &certificate_out));
    assert!(first_close.header.verify::<Sha256, VerifyingKey>(
        &first.context,
        &first_close.roots,
        &first_close.amounts,
    ));

    let mut foreign_roots = first_close.roots;
    foreign_roots.successor = fixture.state.root();
    assert!(!first_close.header.verify::<Sha256, VerifyingKey>(
        &first.context,
        &foreign_roots,
        &first_close.amounts,
    ));

    // The accepted header authenticates the root used to check the transferred history.
    let accepted_root = first_close.roots.successor;
    let mut journal = genesis.clone();
    journal.push(Accepted {
        head: *first.prepared.state().head(),
        mutations: first.prepared.state().mutations().to_vec(),
    });
    for replica in &outgoing_replicas {
        assert_eq!(replica.root(), accepted_root);
        assert_eq!(replica.head(), &journal.last().unwrap().head);
    }
    let second = prepare_epoch(&outgoing_replicas[0], &fixture, EPOCH + 1, &committee_in).await;
    assert_eq!(*second.context.predecessor_root(), accepted_root);

    let mut incomplete = journal.clone();
    incomplete.pop();
    let mut missing_account = journal.clone();
    missing_account[0].mutations.pop();
    let mut altered_balance = journal.clone();
    let balance = altered_balance[0].mutations[0].1.unwrap().get();
    altered_balance[0].mutations[0].1 = NonZeroU64::new(balance + 1);
    let mut extra_batch = journal.clone();
    extra_batch.push(Accepted {
        head: *first.prepared.state().head(),
        mutations: Vec::new(),
    });
    let mut altered_root = journal.clone();
    altered_root.last_mut().unwrap().head = *fixture.state.head();
    for (index, untrusted) in [
        incomplete,
        missing_account,
        altered_balance,
        extra_batch,
        altered_root,
    ]
    .into_iter()
    .enumerate()
    {
        let replica = replay_state(
            context.child("untrusted"),
            &format!("untrusted-{index}"),
            &untrusted,
        )
        .await;
        if index != 0 {
            assert!(replica.is_err());
            continue;
        }
        let replica = replica.unwrap();
        assert_ne!(replica.root(), accepted_root);
        assert!(
            seal::<Sha256, _, _, _, _, AckBatchVerifier, _>(
                &schemes_in[0],
                &replica,
                &second.context,
                &fixture.operator_bls,
                &second.deposits,
                &second.withdrawals,
                second.prepared.encoded().clone(),
                &mut rng,
                &Sequential,
            )
            .await
            .is_err()
        );
    }

    let mut incoming_votes = Vec::new();
    let mut rejected = Vec::new();
    for (index, scheme) in schemes_in.iter().enumerate() {
        // One validator lacks the accepted suffix. Another has already applied it; the
        // remaining validators recover genesis and apply only the missing accepted close.
        let prefix = format!("incoming-{index}");
        let transferred = if index == 1 { &journal } else { &genesis };
        let replica = replay_state(context.child("incoming"), &prefix, transferred)
            .await
            .unwrap();
        let replica = if index == 0 {
            replica
        } else {
            drop(replica.commit().await.unwrap());

            // Already-applied mutation bodies are unavailable to the restart owner. Their
            // authenticated heads still identify the native root and operation count.
            let mut recovered_journal = journal.clone();
            recovered_journal[0].mutations.clear();
            if index == 1 {
                recovered_journal[1].mutations.clear();
            }
            replay_state(context.child("restarted"), &prefix, &recovered_journal)
                .await
                .unwrap()
        };
        if index != 0 {
            assert_eq!(replica.root(), accepted_root);
            assert_eq!(replica.head(), outgoing_replicas[0].head());
            assert_eq!(replica.head(), &journal.last().unwrap().head);
            for (account, _) in &fixture.accounts {
                let key = account_key(account).unwrap();
                assert_eq!(
                    replica.get(&key).await.unwrap(),
                    outgoing_replicas[0].get(&key).await.unwrap()
                );
                assert_eq!(
                    replica
                        .lookup(&key)
                        .await
                        .unwrap()
                        .resolve::<Sha256>(&accepted_root, &key)
                        .unwrap(),
                    replica.get(&key).await.unwrap(),
                );
            }
            let closed = account_key(&fixture.accounts.last().unwrap().0).unwrap();
            assert_eq!(replica.get(&closed).await.unwrap(), None);
            assert_eq!(
                replica
                    .lookup_at(
                        fixture.state.root(),
                        fixture.state.head().operations(),
                        &closed
                    )
                    .await
                    .unwrap()
                    .resolve::<Sha256>(&fixture.state.root(), &closed)
                    .unwrap()
                    .unwrap()
                    .get(),
                OPENING_BALANCE,
            );
            let created = SigningKey::from_seed(40_000 + EPOCH).public_key();
            assert_eq!(
                replica
                    .opening(created)
                    .await
                    .unwrap()
                    .verify::<Sha256>(&accepted_root)
                    .unwrap()
                    .get(),
                50
            );
        }
        if index == 1 {
            let encoded = second.prepared.encoded();
            let mut changed_header = encoded.to_vec();
            changed_header[0] ^= 1;
            let mut changed_body = encoded.to_vec();
            *changed_body.last_mut().unwrap() ^= 1;
            for damaged in [
                encoded.slice(..encoded.len() - 1),
                Bytes::from(changed_header),
                Bytes::from(changed_body),
            ] {
                assert!(
                    seal::<Sha256, _, _, _, _, AckBatchVerifier, _>(
                        scheme,
                        &replica,
                        &second.context,
                        &fixture.operator_bls,
                        &second.deposits,
                        &second.withdrawals,
                        damaged,
                        &mut rng,
                        &Sequential,
                    )
                    .await
                    .is_err()
                );
                assert_eq!(replica.root(), accepted_root);
            }
            assert!(
                seal::<Sha256, _, _, _, _, AckBatchVerifier, _>(
                    &schemes_out[0],
                    &replica,
                    &second.context,
                    &fixture.operator_bls,
                    &second.deposits,
                    &second.withdrawals,
                    second.prepared.encoded().clone(),
                    &mut rng,
                    &Sequential,
                )
                .await
                .is_err()
            );
        }
        match seal::<Sha256, _, _, _, _, AckBatchVerifier, _>(
            scheme,
            &replica,
            &second.context,
            &fixture.operator_bls,
            &second.deposits,
            &second.withdrawals,
            second.prepared.encoded().clone(),
            &mut rng,
            &Sequential,
        )
        .await
        {
            Ok((vote, prepared)) => {
                assert_ne!(index, 0);
                assert!(verifier_in.verify_vote(&second.prepared.close().header, &vote));
                assert_eq!(
                    prepared.state().mutations(),
                    second.prepared.state().mutations()
                );
                let (replica, _) = prepared.apply::<_, Sha256>(replica).await.unwrap();
                let replica = replica.commit().await.unwrap();
                assert_eq!(replica.root(), second.prepared.close().roots.successor);
                assert_eq!(replica.head(), second.prepared.state().head());
                incoming_votes.push(vote);
            }
            Err(_) => rejected.push(index),
        }
    }
    assert_eq!(rejected, vec![0]);
    assert_eq!(incoming_votes.len(), incoming.len() - 1);
    assert!(
        incoming_votes
            .iter()
            .all(|vote| Some(vote.signer) != schemes_in[0].me())
    );
    let quorum_in = committee_in.quorum();
    let certificate_in = schemes_in[1]
        .assemble_exact(incoming_votes.into_iter().take(quorum_in))
        .unwrap();
    let header_next = &second.prepared.close().header;
    assert_eq!(certificate_in.signers.count(), quorum_in);
    assert!(verifier_in.verify_exact(header_next, &certificate_in));
    assert!(!verifier_out.verify_exact(header_next, &certificate_in));
    assert!(!verifier_in.verify_exact(&first_close.header, &certificate_in));
    assert!(!verifier_out.verify_exact(header_next, &certificate_out));
}

#[test]
fn committee_rotation_reconstructs_certified_full_replicas() {
    deterministic::Runner::seeded(7).start(|context| async move {
        rotate(context, &OUTGOING, &INCOMING).await;
    });
}

#[test]
fn committee_rotation_grows_with_independent_full_replicas() {
    deterministic::Runner::seeded(8).start(|context| async move {
        rotate(context, &OUTGOING, &GROWN).await;
    });
}

#[test]
fn committee_rotation_shrinks_with_independent_full_replicas() {
    deterministic::Runner::seeded(9).start(|context| async move {
        rotate(context, &GROWN, &SHRUNK).await;
    });
}
