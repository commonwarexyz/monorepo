use super::{Evidence, EvidenceResponse};
use crate::{protocol, rpc};
use bytes::Bytes;
use commonware_clearing::bajillion::{
    boundary::{DepositBatch, DepositRecord, SignedWithdrawal, WithdrawalAction, WithdrawalBatch},
    custody::{Epoch, SourceMetadata},
    payment::{SendAuthorization, VectorSendBody},
    qmdb::account_key,
    transition::Terminal,
    vector::{OutEntry, OutVector},
};
use commonware_codec::{DecodeExt as _, Encode as _, EncodeSize as _};
use commonware_cryptography::{Sha256, Signer as _, sha256::Digest};
use commonware_cryptography_curve25519::signing::SigningKey;
use commonware_runtime::{Runner as _, Spawner as _, Supervisor as _, deterministic, mocks};
use commonware_utils::{NZU64, NZUsize, TestRng};

#[test]
fn maximum_native_source_proof_round_trips_through_rpc_frame() {
    deterministic::Runner::default().start(maximum_native_source_frame);
}

#[commonware_macros::boxed]
async fn maximum_native_source_frame(context: deterministic::Context) {
    let protocol = protocol::Protocol::new(NZUsize!(1)).unwrap();
    let mut signers = (0..protocol::MAX_ACTIVITY_ROWS)
        .map(|index| SigningKey::from_seed(90_000 + index as u64))
        .collect::<Vec<_>>();
    signers.sort_unstable_by_key(SigningKey::public_key);
    let mut balances = signers
        .iter()
        .map(|signer| (account_key(&signer.public_key()).unwrap(), NZU64!(10)))
        .collect::<Vec<_>>();
    balances.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    let replica = protocol::init_replica(
        context.child("replica"),
        "source-frame",
        protocol.strategy().clone(),
        balances,
    )
    .await
    .unwrap();
    let entries = protocol::MAX_ACCEPTED_PAYMENTS;
    let depositors = &signers[2 * entries..2 * entries + protocol::MAX_DEPOSIT_EVENTS];
    let withdrawal_signers = &signers[2 * entries + protocol::MAX_DEPOSIT_EVENTS..];
    let deposits = DepositBatch::new(
        depositors
            .iter()
            .map(|signer| DepositRecord::new(signer.public_key(), 1).unwrap())
            .collect(),
    )
    .unwrap();
    let withdrawals = WithdrawalBatch::new(
        withdrawal_signers
            .iter()
            .map(|signer| {
                SignedWithdrawal::sign(
                    protocol.deployment(),
                    replica.state().root().digest,
                    Bytes::from(vec![0xa5; protocol::MAX_DESTINATION_BYTES]),
                    WithdrawalAction::Amount(NZU64!(1)),
                    100,
                    signer,
                )
            })
            .collect(),
    )
    .unwrap();
    let registration = protocol
        .registration_at(
            0,
            deposits,
            withdrawals.clone(),
            replica.state().liability(),
            11,
            12,
        )
        .unwrap();
    let terminals = signers[..entries]
        .iter()
        .zip(&signers[entries..2 * entries])
        .map(|(payer, recipient)| {
            let vector = OutVector::new(
                0,
                payer.public_key(),
                vec![OutEntry {
                    recipient: recipient.public_key(),
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
            Terminal {
                operator_signature: protocol.sign_ack_aggregate(&body),
                authorization: SendAuthorization::sign(body, payer),
                vector,
            }
        })
        .collect();
    let prepared = protocol.prepare(registration, terminals).unwrap();
    let (result, candidate) =
        Box::pin(protocol.complete(prepared, &replica, &mut TestRng::new(90_001)))
            .await
            .unwrap();
    assert_eq!(result.rows, protocol::MAX_ACTIVITY_ROWS);
    let replica = replica.apply(candidate).await.unwrap();
    let heads = *replica.logs().head();
    let epoch = Epoch::<protocol::Key, Digest>::load(replica.logs(), 0)
        .await
        .unwrap();
    let proof = epoch.source_proof(replica.logs(), &heads).await.unwrap();
    let metadata = SourceMetadata::<protocol::Key, Digest>::decode(proof.metadata.clone()).unwrap();
    assert_eq!(metadata.rows().len(), protocol::MAX_ACTIVITY_ROWS);
    assert_eq!(
        metadata
            .rows()
            .iter()
            .map(|row| row.entries().len())
            .sum::<usize>(),
        protocol::MAX_ACCEPTED_PAYMENTS,
    );
    assert_eq!(metadata.withdrawals(), &withdrawals);
    assert!(
        metadata.withdrawals().requests().iter().all(|request| {
            request.body().destination().len() == protocol::MAX_DESTINATION_BYTES
        })
    );
    assert!(proof.metadata.len() > protocol::MIN_DEALING_BYTES as usize);
    assert!(proof.metadata.len() <= crate::chain::da::sync::tests::maximum_source_metadata_size());
    let source = proof.verify::<Sha256, protocol::Key>(&heads).unwrap();
    assert_eq!(source.context().deployment(), &protocol.deployment());
    assert_eq!(source.context().payment().epoch(), 0);

    let evidence = EvidenceResponse::Served(Evidence::Source(proof));
    let body = evidence.encode();
    assert_eq!(body.len(), evidence.encode_size());
    assert!(body.len() <= rpc::MAX_BODY_SIZE);
    assert_eq!(EvidenceResponse::decode(body.clone()).unwrap(), evidence);
    let response = rpc::Response::Success { body };
    assert!(response.encode_size() <= rpc::MAX_FRAME_SIZE as usize);
    let (mut sink, mut stream) = mocks::Channel::init();
    let outgoing = response.clone();
    let send = context.child("sender").spawn(move |_| async move {
        rpc::send_response(&mut sink, &outgoing).await.unwrap();
    });
    assert_eq!(rpc::recv_response(&mut stream).await.unwrap(), response);
    send.await.unwrap();
}
