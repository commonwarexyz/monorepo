use super::{Evidence, EvidenceResponse};
use crate::{protocol, rpc};
use bytes::Bytes;
use commonware_clearing::bajillion::{
    boundary::{DepositBatch, DepositRecord, SignedWithdrawal, WithdrawalAction, WithdrawalBatch},
    logs::PayoutOperation,
    payment::{SendAuthorization, VectorSendBody},
    qmdb::account_key,
    transition::{Terminal, WithdrawalClaim},
    vector::{OutEntry, OutVector},
};
use commonware_codec::{DecodeExt as _, Encode as _, EncodeSize as _};
use commonware_cryptography::{Sha256, Signer as _, sha256::Digest};
use commonware_cryptography_curve25519::signing::SigningKey;
use commonware_runtime::{Runner as _, Spawner as _, Supervisor as _, deterministic, mocks};
use commonware_utils::{NZU64, NZUsize, TestRng};
use std::num::NonZeroU64;

#[test]
fn old_payout_proof_from_maximum_native_epoch_fits_rpc_frame() {
    deterministic::Runner::default().start(old_payout_frame_from_maximum_native_epoch);
}

#[commonware_macros::boxed]
async fn old_payout_frame_from_maximum_native_epoch(context: deterministic::Context) {
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
    let initial_liability = balances
        .iter()
        .try_fold(0_u64, |total, (_, balance)| {
            total.checked_add(balance.get())
        })
        .unwrap();
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
    let deposit_total = deposits.total();
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
        .registration_at(0, deposits, withdrawals.clone(), initial_liability, 11, 12)
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
    assert_eq!(
        result.roots.row_count,
        u64::try_from(protocol::MAX_ACTIVITY_ROWS).unwrap()
    );
    let payout_position = result.context.predecessor_logs().payouts.operations;
    let replica = replica.apply(candidate).await.unwrap();

    let successor_liability = initial_liability
        .checked_add(deposit_total)
        .and_then(|total| total.checked_sub(result.withdrawal_total))
        .unwrap();
    let registration = protocol
        .registration_at(
            1,
            DepositBatch::new(Vec::new()).unwrap(),
            WithdrawalBatch::new(Vec::new()).unwrap(),
            successor_liability,
            13,
            14,
        )
        .unwrap();
    let prepared = protocol.prepare(registration, Vec::new()).unwrap();
    let (_, candidate) = Box::pin(protocol.complete(prepared, &replica, &mut TestRng::new(90_002)))
        .await
        .unwrap();
    let replica = replica.apply(candidate).await.unwrap();
    let head = replica.logs().head().payouts;
    let (opening, operations) = replica
        .logs()
        .payout_opening(&head, payout_position, NonZeroU64::MIN)
        .await
        .unwrap();
    let [PayoutOperation::Append(output)] = operations.as_slice() else {
        panic!("withdrawal output is not a native payout append")
    };
    let claim = WithdrawalClaim::new(output.clone(), opening);
    assert_eq!(claim.verify::<Sha256>(&head).unwrap(), *claim.output());

    let evidence = EvidenceResponse::Served(Evidence::Payout(claim));
    let body = evidence.encode();
    assert_eq!(body.len(), evidence.encode_size());
    assert!(
        body.len() < 4 * 1024,
        "payout authentication must not transmit unrelated epoch activity: {} bytes",
        body.len()
    );
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
