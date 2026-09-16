//! Native sync responses remain within the single-frame RPC contract.

use super::*;
use crate::{chain::da::tests::Fixture, protocol::Wallet};
use commonware_clearing::bajillion::{
    logs::{ActivityRecord, Floors},
    payment::{PaymentContext, SendAuthorization, VectorSendBody},
    state::{AccountChange, AccountRow, SettlementOutput},
    vector::{OutEntry, OutVector},
};
use commonware_codec::{EncodeSize as _, FixedSize};
use commonware_runtime::{Runner as _, deterministic};
use commonware_storage::merkle::{Family as _, MAX_PROOF_DIGESTS_PER_ELEMENT};

#[test]
fn maximum_fixed_activity_page_fits_one_rpc_frame() {
    let payer = Wallet::from_seed("max-row-payer", 1);
    let recipient = Wallet::from_seed("max-row-recipient", 2);
    let entry = OutEntry {
        recipient: recipient.public_key(),
        cumulative: u64::MAX,
        count: u64::MAX,
    };
    let vector = OutVector::new(u64::MAX, payer.public_key(), vec![entry.clone()]).unwrap();
    let send_root = vector.root::<Sha256, Digest>().unwrap();
    let context = PaymentContext::new(Digest::from([0xff; 32]), u64::MAX, payer.public_key());
    let body = VectorSendBody::new(&context, payer.public_key(), u64::MAX, u64::MAX, send_root);
    let row = AccountRow {
        account: payer.public_key(),
        predecessor: u64::MAX,
        successor: u64::MAX,
        outgoing: Some(SendAuthorization::sign(body, payer.signer())),
        output: SettlementOutput::Withdrawal(u64::MAX),
    };
    let row = ActivityRecord::Row(AccountChange::from_row(&row, send_root));
    let entry = ActivityRecord::<Key, Digest>::Entry(entry);
    assert_eq!(row.encode_size(), 81);
    assert_eq!(entry.encode_size(), 49);
    let append = u8::SIZE + row.encode_size().max(entry.encode_size());
    let commit = 2 * u8::SIZE + mmr::Family::MAX_LEAVES.encode_size();
    let operation = append.max(commit);
    assert_eq!(append, 82);

    let proof_digests = FETCH_OPERATIONS * MAX_PROOF_DIGESTS_PER_ELEMENT;
    let proof_envelope = mmr::Family::MAX_LEAVES.encode_size()
        + (u32::MAX as usize).encode_size()
        + proof_digests.encode_size();
    let operations = FETCH_OPERATIONS * operation;
    let sync_response = u8::SIZE
        + proof_envelope
        + proof_digests * Digest::SIZE
        + FETCH_OPERATIONS.encode_size()
        + operations;
    let native_response = NativeResponse::Data(Bytes::from(vec![0; sync_response])).encode_size();
    let rpc_response = rpc::Response::Success {
        body: Bytes::from(vec![0; native_response]),
    }
    .encode_size();
    let framed_response = rpc_response.encode_size() + rpc_response;

    assert!(native_response <= rpc::MAX_BODY_SIZE);
    assert!(framed_response < rpc::MAX_FRAME_SIZE as usize);
}

#[test]
fn payout_predecessor_scans_past_the_first_reverse_page() {
    deterministic::Runner::default().start(|context| async move {
        let mut fixture = Fixture::new(&context, "payout-predecessor-pages", 130).await;
        let (empty, _, prepared) = fixture
            .prepare(
                0,
                0,
                Floors {
                    activity: 0,
                    payouts: 0,
                },
            )
            .await;
        fixture.candidate(empty, prepared).await;
        fixture.promote().await;
        let complete = fixture.lane.manifest().complete().checkpoint.clone();
        let preceding_commit = complete.head.logs.payouts.operations - 1;

        let (full, _, prepared) = fixture
            .prepare(
                0,
                130,
                Floors {
                    activity: 0,
                    payouts: 0,
                },
            )
            .await;
        fixture.candidate(full.clone(), prepared).await;
        assert!(
            full.roots.withdrawal_outputs.operations - preceding_commit > FETCH_OPERATIONS as u64
        );
        let found = payout_predecessor(
            fixture.lane.state.as_ref().unwrap().logs().payout_source(),
            &full.roots.withdrawal_outputs,
            complete.retained.payouts,
        )
        .await
        .unwrap();
        assert_eq!(found, preceding_commit);
    });
}
