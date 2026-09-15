//! Native sync responses remain within the single-frame RPC contract.

use super::*;
use crate::protocol::{
    MAX_ACCEPTED_PAYMENTS, MAX_ACTIVITY_ROWS, MAX_DESTINATION_BYTES, MAX_WITHDRAWALS,
};
use commonware_clearing::bajillion::{
    state::ChangeGuard, transition::CloseContext, vector::OutEntry,
};
use commonware_codec::{EncodeSize as _, FixedSize};
use commonware_cryptography::Verifier;
use commonware_storage::merkle::{Family as _, MAX_PROOF_DIGESTS_PER_ELEMENT};

fn maximum_signed_withdrawal_size() -> usize {
    type AccountSignature = <Key as Verifier>::Signature;

    Key::SIZE
        + 2 * Digest::SIZE
        + MAX_DESTINATION_BYTES.encode_size()
        + MAX_DESTINATION_BYTES
        + u8::SIZE
        + u64::SIZE
        + u64::SIZE
        + AccountSignature::SIZE
}

/// Conservative maximum for one terminal
/// [`SourceMetadata`](commonware_clearing::bajillion::custody::SourceMetadata) payload.
pub(crate) fn maximum_source_metadata_size() -> usize {
    let limits = crate::protocol::limits();
    let rows = usize::try_from(limits.max_rows()).expect("terminal row limit fits usize");
    let withdrawals =
        usize::try_from(limits.max_withdrawals()).expect("terminal withdrawal limit fits usize");
    let entries_per_account = usize::try_from(limits.max_account_entries())
        .expect("terminal per-account entry limit fits usize");
    let entries = usize::try_from(limits.max_total_entries())
        .expect("terminal aggregate entry limit fits usize");

    CloseContext::<Key, Digest>::SIZE
        + rows.encode_size()
        + rows * (u64::SIZE + entries_per_account.encode_size())
        + entries * OutEntry::<Key>::SIZE
        + withdrawals.encode_size()
        + withdrawals * maximum_signed_withdrawal_size()
}

#[test]
fn maximum_activity_sync_response_fits_one_rpc_frame() {
    let limits = crate::protocol::limits();
    assert_eq!(limits.max_rows(), MAX_ACTIVITY_ROWS as u64);
    assert_eq!(limits.max_withdrawals(), MAX_WITHDRAWALS as u64);
    assert_eq!(limits.max_account_entries(), MAX_ACCEPTED_PAYMENTS as u64);
    assert_eq!(limits.max_total_entries(), MAX_ACCEPTED_PAYMENTS as u64);

    let entries_per_account = MAX_ACCEPTED_PAYMENTS;
    let fixed_metadata = CloseContext::<Key, Digest>::SIZE
        + MAX_ACTIVITY_ROWS.encode_size()
        + MAX_WITHDRAWALS.encode_size();
    let row_envelope = u64::SIZE + entries_per_account.encode_size();
    let signed_withdrawal = maximum_signed_withdrawal_size();

    // The first Commit may describe Guards before the requested range, so it carries one complete
    // maximum close. Every later Commit's Guards are also in this response: across them there are
    // at most FETCH_OPERATIONS rows and withdrawals. Bounding every such row at the per-account
    // entry maximum is deliberately conservative even though each close also has an aggregate cap.
    let first_metadata = maximum_source_metadata_size();
    let later_metadata = FETCH_OPERATIONS
        * (fixed_metadata
            + row_envelope
            + entries_per_account * OutEntry::<Key>::SIZE
            + signed_withdrawal);

    // A Guard Append is the largest operation envelope after excluding Commit metadata itself.
    // Verify that it also covers the maximum Commit framing: operation/option/record tags, byte
    // length, and the largest native floor location.
    let operation_envelope = 2 * u8::SIZE + ChangeGuard::<Key, Digest>::SIZE;
    let commit_envelope =
        3 * u8::SIZE + first_metadata.encode_size() + mmr::Family::MAX_LEAVES.encode_size();
    assert!(commit_envelope <= operation_envelope);

    let proof_digests = FETCH_OPERATIONS * MAX_PROOF_DIGESTS_PER_ELEMENT;
    let proof_envelope = mmr::Family::MAX_LEAVES.encode_size()
        + (u32::MAX as usize).encode_size()
        + proof_digests.encode_size();
    let operations = first_metadata + later_metadata + FETCH_OPERATIONS * operation_envelope;
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

    assert_eq!(first_metadata, 535_988);
    assert!(native_response <= rpc::MAX_BODY_SIZE);
    assert!(framed_response < rpc::MAX_FRAME_SIZE as usize);
}
