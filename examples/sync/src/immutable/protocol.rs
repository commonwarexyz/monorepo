//! Immutable protocol adapter; delegates to generic net::wire types.

use crate::immutable::Operation;
use crate::net;
use crate::net::wire;
use crate::net::RequestId;
use commonware_cryptography::sha256::Digest;
use commonware_storage::adb::sync::Target;
use commonware_storage::mmr::verification::Proof;
use std::num::NonZeroU64;

pub type Message = wire::Message<Operation, Digest>;
type GetOperationsRequest = wire::GetOperationsRequest;
type GetSyncTargetRequest = wire::GetSyncTargetRequest;

/// Protocol adapter for Immutable protocol
#[derive(Clone)]
pub struct ImmutableProtocol;

impl net::Protocol for ImmutableProtocol {
    type Digest = Digest;
    type Op = Operation;
    type Message = Message;

    fn make_get_target(request_id: RequestId) -> Self::Message {
        Message::GetSyncTargetRequest(GetSyncTargetRequest { request_id })
    }

    fn parse_get_target_response(msg: Self::Message) -> Result<Target<Self::Digest>, crate::Error> {
        match msg {
            Message::GetSyncTargetResponse(r) => Ok(r.target),
            Message::Error(err) => Err(crate::Error::Server {
                code: err.error_code,
                message: err.message,
            }),
            other => Err(crate::Error::UnexpectedResponse {
                request_id: other.request_id(),
            }),
        }
    }

    fn make_get_ops(
        request_id: RequestId,
        size: u64,
        start_loc: u64,
        max_ops: NonZeroU64,
    ) -> Self::Message {
        Message::GetOperationsRequest(GetOperationsRequest {
            request_id,
            size,
            start_loc,
            max_ops,
        })
    }

    fn parse_get_ops_response(
        msg: Self::Message,
    ) -> Result<(Proof<Self::Digest>, Vec<Self::Op>), crate::Error> {
        match msg {
            Message::GetOperationsResponse(r) => Ok((r.proof, r.operations)),
            Message::Error(err) => Err(crate::Error::Server {
                code: err.error_code,
                message: err.message,
            }),
            other => Err(crate::Error::UnexpectedResponse {
                request_id: other.request_id(),
            }),
        }
    }
}
