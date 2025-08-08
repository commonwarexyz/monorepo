//! Any protocol adapter; now delegates wire shape to generic net::wire types.

use crate::net;
use crate::net::wire;
use crate::net::RequestId;
use crate::Operation;
use commonware_cryptography::sha256::Digest;
use commonware_storage::adb::sync::Target;
use commonware_storage::mmr::verification::Proof;
use std::num::NonZeroU64;

pub type Message = wire::Message<Operation, Digest>;
type GetOperationsRequest = wire::GetOperationsRequest;
type GetSyncTargetRequest = wire::GetSyncTargetRequest;

/// Implement Protocol adapter for Any protocol
#[derive(Clone)]
pub struct AnyProtocol;

impl net::Protocol for AnyProtocol {
    type Digest = Digest;
    type Op = crate::Operation;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{ErrorCode, Requester};
    use commonware_codec::{DecodeExt as _, Encode as _};
    use commonware_utils::NZU64;

    #[test]
    fn test_request_id_generation() {
        let requester = Requester::new();
        let id1 = requester.next();
        let id2 = requester.next();
        let id3 = requester.next();

        // Request IDs should be monotonically increasing
        assert!(id2 > id1);
        assert!(id3 > id2);

        // Should be consecutive since we're using a single Requester
        assert_eq!(id2, id1 + 1);
        assert_eq!(id3, id2 + 1);
    }

    #[test]
    fn test_error_code_roundtrip_serialization() {
        let test_cases = vec![
            ErrorCode::InvalidRequest,
            ErrorCode::DatabaseError,
            ErrorCode::NetworkError,
            ErrorCode::Timeout,
            ErrorCode::InternalError,
        ];

        for error_code in test_cases {
            // Serialize
            let encoded = error_code.encode().to_vec();

            // Deserialize
            let decoded = ErrorCode::decode(&encoded[..]).expect("Failed to decode ErrorCode");

            // Verify they match
            match (&error_code, &decoded) {
                (ErrorCode::InvalidRequest, ErrorCode::InvalidRequest) => {}
                (ErrorCode::DatabaseError, ErrorCode::DatabaseError) => {}
                (ErrorCode::NetworkError, ErrorCode::NetworkError) => {}
                (ErrorCode::Timeout, ErrorCode::Timeout) => {}
                (ErrorCode::InternalError, ErrorCode::InternalError) => {}
                _ => panic!("ErrorCode roundtrip failed: {error_code:?} != {decoded:?}"),
            }
        }
    }

    #[test]
    fn test_get_operations_request_validation() {
        // Valid request
        let requester = Requester::new();
        let request = GetOperationsRequest {
            request_id: requester.next(),
            size: 100,
            start_loc: 10,
            max_ops: NZU64!(50),
        };
        assert!(request.validate().is_ok());

        // Invalid start_loc
        let request = GetOperationsRequest {
            request_id: requester.next(),
            size: 100,
            start_loc: 100,
            max_ops: NZU64!(50),
        };
        assert!(matches!(
            request.validate(),
            Err(crate::Error::InvalidRequest(_))
        ));

        // start_loc beyond size
        let request = GetOperationsRequest {
            request_id: requester.next(),
            size: 100,
            start_loc: 150,
            max_ops: NZU64!(50),
        };
        assert!(matches!(
            request.validate(),
            Err(crate::Error::InvalidRequest(_))
        ));
    }
}
