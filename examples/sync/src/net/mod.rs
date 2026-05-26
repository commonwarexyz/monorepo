use commonware_codec::{DecodeExt, Encode, EncodeSize, Error, Read, ReadExt, ReadRangeExt, Write};
use commonware_runtime::{Buf, BufMut};
use std::mem::size_of;

/// Maximum message size in bytes (10MB).
pub const MAX_MESSAGE_SIZE: u32 = 10 * 1024 * 1024;

pub mod request_id;
pub use request_id::RequestId;
pub mod io;
pub mod resolver;
pub mod wire;
pub use resolver::Resolver;

/// A message that can be sent over the wire.
pub(super) trait Message: Encode + DecodeExt<()> + Sized + Send + Sync + 'static {
    fn request_id(&self) -> RequestId;
}

/// Error codes for protocol errors.
#[derive(Debug, Clone)]
pub enum ErrorCode {
    /// Invalid request parameters.
    InvalidRequest,
    /// Database error occurred.
    DatabaseError,
    /// Network error occurred.
    NetworkError,
    /// Compact target went stale and should be retried.
    StaleTarget,
    /// Request timeout.
    Timeout,
    /// Internal server error.
    InternalError,
}

impl Write for ErrorCode {
    fn write(&self, buf: &mut impl BufMut) {
        let discriminant = match self {
            Self::InvalidRequest => 0u8,
            Self::DatabaseError => 1u8,
            Self::NetworkError => 2u8,
            Self::StaleTarget => 3u8,
            Self::Timeout => 4u8,
            Self::InternalError => 5u8,
        };
        discriminant.write(buf);
    }
}

impl EncodeSize for ErrorCode {
    fn encode_size(&self) -> usize {
        size_of::<u8>()
    }
}

impl Read for ErrorCode {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let discriminant = u8::read(buf)?;
        match discriminant {
            0 => Ok(Self::InvalidRequest),
            1 => Ok(Self::DatabaseError),
            2 => Ok(Self::NetworkError),
            3 => Ok(Self::StaleTarget),
            4 => Ok(Self::Timeout),
            5 => Ok(Self::InternalError),
            _ => Err(Error::InvalidEnum(discriminant)),
        }
    }
}

/// Error from the server.
#[derive(Debug, Clone)]
pub struct ErrorResponse {
    /// Unique identifier matching the original request.
    pub request_id: RequestId,
    /// Error code.
    pub error_code: ErrorCode,
    /// Human-readable error message.
    pub message: String,
}

impl Write for ErrorResponse {
    fn write(&self, buf: &mut impl BufMut) {
        self.request_id.write(buf);
        self.error_code.write(buf);
        self.message.as_bytes().to_vec().write(buf);
    }
}

impl EncodeSize for ErrorResponse {
    fn encode_size(&self) -> usize {
        self.request_id.encode_size()
            + self.error_code.encode_size()
            + self.message.as_bytes().to_vec().encode_size()
    }
}

impl Read for ErrorResponse {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let request_id = RequestId::read_cfg(buf, &())?;
        let error_code = ErrorCode::read(buf)?;
        let message_bytes = Vec::<u8>::read_range(buf, 0..=MAX_MESSAGE_SIZE as usize)?;
        let message = String::from_utf8(message_bytes)
            .map_err(|_| Error::Invalid("ErrorResponse", "invalid UTF-8 in message"))?;
        Ok(Self {
            request_id,
            error_code,
            message,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        keyless_compact,
        net::{request_id::Generator, wire, wire::GetOperationsRequest, ErrorCode},
    };
    use commonware_codec::{DecodeExt as _, Encode as _};
    use commonware_cryptography::sha256;
    use commonware_storage::{mmr::Location, qmdb::sync::compact::State};
    use commonware_utils::NZU64;
    use rstest::rstest;

    #[rstest]
    #[case(ErrorCode::InvalidRequest)]
    #[case(ErrorCode::DatabaseError)]
    #[case(ErrorCode::NetworkError)]
    #[case(ErrorCode::StaleTarget)]
    #[case(ErrorCode::Timeout)]
    #[case(ErrorCode::InternalError)]
    fn test_error_code_roundtrip_serialization(#[case] error_code: ErrorCode) {
        // Serialize
        let encoded = error_code.encode().to_vec();

        // Deserialize
        let decoded = ErrorCode::decode(&encoded[..]).expect("Failed to decode ErrorCode");

        // Verify they match
        match (&error_code, &decoded) {
            (ErrorCode::InvalidRequest, ErrorCode::InvalidRequest) => {}
            (ErrorCode::DatabaseError, ErrorCode::DatabaseError) => {}
            (ErrorCode::NetworkError, ErrorCode::NetworkError) => {}
            (ErrorCode::StaleTarget, ErrorCode::StaleTarget) => {}
            (ErrorCode::Timeout, ErrorCode::Timeout) => {}
            (ErrorCode::InternalError, ErrorCode::InternalError) => {}
            _ => panic!("ErrorCode roundtrip failed: {error_code:?} != {decoded:?}"),
        }
    }

    #[test]
    fn test_get_operations_request_validation() {
        // Valid request
        let requester = Generator::new();
        let request = GetOperationsRequest {
            request_id: requester.next(),
            op_count: Location::new(100),
            start_loc: Location::new(10),
            max_ops: NZU64!(50),
            include_pinned_nodes: false,
        };
        assert!(request.validate().is_ok());

        // Invalid start_loc
        let request = GetOperationsRequest {
            request_id: requester.next(),
            op_count: Location::new(100),
            start_loc: Location::new(100),
            max_ops: NZU64!(50),
            include_pinned_nodes: false,
        };
        assert!(matches!(
            request.validate(),
            Err(crate::Error::InvalidRequest(_))
        ));

        // start_loc beyond size
        let request = GetOperationsRequest {
            request_id: requester.next(),
            op_count: Location::new(100),
            start_loc: Location::new(150),
            max_ops: NZU64!(50),
            include_pinned_nodes: false,
        };
        assert!(matches!(
            request.validate(),
            Err(crate::Error::InvalidRequest(_))
        ));
    }

    #[test]
    fn test_get_compact_state_response_roundtrip() {
        let request_id = Generator::new().next();
        let digest_a = sha256::Digest::from([7; 32]);
        let digest_b = sha256::Digest::from([8; 32]);
        let digest_c = sha256::Digest::from([10; 32]);
        let message = wire::Message::GetCompactStateResponse(wire::GetCompactStateResponse {
            request_id,
            state: State {
                leaf_count: Location::new(11),
                pinned_nodes: vec![digest_a, digest_b],
                last_commit_op: keyless_compact::Operation::Commit(None, Location::new(0)),
                last_commit_proof: commonware_storage::mmr::Proof {
                    leaves: Location::new(11),
                    inactive_peaks: 0,
                    digests: vec![digest_c],
                },
            },
        });

        let encoded = message.encode().to_vec();
        let decoded = wire::Message::<
            keyless_compact::Operation,
            commonware_cryptography::sha256::Digest,
        >::decode(&encoded[..])
        .expect("failed to decode compact response");

        match decoded {
            wire::Message::GetCompactStateResponse(response) => {
                assert_eq!(response.request_id, request_id);
                assert_eq!(response.state.leaf_count, Location::new(11));
                assert_eq!(response.state.pinned_nodes.len(), 2);
            }
            other => panic!("unexpected message variant: {other:?}"),
        }
    }

    /// `GetCurrentTargetForRootsRequest` round-trips through encode/decode and clamps
    /// per the configured `MAX_TRUSTED_ROOTS` only on the network-resolver side; the wire
    /// codec itself accepts up to `MAX_TRUSTED_ROOTS` entries and rejects more.
    #[test]
    fn test_get_current_target_for_roots_request_roundtrip() {
        let request_id = Generator::new().next();
        let roots: Vec<sha256::Digest> = (0..3)
            .map(|i| sha256::Digest::from([i as u8 + 1; 32]))
            .collect();
        let message: wire::Message<keyless_compact::Operation, sha256::Digest> =
            wire::Message::GetCurrentTargetForRootsRequest(wire::GetCurrentTargetForRootsRequest {
                request_id,
                trusted_roots: roots.clone(),
            });

        let encoded = message.encode().to_vec();
        let decoded =
            wire::Message::<keyless_compact::Operation, sha256::Digest>::decode(&encoded[..])
                .expect("failed to decode");

        match decoded {
            wire::Message::GetCurrentTargetForRootsRequest(req) => {
                assert_eq!(req.request_id, request_id);
                assert_eq!(req.trusted_roots, roots);
            }
            other => panic!("unexpected message variant: {other:?}"),
        }
    }

    /// `GetCurrentTargetForRootsResponse` round-trips both `None` (cache miss) and
    /// `Some(target)` (cache hit). The strict Option decode is exercised by these paths.
    #[test]
    fn test_get_current_target_for_roots_response_roundtrip_none() {
        let request_id = Generator::new().next();
        let message: wire::Message<keyless_compact::Operation, sha256::Digest> =
            wire::Message::GetCurrentTargetForRootsResponse(
                wire::GetCurrentTargetForRootsResponse {
                    request_id,
                    target: None,
                },
            );

        let encoded = message.encode().to_vec();
        let decoded =
            wire::Message::<keyless_compact::Operation, sha256::Digest>::decode(&encoded[..])
                .expect("failed to decode None response");

        match decoded {
            wire::Message::GetCurrentTargetForRootsResponse(resp) => {
                assert_eq!(resp.request_id, request_id);
                assert!(resp.target.is_none());
            }
            other => panic!("unexpected message variant: {other:?}"),
        }
    }

    /// The wire decode caps `trusted_roots` at `MAX_TRUSTED_ROOTS`. A request encoded with
    /// more than the cap must be rejected at decode — which is why the network resolver
    /// clamps its slice before sending (see `Resolver::get_current_target_for_roots`).
    #[test]
    fn test_get_current_target_for_roots_request_rejects_oversize() {
        let request_id = Generator::new().next();
        let roots: Vec<sha256::Digest> = (0..=wire::MAX_TRUSTED_ROOTS)
            .map(|i| sha256::Digest::from([(i & 0xFF) as u8; 32]))
            .collect();
        assert_eq!(roots.len(), wire::MAX_TRUSTED_ROOTS + 1);

        let message: wire::Message<keyless_compact::Operation, sha256::Digest> =
            wire::Message::GetCurrentTargetForRootsRequest(wire::GetCurrentTargetForRootsRequest {
                request_id,
                trusted_roots: roots,
            });

        let encoded = message.encode().to_vec();
        let result =
            wire::Message::<keyless_compact::Operation, sha256::Digest>::decode(&encoded[..]);
        assert!(
            result.is_err(),
            "wire decode must reject more than MAX_TRUSTED_ROOTS entries, got {result:?}"
        );
    }

    /// The Option discriminant in `GetCurrentTargetForRootsResponse` must accept ONLY 0
    /// and 1. Any other byte value is a malformed encoding and should produce
    /// `CodecError::Invalid`, not be silently interpreted as `Some`.
    #[test]
    fn test_get_current_target_for_roots_response_rejects_invalid_option_discriminant() {
        use commonware_codec::Write as _;
        // Construct the response bytes manually: message tag (10) + request_id + an
        // invalid Option discriminant (2). Strict decode must reject.
        let request_id = Generator::new().next();
        let mut framed = vec![10u8];
        request_id.write(&mut framed);
        2u8.write(&mut framed); // illegal Option discriminant

        let result =
            wire::Message::<keyless_compact::Operation, sha256::Digest>::decode(&framed[..]);
        assert!(
            matches!(result, Err(commonware_codec::Error::Invalid(_, _))),
            "strict decode must reject Option discriminant != 0/1, got {result:?}"
        );
    }
}
