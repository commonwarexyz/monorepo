//! Public message helpers for tests and mocks.

use crate::p2p::wire;
use bytes::{Buf, Bytes};
use commonware_codec::{Encode, Error, Read};
use commonware_utils::Span;

/// Resolver message envelope used by tests and mocks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Envelope<Key: Span> {
    /// Request a value for a specific key.
    Request { id: u64, key: Key },
    /// Respond to a prior request with data.
    Response { id: u64, data: Bytes },
    /// Respond to a prior request with an error.
    Error { id: u64 },
}

impl<Key: Span> Envelope<Key> {
    /// Decode an encoded resolver message.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, Error> {
        let message = wire::Message::<Key>::read_cfg(buf, &())?;
        Ok(match message.payload {
            wire::Payload::Request(key) => Self::Request {
                id: message.id,
                key,
            },
            wire::Payload::Response(data) => Self::Response {
                id: message.id,
                data,
            },
            wire::Payload::Error => Self::Error { id: message.id },
        })
    }

    /// Encode this envelope using the resolver wire format.
    pub fn encode(self) -> Bytes {
        let (id, payload) = match self {
            Self::Request { id, key } => (id, wire::Payload::Request(key)),
            Self::Response { id, data } => (id, wire::Payload::Response(data)),
            Self::Error { id } => (id, wire::Payload::Error),
        };
        wire::Message { id, payload }.encode()
    }
}

#[cfg(test)]
mod tests {
    use super::Envelope;
    use crate::p2p::mocks::Key;
    use bytes::Bytes;

    #[test]
    fn envelope_round_trips_requests() {
        let original = Envelope::Request {
            id: 7,
            key: Key(9),
        };
        let encoded = original.clone().encode();
        let decoded = Envelope::decode(&mut encoded.as_ref()).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn envelope_round_trips_responses() {
        let original = Envelope::<Key>::Response {
            id: 7,
            data: Bytes::from_static(b"payload"),
        };
        let encoded = original.clone().encode();
        let decoded = Envelope::decode(&mut encoded.as_ref()).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn envelope_round_trips_errors() {
        let original = Envelope::<Key>::Error { id: 7 };
        let encoded = original.clone().encode();
        let decoded = Envelope::decode(&mut encoded.as_ref()).unwrap();
        assert_eq!(decoded, original);
    }
}
