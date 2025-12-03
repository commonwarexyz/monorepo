use crate::authenticated::data::Data;
use bytes::{Buf, BufMut};
use commonware_codec::{
    varint::UInt, Encode, EncodeSize, Error as CodecError, Read, ReadExt, ReadRangeExt, Write,
};
use commonware_cryptography::{PublicKey, Signer};
use commonware_runtime::Clock;
use commonware_utils::{IpAddrExt, SystemTimeExt};
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use thiserror::Error;

/// Errors that can occur when interacting with [crate::authenticated::discovery::types].
#[derive(Error, Debug)]
pub enum Error {
    #[error("too many peers: {0}")]
    TooManyPeers(usize),
    #[error("private IPs not allowed: {0}")]
    PrivateIPsNotAllowed(IpAddr),
    #[error("received self")]
    ReceivedSelf,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("synchrony bound violated")]
    SynchronyBound,
}

/// The maximum overhead (in bytes) when encoding a `message` into a [Payload::Data].
///
/// The byte overhead is calculated as the sum of the following:
/// - 1: Payload enum value
/// - 10: Channel varint
/// - 5: Message length varint (lengths longer than 32 bits are forbidden by the codec)
pub const MAX_PAYLOAD_DATA_OVERHEAD: usize = 1 + 10 + 5;

/// Prefix byte used to identify a [Payload] with variant BitVec.
const BIT_VEC_PREFIX: u8 = 0;
/// Prefix byte used to identify a [Payload] with variant Peers.
const PEERS_PREFIX: u8 = 1;
/// Prefix byte used to identify a [Payload] with variant Data.
const DATA_PREFIX: u8 = 2;

// Use chunk size of 1 to minimize encoded size.
type BitMap = commonware_utils::bitmap::BitMap<1>;

/// Configuration for deserializing [Payload].
///
/// This is used to limit the size of the messages received from peers.
#[derive(Clone)]
pub struct PayloadConfig {
    /// The maximum number of bits that can be sent in a `BitVec` message.
    pub max_bit_vec: u64,

    /// The maximum number of peers that can be sent in a `Peers` message.
    pub max_peers: usize,

    /// The maximum length of the data that can be sent in a `Data` message.
    pub max_data_length: usize,
}

/// Payload is the only allowed message format that can be sent between peers.
#[derive(Clone, Debug)]
pub enum Payload<C: PublicKey> {
    /// Bit vector that represents the peers a peer knows about.
    ///
    /// Also used as a ping message to keep the connection alive.
    BitVec(BitVec),

    /// A vector of verifiable peer information.
    Peers(Vec<Info<C>>),

    /// Arbitrary data sent between peers.
    Data(Data),
}

impl<C: PublicKey> EncodeSize for Payload<C> {
    fn encode_size(&self) -> usize {
        (match self {
            Self::BitVec(bit_vec) => bit_vec.encode_size(),
            Self::Peers(peers) => peers.encode_size(),
            Self::Data(data) => data.encode_size(),
        }) + 1
    }
}

impl<C: PublicKey> Write for Payload<C> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::BitVec(bit_vec) => {
                BIT_VEC_PREFIX.write(buf);
                bit_vec.write(buf);
            }
            Self::Peers(peers) => {
                PEERS_PREFIX.write(buf);
                peers.write(buf);
            }
            Self::Data(data) => {
                DATA_PREFIX.write(buf);
                data.write(buf);
            }
        }
    }
}

impl<C: PublicKey> Read for Payload<C> {
    type Cfg = PayloadConfig;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let PayloadConfig {
            max_bit_vec,
            max_peers,
            max_data_length,
        } = cfg;

        let payload_type = <u8>::read(buf)?;
        match payload_type {
            BIT_VEC_PREFIX => {
                let bit_vec = BitVec::read_cfg(buf, max_bit_vec)?;
                Ok(Self::BitVec(bit_vec))
            }
            PEERS_PREFIX => {
                let peers = Vec::<Info<C>>::read_range(buf, ..=*max_peers)?;
                Ok(Self::Peers(peers))
            }
            DATA_PREFIX => {
                let data = Data::read_cfg(buf, &(..=*max_data_length).into())?;
                Ok(Self::Data(data))
            }
            _ => Err(CodecError::Invalid(
                "p2p::authenticated::discovery::Payload",
                "Invalid type",
            )),
        }
    }
}

/// BitVec is a bit vector that represents the peers a peer knows about at a given index.
///
/// A peer should respond with a `Peers` message if they know of any peers that the sender does not.
#[derive(Clone, Debug, PartialEq)]
pub struct BitVec {
    /// The index that the bit vector applies to.
    pub index: u64,

    /// The bit vector itself.
    pub bits: BitMap,
}

impl EncodeSize for BitVec {
    fn encode_size(&self) -> usize {
        UInt(self.index).encode_size() + self.bits.encode_size()
    }
}

impl Write for BitVec {
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.index).write(buf);
        self.bits.write(buf);
    }
}

impl Read for BitVec {
    type Cfg = u64;

    fn read_cfg(buf: &mut impl Buf, max_bits: &u64) -> Result<Self, CodecError> {
        let index = UInt::read(buf)?.into();
        let bits = BitMap::read_cfg(buf, max_bits)?;
        Ok(Self { index, bits })
    }
}

/// A signed message from a peer attesting to its own socket address and public key at a given time.
///
/// This is used to share the peer's socket address and public key with other peers in a verified
/// manner.
#[derive(Clone, Debug)]
pub struct Info<C: PublicKey> {
    /// The socket address of the peer.
    pub socket: SocketAddr,

    /// The timestamp (epoch milliseconds) at which the socket was signed over.
    pub timestamp: u64,

    /// The public key of the peer.
    pub public_key: C,

    /// The peer's signature over the socket and timestamp.
    pub signature: C::Signature,
}

impl<C: PublicKey> Info<C> {
    /// Verify the signature of [Info].
    pub fn verify(&self, namespace: &[u8]) -> bool {
        self.public_key.verify(
            namespace,
            &(self.socket, self.timestamp).encode(),
            &self.signature,
        )
    }

    /// Create a new [InfoVerifier] with the provided configuration.
    pub const fn verifier(
        me: C,
        allow_private_ips: bool,
        peer_gossip_max_count: usize,
        synchrony_bound: Duration,
        ip_namespace: Vec<u8>,
    ) -> InfoVerifier<C> {
        InfoVerifier::new(
            me,
            allow_private_ips,
            peer_gossip_max_count,
            synchrony_bound,
            ip_namespace,
        )
    }

    /// Sign the [Info] message.
    pub fn sign<Sk: Signer<PublicKey = C, Signature = C::Signature>>(
        signer: &Sk,
        namespace: &[u8],
        socket: SocketAddr,
        timestamp: u64,
    ) -> Self {
        let signature = signer.sign(namespace, &(socket, timestamp).encode());
        Self {
            socket,
            timestamp,
            public_key: signer.public_key(),
            signature,
        }
    }
}

impl<C: PublicKey> EncodeSize for Info<C> {
    fn encode_size(&self) -> usize {
        self.socket.encode_size()
            + UInt(self.timestamp).encode_size()
            + self.public_key.encode_size()
            + self.signature.encode_size()
    }
}

impl<C: PublicKey> Write for Info<C> {
    fn write(&self, buf: &mut impl BufMut) {
        self.socket.write(buf);
        UInt(self.timestamp).write(buf);
        self.public_key.write(buf);
        self.signature.write(buf);
    }
}

impl<C: PublicKey> Read for Info<C> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let socket = SocketAddr::read(buf)?;
        let timestamp = UInt::read(buf)?.into();
        let public_key = C::read(buf)?;
        let signature = C::Signature::read(buf)?;
        Ok(Self {
            socket,
            timestamp,
            public_key,
            signature,
        })
    }
}

/// Validate peer gossip payloads against configurability and basic safety checks.
#[derive(Clone)]
pub struct InfoVerifier<C: PublicKey> {
    /// The [PublicKey] of the verifier.
    me: C,

    /// Whether to allow private IPs.
    allow_private_ips: bool,

    /// The maximum number of [Info] allowable in a single message.
    peer_gossip_max_count: usize,

    /// The time bound for synchrony. Messages with timestamps greater than this far into the
    /// future will be considered malformed.
    synchrony_bound: Duration,

    /// The namespace used to sign and verify [Info] messages.
    ip_namespace: Vec<u8>,
}

impl<C: PublicKey> InfoVerifier<C> {
    /// Create a new [InfoVerifier] with the provided configuration.
    const fn new(
        me: C,
        allow_private_ips: bool,
        peer_gossip_max_count: usize,
        synchrony_bound: Duration,
        ip_namespace: Vec<u8>,
    ) -> Self {
        Self {
            me,
            allow_private_ips,
            peer_gossip_max_count,
            synchrony_bound,
            ip_namespace,
        }
    }

    /// Handle an incoming list of peer information.
    ///
    /// Returns an error if the list itself or any entries can be considered malformed.
    pub fn validate(&self, clock: &impl Clock, infos: &[Info<C>]) -> Result<(), Error> {
        // Ensure there aren't too many peers sent
        if infos.len() > self.peer_gossip_max_count {
            return Err(Error::TooManyPeers(infos.len()));
        }

        // We allow peers to be sent in any order when responding to a bit vector (allows
        // for selecting a random subset of peers when there are too many) and allow
        // for duplicates (no need to create an additional set to check this)
        for info in infos {
            // Check if IP is allowed
            #[allow(unstable_name_collisions)]
            if !self.allow_private_ips && !info.socket.ip().is_global() {
                return Err(Error::PrivateIPsNotAllowed(info.socket.ip()));
            }

            // Check if peer is us
            if info.public_key == self.me {
                return Err(Error::ReceivedSelf);
            }

            // Check if timestamp is too far into the future
            if Duration::from_millis(info.timestamp)
                > clock.current().epoch().saturating_add(self.synchrony_bound)
            {
                return Err(Error::SynchronyBound);
            }

            // Check if signature is valid
            if !info.verify(self.ip_namespace.as_ref()) {
                return Err(Error::InvalidSignature);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{Bytes, BytesMut};
    use commonware_codec::{Decode, DecodeRangeExt};
    use commonware_cryptography::{
        secp256r1::standard::{PrivateKey, PublicKey},
        PrivateKeyExt as _,
    };
    use commonware_runtime::{deterministic, Clock, Runner};
    use std::time::Duration;

    const NAMESPACE: &[u8] = b"test";

    fn signed_peer_info() -> Info<PublicKey> {
        let mut rng = rand::thread_rng();
        let c = PrivateKey::from_rng(&mut rng);
        Info {
            socket: SocketAddr::from(([127, 0, 0, 1], 8080)),
            timestamp: 1234567890,
            public_key: c.public_key(),
            signature: c.sign(NAMESPACE, &[1, 2, 3, 4, 5]),
        }
    }

    #[test]
    fn test_bit_vec_codec() {
        let original = BitVec {
            index: 1234,
            bits: BitMap::ones(71),
        };
        let decoded = BitVec::decode_cfg(original.encode(), &71).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_signed_peer_info_codec() {
        let original = vec![signed_peer_info(), signed_peer_info(), signed_peer_info()];
        let encoded = original.encode();
        let decoded = Vec::<Info<PublicKey>>::decode_range(encoded, 3..=3).unwrap();
        for (original, decoded) in original.iter().zip(decoded.iter()) {
            assert_eq!(original.socket, decoded.socket);
            assert_eq!(original.timestamp, decoded.timestamp);
            assert_eq!(original.public_key, decoded.public_key);
            assert_eq!(original.signature, decoded.signature);
        }

        let too_short = Vec::<Info<PublicKey>>::decode_range(original.encode(), ..3);
        assert!(matches!(too_short, Err(CodecError::InvalidLength(3))));

        let too_long = Vec::<Info<PublicKey>>::decode_range(original.encode(), 4..);
        assert!(matches!(too_long, Err(CodecError::InvalidLength(3))));
    }

    #[test]
    fn test_payload_codec() {
        // Config for the codec
        let cfg = PayloadConfig {
            max_bit_vec: 1024,
            max_peers: 10,
            max_data_length: 100,
        };

        // Test BitVec
        let original = BitVec {
            index: 1234,
            bits: BitMap::ones(100),
        };
        let encoded: BytesMut = Payload::<PublicKey>::BitVec(original.clone()).encode();
        let decoded = match Payload::<PublicKey>::decode_cfg(encoded, &cfg) {
            Ok(Payload::<PublicKey>::BitVec(b)) => b,
            _ => panic!(),
        };
        assert_eq!(original, decoded);

        // Test Peers
        let original = vec![signed_peer_info(), signed_peer_info()];
        let encoded = Payload::Peers(original.clone()).encode();
        let decoded = match Payload::<PublicKey>::decode_cfg(encoded, &cfg) {
            Ok(Payload::<PublicKey>::Peers(p)) => p,
            _ => panic!(),
        };
        for (a, b) in original.iter().zip(decoded.iter()) {
            assert_eq!(a.socket, b.socket);
            assert_eq!(a.timestamp, b.timestamp);
            assert_eq!(a.public_key, b.public_key);
            assert_eq!(a.signature, b.signature);
        }

        // Test Data
        let original = Data {
            channel: 12345,
            message: Bytes::from("Hello, world!"),
        };
        let encoded = Payload::<PublicKey>::Data(original.clone()).encode();
        let decoded = match Payload::<PublicKey>::decode_cfg(encoded, &cfg) {
            Ok(Payload::<PublicKey>::Data(d)) => d,
            _ => panic!(),
        };
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_payload_decode_invalid_type() {
        let cfg = PayloadConfig {
            max_bit_vec: 1024,
            max_peers: 10,
            max_data_length: 100,
        };
        let invalid_payload = [3, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let result = Payload::<PublicKey>::decode_cfg(&invalid_payload[..], &cfg);
        assert!(result.is_err());
    }

    #[test]
    fn test_payload_bitvec_respects_limit() {
        let cfg = PayloadConfig {
            max_bit_vec: 8,
            max_peers: 10,
            max_data_length: 32,
        };
        let encoded = Payload::<PublicKey>::BitVec(BitVec {
            index: 5,
            bits: BitMap::ones(9),
        })
        .encode();
        let err = Payload::<PublicKey>::decode_cfg(encoded, &cfg).unwrap_err();
        assert!(matches!(err, CodecError::InvalidLength(9)));
    }

    #[test]
    fn test_payload_peers_respects_limit() {
        let cfg = PayloadConfig {
            max_bit_vec: 1024,
            max_peers: 1,
            max_data_length: 32,
        };
        let peers = vec![signed_peer_info(), signed_peer_info()];
        let encoded = Payload::Peers(peers).encode();
        let err = Payload::<PublicKey>::decode_cfg(encoded, &cfg).unwrap_err();
        assert!(matches!(err, CodecError::InvalidLength(2)));
    }

    #[test]
    fn test_payload_data_respects_limit() {
        let cfg = PayloadConfig {
            max_bit_vec: 1024,
            max_peers: 10,
            max_data_length: 4,
        };
        let encoded = Payload::<PublicKey>::Data(Data {
            channel: 1,
            message: Bytes::from_static(b"hello"),
        })
        .encode();
        let err = Payload::<PublicKey>::decode_cfg(encoded, &cfg).unwrap_err();
        assert!(matches!(err, CodecError::InvalidLength(5)));
    }

    #[test]
    fn test_max_payload_data_overhead() {
        let message = Bytes::from(vec![0; 1 << 29]);
        let message_len = message.len();
        let payload = Payload::<PublicKey>::Data(Data {
            channel: u64::MAX,
            message,
        });
        assert_eq!(
            payload.encode_size(),
            message_len + MAX_PAYLOAD_DATA_OVERHEAD
        );
    }

    #[test]
    fn info_verifier_accepts_valid_peer() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let validator_key = PrivateKey::from_rng(&mut context);
            let peer_key = PrivateKey::from_rng(&mut context);
            let validator = Info::verifier(
                validator_key.public_key(),
                false,
                4,
                Duration::from_secs(30),
                NAMESPACE.to_vec(),
            );
            let timestamp = context.current().epoch().as_millis() as u64;
            let peer = Info::sign(
                &peer_key,
                NAMESPACE,
                SocketAddr::from(([8, 8, 8, 8], 8080)),
                timestamp,
            );
            assert!(validator.validate(&context, &[peer]).is_ok());
        });
    }

    #[test]
    fn info_verifier_rejects_too_many_peers() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let validator_key = PrivateKey::from_rng(&mut context);
            let synchrony_bound = Duration::from_secs(30);
            let timestamp = context.current().epoch().as_millis() as u64;
            let peers = {
                let addr_a = SocketAddr::from(([8, 8, 8, 8], 9000));
                let addr_b = SocketAddr::from(([8, 8, 4, 4], 9001));
                let peer_a = Info::sign(
                    &PrivateKey::from_rng(&mut context),
                    NAMESPACE,
                    addr_a,
                    timestamp,
                );
                let peer_b = Info::sign(
                    &PrivateKey::from_rng(&mut context),
                    NAMESPACE,
                    addr_b,
                    timestamp,
                );
                vec![peer_a, peer_b]
            };
            let validator = Info::verifier(
                validator_key.public_key(),
                true,
                1,
                synchrony_bound,
                NAMESPACE.to_vec(),
            );
            let err = validator.validate(&context, &peers).unwrap_err();
            assert!(matches!(err, Error::TooManyPeers(count) if count == 2));
        });
    }

    #[test]
    fn info_verifier_rejects_private_ips_when_disallowed() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let validator_key = PrivateKey::from_rng(&mut context);
            let peer_key = PrivateKey::from_rng(&mut context);
            let validator = Info::verifier(
                validator_key.public_key(),
                false,
                4,
                Duration::from_secs(30),
                NAMESPACE.to_vec(),
            );
            let timestamp = context.current().epoch().as_millis() as u64;
            let peer = Info::sign(
                &peer_key,
                NAMESPACE,
                SocketAddr::from(([192, 168, 1, 1], 8080)),
                timestamp,
            );
            let err = validator.validate(&context, &[peer]).unwrap_err();
            assert!(matches!(err, Error::PrivateIPsNotAllowed(_)));
        });
    }

    #[test]
    fn info_verifier_rejects_self() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let validator_key = PrivateKey::from_rng(&mut context);
            let validator = Info::verifier(
                validator_key.public_key(),
                true,
                4,
                Duration::from_secs(30),
                NAMESPACE.to_vec(),
            );
            let timestamp = context.current().epoch().as_millis() as u64;
            let peer = Info::sign(
                &validator_key,
                NAMESPACE,
                SocketAddr::from(([203, 0, 113, 1], 8080)),
                timestamp,
            );
            let err = validator.validate(&context, &[peer]).unwrap_err();
            assert!(matches!(err, Error::ReceivedSelf));
        });
    }

    #[test]
    fn info_verifier_rejects_future_timestamp() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let validator_key = PrivateKey::from_rng(&mut context);
            let peer_key = PrivateKey::from_rng(&mut context);
            let synchrony_bound = Duration::from_secs(30);
            let validator = Info::verifier(
                validator_key.public_key(),
                true,
                4,
                synchrony_bound,
                NAMESPACE.to_vec(),
            );
            let future_timestamp =
                (context.current().epoch() + synchrony_bound + Duration::from_secs(1)).as_millis()
                    as u64;
            let peer = Info::sign(
                &peer_key,
                NAMESPACE,
                SocketAddr::from(([198, 51, 100, 1], 8080)),
                future_timestamp,
            );
            let err = validator.validate(&context, &[peer]).unwrap_err();
            assert!(matches!(err, Error::SynchronyBound));
        });
    }

    #[test]
    fn info_verifier_allows_past_timestamp() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let validator_key = PrivateKey::from_rng(&mut context);
            let peer_key = PrivateKey::from_rng(&mut context);
            let synchrony_bound = Duration::from_secs(30);
            let validator = Info::verifier(
                validator_key.public_key(),
                true,
                4,
                synchrony_bound,
                NAMESPACE.to_vec(),
            );

            // Advance current time
            context.sleep(synchrony_bound * 2).await;

            // Create peer with timestamp below current - synchrony bound
            let past_timestamp =
                (context.current().epoch() - synchrony_bound - Duration::from_secs(1)).as_millis()
                    as u64;
            let peer = Info::sign(
                &peer_key,
                NAMESPACE,
                SocketAddr::from(([198, 51, 100, 1], 8080)),
                past_timestamp,
            );
            assert!(validator.validate(&context, &[peer]).is_ok());
        });
    }

    #[test]
    fn info_verifier_rejects_invalid_signature() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let validator_key = PrivateKey::from_rng(&mut context);
            let peer_key = PrivateKey::from_rng(&mut context);
            let validator = Info::verifier(
                validator_key.public_key(),
                true,
                4,
                Duration::from_secs(30),
                NAMESPACE.to_vec(),
            );
            let timestamp = context.current().epoch().as_millis() as u64;
            let peer = Info::sign(
                &peer_key,
                b"wrong-namespace",
                SocketAddr::from(([8, 8, 4, 4], 8080)),
                timestamp,
            );
            let err = validator.validate(&context, &[peer]).unwrap_err();
            assert!(matches!(err, Error::InvalidSignature));
        });
    }
}
