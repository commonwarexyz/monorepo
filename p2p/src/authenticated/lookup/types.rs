use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{varint::UInt, EncodeSize, Error, RangeCfg, Read, ReadExt, Write};

/// The maximum overhead (in bytes) when encoding a [Data].
///
/// The byte overhead is calculated as the sum of the following:
/// - 5: Channel varint
/// - 5: Message length varint (lengths longer than 32 bits are forbidden by the codec)
// TODO danlaine: is this correct?
pub const MAX_PAYLOAD_DATA_OVERHEAD: usize = 5 + 5;

// /// A signed message from a peer attesting to its own socket address and public key at a given time.
// ///
// /// This is used to share the peer's socket address and public key with other peers in a verified
// /// manner.
// #[derive(Clone, Debug)]
// pub struct PeerInfo<C: PublicKey> {
//     /// The socket address of the peer.
//     pub socket: SocketAddr,

//     /// The timestamp (epoch milliseconds) at which the socket was signed over.
//     pub timestamp: u64,

//     /// The public key of the peer.
//     pub public_key: C,

//     /// The peer's signature over the socket and timestamp.
//     pub signature: C::Signature,
// }

// impl<C: PublicKey> PeerInfo<C> {
//     /// Verify the signature of the peer info.
//     // TODO danlaine: use or remove
//     #[allow(dead_code)]
//     pub fn verify(&self, namespace: &[u8]) -> bool {
//         self.public_key.verify(
//             Some(namespace),
//             &(self.socket, self.timestamp).encode(),
//             &self.signature,
//         )
//     }

//     pub fn sign<Sk: Signer<PublicKey = C, Signature = C::Signature>>(
//         signer: &Sk,
//         namespace: &[u8],
//         socket: SocketAddr,
//         timestamp: u64,
//     ) -> Self {
//         let signature = signer.sign(Some(namespace), &(socket, timestamp).encode());
//         PeerInfo {
//             socket,
//             timestamp,
//             public_key: signer.public_key(),
//             signature,
//         }
//     }
// }

// impl<C: PublicKey> EncodeSize for PeerInfo<C> {
//     fn encode_size(&self) -> usize {
//         self.socket.encode_size()
//             + UInt(self.timestamp).encode_size()
//             + self.public_key.encode_size()
//             + self.signature.encode_size()
//     }
// }

// impl<C: PublicKey> Write for PeerInfo<C> {
//     fn write(&self, buf: &mut impl BufMut) {
//         self.socket.write(buf);
//         UInt(self.timestamp).write(buf);
//         self.public_key.write(buf);
//         self.signature.write(buf);
//     }
// }

// impl<C: PublicKey> Read for PeerInfo<C> {
//     type Cfg = ();

//     fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
//         let socket = SocketAddr::read(buf)?;
//         let timestamp = UInt::read(buf)?.into();
//         let public_key = C::read(buf)?;
//         let signature = C::Signature::read(buf)?;
//         Ok(PeerInfo {
//             socket,
//             timestamp,
//             public_key,
//             signature,
//         })
//     }
// }

/// Data is an arbitrary message sent between peers.
#[derive(Clone, Debug, PartialEq)]
pub struct Data {
    /// A unique identifier for the channel the message is sent on.
    ///
    /// This is used to route the message to the correct handler.
    pub channel: u32,

    /// The payload of the message.
    pub message: Bytes,
}

impl EncodeSize for Data {
    fn encode_size(&self) -> usize {
        UInt(self.channel).encode_size() + self.message.encode_size()
    }
}

impl Write for Data {
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.channel).write(buf);
        self.message.write(buf);
    }
}

impl Read for Data {
    type Cfg = RangeCfg;

    fn read_cfg(buf: &mut impl Buf, range: &Self::Cfg) -> Result<Self, Error> {
        let channel = UInt::read(buf)?.into();
        let message = Bytes::read_cfg(buf, range)?;
        Ok(Data { channel, message })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Decode, Encode as _};

    #[test]
    fn test_data_codec() {
        let original = Data {
            channel: 12345,
            message: Bytes::from("Hello, world!"),
        };
        let encoded = original.encode();
        let decoded = Data::decode_cfg(encoded, &(13..=13).into()).unwrap();
        assert_eq!(original, decoded);

        let too_short = Data::decode_cfg(original.encode(), &(0..13).into());
        assert!(matches!(too_short, Err(Error::InvalidLength(13))));

        let too_long = Data::decode_cfg(original.encode(), &(14..).into());
        assert!(matches!(too_long, Err(Error::InvalidLength(13))));
    }

    // #[test]
    // fn test_payload_codec() {
    //     // Test Data
    //     let original = Data {
    //         channel: 12345,
    //         message: Bytes::from("Hello, world!"),
    //     };
    //     let encoded = Payload::Data(original.clone()).encode();
    //     let decoded = match Payload::decode_cfg(encoded, &()) {
    //         Ok(Payload::Data(d)) => d,
    //         _ => panic!(),
    //     };
    //     assert_eq!(original, decoded);
    // }

    // #[test]
    // fn test_payload_decode_invalid_type() {
    //     let invalid_payload = [3, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    //     let result = Payload::decode_cfg(&invalid_payload[..], &());
    //     assert!(result.is_err());
    // }

    // #[test]
    // fn test_max_payload_data_overhead() {
    //     let message = Bytes::from(vec![0; 1 << 29]);
    //     let message_len = message.len();
    //     let payload = Payload::Data(Data {
    //         channel: u32::MAX,
    //         message,
    //     });
    //     assert_eq!(
    //         payload.encode_size(),
    //         message_len + MAX_PAYLOAD_DATA_OVERHEAD
    //     );
    // }
}
