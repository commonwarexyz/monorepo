#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::{Encode, Read};
use commonware_consensus::ordered_broadcast::{
    scheme::ed25519 as ob_ed25519,
    types::{Ack, Node},
};
use commonware_cryptography::{ed25519::PublicKey, sha256::Digest as Sha256Digest};
use libfuzzer_sys::fuzz_target;

type ObScheme = ob_ed25519::Scheme;
type ObNode = Node<PublicKey, ObScheme, Sha256Digest>;
type ObAck = Ack<PublicKey, ObScheme, Sha256Digest>;

#[derive(Arbitrary, Debug)]
enum FuzzInput {
    /// Fuzz Node decode with arbitrary participant count and raw bytes.
    /// Node::Cfg = usize (participant count for ed25519 certificate).
    NodeDecode { participants: u8, data: Vec<u8> },

    /// Fuzz Ack decode with raw bytes.
    /// Ack::Cfg = () for ed25519.
    AckDecode(Vec<u8>),
}

fn fuzz_node(participants: u8, data: &[u8]) {
    let cfg: usize = (participants.max(4)) as usize;
    let mut buf = data;
    if let Ok(node) = ObNode::read_cfg(&mut buf, &cfg) {
        let encoded = node.encode();
        let mut enc_buf = encoded.as_ref();
        let node2 = ObNode::read_cfg(&mut enc_buf, &cfg)
            .expect("re-decode of encoded node must succeed");
        assert_eq!(node, node2, "node roundtrip mismatch");
        assert_eq!(
            node.chunk.height.is_zero(),
            node.parent.is_none(),
            "height/parent consistency violated"
        );
    }
}

fn fuzz_ack(data: &[u8]) {
    let mut buf = data;
    if let Ok(ack) = ObAck::read_cfg(&mut buf, &()) {
        let encoded = ack.encode();
        let mut enc_buf = encoded.as_ref();
        let ack2 = ObAck::read_cfg(&mut enc_buf, &())
            .expect("re-decode of encoded ack must succeed");
        assert_eq!(ack, ack2, "ack roundtrip mismatch");
    }
}

fuzz_target!(|input: FuzzInput| {
    match input {
        FuzzInput::NodeDecode { participants, data } => fuzz_node(participants, &data),
        FuzzInput::AckDecode(data) => fuzz_ack(&data),
    }
});
