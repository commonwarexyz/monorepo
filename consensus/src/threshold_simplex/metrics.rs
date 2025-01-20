use commonware_cryptography::PublicKey;
use commonware_utils::hex;
use prometheus_client::encoding::EncodeLabelSet;

const NOTARIZE_TYPE: i32 = 1;
const NOTARIZATION_TYPE: i32 = 2;
const NULLIFY_TYPE: i32 = 3;
const NULLIFICATION_TYPE: i32 = 4;
const FINALIZE_TYPE: i32 = 5;
const FINALIZATION_TYPE: i32 = 6;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Message {
    pub message: i32,
}

pub const NOTARIZE: Message = Message {
    message: NOTARIZE_TYPE,
};

pub const NOTARIZATION: Message = Message {
    message: NOTARIZATION_TYPE,
};

pub const NULLIFY: Message = Message {
    message: NULLIFY_TYPE,
};

pub const NULLIFICATION: Message = Message {
    message: NULLIFICATION_TYPE,
};

pub const FINALIZE: Message = Message {
    message: FINALIZE_TYPE,
};

pub const FINALIZATION: Message = Message {
    message: FINALIZATION_TYPE,
};

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct PeerMessage {
    pub peer: String,
    pub message: i32,
}

impl PeerMessage {
    pub fn notarize(peer: &PublicKey) -> Self {
        Self {
            peer: hex(peer),
            message: NOTARIZE_TYPE,
        }
    }

    pub fn notarization(peer: &PublicKey) -> Self {
        Self {
            peer: hex(peer),
            message: NOTARIZATION_TYPE,
        }
    }

    pub fn nullify(peer: &PublicKey) -> Self {
        Self {
            peer: hex(peer),
            message: NULLIFY_TYPE,
        }
    }

    pub fn nullification(peer: &PublicKey) -> Self {
        Self {
            peer: hex(peer),
            message: NULLIFICATION_TYPE,
        }
    }

    pub fn finalize(peer: &PublicKey) -> Self {
        Self {
            peer: hex(peer),
            message: FINALIZE_TYPE,
        }
    }

    pub fn finalization(peer: &PublicKey) -> Self {
        Self {
            peer: hex(peer),
            message: FINALIZATION_TYPE,
        }
    }
}
