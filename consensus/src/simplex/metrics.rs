use commonware_utils::Array;
use prometheus_client::encoding::EncodeLabelSet;

const NOTARIZE_TYPE: i32 = 1;
const NOTARIZATION_TYPE: i32 = 2;
const NULLIFY_TYPE: i32 = 3;
const NULLIFICATION_TYPE: i32 = 4;
const FINALIZE_TYPE: i32 = 5;
const FINALIZATION_TYPE: i32 = 6;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Outbound {
    pub message: i32,
}

pub const NOTARIZE: Outbound = Outbound {
    message: NOTARIZE_TYPE,
};

pub const NOTARIZATION: Outbound = Outbound {
    message: NOTARIZATION_TYPE,
};

pub const NULLIFY: Outbound = Outbound {
    message: NULLIFY_TYPE,
};

pub const NULLIFICATION: Outbound = Outbound {
    message: NULLIFICATION_TYPE,
};

pub const FINALIZE: Outbound = Outbound {
    message: FINALIZE_TYPE,
};

pub const FINALIZATION: Outbound = Outbound {
    message: FINALIZATION_TYPE,
};

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Inbound {
    pub peer: String,
    pub message: i32,
}

impl Inbound {
    pub fn notarize(peer: &impl Array) -> Self {
        Self {
            peer: peer.to_string(),
            message: NOTARIZE_TYPE,
        }
    }

    pub fn notarization(peer: &impl Array) -> Self {
        Self {
            peer: peer.to_string(),
            message: NOTARIZATION_TYPE,
        }
    }

    pub fn nullify(peer: &impl Array) -> Self {
        Self {
            peer: peer.to_string(),
            message: NULLIFY_TYPE,
        }
    }

    pub fn nullification(peer: &impl Array) -> Self {
        Self {
            peer: peer.to_string(),
            message: NULLIFICATION_TYPE,
        }
    }

    pub fn finalize(peer: &impl Array) -> Self {
        Self {
            peer: peer.to_string(),
            message: FINALIZE_TYPE,
        }
    }

    pub fn finalization(peer: &impl Array) -> Self {
        Self {
            peer: peer.to_string(),
            message: FINALIZATION_TYPE,
        }
    }
}
