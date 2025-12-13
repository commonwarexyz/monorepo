use crate::consensus::{ConsensusDigest, PublicKey};
use crate::types::StateRoot;
use alloy_evm::revm::primitives::{Address, U256};
use bytes::Bytes;
use futures::channel::oneshot;

pub(crate) enum ControlMessage {
    BlockReceived {
        from: PublicKey,
        bytes: Bytes,
    },
    QueryBalance {
        digest: ConsensusDigest,
        address: Address,
        response: oneshot::Sender<Option<U256>>,
    },
    QueryStateRoot {
        digest: ConsensusDigest,
        response: oneshot::Sender<Option<StateRoot>>,
    },
}
