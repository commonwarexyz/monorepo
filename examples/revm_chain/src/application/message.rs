use crate::consensus::{ConsensusDigest, PublicKey};
use crate::types::StateRoot;
use alloy_evm::revm::primitives::{Address, B256, U256};
use bytes::Bytes;
use futures::channel::oneshot;

pub(crate) enum ApplicationRequest {
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
    QuerySeed {
        digest: ConsensusDigest,
        response: oneshot::Sender<Option<B256>>,
    },
}
