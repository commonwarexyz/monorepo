use super::{ConsensusDigest, PublicKey};
use crate::types::StateRoot;
use alloy_evm::revm::primitives::{Address, U256};
use bytes::Bytes;
use commonware_consensus::{simplex::types::{Activity, Context}, types::Epoch};
use futures::channel::oneshot;

#[derive(Debug)]
pub enum Message {
    Genesis {
        epoch: Epoch,
        response: oneshot::Sender<ConsensusDigest>,
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
    Propose {
        context: Context<ConsensusDigest, PublicKey>,
        response: oneshot::Sender<ConsensusDigest>,
    },
    Verify {
        context: Context<ConsensusDigest, PublicKey>,
        digest: ConsensusDigest,
        response: oneshot::Sender<bool>,
    },
    BlockReceived {
        from: PublicKey,
        bytes: Bytes,
    },
    Report {
        activity: Activity<
            commonware_consensus::simplex::signing_scheme::bls12381_threshold::Scheme<
                PublicKey,
                commonware_cryptography::bls12381::primitives::variant::MinSig,
            >,
            ConsensusDigest,
        >,
    },
}
