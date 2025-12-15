//! Application actor messages.
//!
//! `ConsensusRequest` (in `crate::consensus`) is the consensus-facing API. This module defines a
//! small control plane used by the deterministic simulation harness for observation and out-of-band
//! block ingress.

use crate::{
    consensus::{ConsensusDigest, PublicKey},
    types::StateRoot,
};
use alloy_evm::revm::primitives::{Address, B256, U256};
use bytes::Bytes;
use futures::channel::oneshot;

/// Messages sent to the application actor.
///
/// These are intentionally minimal:
/// - `BlockReceived` is the out-of-band block delivery path used by the simulated network.
/// - `Query*` requests are used by the simulation harness to assert convergence.
pub(crate) enum ApplicationRequest {
    /// Deliver a full block (encoded bytes) out-of-band.
    BlockReceived { from: PublicKey, bytes: Bytes },
    /// Read an account balance from the state snapshot for `digest`.
    QueryBalance {
        digest: ConsensusDigest,
        address: Address,
        response: oneshot::Sender<Option<U256>>,
    },
    /// Read the state commitment for `digest`.
    QueryStateRoot {
        digest: ConsensusDigest,
        response: oneshot::Sender<Option<StateRoot>>,
    },
    /// Read the stored consensus seed hash for `digest`.
    QuerySeed {
        digest: ConsensusDigest,
        response: oneshot::Sender<Option<B256>>,
    },
}
