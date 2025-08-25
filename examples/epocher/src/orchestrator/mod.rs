//! Orchestrator logic for the epocher example.

mod actor;
use crate::types::block::Block;
pub use actor::Orchestrator;
mod ingress;
use commonware_consensus::{
    marshal, threshold_simplex::types::Context, types::Epoch, Automaton, Relay,
};
use commonware_cryptography::{
    bls12381::primitives::{group, poly, variant::MinSig},
    sha256::Digest as Sha256Digest,
    Signer,
};
use commonware_p2p::authenticated::discovery::Oracle;
use commonware_runtime::{Metrics, Spawner};
pub use ingress::{EpochUpdate, Mailbox, Message};

type D = Sha256Digest;

/// Configuration for the orchestrator.
pub struct Config<
    E: Spawner + Metrics,
    C: Signer,
    A: Automaton<Context = Context<D>, Digest = D, Epoch = Epoch> + Relay<Digest = D>,
> {
    pub oracle: Oracle<E, C::PublicKey>,
    pub signer: C,
    pub application: A,
    pub marshal: marshal::Mailbox<MinSig, Block>,
    pub polynomial: poly::Public<MinSig>,
    pub share: group::Share,

    pub namespace: Vec<u8>,
    pub validators: Vec<C::PublicKey>,
    pub muxer_size: usize,
    pub mailbox_size: usize,
}
