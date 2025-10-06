//! Orchestrator logic for the epocher example.

mod actor;
use crate::types::block::Block;
pub use actor::Orchestrator;
mod ingress;
use commonware_consensus::{marshal, threshold_simplex::types::Context, Automaton, Relay};
use commonware_cryptography::{
    bls12381::primitives::{group, poly, variant::MinSig},
    sha256::Digest as Sha256Digest,
    Signer,
};
use commonware_p2p::authenticated::discovery::Oracle;
use commonware_runtime::{Metrics, Spawner};
pub use ingress::{EpochCert, EpochTransition, Mailbox, Message};

type D = Sha256Digest;

/// Configuration for the orchestrator.
pub struct Config<
    E: Spawner + Metrics,
    C: Signer,
    A: Automaton<Context = Context<D>, Digest = D> + Relay<Digest = D>,
> {
    pub oracle: Oracle<E, C::PublicKey>,
    pub signer: C,
    pub application: A,
    pub marshal: marshal::Mailbox<MinSig, Block>,
    pub polynomial: poly::Public<MinSig>,
    pub shares: Vec<group::Share>,

    pub namespace: Vec<u8>,
    pub validators: Vec<C::PublicKey>,
    pub muxer_size: usize,
    pub mailbox_size: usize,

    // Optional indexer base URLs (e.g., http://127.0.0.1:4001)
    pub indexers: Vec<String>,

    // Partition prefix used for orchestrator metadata persistence
    pub partition_prefix: String,
}
