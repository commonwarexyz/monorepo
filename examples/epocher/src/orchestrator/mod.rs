//! Orchestrator logic for the epocher example.

mod actor;
use crate::types::block::Block;
pub use actor::Orchestrator;
mod ingress;
use commonware_consensus::{
    marshal,
    threshold_simplex::types::Context,
    types::{Epoch, View},
    Automaton, Relay, ThresholdSupervisor,
};
use commonware_cryptography::{
    bls12381::primitives::{group, variant::Variant},
    sha256::Digest as Sha256Digest,
    Signer,
};
use commonware_p2p::authenticated::discovery::Oracle;
use commonware_runtime::{Metrics, Spawner};
pub use ingress::{Mailbox, Message};

type D = Sha256Digest;

/// Configuration for the orchestrator.
pub struct Config<
    E: Spawner + Metrics,
    C: Signer,
    V: Variant,
    A: Automaton<Context = Context<D>, Digest = D, Epoch = Epoch> + Relay<Digest = D>,
    S: ThresholdSupervisor<
        Index = View,
        PublicKey = C::PublicKey,
        Identity = V::Public,
        Seed = V::Signature,
        Polynomial = Vec<V::Public>,
        Share = group::Share,
    >,
> {
    pub oracle: Oracle<E, C::PublicKey>,
    pub signer: C,
    pub application: A,
    pub marshal: marshal::Mailbox<V, Block>,
    pub supervisor: S,

    pub namespace: Vec<u8>,
    pub validators: Vec<C::PublicKey>,
    pub muxer_size: usize,
    pub mailbox_size: usize,
}
