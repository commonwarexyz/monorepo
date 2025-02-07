mod actor;
mod ingress;

use crate::{
    threshold_simplex::{Context, View},
    Automaton, Committer, Relay, ThresholdSupervisor,
};
pub use actor::Actor;
use commonware_cryptography::Scheme;
use commonware_cryptography::{bls12381::primitives::group, Array};
pub use ingress::{Mailbox, Message};
use prometheus_client::registry::Registry;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct Config<
    C: Scheme,
    D: Array,
    A: Automaton<Context = Context<D>>,
    R: Relay<Digest = D>,
    F: Committer<Digest = D, Index = View>,
    S: ThresholdSupervisor<Seed = group::Signature, Index = View, Share = group::Share>,
> {
    pub crypto: C,
    pub automaton: A,
    pub relay: R,
    pub committer: F,
    pub supervisor: S,

    pub registry: Arc<Mutex<Registry>>,
    pub namespace: Vec<u8>,
    pub mailbox_size: usize,
    pub leader_timeout: Duration,
    pub notarization_timeout: Duration,
    pub nullify_retry: Duration,
    pub activity_timeout: View,
    pub replay_concurrency: usize,
}
