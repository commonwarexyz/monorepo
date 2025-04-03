mod actor;
mod ingress;

use crate::{
    threshold_simplex::types::{Activity, Context, View},
    Automaton, Relay, Reporter, ThresholdSupervisor,
};
pub use actor::Actor;
use commonware_cryptography::Scheme;
use commonware_cryptography::{bls12381::primitives::group, Digest};
pub use ingress::{Mailbox, Message};
use std::time::Duration;

pub struct Config<
    C: Scheme,
    D: Digest,
    A: Automaton<Context = Context<D>>,
    R: Relay<Digest = D>,
    F: Reporter<Activity = Activity<D>>,
    S: ThresholdSupervisor<Seed = group::Signature, Index = View, Share = group::Share>,
> {
    pub crypto: C,
    pub automaton: A,
    pub relay: R,
    pub reporter: F,
    pub supervisor: S,

    pub namespace: Vec<u8>,
    pub mailbox_size: usize,
    pub leader_timeout: Duration,
    pub notarization_timeout: Duration,
    pub nullify_retry: Duration,
    pub activity_timeout: View,
    pub skip_timeout: View,
    pub replay_concurrency: usize,
}
