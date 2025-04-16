mod actor;
mod ingress;

use crate::simplex::types::{Activity, Context, View};
use crate::{Automaton, Supervisor};
use crate::{Relay, Reporter};
pub use actor::Actor;
use commonware_cryptography::{Scheme, Verifier};
use commonware_utils::Array;
pub use ingress::{Mailbox, Message};
use std::time::Duration;

pub struct Config<
    C: Scheme,
    V: Verifier<PublicKey = C::PublicKey, Signature = C::Signature>,
    D: Array,
    A: Automaton<Context = Context<D>, Digest = D>,
    R: Relay<Digest = D>,
    F: Reporter<Activity = Activity<V, D>>,
    S: Supervisor<Index = View>,
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
