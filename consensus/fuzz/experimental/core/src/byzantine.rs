//! Run-scoped, per-actor counts of the actions Byzantine actors take.
//!
//! An action is a message the simulated network accepted from an actor's
//! sender ([`Counting`]), a twin secondary message the split forwarder
//! addressed to a node other than the twin ([`twin_secondary`]), or a
//! receiver-side forgery an actor reports with [`record`]. Each actor counts
//! under its own label, so a smoke test can require the actor its target
//! exists for to have acted even while another actor of the same run keeps
//! sending.
//!
//! The twins forwarder is part of the adversary's wiring, so the secondary is
//! counted after it; network links and partitions are the environment under
//! fuzz, so nothing is counted at delivery. The counts never gate a fuzz run:
//! many inputs legitimately leave an adversary quiet. Smoke tests read them
//! after a fixed input to catch a regression that silences an adversary.
//!
//! The counts are thread-local. The deterministic runtime executes every task
//! inline on the thread that started it, so a run's actions all land on the
//! caller's counters and concurrent test threads never share them.

use commonware_actor::{Feedback, Unreliable};
use commonware_cryptography::PublicKey;
use commonware_p2p::{
    CheckedSender, LimitedSender, Recipients,
    simulated::{SplitForwarder, SplitOrigin},
};
use commonware_runtime::{IoBuf, IoBufs};
use std::{cell::RefCell, collections::BTreeMap, time::SystemTime};

thread_local! {
    static COUNTS: RefCell<BTreeMap<&'static str, u64>> = const { RefCell::new(BTreeMap::new()) };
}

/// Label of the secondary half of a twin pair, counted by [`twin_secondary`].
pub const TWIN_SECONDARY: &str = "twin_secondary";

/// Actions `actor` took on this thread since the last [`reset`].
pub fn count(actor: &'static str) -> u64 {
    COUNTS.with(|counts| counts.borrow().get(actor).copied().unwrap_or(0))
}

/// Actions every actor took on this thread since the last [`reset`].
pub fn total() -> u64 {
    COUNTS.with(|counts| counts.borrow().values().sum())
}

/// Every actor's count on this thread since the last [`reset`].
pub fn snapshot() -> BTreeMap<&'static str, u64> {
    COUNTS.with(|counts| counts.borrow().clone())
}

/// Restart this thread's counts.
pub fn reset() {
    COUNTS.with(|counts| counts.borrow_mut().clear());
}

/// Count one action of `actor`.
pub fn record(actor: &'static str) {
    COUNTS.with(|counts| *counts.borrow_mut().entry(actor).or_insert(0) += 1);
}

/// A sender that counts, under `actor`, the sends the network accepted for at
/// least one recipient.
#[derive(Clone, Debug)]
pub struct Counting<S> {
    inner: S,
    actor: &'static str,
}

impl<S> Counting<S> {
    pub const fn new(inner: S, actor: &'static str) -> Self {
        Self { inner, actor }
    }
}

impl<S: LimitedSender> LimitedSender for Counting<S> {
    type PublicKey = S::PublicKey;
    type Checked<'a>
        = CountingChecked<S::Checked<'a>>
    where
        Self: 'a;

    fn check(
        &mut self,
        recipients: Recipients<Self::PublicKey>,
    ) -> Result<Self::Checked<'_>, SystemTime> {
        let actor = self.actor;
        self.inner
            .check(recipients)
            .map(|inner| CountingChecked { inner, actor })
    }
}

pub struct CountingChecked<C> {
    inner: C,
    actor: &'static str,
}

impl<C: CheckedSender> CheckedSender for CountingChecked<C> {
    type PublicKey = C::PublicKey;

    fn recipients(&self) -> Vec<Self::PublicKey> {
        self.inner.recipients()
    }

    fn send(self, message: impl Into<IoBufs> + Send, priority: bool) -> Unreliable<Feedback> {
        let addressed = !self.inner.recipients().is_empty();
        let feedback = self.inner.send(message, priority);
        if addressed && feedback.accepted() {
            record(self.actor);
        }
        feedback
    }
}

/// Wraps a twins split forwarder so every secondary message it addresses to a
/// node other than `twin` counts under [`TWIN_SECONDARY`].
///
/// A scripted round may give the secondary an empty set, or one holding only
/// the twin itself. Such a message is accepted by the network but reaches no
/// one, so it is not counted.
pub fn twin_secondary<K: PublicKey, F: SplitForwarder<K>>(
    forwarder: F,
    twin: K,
) -> impl SplitForwarder<K> {
    move |origin: SplitOrigin, recipients: &Recipients<K>, message: &IoBuf| {
        let forwarded = forwarder(origin, recipients, message);
        if origin == SplitOrigin::Secondary
            && forwarded
                .as_ref()
                .is_some_and(|forwarded| reaches_other(forwarded, &twin))
        {
            record(TWIN_SECONDARY);
        }
        forwarded
    }
}

fn reaches_other<K: PublicKey>(recipients: &Recipients<K>, twin: &K) -> bool {
    match recipients {
        Recipients::All => true,
        Recipients::Some(peers) => peers.iter().any(|peer| peer != twin),
        Recipients::One(peer) => peer != twin,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::simplex_certificate_mock as cert_mock;
    use commonware_p2p::{
        Sender as _,
        simulated::{Config, Network},
    };
    use commonware_runtime::{Quota, Runner as _, Supervisor as _, deterministic};
    use commonware_utils::NZUsize;
    use std::num::NonZeroU32;

    #[test]
    fn counts_per_actor_after_forwarding() {
        deterministic::Runner::seeded(1).start(|mut context| async move {
            let peers = cert_mock::fixture(&mut context, b"byzantine_counting", 3).participants;
            let (network, oracle) = Network::new_with_peers(
                context.child("network"),
                Config {
                    max_size: 1024,
                    max_peers_per_set: NZUsize!(3),
                    disconnect_on_block: false,
                    tracked_peer_sets: NZUsize!(1),
                },
                peers.clone(),
            )
            .await;
            network.start();
            let (sender, _receiver) = oracle
                .control(peers[0].clone())
                .register(0, Quota::per_second(NonZeroU32::MAX))
                .await
                .unwrap();

            // The secondary half is routed to the twin itself, as a blind
            // scripted round would, except for the message tagged 2, which
            // reaches a peer, and the message tagged 3, which is rejected.
            let twin = peers[0].clone();
            let peer = peers[1].clone();
            let (primary, secondary) = sender.split_with(twin_secondary(
                move |origin: SplitOrigin, recipients: &Recipients<_>, message: &IoBuf| match (
                    origin,
                    message.as_ref(),
                ) {
                    (SplitOrigin::Primary, _) => Some(recipients.clone()),
                    (SplitOrigin::Secondary, [2]) => Some(Recipients::One(peer.clone())),
                    (SplitOrigin::Secondary, [3]) => None,
                    (SplitOrigin::Secondary, _) => Some(Recipients::Some(vec![twin.clone()])),
                },
                peers[0].clone(),
            ));
            let mut primary = Counting::new(primary, "primary");
            let mut secondary = Counting::new(secondary, "secondary");

            reset();
            assert!(!primary.send(Recipients::All, vec![1u8], false).is_empty());
            assert!(!secondary.send(Recipients::All, vec![1u8], false).is_empty());
            assert!(!secondary.send(Recipients::All, vec![2u8], false).is_empty());
            assert!(secondary.send(Recipients::All, vec![3u8], false).is_empty());
            assert_eq!(count("primary"), 1);
            assert_eq!(
                count("secondary"),
                2,
                "the sender counts every accepted send"
            );
            assert_eq!(
                count(TWIN_SECONDARY),
                1,
                "only the message that reaches a peer"
            );
            assert_eq!(total(), 4);

            record("forgery");
            assert_eq!(count("forgery"), 1);

            reset();
            assert_eq!(total(), 0);
        });
    }
}
