//! Fault injection types for simulation testing.

use commonware_cryptography::PublicKey;
use commonware_p2p::{simulated::Link, Channel};
use std::time::Duration;

/// Fault injection strategy for a simulation run.
#[derive(Clone)]
pub enum Crash<P: PublicKey> {
    /// Periodically crash random validators and restart them after
    /// a downtime period.
    Random {
        /// How often to trigger crashes.
        frequency: Duration,
        /// How long crashed validators stay offline.
        downtime: Duration,
        /// Number of validators to crash each time.
        count: usize,
    },

    /// Delay some validators from starting until after N finalizations.
    Delay {
        /// Number of validators to delay.
        count: usize,
        /// Number of finalizations before starting delayed validators.
        after: u64,
    },

    /// Time-indexed fault schedule for precise control.
    Schedule(Schedule<P>),
}

/// A time-ordered sequence of fault injections.
#[derive(Clone)]
pub struct Schedule<P: PublicKey> {
    /// Time-indexed fault events.
    pub events: Vec<(Duration, Fault<P>)>,
}

impl<P: PublicKey> Schedule<P> {
    /// Create an empty schedule.
    pub const fn new() -> Self {
        Self { events: vec![] }
    }

    /// Add a fault at the given simulation time.
    pub fn at(mut self, time: Duration, fault: Fault<P>) -> Self {
        self.events.push((time, fault));
        self
    }
}

impl<P: PublicKey> Default for Schedule<P> {
    fn default() -> Self {
        Self::new()
    }
}

/// A single fault to inject at a specific time.
#[derive(Clone)]
pub enum Fault<P: PublicKey> {
    /// Partition the network into two groups.
    Partition {
        /// First partition group.
        a: Vec<P>,
        /// Second partition group.
        b: Vec<P>,
    },

    /// Heal all partitions, restoring full connectivity with the given link.
    Heal(Link),

    /// Update a specific directed link by removing and re-adding it.
    UpdateLink {
        /// Source peer.
        from: P,
        /// Destination peer.
        to: P,
        /// New link configuration.
        link: Link,
    },

    /// Update a specific directed link for one channel.
    UpdateChannelLink {
        /// Source peer.
        from: P,
        /// Destination peer.
        to: P,
        /// Channel to update.
        channel: Channel,
        /// New link configuration.
        link: Link,
    },

    /// Crash a specific validator.
    Crash(P),

    /// Restart a previously crashed validator.
    Restart(P),
}
