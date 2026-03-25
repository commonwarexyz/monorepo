//! Simulation action types for testing.

use commonware_cryptography::PublicKey;
use commonware_p2p::simulated::Link;
use std::time::Duration;

/// Crash strategy for a simulation run.
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

    /// Time-indexed action schedule for precise control.
    Schedule(Schedule<P>),
}

/// A time-ordered sequence of simulation actions.
#[derive(Clone)]
pub struct Schedule<P: PublicKey> {
    /// Time-indexed actions.
    pub events: Vec<(Duration, Action<P>)>,
}

impl<P: PublicKey> Schedule<P> {
    /// Create an empty schedule.
    pub const fn new() -> Self {
        Self { events: vec![] }
    }

    /// Add an action at the given simulation time.
    pub fn at(mut self, time: Duration, action: Action<P>) -> Self {
        self.events.push((time, action));
        self
    }
}

impl<P: PublicKey> Default for Schedule<P> {
    fn default() -> Self {
        Self::new()
    }
}

/// A single simulation action to apply at a specific time.
#[derive(Clone)]
pub enum Action<P: PublicKey> {
    /// Reset all directed links, restoring full connectivity with the given link.
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

    /// Crash a specific validator.
    Crash(P),

    /// Restart a previously crashed validator.
    Restart(P),
}
