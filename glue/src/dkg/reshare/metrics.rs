//! Metrics for the reshare actor.

use commonware_cryptography::{
    PublicKey,
    bls12381::{dkg::feldman_desmedt::Output, primitives::variant::Variant},
};
use commonware_runtime::{
    Metrics as RuntimeMetrics,
    telemetry::metrics::{Counter, EncodeStruct, Gauge, GaugeExt, GaugeFamily, MetricsExt as _},
};

/// Per-peer metric label.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeStruct)]
pub(crate) struct Peer<P: PublicKey> {
    peer: P,
}

impl<P: PublicKey> From<P> for Peer<P> {
    fn from(peer: P) -> Self {
        Self { peer }
    }
}

/// Reshare actor phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    /// Observing the epoch without participating.
    Following = 0,
    /// Loading state and participant sets.
    Setup = 1,
    /// Exchanging dealer messages and player acknowledgments.
    Dealing = 2,
    /// Including signed dealer logs and committing the next epoch when the
    /// final block finalizes.
    Inclusion = 3,
}

/// Metrics for the reshare actor.
pub(crate) struct Metrics<P: PublicKey> {
    /// Number of successful epochs.
    pub(crate) successful_epochs: Counter,
    /// Number of failed epochs.
    pub(crate) failed_epochs: Counter,
    /// Number of successful epochs that revealed the local share.
    pub(crate) our_reveals: Counter,
    /// Total revealed shares across successful epochs.
    pub(crate) all_reveals: Counter,
    /// Latest epoch where a valid share was received from a dealer.
    pub(crate) latest_share: GaugeFamily<Peer<P>>,
    /// Latest epoch where a valid ack was received from a player.
    pub(crate) latest_ack: GaugeFamily<Peer<P>>,
    /// Current DKG epoch.
    pub(crate) current_epoch: Gauge,
    /// Current DKG round.
    pub(crate) current_round: Gauge,
    /// Current actor phase.
    pub(crate) phase: Gauge,
    /// Final-block requests held through a dealing window.
    pub(crate) held_requests: Counter,
    /// Final-block requests superseded by the epoch's finalization.
    pub(crate) superseded_requests: Counter,
    /// Dealer logs applied from a state-sync inclusion window at setup.
    pub(crate) window_logs: Gauge,
}

impl<P: PublicKey> Metrics<P> {
    /// Registers reshare metrics in `context`.
    pub(crate) fn new<E: RuntimeMetrics>(context: &E) -> Self {
        let current_epoch = context.gauge("current_epoch", "Current DKG epoch");
        let _ = current_epoch.try_set(0);

        let current_round = context.gauge("current_round", "Current DKG round");
        let _ = current_round.try_set(0);

        let phase = context.gauge("phase", "Current reshare actor phase");
        let _ = phase.try_set(Phase::Setup as i64);

        let window_logs = context.gauge(
            "window_logs",
            "Dealer logs applied from a state-sync inclusion window at setup",
        );
        let _ = window_logs.try_set(0);

        Self {
            successful_epochs: context.counter("successful_epochs", "Successful epochs"),
            failed_epochs: context.counter("failed_epochs", "Failed epochs"),
            our_reveals: context.counter("our_reveals", "Our share was revealed"),
            all_reveals: context.counter("all_reveals", "All share reveals"),
            latest_share: context.family(
                "latest_share",
                "Epoch of latest valid share received per dealer",
            ),
            latest_ack: context.family(
                "latest_ack",
                "Epoch of latest valid ack received per player",
            ),
            current_epoch,
            current_round,
            phase,
            held_requests: context.counter(
                "held_requests",
                "Final-block requests held through a dealing window",
            ),
            superseded_requests: context.counter(
                "superseded_requests",
                "Final-block requests superseded by the epoch's finalization",
            ),
            window_logs,
        }
    }

    /// Records the current epoch and its ceremony round.
    pub(crate) fn set_epoch(&self, epoch: u64) {
        let _ = self.current_epoch.try_set(epoch as i64);
        let _ = self.current_round.try_set(epoch as i64);
    }

    /// Records the current phase.
    pub(crate) fn set_phase(&self, phase: Phase) {
        let _ = self.phase.try_set(phase as i64);
    }

    /// Records how many inclusion-window logs the latest setup applied.
    pub(crate) fn set_window_logs(&self, applied: u64) {
        let _ = self.window_logs.try_set(applied as i64);
    }

    /// Records the latest epoch where a valid share was received from `dealer`.
    pub(crate) fn record_share(&self, dealer: &P, epoch: u64) {
        let peer = Peer::from(dealer.clone());
        let _ = self.latest_share.get_or_create(&peer).try_set_max(epoch);
    }

    /// Records the latest epoch where a valid ack was received from `player`.
    pub(crate) fn record_ack(&self, player: &P, epoch: u64) {
        let peer = Peer::from(player.clone());
        let _ = self.latest_ack.get_or_create(&peer).try_set_max(epoch);
    }

    /// Records a successful ceremony and its reveals, including whether `ours`
    /// was revealed.
    pub(crate) fn record_success<V: Variant>(&self, output: &Output<V, P>, ours: &P) {
        self.successful_epochs.inc();
        let revealed = output.revealed();
        self.all_reveals.inc_by(revealed.len() as u64);
        if revealed.position(ours).is_some() {
            self.our_reveals.inc();
        }
    }
}
