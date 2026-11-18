//! Metrics for the reshare actor.

use commonware_cryptography::{
    PublicKey,
    bls12381::{dkg::feldman_desmedt::Output, primitives::variant::Variant},
};
use commonware_runtime::{
    Metrics as RuntimeMetrics,
    telemetry::metrics::{Counter, EncodeStruct, Gauge, GaugeExt, GaugeFamily, MetricsExt as _},
};
use commonware_utils::ordered::Set;

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
    /// Latest epoch where a valid share was received, per dealer of the installed epoch.
    pub(crate) latest_share: GaugeFamily<Peer<P>>,
    /// Latest epoch where a valid ack was received, per player of the installed epoch.
    pub(crate) latest_ack: GaugeFamily<Peer<P>>,
    /// Current DKG epoch.
    pub(crate) current_epoch: Gauge,
    /// Current DKG round.
    pub(crate) current_round: Gauge,
    /// Current actor phase.
    pub(crate) phase: Gauge,
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
        }
    }

    /// Installs an epoch's dealers and players by dropping the gauges of every other peer. A
    /// peer that keeps its role keeps its latest epoch.
    pub(crate) fn reconcile(&self, dealers: &Set<P>, players: &Set<P>) {
        for (family, peers) in [(&self.latest_share, dealers), (&self.latest_ack, players)] {
            // Read the kept values before clearing. Each lookup holds the family's read lock
            // and `clear` needs the write lock.
            let kept: Vec<_> = peers
                .iter()
                .filter_map(|peer| family.get_by(peer).map(|gauge| (peer.clone(), gauge.get())))
                .collect();
            family.clear();
            for (peer, value) in kept {
                family.get_or_create_by(&peer).set(value);
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{
        Signer as _,
        ed25519::{PrivateKey, PublicKey},
    };
    use commonware_runtime::{
        Runner as _, Supervisor as _, deterministic, telemetry::metrics::metric_samples,
    };
    use std::collections::BTreeMap;

    /// `latest_share` and `latest_ack` cover only the installed epoch's dealers and players.
    #[test]
    fn reconcile_prunes_peers_that_left_their_role() {
        deterministic::Runner::default().start(|context| async move {
            let reshare = context.child("reshare");
            let metrics = Metrics::new(&reshare);
            let peers: Vec<PublicKey> = (0..3)
                .map(|seed| PrivateKey::from_seed(seed).public_key())
                .collect();
            let set = |peers: &[&PublicKey]| Set::from_iter_dedup(peers.iter().map(|&p| p.clone()));
            let exported = |name: &str| -> BTreeMap<String, u64> {
                metric_samples(&context.encode(), name)
                    .map(|(labels, value)| (labels.to_string(), value.parse().unwrap()))
                    .collect()
            };
            let label = |peer: &PublicKey| format!("peer=\"{peer}\"");

            // Observed dealers and players are exported with their latest epochs.
            let all = set(&[&peers[0], &peers[1], &peers[2]]);
            metrics.reconcile(&all, &all);
            metrics.record_share(&peers[0], 1);
            metrics.record_share(&peers[1], 1);
            metrics.record_ack(&peers[0], 1);
            metrics.record_ack(&peers[2], 1);
            assert_eq!(
                exported("reshare_latest_share"),
                BTreeMap::from([(label(&peers[0]), 1), (label(&peers[1]), 1)])
            );
            assert_eq!(
                exported("reshare_latest_ack"),
                BTreeMap::from([(label(&peers[0]), 1), (label(&peers[2]), 1)])
            );

            // Leaving a role removes that role's gauge, a peer that keeps its role keeps its
            // epoch, and a dealer appears only once it deals.
            metrics.reconcile(&set(&[&peers[1], &peers[2]]), &set(&[&peers[0]]));
            assert_eq!(
                exported("reshare_latest_share"),
                BTreeMap::from([(label(&peers[1]), 1)])
            );
            assert_eq!(
                exported("reshare_latest_ack"),
                BTreeMap::from([(label(&peers[0]), 1)])
            );
            metrics.record_share(&peers[1], 2);
            metrics.record_share(&peers[2], 2);
            assert_eq!(
                exported("reshare_latest_share"),
                BTreeMap::from([(label(&peers[1]), 2), (label(&peers[2]), 2)])
            );
        });
    }
}
