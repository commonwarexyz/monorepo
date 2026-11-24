//! Recent peer activity for the early leader timeout.

use crate::types::Participant;
use std::time::{Duration, SystemTime};

/// Last admitted observation from each committee peer.
///
/// A view timer fires immediately for a leader that has been silent for the activity window,
/// unless too few peers are active to judge silence.
pub(crate) struct PeerActivity {
    /// Last admitted observation per participant; empty on restart.
    last: Vec<Option<SystemTime>>,
    /// This replica, which always counts as active.
    local: Option<Participant>,
    /// The activity window, or `None` when the policy is disabled.
    window: Option<Duration>,
    /// Active participants required before silence counts against a leader.
    quorum: usize,
}

impl PeerActivity {
    /// Creates an empty record for `participants` peers.
    pub(crate) fn new(
        participants: usize,
        local: Option<Participant>,
        window: Option<Duration>,
        quorum: usize,
    ) -> Self {
        Self {
            last: vec![None; participants],
            local,
            window,
            quorum,
        }
    }

    /// Records an admitted observation from `participant` at `now`.
    pub(crate) fn observe(&mut self, participant: Participant, now: SystemTime) {
        if Some(participant) != self.local {
            self.last[usize::from(participant)] = Some(now);
        }
    }

    /// Returns true for local or recently observed participants, or without an active quorum.
    pub(crate) fn is_active(&self, participant: Participant, now: SystemTime) -> bool {
        let Some(window) = self.window else {
            return true;
        };
        if self.local == Some(participant) {
            return true;
        }
        let min_time = now.checked_sub(window).unwrap_or(SystemTime::UNIX_EPOCH);
        let recent = |activity: &Option<SystemTime>| activity.is_some_and(|at| at >= min_time);
        let active =
            self.last.iter().filter(|at| recent(at)).count() + usize::from(self.local.is_some());
        active < self.quorum || recent(&self.last[usize::from(participant)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WINDOW: Duration = Duration::from_secs(1);

    fn at(millis: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_millis(millis)
    }

    #[test]
    fn silent_leader_is_inactive_only_under_an_active_quorum() {
        let local = Participant::new(0);
        let mut activity = PeerActivity::new(4, Some(local), Some(WINDOW), 3);
        let now = at(5_000);

        // Without an active quorum, silence does not count against anyone.
        assert!(activity.is_active(Participant::new(3), now));

        activity.observe(Participant::new(1), now);
        activity.observe(Participant::new(2), now);
        assert!(activity.is_active(local, now));
        assert!(activity.is_active(Participant::new(1), now));
        assert!(!activity.is_active(Participant::new(3), now));

        // Observations older than the window expire.
        let later = now + WINDOW + Duration::from_millis(1);
        assert!(activity.is_active(Participant::new(3), later));
    }

    #[test]
    fn local_observations_are_ignored_and_disabled_policy_is_always_active() {
        let local = Participant::new(0);
        let mut activity = PeerActivity::new(2, Some(local), Some(WINDOW), 2);
        activity.observe(local, at(10));
        assert_eq!(activity.last[0], None);

        let disabled = PeerActivity::new(2, Some(local), None, 2);
        assert!(disabled.is_active(Participant::new(1), at(10)));
    }
}
