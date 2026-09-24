//! Round-local timeouts.
//!
//! A nullify vote ends the view's deadlines. [Timer] discards them, along with
//! any latched timeout, so only the retry schedule can fire afterward.

use crate::simplex::metrics::TimeoutReason;
use std::time::{Duration, SystemTime};

/// View deadline selected by the round's progress.
pub enum Deadline {
    /// Live until a proposal is known.
    Leader,
    /// Live until the proposal is certified.
    Certification,
}

/// Timeouts that drive a round to a nullify vote and then retry it.
///
/// The phase also records our nullify vote, which blocks notarize and finalize
/// votes, so it never returns to pending.
pub struct Timer(Phase);

/// Nullify vote status, holding only the timeouts live in that status.
enum Phase {
    /// No nullify vote broadcast.
    Pending {
        /// Leader deadline, armed when the view is entered.
        leader: Option<SystemTime>,
        /// Certification deadline, armed when the view is entered.
        certification: Option<SystemTime>,
        /// First explicit timeout, which can precede view entry.
        latch: Option<(SystemTime, TimeoutReason)>,
    },
    /// Nullify vote broadcast. The next retry is scheduled on the first poll.
    Nullified { retry: Option<SystemTime> },
}

impl Timer {
    pub const fn new() -> Self {
        Self(Phase::Pending {
            leader: None,
            certification: None,
            latch: None,
        })
    }

    /// Returns true once a nullify vote was broadcast.
    pub const fn nullified(&self) -> bool {
        matches!(self.0, Phase::Nullified { .. })
    }

    /// Arms the view deadlines, keeping any latch. A nullified round ignores
    /// them.
    pub const fn arm(&mut self, leader: SystemTime, certification: SystemTime) {
        if let Phase::Pending { latch, .. } = self.0 {
            self.0 = Phase::Pending {
                leader: Some(leader),
                certification: Some(certification),
                latch,
            };
        }
    }

    /// Latches the first explicit timeout. Later latches, and any latch after
    /// a nullify vote, are ignored.
    pub const fn latch(&mut self, now: SystemTime, reason: TimeoutReason) {
        if let Phase::Pending { latch, .. } = &mut self.0
            && latch.is_none()
        {
            *latch = Some((now, reason));
        }
    }

    /// Records a nullify vote, discarding the view deadlines and latch. The
    /// next poll schedules a fresh retry.
    pub const fn nullify(&mut self) {
        self.0 = Phase::Nullified { retry: None };
    }

    /// Returns the next timeout and its reason.
    ///
    /// A nullified round retries `interval` after the first poll. Otherwise
    /// the latch fires first when `allow` is set, then the `live` deadline.
    pub fn next(
        &mut self,
        now: SystemTime,
        interval: Duration,
        allow: bool,
        live: Option<Deadline>,
    ) -> Option<(SystemTime, TimeoutReason)> {
        match &mut self.0 {
            Phase::Nullified { retry } => {
                let deadline = *retry.get_or_insert_with(|| now + interval);
                Some((deadline, TimeoutReason::Retry))
            }
            Phase::Pending {
                latch: Some(latch), ..
            } if allow => Some(*latch),
            Phase::Pending {
                leader,
                certification,
                ..
            } => match live? {
                Deadline::Leader => leader.map(|at| (at, TimeoutReason::LeaderTimeout)),
                Deadline::Certification => {
                    certification.map(|at| (at, TimeoutReason::CertificationTimeout))
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RETRY: Duration = Duration::from_secs(3);

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn nullify_discards_deadlines_and_latch() {
        let mut timer = Timer::new();
        timer.arm(at(1), at(2));
        timer.latch(at(0), TimeoutReason::InvalidProposal);
        timer.nullify();
        timer.latch(at(5), TimeoutReason::LeaderNullify);
        assert_eq!(
            timer.next(at(5), RETRY, true, Some(Deadline::Leader)),
            Some((at(8), TimeoutReason::Retry))
        );
    }

    #[test]
    fn arm_after_nullify_keeps_retrying() {
        // A replayed nullify can precede view entry.
        let mut timer = Timer::new();
        timer.nullify();
        timer.arm(at(1), at(2));
        assert_eq!(
            timer.next(at(0), RETRY, true, Some(Deadline::Leader)),
            Some((at(3), TimeoutReason::Retry))
        );
    }

    #[test]
    fn latch_survives_arm() {
        // A lookahead round can latch before view entry.
        let mut timer = Timer::new();
        timer.latch(at(0), TimeoutReason::InvalidProposal);
        timer.arm(at(1), at(2));
        assert_eq!(
            timer.next(at(0), RETRY, true, Some(Deadline::Leader)),
            Some((at(0), TimeoutReason::InvalidProposal))
        );
        assert_eq!(
            timer.next(at(0), RETRY, false, Some(Deadline::Certification)),
            Some((at(2), TimeoutReason::CertificationTimeout))
        );
        assert_eq!(timer.next(at(0), RETRY, false, None), None);
    }
}
