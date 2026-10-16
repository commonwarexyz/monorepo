//! Deadlines the voter arms on behalf of the machine.

use crate::multimmit::machine::{Now, TimerFamily};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Returns the wall-clock instant of the machine clock reading `at`.
///
/// The voter reads the machine clock as milliseconds since the Unix epoch, so this inverts it.
pub(crate) fn instant(at: Now) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(at.millis())
}

/// The machine's deadlines, one per timer family, plus the voter's heartbeat deadline.
pub(crate) struct Timers {
    deadlines: [Option<SystemTime>; TimerFamily::COUNT],
    /// When periodic metrics next run.
    ///
    /// Every wait rebuilds its sleeps, so the heartbeat is kept as an absolute deadline.
    heartbeat_at: SystemTime,
}

impl Timers {
    pub(crate) const fn new(heartbeat_at: SystemTime) -> Self {
        Self {
            deadlines: [None; TimerFamily::COUNT],
            heartbeat_at,
        }
    }

    /// Arms `family` to fire at `at`, replacing its earlier deadline.
    pub(crate) const fn arm(&mut self, family: TimerFamily, at: SystemTime) {
        self.deadlines[family as usize] = Some(at);
    }

    /// Drops `family`'s deadline.
    pub(crate) const fn cancel(&mut self, family: TimerFamily) {
        self.deadlines[family as usize] = None;
    }

    /// Disarms every machine deadline.
    pub(crate) const fn clear(&mut self) {
        self.deadlines = [None; TimerFamily::COUNT];
    }

    /// Returns whether `family` is armed.
    pub(crate) const fn armed(&self, family: TimerFamily) -> bool {
        self.deadlines[family as usize].is_some()
    }

    /// Returns whether `family` is armed and due at `now`.
    pub(crate) fn due(&self, family: TimerFamily, now: SystemTime) -> bool {
        self.deadlines[family as usize].is_some_and(|deadline| deadline <= now)
    }

    /// Returns the earliest armed machine deadline.
    pub(crate) fn earliest(&self) -> Option<SystemTime> {
        self.deadlines.iter().flatten().min().copied()
    }

    /// Returns when the heartbeat next runs.
    pub(crate) const fn heartbeat_at(&self) -> SystemTime {
        self.heartbeat_at
    }

    /// Schedules the next heartbeat.
    pub(crate) const fn set_heartbeat(&mut self, at: SystemTime) {
        self.heartbeat_at = at;
    }
}

/// Returns the rotation index of the timer family after `family`.
pub(crate) const fn next_index(family: TimerFamily) -> usize {
    (family as usize + 1) % TimerFamily::COUNT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn families_index_their_slot() {
        for (index, family) in TimerFamily::ALL.into_iter().enumerate() {
            assert_eq!(family as usize, index);
            assert_eq!(next_index(family), (index + 1) % TimerFamily::COUNT);
        }
    }

    #[test]
    fn deadlines_replace_and_cancel_per_family() {
        let start = instant(Now::from_millis(0));
        let mut timers = Timers::new(start);
        let at = |millis| instant(Now::from_millis(millis));
        timers.arm(TimerFamily::Update, at(30));
        timers.arm(TimerFamily::Liveness, at(20));
        timers.arm(TimerFamily::Update, at(10));
        assert_eq!(timers.earliest(), Some(at(10)));
        assert!(timers.due(TimerFamily::Update, at(10)));
        assert!(!timers.due(TimerFamily::Liveness, at(10)));
        timers.cancel(TimerFamily::Update);
        assert!(!timers.armed(TimerFamily::Update));
        assert_eq!(timers.earliest(), Some(at(20)));
        timers.clear();
        assert_eq!(timers.earliest(), None);
    }
}
