//! Deadlines the voter arms on behalf of the machine.

use crate::multimmit::{
    actors::voter::telemetry::TraceContext,
    machine::{ProductionTimer, ViewTimer},
};
use commonware_cryptography::Digest;
use std::time::SystemTime;

/// Why a view timer fires when it does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TimeoutReason {
    /// The machine's view timeout elapsed.
    Deadline,
    /// The view's leader has been silent for the activity window, so the timer fires at once.
    InactiveLeader,
}

impl TimeoutReason {
    /// Returns the reason recorded on the round timeout span.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Deadline => "deadline",
            Self::InactiveLeader => "inactive_leader",
        }
    }
}

/// An armed view timer.
pub(crate) struct Armed<T> {
    pub(crate) timer: T,
    pub(crate) deadline: SystemTime,
    pub(crate) reason: TimeoutReason,
}

/// An armed production timer and the trace context of the step that armed it.
pub(crate) struct ArmedProduction<D: Digest> {
    pub(crate) timer: ProductionTimer<D>,
    pub(crate) deadline: SystemTime,
    pub(crate) trace: TraceContext,
}

/// The two machine timers the voter can fire, in rotation order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TimerKind {
    View,
    Production,
}

impl TimerKind {
    pub(crate) const ALL: [Self; 2] = [Self::View, Self::Production];

    /// Returns the rotation index of the timer after this one.
    pub(crate) const fn next_index(self) -> usize {
        (self as usize + 1) % Self::ALL.len()
    }
}

/// The machine's view and production timers plus the voter's heartbeat deadline.
pub(crate) struct Timers<D: Digest> {
    view: Option<Armed<ViewTimer>>,
    production: Option<ArmedProduction<D>>,
    /// When periodic metrics and producer-stall checks next run.
    ///
    /// This is an absolute deadline rather than a relative sleep because every wait rebuilds its
    /// sleeps.
    heartbeat_at: SystemTime,
}

impl<D: Digest> Timers<D> {
    pub(crate) const fn new(heartbeat_at: SystemTime) -> Self {
        Self {
            view: None,
            production: None,
            heartbeat_at,
        }
    }

    /// Arms the view timer, replacing any armed one.
    pub(crate) const fn arm_view(
        &mut self,
        timer: ViewTimer,
        deadline: SystemTime,
        reason: TimeoutReason,
    ) {
        self.view = Some(Armed {
            timer,
            deadline,
            reason,
        });
    }

    /// Arms the production timer, replacing any armed one.
    pub(crate) fn arm_production(
        &mut self,
        timer: ProductionTimer<D>,
        deadline: SystemTime,
        trace: TraceContext,
    ) {
        self.production = Some(ArmedProduction {
            timer,
            deadline,
            trace,
        });
    }

    /// Disarms both machine timers.
    pub(crate) fn clear(&mut self) {
        self.view = None;
        self.production = None;
    }

    /// Returns whether the view timer is armed.
    pub(crate) const fn view_armed(&self) -> bool {
        self.view.is_some()
    }

    /// Returns the deadline of `kind`, if armed.
    pub(crate) fn deadline(&self, kind: TimerKind) -> Option<SystemTime> {
        match kind {
            TimerKind::View => self.view.as_ref().map(|armed| armed.deadline),
            TimerKind::Production => self.production.as_ref().map(|armed| armed.deadline),
        }
    }

    /// Returns whether `kind` is armed and due at `now`.
    pub(crate) fn due(&self, kind: TimerKind, now: SystemTime) -> bool {
        self.deadline(kind).is_some_and(|deadline| deadline <= now)
    }

    /// Takes the armed view timer.
    pub(crate) const fn take_view(&mut self) -> Option<Armed<ViewTimer>> {
        self.view.take()
    }

    /// Takes the armed production timer.
    pub(crate) const fn take_production(&mut self) -> Option<ArmedProduction<D>> {
        self.production.take()
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
