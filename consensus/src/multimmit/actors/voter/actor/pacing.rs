//! Advisory timing for ordinary votes; protocol deadlines retain control of rescue.

use super::{VoterTypes, live::Live, timers::TimerKind};
use crate::{
    multimmit::{config::VotePacing, diagnostics, types::ArtifactId},
    types::View,
};
use commonware_cryptography::Digest;
use commonware_p2p::Sender;
use commonware_runtime::Clock as _;
use commonware_utils::SystemTimeExt as _;
use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime},
};

pub(crate) struct Pacing<D: Digest> {
    receipts: BTreeMap<ArtifactId<D>, (View, SystemTime)>,
    config: VotePacing,
    scores: Vec<Duration>,
    view: Option<View>,
    pub(crate) deadline: Option<SystemTime>,
}

impl<D: Digest> Pacing<D> {
    pub(crate) fn new(config: VotePacing) -> Self {
        Self {
            receipts: BTreeMap::new(),
            scores: Vec::with_capacity(config.participants()),
            config,
            view: None,
            deadline: None,
        }
    }
    pub(crate) fn observe(
        &mut self,
        id: ArtifactId<D>,
        view: View,
        received: SystemTime,
        current: View,
    ) {
        self.receipts.retain(|_, (view, _)| *view >= current);
        if let Some((_, at)) = self.receipts.get_mut(&id) {
            *at = (*at).min(received);
            return;
        }
        if view < current
            || view > current.next()
            || self.receipts.len() >= self.config.participants().saturating_mul(2)
        {
            return;
        }
        self.receipts.insert(id, (view, received));
    }
}

impl<T: VoterTypes, S: Sender<PublicKey = T::PublicKey>> Live<T, S> {
    pub(crate) fn refresh_vote_pacing(&mut self) {
        let Some(pacing) = &mut self.pacing else {
            return;
        };
        let view = self.machine.machine().view();
        if pacing.view.is_some_and(|previous| previous != view) {
            if pacing.deadline.is_some() {
                diagnostics::record(
                    "vote_pacing_cancel",
                    &[
                        ("view", &pacing.view.map(View::get)),
                        ("reason", &"view_changed"),
                    ],
                );
            }
            pacing.view = None;
            pacing.deadline = None;
            self.machine.hold_vote(None);
        }
        if pacing.view.is_some() {
            return;
        }
        let Some(proposal) = self.machine.machine().vote_proposal_id() else {
            return;
        };
        let Some(me) = self.participant else { return };
        let leader = self.leaders.leader(view);
        let next = self.leaders.leader(view.next());
        let wait = pacing.config.delay(
            leader.get() as usize,
            next.get() as usize,
            me.get() as usize,
            self.machine.machine().profile().codec().view_quorum(),
            &mut pacing.scores,
        );
        let now = self.context.current();
        // Missing receipts (recovery or a full advisory cache) bypass pacing.
        let received = pacing.receipts.get(&proposal).map(|(_, at)| *at);
        let wait = if received.is_some() {
            wait
        } else {
            Duration::ZERO
        };
        let received = received.unwrap_or(now);
        let mut deadline = received.saturating_add_ext(wait);
        if let Some(timeout) = self.timers.deadline(TimerKind::View) {
            deadline = deadline.min(timeout);
        }
        pacing.view = Some(view);
        if deadline > now || self.timers.due(TimerKind::View, now) {
            pacing.deadline = Some(deadline);
            self.machine.hold_vote(Some(view));
        }
        diagnostics::record(
            "vote_pacing_wait",
            &[
                ("view", &view.get()),
                ("leader", &leader.get()),
                ("next_leader", &next.get()),
                ("proposal_received_at_wall", &received),
                ("vote_eligible_at_wall", &now),
                ("proposal", &proposal),
                ("requested_wait_ns", &wait.as_nanos()),
                (
                    "remaining_wait_ns",
                    &deadline.duration_since(now).unwrap_or_default().as_nanos(),
                ),
                ("deadline_wall", &deadline),
            ],
        );
        if deadline <= now {
            self.release_vote_pacing();
        }
    }

    pub(crate) fn release_vote_pacing(&mut self) {
        let timed_out = self.timers.due(TimerKind::View, self.context.current());
        if let Some(pacing) = &mut self.pacing {
            pacing.deadline = None;
            diagnostics::record(
                "vote_pacing_release",
                &[
                    ("view", &pacing.view.map(View::get)),
                    ("released_at_wall", &self.context.current()),
                    (
                        "reason",
                        &if timed_out {
                            "timeout_cutoff"
                        } else {
                            "pacing_deadline"
                        },
                    ),
                ],
            );
        }
        // A due timeout must freeze its cutoff before ordinary signing can resume.
        if !timed_out {
            self.machine.hold_vote(None);
        }
    }

    pub(crate) fn vote_release_deadline(&self) -> Option<SystemTime> {
        self.pacing.as_ref().and_then(|pacing| pacing.deadline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Hasher as _, Sha256};

    #[test]
    fn proposal_receipts_are_earliest_and_bounded() {
        let mut pacing = Pacing::new(VotePacing::new(vec![vec![0.]], 1., None).unwrap());
        let id = |n: u8| ArtifactId::new(Sha256::hash(&[&[n]]));
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        let view = View::new(1);
        pacing.observe(id(0), view, now, view);
        pacing.observe(id(0), view, now + Duration::from_secs(1), view);
        assert_eq!(pacing.receipts[&id(0)].1, now);
        pacing.observe(id(1), view.next(), now, view);
        pacing.observe(id(2), view, now, view);
        assert_eq!(pacing.receipts.len(), 2);
        pacing.observe(id(0), view, now - Duration::from_secs(1), view);
        assert_eq!(pacing.receipts[&id(0)].1, now - Duration::from_secs(1));
        pacing.observe(id(3), view.next(), now, view.next());
        assert!(!pacing.receipts.contains_key(&id(0)));
        assert_eq!(pacing.receipts.len(), 2);
        pacing.observe(id(4), View::new(4), now, View::new(2));
        assert!(!pacing.receipts.contains_key(&id(4)));
    }
}
