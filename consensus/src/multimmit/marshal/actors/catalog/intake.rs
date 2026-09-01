//! The catalog's request lanes and the readiness rules that park requests.
//!
//! A request that cannot run yet is parked in its lane, which stops that lane until the request
//! runs. Only commands and reads park; cursor updates always run.

use super::mailbox::{Command, CursorMessage, Message, Read, Traced};
use crate::multimmit::types::Body;
use commonware_actor::mailbox::{self, Policy};
use commonware_cryptography::{Hasher, bls12381::primitives::variant::Variant};
use std::sync::mpsc::TryRecvError;

/// One mailbox and the request taken from it that is waiting to run.
pub(super) struct Lane<T: Policy> {
    receiver: mailbox::Receiver<T>,
    open: bool,
    parked: Option<T>,
}

impl<T: Policy> Lane<T> {
    pub(super) const fn new(receiver: mailbox::Receiver<T>) -> Self {
        Self {
            receiver,
            open: true,
            parked: None,
        }
    }

    /// Returns whether the lane's senders may still deliver requests.
    pub(super) const fn is_open(&self) -> bool {
        self.open
    }

    /// Returns the parked request.
    pub(super) const fn parked(&self) -> Option<&T> {
        self.parked.as_ref()
    }

    /// Parks `request` until catalog state lets it run.
    pub(super) fn park(&mut self, request: T) {
        assert!(self.parked.is_none(), "a lane parks one request");
        self.parked = Some(request);
    }

    /// Takes the parked request.
    pub(super) const fn unpark(&mut self) -> Option<T> {
        self.parked.take()
    }

    /// Takes a queued request without waiting, closing the lane once every sender is gone.
    pub(super) fn try_recv(&mut self) -> Option<T> {
        if !self.open {
            return None;
        }
        match self.receiver.try_recv() {
            Ok(request) => Some(request),
            Err(TryRecvError::Disconnected) => {
                self.open = false;
                None
            }
            Err(TryRecvError::Empty) => None,
        }
    }

    /// Waits for a queued request, closing the lane once every sender is gone.
    pub(super) async fn recv(&mut self) -> Option<T> {
        let request = self.receiver.recv().await;
        if request.is_none() {
            self.open = false;
        }
        request
    }

    /// Returns whether the lane is closed with nothing parked.
    pub(super) const fn is_drained(&self) -> bool {
        !self.open && self.parked.is_none()
    }
}

impl<H, B> Lane<Traced<Read<H, B>>>
where
    H: Hasher,
    B: Body<H>,
{
    /// Returns the parked read once `parked_ready` or its caller stops waiting, and otherwise the
    /// next queued read.
    pub(super) async fn next_read(&mut self, parked_ready: bool) -> Option<Traced<Read<H, B>>> {
        if let Some(read) = &mut self.parked {
            if !parked_ready {
                read.message.canceled().await;
            }
            return self.parked.take();
        }
        self.recv().await
    }
}

/// The catalog's request lanes.
pub(super) struct Intake<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    /// Ordered commands.
    pub(super) commands: Lane<Traced<Message<H, V, B>>>,
    /// Independent reads.
    pub(super) reads: Lane<Traced<Read<H, B>>>,
    /// Delivery-cursor updates.
    pub(super) cursors: Lane<CursorMessage>,
}

impl<H, V, B> Intake<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    /// Returns whether the read lane may deliver requests.
    ///
    /// A parked floor installation closes read intake while existing reads drain.
    pub(super) fn accepts_reads(&self) -> bool {
        self.reads.is_open()
            && self.commands.parked().is_none_or(|parked| {
                !matches!(parked.message, Message::Command(Command::Install { .. }))
            })
    }

    /// Returns whether every lane is closed with nothing parked.
    pub(super) const fn is_drained(&self) -> bool {
        self.commands.is_drained() && self.reads.is_drained() && self.cursors.is_drained()
    }
}

/// Catalog state that decides whether a request may run now or must park.
#[derive(Clone, Copy, Debug)]
pub(super) struct Readiness {
    /// No commit, admission cut, or durability work is in flight.
    pub(super) barrier: bool,
    /// No body read is materializing.
    pub(super) materializer_idle: bool,
    /// No admission cut is syncing or waiting to start.
    pub(super) admission_idle: bool,
    /// Admissions the waiting cut can still take.
    pub(super) admission_room: usize,
    /// Most admissions one cut holds.
    pub(super) admission_capacity: usize,
    /// Whether another body request may wait for materialization.
    pub(super) body_waiter_room: bool,
}

impl Readiness {
    /// Returns whether an admission request of `len` items may run now.
    ///
    /// Empty and oversized requests run so they can be answered immediately.
    pub(super) const fn admits(&self, len: usize) -> bool {
        len == 0 || len > self.admission_capacity || len <= self.admission_room
    }

    /// Returns whether `message` may run now.
    ///
    /// Pruning waits for every commit and admission cut to finish; a floor installation also
    /// waits for body reads, whose segments it may reuse. A body request is always ready here;
    /// the catalog parks it only when it would need a waiter slot and none is free.
    pub(super) const fn command<H, V, B>(&self, message: &Message<H, V, B>) -> bool
    where
        H: Hasher,
        V: Variant,
        B: Body<H>,
    {
        match message {
            Message::Admit { admissions, .. } => self.admits(admissions.len()),
            Message::Command(Command::Promoted { .. }) => self.admission_idle,
            Message::Command(Command::Prune { .. }) => self.barrier,
            Message::Command(Command::Install { .. }) => self.barrier && self.materializer_idle,
            Message::Command(_) => true,
        }
    }

    /// Returns whether `read` may run now.
    pub(super) const fn read<H, B>(&self, read: &Read<H, B>) -> bool
    where
        H: Hasher,
        B: Body<H>,
    {
        !matches!(read, Read::Bodies { .. }) || self.body_waiter_room
    }
}

/// Read-lane gates for one loop turn.
#[derive(Clone, Copy, Debug)]
pub(super) struct ReadGates {
    /// Whether the read lane may deliver a request.
    pub(super) accept: bool,
    /// Whether a parked read may run.
    pub(super) parked_ready: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn readiness() -> Readiness {
        Readiness {
            barrier: true,
            materializer_idle: true,
            admission_idle: true,
            admission_room: 2,
            admission_capacity: 4,
            body_waiter_room: true,
        }
    }

    #[test]
    fn admissions_run_when_they_fit_or_cannot_ever_fit() {
        let readiness = readiness();
        assert!(readiness.admits(0));
        assert!(readiness.admits(2));
        assert!(!readiness.admits(3));
        assert!(!readiness.admits(4));
        assert!(readiness.admits(5));
    }
}
