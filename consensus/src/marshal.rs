//! Engine-neutral views of a marshal's finalized stream.
//!
//! Every consensus engine's marshal delivers finalized blocks to its application in order, each at
//! the next [`OutputIndex`]. The traits here let code downstream of consensus consume that stream
//! without naming the engine:
//!
//! - [`Delivery`]: an item a marshal reports to its application, which may carry a [`Finalized`]
//!   block or announce a final block before it is ordered (see [`Reported`]).
//! - [`Ledger`]: the finalized stream's retention and acknowledgement window.
//! - [`Floors`]: where a marshal can resume from, for state sync.
//! - [`Linear`]: a stream that is one chain, whose blocks' heights are their indices.

use crate::{Block, Roundable, types::OutputIndex};
use commonware_utils::{Acknowledgement, acknowledgement::Exact};
use std::{future::Future, num::NonZeroUsize, sync::Arc};

/// A finalized block at its index in a marshal's stream.
#[derive(Clone, Debug)]
pub struct Finalized<B, A = Exact> {
    /// The block's index in the stream.
    pub index: OutputIndex,
    /// The finalized block.
    pub block: Arc<B>,
    /// Acknowledged once the consumer has durably processed the block.
    ///
    /// The marshal keeps redelivering the block after a restart until it is acknowledged.
    pub acknowledgement: A,
}

/// An item a marshal reports to its application.
pub trait Delivery: Send + 'static {
    /// The block type of the stream.
    type Block: Block;

    /// The acknowledgement a finalized block carries.
    type Acknowledgement: Acknowledgement;

    /// Returns what this item reports.
    fn reported(self) -> Reported<Self::Block, Self::Acknowledgement>;
}

/// What a [`Delivery`] item reports.
#[derive(Clone, Debug)]
pub enum Reported<B, A = Exact> {
    /// A finalized block at its index in the stream.
    Finalized(Finalized<B, A>),
    /// A block that is final but not yet delivered in the stream.
    ///
    /// The block will be delivered later as a [`Reported::Finalized`] item at an index not yet
    /// known, unless installing a floor resumes the stream past it. Consumers can use it to start
    /// work for the block early, such as warming storage, while earlier blocks are still being
    /// ordered or processed.
    ///
    /// It carries no acknowledgement and leaves the stream unchanged. Within one run of a marshal,
    /// it never follows the block's [`Reported::Finalized`] delivery. After a restart, a marshal may
    /// report again any block it has not yet delivered in the new run, including one a previous
    /// run delivered and the consumer already processed, so consumers must tolerate repeats.
    Final(Arc<B>),
    /// An advisory item that carries no block.
    Advisory,
}

impl<B: Block, A: Acknowledgement> Delivery for Finalized<B, A> {
    type Block = B;
    type Acknowledgement = A;

    fn reported(self) -> Reported<B, A> {
        Reported::Finalized(self)
    }
}

/// A marshal's finalized stream, as its consumer bounds what the marshal retains.
pub trait Ledger: Clone + Send + Sync + 'static {
    /// The block type of the stream.
    type Block: Block;

    /// Why the marshal could not serve a request, such as a full queue or a stopped marshal.
    ///
    /// The same request may succeed if retried.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Allows the marshal to drop finalized data below `below`.
    ///
    /// Blocks at and above `below` stay retained, and so does everything the marshal still needs
    /// to deliver unacknowledged blocks. A marshal may keep more.
    fn prune(&self, below: OutputIndex) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Returns how many delivered blocks may await acknowledgement at once.
    fn ack_window(&self) -> NonZeroUsize;
}

/// A [`Ledger`] that serves floors: states a node can install to resume the stream after an
/// index, for state sync.
pub trait Floors: Ledger {
    /// Everything a marshal needs to resume the stream, finalized by a consensus certificate in
    /// its round. A floor of a newer round resumes the stream no earlier.
    type Floor: Roundable + Clone + Send + Sync + 'static;

    /// Returns the newest retained floor that resumes the stream after an index at or below `at`,
    /// with that index.
    ///
    /// Pruning below an index keeps this answering for every `at` from that index on, whenever it
    /// answered before.
    fn floor_at(
        &self,
        at: OutputIndex,
    ) -> impl Future<Output = Result<Option<(OutputIndex, Self::Floor)>, Self::Error>> + Send;

    /// Makes the marshal resume the stream from `floor`, and returns the index it resumes after,
    /// or `None` if the marshal rejected the floor.
    ///
    /// `floor` may come from an untrusted peer: the marshal verifies it and rejects one that does
    /// not verify, or of a round it already passed. It returns once the floor is durably installed,
    /// which may wait for the marshal to fetch the floor's data from peers. After a rejection, the
    /// caller may install another floor.
    ///
    /// A node installs a floor before relying on anything the marshal delivers. Once one is
    /// installed, acknowledging a block the marshal delivered before it has no effect.
    fn install(
        &self,
        floor: Self::Floor,
    ) -> impl Future<Output = Result<Option<OutputIndex>, Self::Error>> + Send;
}

/// A [`Ledger`] whose stream is one chain: the block at index `i` has height `i`, and its parent is
/// the block at index `i - 1`.
pub trait Linear: Ledger {}
