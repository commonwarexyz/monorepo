//! Engine-neutral views of a marshal's finalized stream.
//!
//! Every consensus engine's marshal delivers finalized blocks to its application in order, each at
//! the next [`OutputIndex`]. The traits here let code downstream of consensus consume that stream
//! without naming the engine:
//!
//! - [`Delivery`]: an item a marshal reports to its application, which may carry a [`Finalized`]
//!   block.
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

    /// Returns the finalized block this item carries, or `None` for an advisory item.
    fn finalized(self) -> Option<Finalized<Self::Block, Self::Acknowledgement>>;
}

impl<B: Block, A: Acknowledgement> Delivery for Finalized<B, A> {
    type Block = B;
    type Acknowledgement = A;

    fn finalized(self) -> Option<Self> {
        Some(self)
    }
}

/// A marshal's finalized stream, as its consumer bounds what the marshal retains.
pub trait Ledger: Clone + Send + Sync + 'static {
    /// The block type of the stream.
    type Block: Block;

    /// Allows the marshal to drop finalized data below `below`.
    ///
    /// Blocks at and above `below` stay retained, and so does everything the marshal still needs
    /// to deliver unacknowledged blocks. A marshal may keep more.
    fn prune(&self, below: OutputIndex) -> impl Future<Output = ()> + Send;

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
    ) -> impl Future<Output = Option<(OutputIndex, Self::Floor)>> + Send;

    /// Makes the marshal resume the stream from `floor`, and returns the index it resumes after
    /// once the marshal holds the floor, or `None` if it rejected it.
    ///
    /// `floor`'s certificate must verify. A floor does not always state where it resumes, so the
    /// index is known only once the marshal holds it. A marshal rejects a floor of a round it
    /// already passed. A node installs one floor, before relying on anything the marshal delivers.
    fn install(&self, floor: Self::Floor) -> impl Future<Output = Option<OutputIndex>> + Send;
}

/// A [`Ledger`] whose stream is one chain: the block at index `i` has height `i`, and its parent is
/// the block at index `i - 1`.
pub trait Linear: Ledger {}
