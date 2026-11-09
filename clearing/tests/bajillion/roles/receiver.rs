//! A reference receiver that holds the operator to its preconfirmations.

use commonware_clearing::bajillion::{
    Amount, Challenge, Epoch, InvalidOpening, Namespace, Opening, Receipt,
};
use commonware_codec::Encode as _;
use commonware_cryptography::{Digest, Hasher, PublicKey};
use core::hash::Hash;
use std::collections::BTreeMap;

/// Why the receiver refused a receipt or an audit.
#[derive(Debug, thiserror::Error)]
pub enum Refusal {
    /// The receipt pays another account.
    #[error("the receipt pays another account")]
    WrongReceiver,
    /// The receipt promises no more than one already held.
    #[error("the receipt promises no more than one already held")]
    NotIncreasing,
    /// The close of the receipt's epoch already posted.
    #[error("the close of the receipt's epoch already posted")]
    Closed,
    /// The ledger halted.
    #[error("the ledger halted")]
    Halted,
    /// The close of the audited epoch has not posted.
    #[error("the close of the audited epoch has not posted")]
    NotClosed,
    /// The receipt does not verify.
    #[error("invalid receipt")]
    InvalidReceipt,
    /// The opening does not verify.
    #[error("invalid opening")]
    InvalidOpening,
}

impl From<InvalidOpening> for Refusal {
    fn from(InvalidOpening: InvalidOpening) -> Self {
        Self::InvalidOpening
    }
}

/// The largest receipt held per epoch and sender.
pub type Receipts<P, O, D, A> = BTreeMap<Epoch, BTreeMap<P, Receipt<P, O, D, A>>>;

/// What the receiver persists (R2). A restart resumes from it alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Persisted<P: PublicKey, O: PublicKey, D: Digest, A: Amount> {
    /// Epoch of the close the ledger expects, as far as the receiver knows.
    pub next: Epoch,
    /// Whether the ledger halted.
    pub halted: bool,
    /// The largest receipt held per epoch and sender.
    pub receipts: Receipts<P, O, D, A>,
}

impl<P: PublicKey, O: PublicKey, D: Digest, A: Amount> Hash for Persisted<P, O, D, A> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        let Self {
            next,
            halted,
            receipts,
        } = self;
        next.hash(state);
        halted.hash(state);
        receipts.len().hash(state);
        for (epoch, receipts) in receipts {
            epoch.hash(state);
            receipts.len().hash(state);
            for (sender, receipt) in receipts {
                sender.hash(state);
                receipt.encode().hash(state);
            }
        }
    }
}

/// A receiver keeping the largest receipt per epoch and sender until it audits that epoch's
/// posted close. Two receivers are equal when they persisted the same records.
pub struct Receiver<P: PublicKey, O: PublicKey, H: Hasher, A: Amount> {
    account: P,
    namespace: Namespace,
    operator: O,
    persisted: Persisted<P, O, H::Digest, A>,
}

// The hasher is a type parameter only, so the derived impl would bound it.
impl<P: PublicKey, O: PublicKey, H: Hasher, A: Amount> Clone for Receiver<P, O, H, A> {
    fn clone(&self) -> Self {
        Self {
            account: self.account.clone(),
            namespace: self.namespace.clone(),
            operator: self.operator.clone(),
            persisted: self.persisted.clone(),
        }
    }
}

impl<P: PublicKey, O: PublicKey, H: Hasher, A: Amount> PartialEq for Receiver<P, O, H, A> {
    fn eq(&self, other: &Self) -> bool {
        self.persisted == other.persisted
    }
}

impl<P: PublicKey, O: PublicKey, H: Hasher, A: Amount> Eq for Receiver<P, O, H, A> {}

impl<P: PublicKey, O: PublicKey, H: Hasher, A: Amount> Hash for Receiver<P, O, H, A> {
    fn hash<T: core::hash::Hasher>(&self, state: &mut T) {
        self.persisted.hash(state);
    }
}

impl<P: PublicKey, O: PublicKey, H: Hasher, A: Amount> Receiver<P, O, H, A> {
    /// Returns a receiver while the ledger expects the close of `next`.
    pub const fn new(account: P, namespace: Namespace, operator: O, next: Epoch) -> Self {
        Self {
            account,
            namespace,
            operator,
            persisted: Persisted {
                next,
                halted: false,
                receipts: BTreeMap::new(),
            },
        }
    }

    /// Returns a receiver resuming from the halt it recorded and the receipts it held, in any
    /// order.
    pub fn resume(
        account: P,
        namespace: Namespace,
        operator: O,
        next: Epoch,
        halted: bool,
        receipts: impl IntoIterator<Item = Receipt<P, O, H::Digest, A>>,
    ) -> Result<Self, Refusal> {
        let mut receiver = Self::new(account, namespace, operator, next);
        receiver.persisted.halted = halted;
        for receipt in receipts {
            receiver.verify(&receipt)?;
            if receipt.amount > receiver.amount(receipt.state.epoch, &receipt.state.account) {
                receiver.insert(receipt);
            }
        }
        Ok(receiver)
    }

    /// Returns the receiving account.
    pub const fn account(&self) -> &P {
        &self.account
    }

    /// Returns the largest amount a held receipt promises from `sender` in `epoch`.
    pub fn amount(&self, epoch: Epoch, sender: &P) -> A {
        self.persisted
            .receipts
            .get(&epoch)
            .and_then(|receipts| receipts.get(sender))
            .map_or(A::ZERO, |receipt| receipt.amount)
    }

    /// Returns the receipts held for `epoch`, one per sender.
    pub fn receipts(&self, epoch: Epoch) -> impl Iterator<Item = &Receipt<P, O, H::Digest, A>> {
        self.persisted
            .receipts
            .get(&epoch)
            .into_iter()
            .flat_map(BTreeMap::values)
    }

    /// Checks that `receipt` pays this account and that [Receipt::verify] accepts it (R1).
    fn verify(&self, receipt: &Receipt<P, O, H::Digest, A>) -> Result<(), Refusal> {
        if receipt.receiver != self.account {
            return Err(Refusal::WrongReceiver);
        }
        if !receipt.verify::<H>(&self.namespace, &self.operator) {
            return Err(Refusal::InvalidReceipt);
        }
        Ok(())
    }

    /// Holds `receipt` in place of any earlier one from its sender in its epoch.
    fn insert(&mut self, receipt: Receipt<P, O, H::Digest, A>) {
        self.persisted
            .receipts
            .entry(receipt.state.epoch)
            .or_default()
            .insert(receipt.state.account.clone(), receipt);
    }

    /// Relies on a receipt (R1, R2), and returns the amount it promises.
    pub fn receive(&mut self, receipt: Receipt<P, O, H::Digest, A>) -> Result<A, Refusal> {
        if self.persisted.halted {
            return Err(Refusal::Halted);
        }
        if receipt.state.epoch < self.persisted.next {
            return Err(Refusal::Closed);
        }

        // The receipt is verified before it is compared with the one held, so a receipt this
        // account cannot rely on reveals nothing about what it holds from the receipt's sender.
        self.verify(&receipt)?;
        if receipt.amount <= self.amount(receipt.state.epoch, &receipt.state.account) {
            return Err(Refusal::NotIncreasing);
        }
        let amount = receipt.amount;
        self.insert(receipt);
        Ok(amount)
    }

    /// Records the final post of `epoch`, after which no receipt of it is accepted.
    pub fn posted(&mut self, epoch: Epoch) {
        self.persisted.next = self.persisted.next.max(epoch.saturating_add(1));
    }

    /// Records that the ledger halted, after which no receipt is accepted.
    pub const fn halt(&mut self) {
        self.persisted.halted = true;
    }

    /// Compares the receipt held from `sender` in `epoch` with what the posted close credits under
    /// its matrix root `root` (R3). Returns the challenge to submit if it credits less.
    #[allow(clippy::type_complexity)]
    pub fn audit(
        &self,
        epoch: Epoch,
        root: &H::Digest,
        sender: &P,
        opening: &Opening<P, H::Digest, A>,
    ) -> Result<Option<Challenge<P, O, H::Digest, A>>, Refusal> {
        if epoch >= self.persisted.next {
            return Err(Refusal::NotClosed);
        }
        let Some(receipt) = self
            .persisted
            .receipts
            .get(&epoch)
            .and_then(|receipts| receipts.get(sender))
        else {
            return Ok(None);
        };
        if opening.verify::<H>(root, sender, &self.account)? >= receipt.amount {
            return Ok(None);
        }
        Ok(Some(Challenge {
            receipt: receipt.clone(),
            opening: opening.clone(),
        }))
    }

    /// Forgets the receipts of epochs before `epoch`, once their closes are audited.
    pub fn prune(&mut self, epoch: Epoch) {
        self.persisted.receipts = self.persisted.receipts.split_off(&epoch);
    }
}
