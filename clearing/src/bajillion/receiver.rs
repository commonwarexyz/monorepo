//! Receiving payments and holding the operator to its preconfirmations.

use super::{Challenge, Epoch, Error, Namespace, Opening, Receipt};
use commonware_cryptography::{Hasher, PublicKey};
use std::collections::BTreeMap;

/// An account receiving payments.
///
/// A receiver keeps, for each epoch and sender, the receipt preconfirming the largest amount. It
/// accepts receipts only for epochs whose close has not posted and while the ledger has not
/// halted, so every receipt it relies on can still be checked against the close of its epoch.
pub struct Receiver<P: PublicKey, O: PublicKey, H: Hasher> {
    account: P,
    operator: O,
    namespace: Namespace,
    /// Epoch whose close the ledger expects next.
    next: Epoch,
    halted: bool,
    /// The receipt promising the largest amount, by epoch and sender.
    #[allow(clippy::type_complexity)]
    receipts: BTreeMap<Epoch, BTreeMap<P, Receipt<P, O, H::Digest>>>,
}

impl<P: PublicKey, O: PublicKey, H: Hasher> Receiver<P, O, H> {
    /// Creates a receiver for `account` while the ledger expects the close of `next`.
    pub const fn new(account: P, operator: O, namespace: Namespace, next: Epoch) -> Self {
        Self {
            account,
            operator,
            namespace,
            next,
            halted: false,
            receipts: BTreeMap::new(),
        }
    }

    /// Resumes a receiver for `account` from the receipts it accepted, while the ledger expects
    /// the close of `next` and has `halted` or not.
    ///
    /// Returns an error if a receipt is for another account or does not verify.
    pub fn resume(
        account: P,
        operator: O,
        namespace: Namespace,
        next: Epoch,
        halted: bool,
        receipts: impl IntoIterator<Item = Receipt<P, O, H::Digest>>,
    ) -> Result<Self, Error> {
        let mut receiver = Self::new(account, operator, namespace, next);
        receiver.halted = halted;
        for receipt in receipts {
            receiver.verify(&receipt)?;
            let amount = receiver.amount(receipt.state.epoch, &receipt.state.account);
            if receipt.amount > amount {
                receiver.insert(receipt);
            }
        }
        Ok(receiver)
    }

    /// Returns the account receiving.
    pub const fn account(&self) -> &P {
        &self.account
    }

    /// Returns the amount preconfirmed from `sender` in `epoch`.
    pub fn amount(&self, epoch: Epoch, sender: &P) -> u64 {
        self.receipts
            .get(&epoch)
            .and_then(|receipts| receipts.get(sender))
            .map_or(0, |receipt| receipt.amount)
    }

    /// Returns the receipts held for `epoch`, one per sender, in sender order.
    pub fn receipts(&self, epoch: Epoch) -> impl Iterator<Item = &Receipt<P, O, H::Digest>> {
        self.receipts
            .get(&epoch)
            .into_iter()
            .flat_map(BTreeMap::values)
    }

    /// Returns an error unless `receipt` pays this account and verifies.
    fn verify(&self, receipt: &Receipt<P, O, H::Digest>) -> Result<(), Error> {
        if receipt.receiver != self.account {
            return Err(Error::WrongReceiver);
        }
        receipt.verify::<H>(&self.namespace, &self.operator)
    }

    /// Holds `receipt` as the largest preconfirmation from its sender in its epoch.
    fn insert(&mut self, receipt: Receipt<P, O, H::Digest>) {
        self.receipts
            .entry(receipt.state.epoch)
            .or_default()
            .insert(receipt.state.account.clone(), receipt);
    }

    /// Accepts a receipt and returns the total it preconfirms from its sender in its epoch.
    ///
    /// Returns an error if the ledger halted or posted the close of the receipt's epoch, the
    /// receipt is for another account, it does not increase the amount preconfirmed, or it does
    /// not verify.
    pub fn receive(&mut self, receipt: Receipt<P, O, H::Digest>) -> Result<u64, Error> {
        if self.halted {
            return Err(Error::Halted);
        }
        if receipt.state.epoch < self.next {
            return Err(Error::Closed);
        }
        if receipt.amount <= self.amount(receipt.state.epoch, &receipt.state.account) {
            return Err(Error::NotIncreasing);
        }
        self.verify(&receipt)?;
        let amount = receipt.amount;
        self.insert(receipt);
        Ok(amount)
    }

    /// Records that the ledger posted the close of `epoch`.
    pub fn posted(&mut self, epoch: Epoch) {
        self.next = self.next.max(epoch.saturating_add(1));
    }

    /// Stops accepting receipts because the ledger halted.
    pub const fn halt(&mut self) {
        self.halted = true;
    }

    /// Checks the posted close of `epoch`, with matrix root `root`, against the receipt from
    /// `sender`, where `opening` opens `sender`'s payment to this account.
    ///
    /// Returns a challenge if the close credits less than the receipt, or `None` if it credits at
    /// least as much or no receipt is held. Returns an error if the opening does not verify.
    #[allow(clippy::type_complexity)]
    pub fn audit(
        &self,
        epoch: Epoch,
        root: &H::Digest,
        sender: &P,
        opening: &Opening<P, H::Digest>,
    ) -> Result<Option<Challenge<P, O, H::Digest>>, Error> {
        let Some(receipt) = self
            .receipts
            .get(&epoch)
            .and_then(|receipts| receipts.get(sender))
        else {
            return Ok(None);
        };
        let amount = opening.verify::<H>(root, sender, &self.account)?;
        if amount >= receipt.amount {
            return Ok(None);
        }
        Ok(Some(Challenge {
            receipt: receipt.clone(),
            opening: opening.clone(),
        }))
    }

    /// Forgets the receipts of epochs before `epoch`.
    pub fn prune(&mut self, epoch: Epoch) {
        self.receipts = self.receipts.split_off(&epoch);
    }
}
