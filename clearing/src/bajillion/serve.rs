//! Account activity and settlement claims from one retained complete close.
//!
//! Current balance membership and absence are served by the QMDB state owner. This index
//! serves epoch activity independently, including accounts whose balance did not change.

use crate::bajillion::{
    challenge::{self, AccountLookup, ChangeAbsence, ChangeOpening, HigherEntryLookup},
    transition::{ChangeParts, Close, ExternalPayoutClaim, TransitionError, WithdrawalClaim},
};
use alloc::boxed::Box;
use commonware_cryptography::{Digest, Hasher, PublicKey};
use thiserror::Error;

/// A view of retained BMT evidence for every account in one close.
pub struct Index<'a, P: PublicKey, D: Digest> {
    close: &'a Close<P, D>,
}
impl<'a, P: PublicKey, D: Digest> Index<'a, P, D> {
    /// Indexes a locally retained close whose descriptor was authenticated.
    pub const fn new(close: &'a Close<P, D>) -> Self {
        Self { close }
    }
    /// Opens the public epoch debit or proves that the account had no activity.
    pub fn account_lookup<H: Hasher<Digest = D>>(
        &self,
        account: &P,
    ) -> Result<AccountLookup<P, D>, ServeError> {
        let lookup = match self.close.changes.change_parts(account)? {
            ChangeParts::Present { leaf, proof } => {
                AccountLookup::Present(Box::new(ChangeOpening {
                    value: leaf.value(),
                    proof,
                }))
            }
            ChangeParts::Absent {
                predecessor,
                successor,
                opening,
            } => AccountLookup::Absent(ChangeAbsence {
                predecessor,
                successor,
                opening,
            }),
        };
        lookup.resolve::<H>(&self.close.roots.change, account)?;
        Ok(lookup)
    }
    /// Opens the compact activity value for a participating account.
    pub fn change_opening<H: Hasher<Digest = D>>(
        &self,
        account: &P,
    ) -> Result<ChangeOpening<D>, ServeError> {
        match self.account_lookup::<H>(account)? {
            AccountLookup::Present(opening) => Ok(*opening),
            AccountLookup::Absent(_) => Err(ServeError::Absent),
        }
    }
    /// Opens the public terminal entry or its authenticated absence.
    pub fn higher_entry_lookup<H: Hasher<Digest = D>>(
        &self,
        payer: &P,
        recipient: &P,
    ) -> Result<HigherEntryLookup<P, D>, ServeError> {
        let lookup = match self.close.changes.change_parts(payer)? {
            ChangeParts::Present { leaf, proof } => {
                let index = self
                    .close
                    .rows
                    .binary_search_by(|row| row.account.as_ref().cmp(payer.as_ref()))
                    .map_err(|_| ServeError::Absent)?;
                HigherEntryLookup::Present {
                    value: leaf.value().core(),
                    proof,
                    entry: self
                        .close
                        .out_vectors
                        .get(index)
                        .ok_or(ServeError::Absent)?
                        .lookup::<H, D>(recipient)
                        .map_err(TransitionError::from)?,
                }
            }
            ChangeParts::Absent {
                predecessor,
                successor,
                opening,
            } => HigherEntryLookup::Absent(ChangeAbsence {
                predecessor,
                successor,
                opening,
            }),
        };
        lookup.resolve::<H>(&self.close.roots.change, payer, recipient)?;
        Ok(lookup)
    }
    /// Opens an output for one registered withdrawal.
    pub fn withdrawal_claim<H: Hasher<Digest = D>>(
        &self,
        account: &P,
    ) -> Result<WithdrawalClaim<D>, ServeError> {
        let claim = self.close.withdrawal_claim(account)?;
        claim.verify::<H>(&self.close.roots.withdrawal_outputs)?;
        Ok(claim)
    }
    /// Opens a positive external payout.
    pub fn external_payout_claim<H: Hasher<Digest = D>>(
        &self,
        account: &P,
    ) -> Result<ExternalPayoutClaim<P, D>, ServeError> {
        let claim = self.close.external_payout_claim(account)?;
        claim.verify::<H>(&self.close.roots.change)?;
        Ok(claim)
    }
}
/// A missing requested activity or invalid retained proof.
#[derive(Debug, Error)]
pub enum ServeError {
    /// The account has no matching activity in this close.
    #[error("account has no matching activity")]
    Absent,
    /// Retained close construction or claim verification failed.
    #[error(transparent)]
    Transition(#[from] TransitionError),
    /// An activity proof did not match the close root.
    #[error(transparent)]
    Challenge(#[from] challenge::ChallengeError),
}
