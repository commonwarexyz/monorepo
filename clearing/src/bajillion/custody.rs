//! Compact activity proofs reconstructed from retained native operations.
//!
//! Certified close descriptors own the epoch and account-row interval. Positive outgoing
//! amounts delimit each row's original entries by its terminal debit. Payout proofs use the
//! payout log independently of this view.
//!
//! Native reads guide discovery. Returned rows come from typed native proofs, and reconstructed
//! outgoing entries must match the payer root in the proven row.

use crate::bajillion::{
    challenge::{AccountLookup, ChallengeError, ChangeAbsence, ChangeOpening, HigherEntryLookup},
    commitment::MAX_VECTOR_LENGTH,
    logs::{self, ActivityOperation, ActivityRecord, Logs},
    state::AccountChange,
    transition::{ActivityRange, TransitionError},
    vector::OutVector,
};
use alloc::{boxed::Box, vec::Vec};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_parallel::Strategy;
use commonware_runtime::Spawner;
use commonware_storage::{Context, merkle::Location};
use core::num::NonZeroU64;
use thiserror::Error;

/// Native activity proof construction or verification failed.
#[derive(Debug, Error)]
pub enum Error {
    /// Native records do not construct the requested activity proof.
    #[error(transparent)]
    Transition(#[from] TransitionError),
    /// The activity proof does not match the authenticated interval.
    #[error(transparent)]
    Challenge(#[from] ChallengeError),
}

/// Ephemeral view of one independently authenticated activity interval.
pub struct Epoch<D: Digest> {
    epoch: u64,
    range: ActivityRange<D>,
}

impl<D: Digest> Epoch<D> {
    /// Opens the retained native interval supplied by a certified close descriptor.
    ///
    /// The caller authenticates `epoch` and `range` together. This checks native availability
    /// and the terminal Commit without introducing another authority for the descriptor.
    pub async fn at<E, H, P, S>(
        logs: &Logs<E, H, P, S>,
        epoch: u64,
        range: ActivityRange<D>,
    ) -> Result<Self, TransitionError>
    where
        E: Context + Spawner,
        H: Hasher<Digest = D>,
        P: PublicKey,
        S: Strategy,
    {
        if !range.contains(range.start, 0) || range.end - range.start > u64::from(MAX_VECTOR_LENGTH)
        {
            return Err(TransitionError::LogRange);
        }
        match logs
            .raw_activity_record_at(&range.head, range.head.operations - 1)
            .await?
        {
            ActivityOperation::Commit(None, floor) if *floor == range.head.floor => {
                Ok(Self { epoch, range })
            }
            _ => Err(TransitionError::LogRange),
        }
    }

    async fn row<E, H, P, S>(
        &self,
        logs: &Logs<E, H, P, S>,
        index: u64,
    ) -> Result<AccountChange<P, D>, TransitionError>
    where
        E: Context + Spawner,
        H: Hasher<Digest = D>,
        P: PublicKey,
        S: Strategy,
    {
        match logs
            .activity_source()
            .get(Location::new(index))
            .await
            .map_err(logs::Error::from)?
        {
            Some(ActivityRecord::Row(row)) => Ok(row),
            _ => Err(TransitionError::LogRange),
        }
    }

    async fn find<E, H, P, S>(
        &self,
        logs: &Logs<E, H, P, S>,
        account: &P,
    ) -> Result<Result<u64, u64>, TransitionError>
    where
        E: Context + Spawner,
        H: Hasher<Digest = D>,
        P: PublicKey,
        S: Strategy,
    {
        let mut start = self.range.start;
        let mut end = self.range.end;
        while start < end {
            let middle = start + (end - start) / 2;
            let row = self.row(logs, middle).await?;
            match row.account().as_ref().cmp(account.as_ref()) {
                core::cmp::Ordering::Less => start = middle + 1,
                core::cmp::Ordering::Greater => end = middle,
                core::cmp::Ordering::Equal => return Ok(Ok(middle)),
            }
        }
        Ok(Err(start))
    }

    async fn outgoing<E, H, P, S>(
        &self,
        logs: &Logs<E, H, P, S>,
        index: u64,
        payer: &AccountChange<P, D>,
    ) -> Result<OutVector<P>, TransitionError>
    where
        E: Context + Spawner,
        H: Hasher<Digest = D>,
        P: PublicKey,
        S: Strategy,
    {
        if !payer.has_outgoing() {
            return Ok(OutVector::empty(self.epoch, payer.account().clone()));
        }

        let mut position = self.range.end;
        let terminal = self.range.head.operations - 1;
        let mut page = Vec::new().into_iter();
        let mut entries = Vec::new();
        for row_index in self.range.start..=index {
            let row = if row_index == index {
                payer.clone()
            } else {
                self.row(logs, row_index).await?
            };
            let mut debit = 0_u64;
            let mut length = 0_u32;
            let mut previous: Option<P> = None;
            while debit < row.terminal_debit() {
                if position == terminal || length == MAX_VECTOR_LENGTH {
                    return Err(TransitionError::NonCanonicalRows);
                }
                if page.len() == 0 {
                    let end = position + (terminal - position).min(128);
                    let locations = (position..end).map(Location::new).collect::<Vec<_>>();
                    page = logs
                        .activity_source()
                        .get_many(&locations)
                        .await
                        .map_err(logs::Error::from)?
                        .into_iter();
                }
                let Some(Some(ActivityRecord::Entry(entry))) = page.next() else {
                    return Err(TransitionError::NonCanonicalRows);
                };
                if entry.count == 0
                    || entry.cumulative < entry.count
                    || previous
                        .as_ref()
                        .is_some_and(|key| key.as_ref() >= entry.recipient.as_ref())
                {
                    return Err(TransitionError::NonCanonicalRows);
                }
                debit = debit
                    .checked_add(entry.cumulative)
                    .filter(|sum| *sum <= row.terminal_debit())
                    .ok_or(TransitionError::NonCanonicalRows)?;
                previous = Some(entry.recipient.clone());
                position += 1;
                length += 1;
                if row_index == index {
                    entries.push(entry);
                }
            }
        }
        if index + 1 == self.range.end && position != terminal {
            return Err(TransitionError::NonCanonicalRows);
        }
        Ok(OutVector::new(
            self.epoch,
            payer.account().clone(),
            entries,
        )?)
    }

    async fn absence<E, H, P, S>(
        &self,
        logs: &Logs<E, H, P, S>,
        index: u64,
    ) -> Result<ChangeAbsence<P, D>, TransitionError>
    where
        E: Context + Spawner,
        H: Hasher<Digest = D>,
        P: PublicKey,
        S: Strategy,
    {
        let has_predecessor = index > self.range.start;
        let has_successor = index < self.range.end;
        let count = u64::from(has_predecessor) + u64::from(has_successor);
        let Some(count) = NonZeroU64::new(count) else {
            return Ok(ChangeAbsence {
                predecessor: None,
                successor: None,
                opening: None,
            });
        };
        let (opening, operations) = logs
            .activity_opening(&self.range.head, index - u64::from(has_predecessor), count)
            .await?;
        let mut operations = operations.into_iter();
        let mut next_row = || match operations.next() {
            Some(ActivityOperation::Append(ActivityRecord::Row(row))) => Ok(row),
            _ => Err(TransitionError::LogRange),
        };
        Ok(ChangeAbsence {
            predecessor: has_predecessor.then(&mut next_row).transpose()?,
            successor: has_successor.then(&mut next_row).transpose()?,
            opening: Some(opening),
        })
    }

    /// Generates compact account membership or ordered absence from native operations.
    pub async fn account_lookup<E, H, P, S>(
        &self,
        logs: &Logs<E, H, P, S>,
        account: &P,
    ) -> Result<AccountLookup<P, D>, Error>
    where
        E: Context + Spawner,
        H: Hasher<Digest = D>,
        P: PublicKey,
        S: Strategy,
    {
        let lookup = match self.find(logs, account).await? {
            Ok(index) => {
                let (proof, operations) = logs
                    .activity_opening(&self.range.head, index, NonZeroU64::MIN)
                    .await
                    .map_err(TransitionError::from)?;
                let [ActivityOperation::Append(ActivityRecord::Row(row))] = operations.as_slice()
                else {
                    return Err(TransitionError::LogRange.into());
                };
                let value = row.value();
                AccountLookup::Present(Box::new(ChangeOpening { value, proof }))
            }
            Err(index) => AccountLookup::Absent(self.absence(logs, index).await?),
        };
        lookup.resolve::<H>(&self.range, account)?;
        Ok(lookup)
    }

    /// Rebuilds the requested payer's BMT and combines it with its native row proof.
    pub async fn higher_entry_lookup<E, H, P, S>(
        &self,
        logs: &Logs<E, H, P, S>,
        payer: &P,
        recipient: &P,
    ) -> Result<HigherEntryLookup<P, D>, Error>
    where
        E: Context + Spawner,
        H: Hasher<Digest = D>,
        P: PublicKey,
        S: Strategy,
    {
        let lookup = match self.find(logs, payer).await? {
            Ok(index) => {
                let (proof, operations) = logs
                    .activity_opening(&self.range.head, index, NonZeroU64::MIN)
                    .await
                    .map_err(TransitionError::from)?;
                let [ActivityOperation::Append(ActivityRecord::Row(row))] = operations.as_slice()
                else {
                    return Err(TransitionError::LogRange.into());
                };
                let vector = self.outgoing(logs, index, row).await?;
                let value = row.value().core();
                let entry = vector
                    .lookup::<H, D>(recipient)
                    .map_err(TransitionError::from)?;
                HigherEntryLookup::Present {
                    value,
                    proof,
                    entry,
                }
            }
            Err(index) => HigherEntryLookup::Absent(self.absence(logs, index).await?),
        };
        lookup.resolve::<H>(&self.range, payer, recipient)?;
        Ok(lookup)
    }
}
