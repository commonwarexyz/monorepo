//! Choosing the transfers of a batch in block order, for a proposer.

use super::{
    Account, Change, KeyIndex, PREFETCH_DISTANCE, Transfer, estimated_changes, for_each_touch,
    settle_batches, settled_slot,
};
use ahash::RandomState;
use commonware_parallel::Strategy;
use commonware_storage::qmdb::any::batch::Slot;
use commonware_utils::{
    Array,
    prefetch::{self, Lookahead},
};
use std::{convert::Infallible, ops::Range};

/// Selects the transfers of a batch in block order against the accounts the batch starts from.
///
/// Each candidate applies in order and is accepted only if the batch still settles, so one
/// candidate that cannot settle does not reject the others. Credits never fund debits in a batch,
/// so a credit that an accepted candidate receives cannot pay for a later candidate, and each key's
/// accepted debits must fit its starting balance. A candidate that does not fit, or whose effect an
/// account refuses, is dropped with no debit, credit, or effect left behind, so a verifier settling
/// the accepted transfers as a batch reaches the same accounts.
///
/// Candidates arrive in rounds. [`touch`](Self::touch) records the keys a round touches and returns
/// the range holding the new ones, in the order their accounts must be staged, so the staged slots
/// line up with [`keys`](Self::keys). [`register`](Self::register) takes those accounts,
/// [`apply`](Self::apply) applies the round, and [`settle`](Self::settle) produces the slot to
/// merkleize for every key.
#[derive(Debug)]
pub struct Selection<K, A: Account> {
    /// The hasher that places keys in the table, keyed afresh for each selection.
    hasher: RandomState,
    /// Every touched key and its index, in staging order.
    index: KeyIndex<K>,
    /// The index of each non-empty change's key in the round touched last, in order.
    round: Vec<usize>,
    /// Each registered key's starting account, `None` for a key the database does not hold.
    reads: Vec<Option<A>>,
    /// Each registered key's starting balance.
    starts: Vec<u64>,
    /// Each registered key's starting account with the accepted effects applied.
    accounts: Vec<A>,
    /// The sum of the accepted debits to each registered key.
    debits: Vec<u64>,
    /// The sum of the accepted credits to each registered key.
    credits: Vec<u64>,
    /// Scratch space for the changes of the transfer being applied, each with its key's index.
    changes: Vec<(usize, Change<A::Effect>)>,
    /// Scratch space for each account as it was before an effect of the transfer being applied,
    /// with its key's index.
    undo: Vec<(usize, A)>,
}

impl<K: Array, A: Account> Default for Selection<K, A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Array, A: Account> Selection<K, A> {
    /// A selection with no keys, keyed randomly.
    pub fn new() -> Self {
        Self::with_hasher(RandomState::new())
    }

    /// A selection with a reproducible hash key.
    ///
    /// A seed adversaries can predict lets them choose colliding keys. Use this for reproducible
    /// runs, such as tests under the deterministic runtime. [`new`](Self::new) keys each selection
    /// randomly.
    pub fn with_seed(seed: u64) -> Self {
        Self::with_hasher(RandomState::with_seeds(seed, 0, 0, 0))
    }

    fn with_hasher(hasher: RandomState) -> Self {
        Self {
            hasher,
            index: KeyIndex::with_capacity(0),
            round: Vec::new(),
            reads: Vec::new(),
            starts: Vec::new(),
            accounts: Vec::new(),
            debits: Vec::new(),
            credits: Vec::new(),
            changes: Vec::new(),
            undo: Vec::new(),
        }
    }

    /// Every key touched so far, in the order their accounts are staged.
    pub fn keys(&self) -> &[K] {
        self.index.keys()
    }

    /// Records the keys `transfers` touch and returns the range of [`keys`](Self::keys) holding
    /// the ones not touched before, in the order their accounts must be staged and registered.
    /// Keys touched only by empty changes are left out.
    ///
    /// # Panics
    ///
    /// Panics if the selection would hold more than `u32::MAX` keys.
    pub fn touch<T: Transfer<Key = K, Account = A>>(&mut self, transfers: &[T]) -> Range<usize> {
        // Every key is hashed first, so the index is sized for the round before the first lookup
        // and each key's home slot is prefetched ahead of its lookup. Room for half again the keys
        // it already holds makes a growing index move to a larger table at a lower load, with
        // fewer placed keys to rehash, at the cost of a table that may be larger than it needs.
        let start = self.index.len();
        let mut hashed: Vec<(&K, u64)> = Vec::with_capacity(estimated_changes(transfers));
        for_each_touch(transfers, &self.hasher, |touch| {
            hashed.push((touch.key, touch.hash))
        });
        self.index
            .reserve(hashed.len() + self.index.len() / 2, &self.hasher);

        // Each change's index is kept, so applying this round looks up no key again.
        self.round.clear();
        self.round.reserve(hashed.len());
        let mut ahead = Lookahead::new(PREFETCH_DISTANCE);
        let mut scan = hashed.into_iter();
        loop {
            if prefetch::ENABLED {
                for &(_, hash) in ahead.advance(scan.as_slice()) {
                    self.index.prefetch(hash);
                }
            }
            let Some((key, hash)) = scan.next() else {
                break;
            };
            let (index, _) = self.index.find_or_insert(key, hash, &self.hasher);
            self.round.push(index);
        }
        start..self.index.len()
    }

    /// Registers the starting accounts of the keys touched since the last registration, in
    /// [`keys`](Self::keys) order, `None` for a key the database does not hold.
    ///
    /// # Panics
    ///
    /// Panics if `reads` does not hold one account per key touched since the last registration.
    pub fn register(&mut self, reads: Vec<Option<A>>) {
        assert_eq!(
            self.reads.len() + reads.len(),
            self.index.len(),
            "reads must hold the accounts of exactly the unregistered keys"
        );
        self.accounts
            .extend(reads.iter().map(|read| read.clone().unwrap_or_default()));
        self.starts
            .extend(self.accounts[self.reads.len()..].iter().map(A::balance));
        self.reads.extend(reads);
        self.debits.resize(self.index.len(), 0);
        self.credits.resize(self.index.len(), 0);
    }

    /// Applies `transfers` in order, returning whether each was accepted.
    ///
    /// # Panics
    ///
    /// Panics if a transfer touches a key whose account is not registered.
    pub fn apply<T: Transfer<Key = K, Account = A>>(&mut self, transfers: &[T]) -> Vec<bool> {
        let mut cursor = 0;
        transfers
            .iter()
            .map(|transfer| self.apply_one(transfer, &mut cursor))
            .collect()
    }

    /// Applies one transfer, accepting it only if every key it touches still settles.
    fn apply_one<T: Transfer<Key = K, Account = A>>(
        &mut self,
        transfer: &T,
        cursor: &mut usize,
    ) -> bool {
        // Resolve every change to its key's index before applying any, so undoing a dropped
        // transfer needs no further lookups. A change in the same place as in the round touched
        // last takes the index found then, once its key confirms it.
        self.changes.clear();
        for (key, change) in transfer.changes() {
            if change.is_empty() {
                continue;
            }
            let touched = self
                .round
                .get(*cursor)
                .copied()
                .filter(|&index| self.index.keys()[index] == *key);
            *cursor += 1;
            let index = touched
                .or_else(|| self.index.find(key, self.hasher.hash_one(key.as_ref())))
                .unwrap_or(self.index.len());
            assert!(
                index < self.reads.len(),
                "every key a transfer touches must be registered before the transfer is applied"
            );
            self.changes.push((index, change));
        }

        // Apply every change before checking any key, so each key is checked against all of the
        // transfer's changes to it, as when the batch settles. A change's effect saves its key's
        // account and then applies to it, in the order listed. Its debit and credit are both
        // checked against `u64::MAX` before either is added to its key's sums, so the two are added
        // together or not at all. A refused effect or a sum past `u64::MAX` cannot settle.
        self.undo.clear();
        let mut applied = 0;
        let mut fits = true;
        for &(index, ref change) in &self.changes {
            if let Some(effect) = &change.effect {
                self.undo.push((index, self.accounts[index].clone()));
                if !self.accounts[index].apply(effect.clone()) {
                    fits = false;
                    break;
                }
            }
            let debit = if change.debit == 0 {
                None
            } else if let Some(sum) = self.debits[index].checked_add(change.debit) {
                Some(sum)
            } else {
                fits = false;
                break;
            };
            let credit = if change.credit == 0 {
                None
            } else if let Some(sum) = self.credits[index].checked_add(change.credit) {
                Some(sum)
            } else {
                fits = false;
                break;
            };
            if let Some(sum) = debit {
                self.debits[index] = sum;
            }
            if let Some(sum) = credit {
                self.credits[index] = sum;
            }
            applied += 1;
        }

        // Each touched key's debits must fit its starting balance, and its final balance must fit
        // in a `u64`.
        fits = fits
            && self.changes.iter().all(|&(index, _)| {
                self.starts[index]
                    .checked_sub(self.debits[index])
                    .and_then(|remaining| remaining.checked_add(self.credits[index]))
                    .is_some()
            });

        // A dropped transfer leaves no debit, credit, or effect behind. The saved accounts are
        // restored newest first, so an account saved more than once ends at its earliest save, as
        // it was before the transfer.
        if !fits {
            for &(index, ref change) in &self.changes[..applied] {
                self.debits[index] -= change.debit;
                self.credits[index] -= change.credit;
            }
            while let Some((index, account)) = self.undo.pop() {
                self.accounts[index] = account;
            }
            return false;
        }
        true
    }

    /// Settles the accepted transfers, returning the slot to merkleize for every key in
    /// [`keys`](Self::keys) order.
    ///
    /// # Panics
    ///
    /// Panics if a touched key's account is not registered.
    pub fn settle(self, strategy: &impl Strategy) -> Vec<Slot<A>> {
        assert_eq!(
            self.reads.len(),
            self.index.len(),
            "every touched key must be registered before the selection settles"
        );

        // `apply` accepts a transfer only if every key it touches still settles, so no balance here
        // underflows or overflows.
        let Ok(slots) = settle_batches(self.index.len(), strategy, |range, slots| {
            let default = A::default();
            for (index, slot) in range.zip(slots) {
                let start = self.reads[index].clone().unwrap_or_default();
                let balance = self.starts[index] - self.debits[index] + self.credits[index];
                *slot = settled_slot(self.accounts[index].clone(), balance, &start, &default);
            }
            Ok::<_, Infallible>(())
        });
        slots
    }
}
