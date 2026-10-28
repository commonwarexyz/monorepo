//! Choosing the transfers of a batch in block order, for a proposer.

use super::{Account, Change, PREFETCH_DISTANCE, Plan, Transfer, group_effects};
use ahash::RandomState;
use commonware_parallel::Strategy;
use commonware_storage::qmdb::any::batch::Slot;
use commonware_utils::{Array, Widen, handles::Table};
use std::ops::Range;

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
pub struct Selection<K, A: Account> {
    /// The hasher that places keys in the table, keyed afresh for each selection.
    hasher: RandomState,
    /// The table from each key's hash to its index in `keys`.
    table: Table<u32>,
    /// Every touched key, in staging order.
    keys: Vec<K>,
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
    /// The accepted effects in the order applied, each with its key's index.
    effects: Vec<(usize, A::Effect)>,
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
    /// A selection with no keys.
    pub fn new() -> Self {
        Self {
            hasher: RandomState::new(),
            table: Table::new(),
            keys: Vec::new(),
            reads: Vec::new(),
            starts: Vec::new(),
            accounts: Vec::new(),
            debits: Vec::new(),
            credits: Vec::new(),
            effects: Vec::new(),
            changes: Vec::new(),
            undo: Vec::new(),
        }
    }

    /// Every key touched so far, in the order their accounts are staged.
    pub fn keys(&self) -> &[K] {
        &self.keys
    }

    /// Records the keys `transfers` touch and returns the range of [`keys`](Self::keys) holding
    /// the ones not touched before, in the order their accounts must be staged and registered.
    ///
    /// # Panics
    ///
    /// Panics if the selection would hold more than `u32::MAX` keys.
    pub fn touch<T: Transfer<Key = K, Account = A>>(&mut self, transfers: &[T]) -> Range<usize> {
        let start = self.keys.len();

        // Every key is hashed first, so the table is sized for the round before the first lookup
        // and each key's home slot is prefetched ahead of its lookup.
        let keys: Vec<&K> = transfers
            .iter()
            .flat_map(Transfer::changes)
            .map(|(key, _)| key)
            .collect();
        let hashes: Vec<u64> = keys
            .iter()
            .map(|key| self.hasher.hash_one(key.as_ref()))
            .collect();
        let (hasher, known) = (&self.hasher, &self.keys);
        self.table.reserve(keys.len(), |index| {
            hasher.hash_one(known[Widen::widen(index)].as_ref())
        });
        for (position, (key, &hash)) in keys.iter().zip(&hashes).enumerate() {
            if let Some(&ahead) = hashes.get(position + PREFETCH_DISTANCE) {
                self.table.prefetch(ahead);
            }
            self.index(key, hash, true);
        }
        start..self.keys.len()
    }

    /// Registers the starting accounts of the keys touched since the last registration, in
    /// [`keys`](Self::keys) order, `None` for a key the database does not hold.
    ///
    /// # Panics
    ///
    /// Panics if `reads` does not hold one account per key touched since the last registration.
    pub fn register(&mut self, reads: &[Option<A>]) {
        assert_eq!(
            self.reads.len() + reads.len(),
            self.keys.len(),
            "reads must hold the accounts of exactly the unregistered keys"
        );
        self.accounts
            .extend(reads.iter().map(|read| read.clone().unwrap_or_default()));
        self.starts
            .extend(self.accounts[self.reads.len()..].iter().map(A::balance));
        self.reads.extend_from_slice(reads);
        self.debits.resize(self.keys.len(), 0);
        self.credits.resize(self.keys.len(), 0);
    }

    /// Applies `transfers` in order, returning whether each was accepted.
    ///
    /// # Panics
    ///
    /// Panics if a transfer touches a key whose account is not registered.
    pub fn apply<T: Transfer<Key = K, Account = A>>(&mut self, transfers: &[T]) -> Vec<bool> {
        transfers
            .iter()
            .map(|transfer| self.apply_one(transfer))
            .collect()
    }

    /// Applies one transfer, accepting it only if every key it touches still settles.
    fn apply_one<T: Transfer<Key = K, Account = A>>(&mut self, transfer: &T) -> bool {
        // Resolve every change to its key's index before applying any, so undoing a dropped
        // transfer needs no further lookups.
        self.changes.clear();
        for (key, change) in transfer.changes() {
            let index = self.index(key, self.hasher.hash_one(key.as_ref()), false);
            assert!(
                index < self.reads.len(),
                "every key a transfer touches must be registered before the transfer is applied"
            );
            self.changes.push((index, change));
        }

        // Apply every change before checking any key, so each key is checked against all of the
        // transfer's changes to it, as when the batch settles. Debits and credits add to their
        // key's sums. Each effect saves its key's account and then applies to it, in the order
        // listed. A sum past `u64::MAX` or a refused effect cannot settle.
        self.undo.clear();
        let recorded = self.effects.len();
        let mut applied = 0;
        let mut fits = true;
        for &(index, change) in &self.changes {
            let (sum, amount) = match change {
                Change::Debit(amount) => (&mut self.debits[index], amount),
                Change::Credit(amount) => (&mut self.credits[index], amount),
                Change::Effect(effect) => {
                    self.undo.push((index, self.accounts[index].clone()));
                    applied += 1;
                    if !self.accounts[index].apply(effect) {
                        fits = false;
                        break;
                    }
                    self.effects.push((index, effect));
                    continue;
                }
            };
            let Some(total) = sum.checked_add(amount) else {
                fits = false;
                break;
            };
            *sum = total;
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
            for &(index, change) in &self.changes[..applied] {
                match change {
                    Change::Debit(amount) => self.debits[index] -= amount,
                    Change::Credit(amount) => self.credits[index] -= amount,
                    Change::Effect(_) => {}
                }
            }
            while let Some((index, account)) = self.undo.pop() {
                self.accounts[index] = account;
            }
            self.effects.truncate(recorded);
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
            self.keys.len(),
            "every touched key must be registered before the selection settles"
        );

        // The accepted changes settle as a plan of the accepted transfers would. A key that no
        // accepted transfer changes is left as it started, so its slot is a keep. Settling cannot
        // fail, since `apply` accepts a transfer only if every key it touches still settles.
        let (effect_ends, effects) = group_effects(self.keys.len(), &self.effects);
        let plan = Plan {
            keys: self.keys,
            debits: self.debits,
            credits: self.credits,
            effect_ends,
            effects,
        };
        plan.settle(&self.reads, strategy)
            .expect("accepted transfers must settle")
    }

    /// Returns the index of `key` given its `hash`. An absent key is added when `insert` is set
    /// and otherwise yields the key count.
    fn index(&mut self, key: &K, hash: u64, insert: bool) -> usize {
        if !insert {
            return self
                .table
                .get(hash)
                .find(|&index| self.keys[Widen::widen(index)] == *key)
                .map_or(self.keys.len(), Widen::widen);
        }

        // The key either finds its own index among the table's candidates or takes the next one,
        // in one walk. When the table grows, it resolves each index back to its key's hash.
        let next =
            u32::try_from(self.keys.len()).expect("a selection must hold at most u32::MAX keys");
        let (hasher, keys) = (&self.hasher, &self.keys);
        let (index, inserted) = self.table.get_or_insert_with(
            hash,
            |index| keys[Widen::widen(index)] == *key,
            next,
            |index| hasher.hash_one(keys[Widen::widen(index)].as_ref()),
        );
        if inserted {
            self.keys.push(key.clone());
        }
        Widen::widen(index)
    }
}
