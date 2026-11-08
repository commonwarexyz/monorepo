//! A reference operator that admits payments and soft withdrawals and closes each epoch.

use commonware_clearing::bajillion::{
    Admission, Amount, Amounts, Close, Epoch, Error, Flow, Limits, Namespace, Queue, Request, Row,
    State, Withdrawal,
};
use commonware_cryptography::{Digest, Hasher, PublicKey, Signer};
use core::cell::Cell;
use std::collections::BTreeMap;

/// Why the operator refused a request or a soft withdrawal.
#[derive(Debug, thiserror::Error)]
pub enum Refusal {
    /// Admitting it would take the close past the operator's limits.
    #[error("admitting it would take the close past the operator's limits")]
    Full,
    /// The batch exceeds what the sender can still spend in the epoch.
    #[error("the batch exceeds what the sender can still spend in the epoch")]
    InsufficientBalance,
    /// A helper refused it.
    #[error(transparent)]
    Error(#[from] Error),
}

/// Per-account records that count their lookups, so a test can check that a call reads none.
#[derive(Clone, Debug)]
pub struct Records<K: Ord, V> {
    entries: BTreeMap<K, V>,
    reads: Cell<usize>,
}

impl<K: Ord, V> Default for Records<K, V> {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            reads: Cell::new(0),
        }
    }
}

impl<K: Ord, V: PartialEq> PartialEq for Records<K, V> {
    fn eq(&self, other: &Self) -> bool {
        self.entries == other.entries
    }
}

impl<K: Ord, V> Records<K, V> {
    /// Returns the record of `key`, counting the lookup.
    fn get(&self, key: &K) -> Option<&V> {
        self.reads.set(self.reads.get() + 1);
        self.entries.get(key)
    }
}

/// A sender's latest countersigned state in the current epoch, with its payment map and the
/// sender's signature over it. Together they form the sender's row.
#[derive(Clone, Debug, PartialEq)]
pub struct Admitted<P: PublicKey, D: Digest, A: Amount> {
    /// The countersigned state.
    pub state: State<P, D>,
    /// The payment map the state commits to.
    pub payments: Amounts<P, A>,
    /// The sender's signature over the state.
    pub signature: P::Signature,
}

/// What the operator persists (O7). A restart resumes from it alone.
#[derive(Clone, Debug, PartialEq)]
pub struct Persisted<P: PublicKey, O: PublicKey, D: Digest, A: Amount> {
    /// Epoch the operator admits in.
    pub epoch: Epoch,
    /// Every positive balance as of the last close the operator applied.
    pub balances: Records<P, A>,
    /// Root of each sender's row in the close of the epoch before.
    pub previous: Records<P, D>,
    /// Each sender's latest admission in the epoch, persisted before its acknowledgement is
    /// released.
    pub admitted: Records<P, Admitted<P, D, A>>,
    /// The soft withdrawals collected in the epoch, keyed by account, amount, and tag.
    pub withdrawals: BTreeMap<(P, A, u64), Withdrawal<P, A>>,
    /// The last close, persisted before it is released so a restart can release it again.
    pub released: Option<Close<P, O, A>>,
}

/// An operator that serves every account and applies each close it assembles at once.
///
/// Its balances follow the posted closes only if every close it assembles posts, so it suits a
/// deployment whose validators accept its closes.
pub struct Operator<P: PublicKey, K: Signer, H: Hasher, A: Amount> {
    signer: K,
    namespace: Namespace,
    limits: Limits,
    persisted: Persisted<P, K::PublicKey, H::Digest, A>,
}

impl<P: PublicKey, K: Signer, H: Hasher, A: Amount> Operator<P, K, H, A> {
    /// Returns an operator admitting in the first epoch, with no balances.
    pub fn new(signer: K, namespace: Namespace, limits: Limits) -> Self {
        let persisted = Persisted {
            epoch: 1,
            balances: Records::default(),
            previous: Records::default(),
            admitted: Records::default(),
            withdrawals: BTreeMap::new(),
            released: None,
        };
        Self::restart(signer, namespace, limits, persisted)
    }

    /// Returns an operator resuming from what it persisted.
    pub const fn restart(
        signer: K,
        namespace: Namespace,
        limits: Limits,
        persisted: Persisted<P, K::PublicKey, H::Digest, A>,
    ) -> Self {
        Self {
            signer,
            namespace,
            limits,
            persisted,
        }
    }

    /// Returns what the operator persisted.
    pub const fn persisted(&self) -> &Persisted<P, K::PublicKey, H::Digest, A> {
        &self.persisted
    }

    /// Returns the epoch the operator admits in.
    pub const fn epoch(&self) -> Epoch {
        self.persisted.epoch
    }

    /// Returns how many times the operator looked up an account's balance, previous row root, or
    /// admission.
    pub const fn reads(&self) -> usize {
        self.persisted.balances.reads.get()
            + self.persisted.previous.reads.get()
            + self.persisted.admitted.reads.get()
    }

    /// Returns the account's balance as of the last close.
    pub fn balance(&self, account: &P) -> A {
        self.persisted
            .balances
            .get(account)
            .copied()
            .unwrap_or(A::ZERO)
    }

    /// Returns what the account can still pay in the current epoch, its balance less what it
    /// already paid. Incoming payments count only once a close settles them.
    pub fn live(&self, account: &P) -> A {
        let paid = self.payments(account).map_or(A::ZERO, |payments| {
            payments
                .total()
                .expect("an admitted map must fit an amount")
        });
        self.balance(account)
            .checked_sub(paid)
            .expect("admitted payments must not exceed the balance")
    }

    /// Returns the account's countersigned payment map in the current epoch.
    pub fn payments(&self, account: &P) -> Option<&Amounts<P, A>> {
        self.persisted
            .admitted
            .get(account)
            .map(|admitted| &admitted.payments)
    }

    /// Returns the rows of the current epoch.
    pub fn rows(&self) -> impl Iterator<Item = Row<P, A>> + '_ {
        self.persisted
            .admitted
            .entries
            .values()
            .map(|admitted| Row {
                account: admitted.state.account.clone(),
                payments: admitted.payments.clone(),
                signature: admitted.signature.clone(),
            })
    }

    /// Returns the soft withdrawals collected in the current epoch.
    pub fn withdrawals(&self) -> impl Iterator<Item = &Withdrawal<P, A>> {
        self.persisted.withdrawals.values()
    }

    /// Countersigns the state `request` asks for in the current epoch.
    ///
    /// A retry of the latest countersigned state is countersigned again and pays nothing twice. A
    /// new state is admitted only within the limits and the sender's live balance, and persisted
    /// before its acknowledgement is released.
    pub fn accept(&mut self, request: &Request<P, H::Digest, A>) -> Result<K::Signature, Refusal> {
        // The signature is checked before any record of the sender is looked up, so a forged
        // request causes no read and is refused alike whatever the account holds or paid.
        let verified = request.verify::<H>(&self.namespace, self.persisted.epoch)?;

        // The state must repeat or extend the sender's latest admission in the epoch, on top of
        // its row root in the close of the epoch before or the empty map's root (O2, O4).
        let empty = Amounts::<P, A>::empty().root::<H>();
        let previous = self
            .persisted
            .previous
            .get(&request.account)
            .unwrap_or(&empty);
        let latest = self.persisted.admitted.get(&request.account);
        let admission = verified.admit::<H>(
            latest.map(|latest| (&latest.state, &latest.payments)),
            previous,
        )?;
        let state = match admission {
            Admission::Retry(state) => state,
            Admission::New {
                state,
                payments,
                signature,
            } => {
                // A new state must fit the close's limits and the sender's live balance (O3, O5),
                // and it is recorded before its acknowledgement is released (O7).
                if (latest.is_none() && self.persisted.admitted.entries.len() >= self.limits.rows)
                    || payments.len() > self.limits.receivers
                {
                    return Err(Refusal::Full);
                }
                let live = self.live(&request.account);
                if request.batch.total().is_none_or(|total| total > live) {
                    return Err(Refusal::InsufficientBalance);
                }
                let admitted = Admitted {
                    state: state.clone(),
                    payments,
                    signature,
                };
                self.persisted
                    .admitted
                    .entries
                    .insert(request.account.clone(), admitted);
                state
            }
        };
        Ok(state.acknowledge(&self.signer, &self.namespace))
    }

    /// Collects a soft withdrawal for the current epoch. Collecting one again has no effect.
    pub fn withdraw(&mut self, withdrawal: Withdrawal<P, A>) -> Result<(), Refusal> {
        let epoch = self.persisted.epoch;
        if withdrawal.epoch != epoch {
            return Err(Error::WrongEpoch {
                expected: epoch,
                found: withdrawal.epoch,
            }
            .into());
        }
        if !withdrawal.verify(&self.namespace) {
            return Err(Error::InvalidSignature.into());
        }

        // A request already collected stays as it is, and a new one must fit the limits (O5).
        let request = (
            withdrawal.account.clone(),
            withdrawal.amount,
            withdrawal.tag,
        );
        let withdrawals = &mut self.persisted.withdrawals;
        if !withdrawals.contains_key(&request) && withdrawals.len() >= self.limits.withdrawals {
            return Err(Refusal::Full);
        }
        withdrawals.entry(request).or_insert(withdrawal);
        Ok(())
    }

    /// Closes the current epoch, processing the oldest `deposits` and `forced_withdrawals`
    /// requests in `queue`, applies every flow of the close to the balances, and opens the next
    /// epoch. The close is persisted before it is returned for release. A refusal leaves the
    /// operator unchanged.
    #[allow(clippy::type_complexity)]
    pub fn close(
        &mut self,
        queue: &Queue<P, A>,
        deposits: u64,
        forced_withdrawals: u64,
    ) -> Result<(Close<P, K::PublicKey, A>, Vec<(P, Flow<A>)>), Error> {
        let epoch = self.persisted.epoch;
        if queue.epoch != epoch {
            return Err(Error::WrongEpoch {
                expected: epoch,
                found: queue.epoch,
            });
        }
        let next = epoch.checked_add(1).ok_or(Error::Overflow)?;
        let (close, flows) = Close::assemble::<H, K>(
            &self.signer,
            &self.namespace,
            queue,
            self.rows(),
            self.withdrawals().cloned(),
            deposits,
            forced_withdrawals,
        )?;

        // Every flow settles before anything changes, so a refusal leaves the operator unchanged.
        let settled = flows
            .iter()
            .map(|(account, flow)| {
                let (balance, _) = flow.settle(self.balance(account))?;
                Ok((account.clone(), balance))
            })
            .collect::<Result<Vec<_>, Error>>()?;

        // Every flow of the close applies at once, with the close's row roots, before anything of
        // the next epoch is admitted.
        let persisted = &mut self.persisted;
        for (account, balance) in settled {
            if balance == A::ZERO {
                persisted.balances.entries.remove(&account);
            } else {
                persisted.balances.entries.insert(account, balance);
            }
        }
        persisted.previous.entries = close
            .rows()
            .iter()
            .map(|row| (row.account.clone(), row.payments.root::<H>()))
            .collect();
        persisted.epoch = next;
        persisted.admitted.entries.clear();
        persisted.withdrawals.clear();
        persisted.released = Some(close.clone());
        Ok((close, flows))
    }
}
