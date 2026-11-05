//! Preconfirming payments and closing epochs.

use super::{
    Acknowledgement, Amounts, Close, Epoch, Error, Matrix, Namespace, Queue, Request, Row, State,
    Withdrawal, matrix, settlement::Flows,
};
use commonware_cryptography::{Hasher, PublicKey, Signer};
use std::{
    collections::{BTreeMap, HashMap},
    marker::PhantomData,
};

/// A sender's payments in the current epoch.
struct Account<P: PublicKey, D> {
    /// The payment map of the last state countersigned.
    payments: Amounts<P>,
    /// Root of `payments`.
    root: D,
    /// The sender's signature over the last state countersigned.
    signature: P::Signature,
}

/// Preconfirms payments, collects soft withdrawals, and closes epochs.
///
/// The operator accepts a payment only if it fits the sender's live balance. The live balance is
/// the sender's balance at the last close less everything it has paid in the current epoch.
/// Incoming payments and deposits become spendable once a close processes them, so senders never
/// wait on one another and every close the operator builds settles.
///
/// The operator opens the next epoch as soon as it closes one, while the close is checked and
/// posted. It computes the balances the close posts the same way validators do.
pub struct Operator<P: PublicKey, O: PublicKey, S: Signer, H: Hasher> {
    signer: S,
    namespace: Namespace,
    epoch: Epoch,
    /// Positive balances as of the last close.
    balances: HashMap<P, u64>,
    /// Senders that paid in the current epoch.
    accounts: HashMap<P, Account<P, H::Digest>>,
    /// Roots of the payment maps the last close settled.
    previous: HashMap<P, H::Digest>,
    /// Soft withdrawals collected for the current epoch, keyed by their signed request.
    withdrawals: BTreeMap<(Epoch, P, u64, u64), Withdrawal<P>>,
    _operator: PhantomData<O>,
}

impl<P, O, S, H> Operator<P, O, S, H>
where
    P: PublicKey,
    O: PublicKey,
    S: Signer<PublicKey = O, Signature = O::Signature>,
    H: Hasher,
{
    /// Creates an operator for the first epoch, before any balance exists.
    pub fn new(signer: S, namespace: Namespace) -> Self {
        Self {
            signer,
            namespace,
            epoch: 1,
            balances: HashMap::new(),
            accounts: HashMap::new(),
            previous: HashMap::new(),
            withdrawals: BTreeMap::new(),
            _operator: PhantomData,
        }
    }

    /// Resumes an operator at the start of `epoch`, after it closed the epoch before.
    ///
    /// `balances` holds every positive balance that close leaves and `previous` the payment
    /// matrix it settles. The application then replays the requests and soft withdrawals the
    /// operator accepted in `epoch`.
    ///
    /// Returns an error if `epoch` is zero, a balance is zero, or an account has two balances.
    pub fn resume(
        signer: S,
        namespace: Namespace,
        epoch: Epoch,
        balances: impl IntoIterator<Item = (P, u64)>,
        previous: &Matrix<P, H::Digest>,
    ) -> Result<Self, Error> {
        if epoch == 0 {
            return Err(Error::ZeroEpoch);
        }
        let mut operator = Self::new(signer, namespace);
        operator.epoch = epoch;
        for (account, balance) in balances {
            if balance == 0 {
                return Err(Error::ZeroAmount);
            }
            if operator.balances.insert(account, balance).is_some() {
                return Err(Error::DuplicateAccount);
            }
        }
        operator.previous = previous.rows().iter().cloned().collect();
        Ok(operator)
    }

    /// Returns the operator's public key.
    pub fn public_key(&self) -> O {
        self.signer.public_key()
    }

    /// Returns the current epoch.
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns `account`'s balance as of the last close.
    pub fn balance(&self, account: &P) -> u64 {
        self.balances.get(account).copied().unwrap_or(0)
    }

    /// Iterates over every positive balance as of the last close, in no particular order.
    pub fn balances(&self) -> impl Iterator<Item = (&P, u64)> {
        self.balances
            .iter()
            .map(|(account, balance)| (account, *balance))
    }

    /// Returns what `account` can still pay in the current epoch.
    pub fn live(&self, account: &P) -> u64 {
        let paid = self
            .accounts
            .get(account)
            .map_or(0, |entry| entry.payments.total());
        u64::try_from(u128::from(self.balance(account)) - paid)
            .expect("payments must not exceed the balance")
    }

    /// Returns `account`'s payment map in the current epoch, if it paid in it.
    pub fn payments(&self, account: &P) -> Option<&Amounts<P>> {
        self.accounts.get(account).map(|entry| &entry.payments)
    }

    /// Countersigns the state that `request` settles in the current epoch.
    ///
    /// The state pays the request's batch on top of the sender's last countersigned map, and on
    /// top of the map the last close settled for the sender in the previous epoch. The request
    /// must be for the current epoch, or pipelined from the previous one. Accepting a request
    /// again returns another acknowledgement of the same state without paying the batch twice, so
    /// a sender can retry a request whose acknowledgement was lost.
    ///
    /// Returns an error, refusing every state of the request, if it is for another epoch, the
    /// batch exceeds the sender's live balance, or the sender did not sign the state.
    pub fn accept(&mut self, request: &Request<P>) -> Result<Acknowledgement<O>, Error> {
        let signature = if request.epoch == self.epoch {
            Some(&request.signature)
        } else if request.epoch.checked_add(1) == Some(self.epoch) {
            request.pipelined.as_ref()
        } else {
            None
        };
        let Some(signature) = signature else {
            return Err(Error::WrongEpoch {
                expected: self.epoch,
                found: request.epoch,
            });
        };
        let previous = self
            .previous
            .get(&request.account)
            .copied()
            .unwrap_or_else(|| Amounts::<P>::empty().root::<H>());
        let current = self.accounts.get(&request.account);
        if let Some(current) = current
            && current.signature == *signature
        {
            let state = State {
                epoch: self.epoch,
                account: request.account.clone(),
                payments: current.root,
                previous,
            };
            return Ok(Acknowledgement {
                epoch: self.epoch,
                signature: state.acknowledge(&self.signer, &self.namespace),
            });
        }
        if request.batch.is_empty() {
            return Err(Error::NoReceivers);
        }
        if request.batch.total() > u128::from(self.live(&request.account)) {
            return Err(Error::InsufficientBalance);
        }

        let payments = match current {
            Some(current) => current.payments.combine(&request.batch)?,
            None => request.batch.clone(),
        };
        let state = State {
            epoch: self.epoch,
            account: request.account.clone(),
            payments: payments.root::<H>(),
            previous,
        };
        if !state.verify(&self.namespace, signature) {
            return Err(Error::InvalidSignature);
        }

        let acknowledgement = state.acknowledge(&self.signer, &self.namespace);
        self.accounts.insert(
            request.account.clone(),
            Account {
                payments,
                root: state.payments,
                signature: signature.clone(),
            },
        );
        Ok(Acknowledgement {
            epoch: self.epoch,
            signature: acknowledgement,
        })
    }

    /// Collects a soft withdrawal for the current epoch.
    ///
    /// Collecting a request already collected has no effect.
    ///
    /// Returns an error if the request is for another epoch or does not verify.
    pub fn withdraw(&mut self, withdrawal: Withdrawal<P>) -> Result<(), Error> {
        if withdrawal.epoch != self.epoch {
            return Err(Error::WrongEpoch {
                expected: self.epoch,
                found: withdrawal.epoch,
            });
        }
        if !withdrawal.verify(&self.namespace) {
            return Err(Error::InvalidSignature);
        }
        let (epoch, account, amount, tag) = withdrawal.request();
        self.withdrawals
            .entry((epoch, account.clone(), amount, tag))
            .or_insert(withdrawal);
        Ok(())
    }

    /// Closes the current epoch and opens the next one.
    ///
    /// The close settles every countersigned payment map and collected soft withdrawal, and
    /// processes the oldest `deposits` deposits and `forced_withdrawals` forced withdrawals in
    /// `queue`, the ledger's queues while it expects this close.
    ///
    /// Returns an error, leaving the epoch open, if the ledger expects the close of another epoch
    /// or a count is below what the close must process or above what is queued.
    pub fn close(
        &mut self,
        queue: &Queue<P>,
        deposits: u64,
        forced_withdrawals: u64,
    ) -> Result<Close<P, O>, Error> {
        if queue.epoch != self.epoch {
            return Err(Error::WrongEpoch {
                expected: self.epoch,
                found: queue.epoch,
            });
        }
        let (queued_deposits, queued_forced_withdrawals) =
            queue.prefix(deposits, forced_withdrawals)?;
        let next = self.epoch.checked_add(1).ok_or(Error::Overflow)?;

        // Settle without changing the epoch's state, so that a failure leaves the epoch open.
        let mut rows: Vec<_> = self.accounts.iter().collect();
        rows.sort_unstable_by_key(|(account, _)| *account);
        let withdrawals: Vec<_> = self.withdrawals.values().cloned().collect();
        let flows = Flows::new(
            rows.iter()
                .map(|(account, entry)| (*account, &entry.payments)),
            &withdrawals,
            queued_deposits,
            queued_forced_withdrawals,
        )?;
        let balances: Vec<_> = flows
            .accounts()
            .map(|account| self.balance(account))
            .collect();
        let settlement = flows.settle(balances)?;
        let root =
            matrix::root::<H, P>(rows.iter().map(|(account, entry)| (*account, &entry.root)));
        let signature = self.signer.sign(
            &self.namespace.close,
            &Close::<P, O>::message(
                self.epoch,
                &root,
                &withdrawals,
                deposits,
                forced_withdrawals,
            ),
        );
        let order: Vec<_> = rows
            .into_iter()
            .map(|(account, _)| account.clone())
            .collect();

        // Open the next epoch on top of the balances the close posts.
        let mut accounts = std::mem::take(&mut self.accounts);
        let mut previous = HashMap::with_capacity(order.len());
        let rows: Vec<_> = order
            .into_iter()
            .map(|account| {
                let entry = accounts
                    .remove(&account)
                    .expect("account must have paid this epoch");
                previous.insert(account.clone(), entry.root);
                Row {
                    account,
                    payments: entry.payments,
                    signature: entry.signature,
                }
            })
            .collect();
        self.previous = previous;
        for (account, balance) in settlement.balances {
            if balance == 0 {
                self.balances.remove(&account);
            } else {
                self.balances.insert(account, balance);
            }
        }
        self.withdrawals.clear();
        let close = Close::new(
            self.epoch,
            rows,
            withdrawals,
            deposits,
            forced_withdrawals,
            signature,
        );
        self.epoch = next;
        Ok(close)
    }
}
