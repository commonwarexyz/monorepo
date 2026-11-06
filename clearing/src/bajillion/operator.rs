//! Preconfirming payments and closing epochs, alone or as one shard of the operator.

use super::{
    Acknowledgement, Amount, Amounts, Balances, Close, Cut, Epoch, Error, Flow, ForcedWithdrawal,
    Limits, Namespace, Queue, Request, Row, State, Withdrawal, settlement::Total,
};
use commonware_cryptography::{Hasher, PublicKey, Signer};
use commonware_utils::iter::zip_eq;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    marker::PhantomData,
};

/// A sender's payments in the current epoch.
struct Account<P: PublicKey, D, A: Amount> {
    /// The payment map of the last state countersigned.
    payments: Amounts<P, A>,
    /// Sum of `payments`.
    paid: A,
    /// Root of `payments`.
    root: D,
    /// The sender's signature over the last state countersigned.
    signature: P::Signature,
}

/// The floor deductions of the last cut, held until its epoch settles.
struct Pending<P: PublicKey, A: Amount> {
    /// Epoch of the last cut.
    epoch: Epoch,
    /// What the close of `epoch` may take from each account active in it.
    deductions: HashMap<P, Total<A>>,
}

/// Preconfirms payments, collects soft withdrawals, and closes epochs, alone or as one shard of the
/// operator.
///
/// The operator serves the accounts the deployment routes to it. It accepts a payment only if it
/// fits the sender's live balance. The live balance is the sender's finalized balance less what
/// the last cut, while unsettled, may take from it, and less everything it has paid in the current
/// epoch. Incoming payments and deposits become spendable once their epoch settles, so senders
/// never wait on one another and every close the operator builds settles.
///
/// The operator admits no more senders, receivers in one sender's payment map, or soft withdrawals
/// in an epoch than its [Limits] allow, so validators decoding the close with the same limits
/// accept its size.
///
/// Finalized balances live in the store `B`. The operator reads an account's balance only when the
/// account pays or settles, and keeps it while the current epoch or the unsettled cut involves the
/// account. Its memory therefore grows with activity, not with the number of accounts.
pub struct Operator<P, O, S, H, A, B>
where
    P: PublicKey,
    O: PublicKey,
    S: Signer,
    H: Hasher,
    A: Amount,
    B: Balances<P, A>,
{
    /// Key that countersigns states and signs closes.
    signer: S,
    /// Namespaces of the signatures the operator makes and checks.
    namespace: Namespace,
    /// Bounds on what the operator admits in an epoch.
    limits: Limits,
    /// The epoch the operator admits requests and soft withdrawals in.
    epoch: Epoch,
    /// Finalized balances of the accounts this operator serves, or none once a write failed.
    store: Option<B>,
    /// The epoch of the last close `store` holds, as the operator last read or wrote it.
    stored: Epoch,
    /// Balances read from `store`, kept while the current epoch or `pending` involves them.
    cache: HashMap<P, A>,
    /// The deductions of the last cut, if its epoch is not settled yet.
    pending: Option<Pending<P, A>>,
    /// The epoch of the last cut the operator settled, or zero if it does not know of one.
    settled_cut: Epoch,
    /// Senders that paid in the current epoch.
    accounts: HashMap<P, Account<P, H::Digest, A>>,
    /// Roots of the payment maps the current epoch's states commit to as previous.
    previous: HashMap<P, H::Digest>,
    /// Soft withdrawals collected for the current epoch, keyed by their signed request.
    withdrawals: BTreeMap<(Epoch, P, A, u64), Withdrawal<P, A>>,
    _operator: PhantomData<O>,
}

impl<P, O, S, H, A, B> Operator<P, O, S, H, A, B>
where
    P: PublicKey,
    O: PublicKey,
    S: Signer<PublicKey = O, Signature = O::Signature>,
    H: Hasher,
    A: Amount,
    B: Balances<P, A>,
{
    /// Starts an operator on top of `store` that admits each epoch within `limits`.
    ///
    /// It reads the epoch of the last close the store holds with one [get](Balances::get). `cut` is
    /// the last cut the operator took, if any. A cut of an epoch the store does not include yet is
    /// pending, so the operator holds its deductions and opens the epoch after the cut. Otherwise
    /// the operator opens the epoch after the store's, and catches up with [Self::settle] if the
    /// deployment moved on since. The application then replays the requests and soft withdrawals
    /// the operator accepted in the open epoch.
    ///
    /// `previous` holds the roots of the payment maps the close the store last includes settled,
    /// at least for the accounts the operator serves, because their next states commit to them. A
    /// cut of the store's epoch adds the roots of its rows, and a pending cut supplies the open
    /// epoch's previous maps itself. A shard that keeps its last cut therefore passes none. An
    /// operator that closes with [Self::close] has no cut to keep, so it passes the rows of that
    /// close's [Matrix](super::Matrix).
    ///
    /// Returns an error if the store fails or the epoch to open does not fit an epoch number.
    pub async fn init(
        signer: S,
        namespace: Namespace,
        limits: Limits,
        store: B,
        previous: impl IntoIterator<Item = (P, H::Digest)>,
        cut: Option<&Cut<P, H::Digest, A>>,
    ) -> Result<Self, Error> {
        let (settled, _) = store.get(&[]).await.map_err(wrap)?;
        let mut operator = Self {
            signer,
            namespace,
            limits,
            epoch: settled.checked_add(1).ok_or(Error::Overflow)?,
            store: Some(store),
            stored: settled,
            cache: HashMap::new(),
            pending: None,
            settled_cut: 0,
            accounts: HashMap::new(),
            previous: previous.into_iter().collect(),
            withdrawals: BTreeMap::new(),
            _operator: PhantomData,
        };
        if let Some(cut) = cut {
            if cut.epoch > settled {
                let next = cut.epoch.checked_add(1).ok_or(Error::Overflow)?;
                operator.settled_cut = cut.settled;
                operator.open(cut, cut.deductions.iter().cloned().collect(), next);
            } else {
                operator.settled_cut = cut.epoch;
                if cut.epoch == settled {
                    operator.previous.extend(
                        cut.rows
                            .iter()
                            .map(|(row, root)| (row.account.clone(), *root)),
                    );
                }
            }
        }
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

    /// Returns whether the operator admitted nothing in its current epoch.
    fn idle(&self) -> bool {
        self.accounts.is_empty() && self.withdrawals.is_empty()
    }

    /// Returns the store, or an error if a write to it failed.
    fn store(&self) -> Result<&B, Error> {
        self.store.as_ref().ok_or(Error::Failed)
    }

    /// Caches the balances of `accounts` that are not cached yet with one read of the store, so
    /// admitting their requests reads nothing more.
    ///
    /// Returns an error if the store fails.
    pub async fn load(&mut self, accounts: &[P]) -> Result<(), Error> {
        let store = self.store()?;
        let missing: Vec<_> = accounts
            .iter()
            .filter(|account| !self.cache.contains_key(*account))
            .cloned()
            .collect();
        if missing.is_empty() {
            return Ok(());
        }
        let (_, balances) = store.get(&missing).await.map_err(wrap)?;
        self.cache.extend(zip_eq(missing, balances));
        Ok(())
    }

    /// Returns `account`'s balance as of the last close the store includes.
    ///
    /// Returns an error if the store fails.
    pub async fn balance(&self, account: &P) -> Result<A, Error> {
        let store = self.store()?;
        if let Some(balance) = self.cache.get(account) {
            return Ok(*balance);
        }
        let (_, balances) = store
            .get(std::slice::from_ref(account))
            .await
            .map_err(wrap)?;
        Ok(balances[0])
    }

    /// Returns what `account` can still pay in the current epoch.
    ///
    /// Returns an error if the store fails.
    pub async fn live(&self, account: &P) -> Result<A, Error> {
        Ok(self.floor(account, self.balance(account).await?))
    }

    /// Returns what `account` can still pay in the current epoch given its stored `balance`.
    fn floor(&self, account: &P, balance: A) -> A {
        let deducted = self
            .pending
            .as_ref()
            .and_then(|pending| pending.deductions.get(account))
            .copied()
            .unwrap_or(Total::ZERO);
        let paid = self
            .accounts
            .get(account)
            .map_or(A::ZERO, |entry| entry.paid);
        Total::new(balance)
            .sub(deducted)
            .and_then(|floor| floor.sub(Total::new(paid)))
            .and_then(Total::get)
            .unwrap_or(A::ZERO)
    }

    /// Returns `account`'s payment map in the current epoch, if it paid in it.
    pub fn payments(&self, account: &P) -> Option<&Amounts<P, A>> {
        self.accounts.get(account).map(|entry| &entry.payments)
    }

    /// Countersigns the state that `request` settles in the current epoch.
    ///
    /// The state adds the request's batch to the sender's last countersigned map and commits to the
    /// map the last close settled for the sender in the previous epoch. The request must be for the
    /// current epoch, or pipelined from the previous one. Accepting a request again returns another
    /// acknowledgement of the same state without paying the batch twice, so a sender can retry a
    /// request whose acknowledgement was lost.
    ///
    /// Returns an error, refusing every state of the request, if the request is for another epoch,
    /// pays no receiver, would take the operator's close past its limits, or exceeds the sender's
    /// live balance. It also returns an error if the sender did not sign the state or the store
    /// fails.
    pub async fn accept(&mut self, request: &Request<P, A>) -> Result<Acknowledgement<O>, Error> {
        self.store()?;
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
            .unwrap_or_else(|| Amounts::<P, A>::empty().root::<H>());
        if let Some(current) = self.accounts.get(&request.account)
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

        // Verify the sender's signature before reading the account's balance or checking limits,
        // so a request the account did not sign causes no store read and its refusal reveals
        // nothing about the account's balance or payments. A batch that overflows the sender's map
        // yields no state the sender could have signed.
        let current = self.accounts.get(&request.account);
        let payments = match current {
            Some(current) => current
                .payments
                .combine(&request.batch)
                .map_err(|_| Error::InvalidSignature)?,
            None => request.batch.clone(),
        };
        let paid = current.map(|current| current.paid);
        let state = State {
            epoch: self.epoch,
            account: request.account.clone(),
            payments: payments.root::<H>(),
            previous,
        };
        if !state.verify(&self.namespace, signature) {
            return Err(Error::InvalidSignature);
        }

        if (paid.is_none() && self.accounts.len() >= self.limits.rows)
            || payments.len() > self.limits.receivers
        {
            return Err(Error::Full);
        }
        self.load(std::slice::from_ref(&request.account)).await?;
        let live = self.floor(&request.account, self.cache[&request.account]);
        let Some(total) = request.batch.total().filter(|total| *total <= live) else {
            return Err(Error::InsufficientBalance);
        };
        let paid = paid.map_or(total, |paid| {
            paid.checked_add(total)
                .expect("payments must not exceed the balance")
        });

        let acknowledgement = state.acknowledge(&self.signer, &self.namespace);
        self.accounts.insert(
            request.account.clone(),
            Account {
                payments,
                paid,
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
    /// Returns an error if the request is for another epoch, would take the operator's close past
    /// its limits, or does not verify.
    pub fn withdraw(&mut self, withdrawal: Withdrawal<P, A>) -> Result<(), Error> {
        self.store()?;
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
        let request = (epoch, account.clone(), amount, tag);
        if !self.withdrawals.contains_key(&request)
            && self.withdrawals.len() >= self.limits.withdrawals
        {
            return Err(Error::Full);
        }
        self.withdrawals.entry(request).or_insert(withdrawal);
        Ok(())
    }

    /// Cuts the current epoch and opens the next one.
    ///
    /// The cut freezes every countersigned payment map and collected soft withdrawal, and records
    /// that the close processes `deposits` deposits and `forced_withdrawals` forced withdrawals of
    /// the ledger's queues. [Close::assemble] checks the counts against the ledger's queues.
    ///
    /// `processed` holds exactly the forced withdrawals the close processes for the accounts the
    /// operator serves. A forced withdrawal of another shard's account would make [Self::settle]
    /// expect a flow the deployment routes to that shard, and one left out would let its account
    /// spend again what the close takes.
    ///
    /// The operator deducts from each account its payments and soft withdrawals in the cut and its
    /// forced withdrawals in `processed`. It admits the next epoch at once against the floor these
    /// deductions leave, until it settles the cut epoch.
    ///
    /// ```text
    ///                        cut(e)                                 settle(e)
    ///   ---------------------x--------------------------------------s---------------------> time
    ///    accept, withdraw    |  accept, withdraw, against the floor  ^  accept, withdraw,
    ///                        |                                       |  against the balance
    ///                        '-- Cut(e) --> Close::assemble -- flows '
    /// ```
    ///
    /// Returns an error, leaving the epoch open, if a store write failed, the last cut is not
    /// settled, or `epoch` is not the current epoch.
    pub fn cut(
        &mut self,
        epoch: Epoch,
        deposits: u64,
        forced_withdrawals: u64,
        processed: &[ForcedWithdrawal<P, A>],
    ) -> Result<Cut<P, H::Digest, A>, Error> {
        self.store()?;
        if self.pending.is_some() {
            return Err(Error::Unsettled);
        }
        if epoch != self.epoch {
            return Err(Error::WrongEpoch {
                expected: self.epoch,
                found: epoch,
            });
        }
        let next = self.epoch.checked_add(1).ok_or(Error::Overflow)?;
        let payments = self
            .accounts
            .iter()
            .map(|(account, entry)| (account, entry.paid));
        let withdrawals = self
            .withdrawals
            .values()
            .map(|withdrawal| (&withdrawal.account, withdrawal.amount));
        let forced = processed
            .iter()
            .map(|withdrawal| (&withdrawal.account, withdrawal.amount));
        let mut deductions = HashMap::new();
        for (account, amount) in payments.chain(withdrawals).chain(forced) {
            let deduction = deductions.entry(account.clone()).or_insert(Total::ZERO);
            *deduction = deduction.add(Total::new(amount))?;
        }

        let rows = self
            .accounts
            .drain()
            .map(|(account, entry)| {
                let row = Row {
                    account,
                    payments: entry.payments,
                    signature: entry.signature,
                };
                (row, entry.root)
            })
            .collect();
        let cut = Cut {
            epoch,
            settled: self.settled_cut,
            rows,
            withdrawals: std::mem::take(&mut self.withdrawals)
                .into_values()
                .collect(),
            deposits,
            forced_withdrawals,
            deductions: deductions
                .iter()
                .map(|(account, deduction)| (account.clone(), *deduction))
                .collect(),
        };
        self.open(&cut, deductions, next);
        Ok(cut)
    }

    /// Opens epoch `next` after `cut`, holding `deductions` until the cut epoch settles.
    fn open(&mut self, cut: &Cut<P, H::Digest, A>, deductions: HashMap<P, Total<A>>, next: Epoch) {
        self.previous = cut
            .rows
            .iter()
            .map(|(row, root)| (row.account.clone(), *root))
            .collect();
        self.pending = Some(Pending {
            epoch: cut.epoch,
            deductions,
        });
        self.epoch = next;
    }

    /// Settles `epoch` with the flows of the accounts this operator serves in the epoch after it.
    ///
    /// With a cut of `epoch` pending, it reads the previous balance of every account in `flows`,
    /// applies to each the rule validators apply, and writes the new balances to the store with
    /// `epoch`. Only then does it drop the cut's floor deductions. The root a flow carries becomes
    /// the previous map of its account's next states.
    ///
    /// Without a cut of `epoch`, the operator admitted nothing since its last settle. It settles
    /// flows that only credit their accounts, or none, records `epoch` in the store, and opens the
    /// epoch after it. `epoch` may lie several epochs ahead, so one call skips every epoch the
    /// shard had nothing to do in, and every account's previous map is empty after them. A shard
    /// catches up this way before it cuts an epoch after skipped ones. The deployment, never a
    /// request, chooses `epoch`.
    ///
    /// Settling is idempotent. Repeating the settle of the latest epoch the store includes returns
    /// without effect, so the deployment may retry a settle whose outcome it did not learn. Each
    /// epoch's flows for the operator arrive in one settle, and a retry carries the same flows. The
    /// first settle of an epoch is final, so flows split across settles would lose the later parts.
    ///
    /// A repeated flow that takes from its account needs the operator to have cut that epoch,
    /// because only a cut's settle applies such a flow. When the operator caught up over the epoch,
    /// the settle returns [Error::MissingCut]. A settle of an older epoch returns [Error::Late].
    ///
    /// A flow missing for an account the cut deducted from would lift a deduction without applying
    /// what the close took, so settling refuses it. A missing flow that only credits its account
    /// leaves the stored balance below the validators'. That only holds the account back.
    ///
    /// Returns an error, leaving the operator unchanged, if a cut of another epoch is pending, a
    /// flow is of another epoch, an account has two flows, an account the cut deducted from has no
    /// flow, or a balance would go negative or exceed the largest amount. Without a cut of `epoch`,
    /// it also returns an error if a flow debits its account or asks to withdraw from it, or if the
    /// current epoch holds activity not yet cut.
    ///
    /// A failed store read also leaves the operator unchanged, but a store write that fails or is
    /// abandoned leaves it failed, so every later call returns [Error::Failed] until it restarts
    /// from its store and its last cut. So does a put the store refuses because it holds another
    /// close than the one the operator last read or wrote. Such a refusal exposes another writer or
    /// a second process on the store.
    pub async fn settle(
        &mut self,
        epoch: Epoch,
        flows: impl IntoIterator<Item = (P, Flow<H::Digest, A>)>,
    ) -> Result<(), Error> {
        let flows: Vec<_> = flows.into_iter().collect();
        if !self.check(epoch, &flows)? {
            return Ok(());
        }
        let next = epoch.checked_add(1).ok_or(Error::Overflow)?;
        let store = self
            .store
            .as_ref()
            .expect("the check must have found the store");
        let (read, changes) = Self::settled(&self.cache, store, &flows).await?;

        // The cut's deductions hold until the store includes its epoch.
        let store = self.store.take().expect("the store must be present");
        self.store = Some(
            store
                .put(self.stored, epoch, &changes)
                .await
                .map_err(wrap)?,
        );
        self.commit(epoch, flows, read, changes);
        if self.epoch < next {
            self.epoch = next;
            self.previous.clear();
        }
        Ok(())
    }

    /// Checks that `flows` can settle `epoch`, and returns whether the operator still has to
    /// settle it.
    fn check(&self, epoch: Epoch, flows: &[(P, Flow<H::Digest, A>)]) -> Result<bool, Error> {
        self.store()?;
        let found = self.stored;
        if let Some((_, flow)) = flows.iter().find(|(_, flow)| flow.epoch() != epoch) {
            return Err(Error::WrongEpoch {
                expected: epoch,
                found: flow.epoch(),
            });
        }
        let mut accounts = HashSet::with_capacity(flows.len());
        if !flows.iter().all(|(account, _)| accounts.insert(account)) {
            return Err(Error::DuplicateAccount);
        }

        // The store records `epoch` or later only once the operator settled it or caught up past
        // it. Only the latest settle may repeat, and its flows may take from their accounts only if
        // the operator cut that epoch.
        if found >= epoch {
            if epoch < found {
                return Err(Error::Late { epoch, found });
            }
            if self.settled_cut != epoch && flows.iter().any(|(_, flow)| flow.takes()) {
                return Err(Error::MissingCut);
            }
            return Ok(false);
        }

        match &self.pending {
            Some(pending) if pending.epoch != epoch => {
                return Err(Error::WrongEpoch {
                    expected: pending.epoch,
                    found: epoch,
                });
            }
            Some(pending) => {
                if pending
                    .deductions
                    .keys()
                    .any(|account| !accounts.contains(account))
                {
                    return Err(Error::MissingFlow);
                }
            }
            None => {
                if flows.iter().any(|(_, flow)| flow.takes()) {
                    return Err(Error::MissingCut);
                }
                if !self.idle() {
                    return Err(Error::Active);
                }
            }
        }
        Ok(true)
    }

    /// Returns the previous balances `flows` need that it read from `store`, and the balances the
    /// flows change.
    ///
    /// It caches nothing, so a settle that fails leaves the operator unchanged.
    async fn settled(
        cache: &HashMap<P, A>,
        store: &B,
        flows: &[(P, Flow<H::Digest, A>)],
    ) -> Result<(HashMap<P, A>, Vec<(P, A)>), Error> {
        let missing: Vec<_> = flows
            .iter()
            .filter(|(account, _)| !cache.contains_key(account))
            .map(|(account, _)| account.clone())
            .collect();
        let read: HashMap<_, _> = if missing.is_empty() {
            HashMap::new()
        } else {
            let (_, balances) = store.get(&missing).await.map_err(wrap)?;
            zip_eq(missing, balances).collect()
        };
        let mut changes = Vec::new();
        for (account, flow) in flows {
            let previous = cache
                .get(account)
                .or_else(|| read.get(account))
                .copied()
                .expect("every previous balance must be cached or read");
            let (balance, _) = flow.settle(previous)?;
            if balance != previous {
                changes.push((account.clone(), balance));
            }
        }
        Ok((read, changes))
    }

    /// Records that the store holds the close of `epoch`, with `changes` in place of the balances
    /// `read`, and drops the cut's deductions.
    fn commit(
        &mut self,
        epoch: Epoch,
        flows: Vec<(P, Flow<H::Digest, A>)>,
        read: HashMap<P, A>,
        changes: Vec<(P, A)>,
    ) {
        self.stored = epoch;
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| pending.epoch == epoch)
        {
            self.settled_cut = epoch;
        }
        self.cache.extend(read);
        self.cache.extend(changes);
        for (account, flow) in flows {
            if let Some(root) = flow.root() {
                self.previous.insert(account, *root);
            }
        }
        self.pending = None;
        let accounts = &self.accounts;
        self.cache
            .retain(|account, _| accounts.contains_key(account));
    }

    /// Closes the current epoch, settles it, and opens the next one, as one operator serving every
    /// account.
    ///
    /// The close settles every countersigned payment map and collected soft withdrawal, and
    /// processes the oldest `deposits` deposits and `forced_withdrawals` forced withdrawals in
    /// `queue`, the ledger's queues while it expects this close. Like [Self::settle], it writes
    /// only if the store still holds the close the operator last read or wrote.
    ///
    /// Returns an error, leaving the operator unchanged, if a store write failed, the last cut is
    /// not settled, the ledger expects the close of another epoch, or a count is below what the
    /// close must process or above what is queued.
    ///
    /// Only this call holds the flows of the epoch it cuts, so any later failure, or abandoning the
    /// call, leaves the operator failed. Short of a failed store write, nothing reaches the store,
    /// and the operator restarts with the epoch still open. A failed write may still have stored
    /// the epoch, so a deployment that must not lose a close calls [Self::cut], [Close::assemble],
    /// and [Self::settle] itself and persists the close before settling.
    pub async fn close(
        &mut self,
        queue: &Queue<P, A>,
        deposits: u64,
        forced_withdrawals: u64,
    ) -> Result<Close<P, O, A>, Error> {
        self.store()?;
        let (_, processed) = queue.prefix(deposits, forced_withdrawals)?;
        let cut = self.cut(queue.epoch, deposits, forced_withdrawals, processed)?;
        let epoch = cut.epoch;
        let assembled = Close::assemble::<H, _>(
            &self.signer,
            &self.namespace,
            queue,
            deposits,
            forced_withdrawals,
            [cut],
        )
        .and_then(|(close, flows)| self.check(epoch, &flows).map(|_| (close, flows)));
        let store = self
            .store
            .take()
            .expect("the cut must have found the store");
        let (close, flows) = assembled?;
        let (read, changes) = Self::settled(&self.cache, &store, &flows).await?;
        self.store = Some(
            store
                .put(self.stored, epoch, &changes)
                .await
                .map_err(wrap)?,
        );
        self.commit(epoch, flows, read, changes);
        Ok(close)
    }

    /// Returns how many balances the operator caches.
    #[cfg(test)]
    pub(crate) fn cached(&self) -> usize {
        self.cache.len()
    }
}

/// Wraps a store error.
fn wrap(error: impl std::error::Error + Send + Sync + 'static) -> Error {
    Error::Store(Box::new(error))
}
