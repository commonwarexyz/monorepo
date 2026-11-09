//! A reference ledger that holds deposited funds, posts certified summaries, pays out posted
//! payouts, and pays claims after a halt.

use commonware_clearing::bajillion::{
    Amount, BalanceProof, Challenge, ChallengeError, Deposit, Epoch, ForcedWithdrawal, Namespace,
    PayoutProof, Queue, Summary, SummaryError,
};
use commonware_cryptography::{Digest, Digestible, Hasher, PublicKey, certificate::Verifier};
use core::hash::Hash;
use rand_core::CryptoRng;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Why the ledger halted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Halt {
    /// A challenge showed that the posted close of `epoch` credits a receiver less than a receipt
    /// promised.
    Challenge { epoch: Epoch },
    /// The deployment's own policy halted it.
    Fault,
}

/// Why the ledger refused a call.
#[derive(Debug, thiserror::Error)]
pub enum Refusal {
    /// The ledger halted.
    #[error("the ledger halted")]
    Halted,
    /// The ledger has not halted.
    #[error("the ledger has not halted")]
    NotHalted,
    /// The account has nothing left to claim.
    #[error("the account has nothing left to claim")]
    NothingToClaim,
    /// The call would take more than the ledger holds or can hold.
    #[error("the call would take more than the ledger holds or can hold")]
    Custody,
    /// No close of the challenged epoch has posted.
    #[error("no close of the challenged epoch has posted")]
    NotPosted,
    /// The payout at the proven index was already paid.
    #[error("the payout at the proven index was already paid")]
    Withdrawn,
    /// The balance or payout proof does not verify under the last posted root.
    #[error("the balance or payout proof does not verify under the last posted root")]
    InvalidProof,
    /// A deposit or withdrawal of nothing.
    #[error("amount is zero")]
    ZeroAmount,
    /// The post does not verify.
    #[error(transparent)]
    Summary(#[from] SummaryError),
    /// The challenge does not verify.
    #[error(transparent)]
    Challenge(#[from] ChallengeError),
}

/// What the ledger persists, as its queues, its posts, its payout ranges, and the funds it
/// holds.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Persisted<P: PublicKey, D: Digest, A: Amount> {
    /// Digest of the last posted summary.
    pub parent: D,
    /// Balances root of the last posted summary.
    pub balances: D,
    /// Payouts root of the last posted summary.
    pub payouts: D,
    /// Matrix root of each posted close, in epoch order.
    pub matrices: Vec<D>,
    /// Funds the ledger holds. A deposit adds to them and every transfer takes from them.
    pub held: A,
    /// Queued deposits, oldest first.
    pub deposits: VecDeque<Deposit<P, A>>,
    /// Number of queued deposits the next close must process.
    pub required_deposits: usize,
    /// Queued forced withdrawals, oldest first.
    pub forced_withdrawals: VecDeque<ForcedWithdrawal<P, A>>,
    /// Number of queued forced withdrawals the next close must process.
    pub required_forced_withdrawals: usize,
    /// Payout log indices that hold a commit or a paid payout, as ranges from start to exclusive
    /// end. No two ranges overlap or touch.
    pub ranges: BTreeMap<u64, u64>,
    /// Why the ledger halted, if it has.
    pub halt: Option<Halt>,
    /// Accounts that claimed their balance after the halt.
    pub claimed: BTreeSet<P>,
    /// Deposits no close processed that each account can still claim after the halt.
    pub claimable: BTreeMap<P, A>,
}

/// A ledger following L1-L11 that counts the funds it holds as one amount and tracks paid payouts
/// by ranges of payout log indices.
///
/// Every transfer goes to the account it pays (L10). The amount returned by a payout withdrawal
/// or a claim stands for that transfer. Two ledgers are equal when they persisted the same
/// state.
pub struct Ledger<P: PublicKey, O: PublicKey, V: Verifier, H: Hasher, A: Amount> {
    /// Signature namespaces of the deployment.
    namespace: Namespace,
    /// Key the operator countersigns states with.
    operator: O,
    /// Verifier of the validators' certificates.
    verifier: V,
    persisted: Persisted<P, H::Digest, A>,
}

// The hasher is a type parameter only, so the derived impl would bound it.
impl<P: PublicKey, O: PublicKey, V: Verifier, H: Hasher, A: Amount> Clone
    for Ledger<P, O, V, H, A>
{
    fn clone(&self) -> Self {
        Self {
            namespace: self.namespace.clone(),
            operator: self.operator.clone(),
            verifier: self.verifier.clone(),
            persisted: self.persisted.clone(),
        }
    }
}

impl<P: PublicKey, O: PublicKey, V: Verifier, H: Hasher, A: Amount> PartialEq
    for Ledger<P, O, V, H, A>
{
    fn eq(&self, other: &Self) -> bool {
        self.persisted == other.persisted
    }
}

impl<P: PublicKey, O: PublicKey, V: Verifier, H: Hasher, A: Amount> Eq for Ledger<P, O, V, H, A> {}

impl<P: PublicKey, O: PublicKey, V: Verifier, H: Hasher, A: Amount> Hash for Ledger<P, O, V, H, A> {
    fn hash<S: core::hash::Hasher>(&self, state: &mut S) {
        self.persisted.hash(state);
    }
}

impl<P, O, V, H, A> Ledger<P, O, V, H, A>
where
    P: PublicKey,
    O: PublicKey,
    V: for<'a> Verifier<Subject<'a, H::Digest> = &'a Summary<H>>,
    H: Hasher,
    A: Amount,
{
    /// Returns a ledger whose last post is the genesis summary over the empty balances root
    /// `balances` (L1).
    pub fn new(namespace: Namespace, operator: O, verifier: V, balances: H::Digest) -> Self {
        let genesis = Summary::<H>::genesis::<P, A>(balances);
        let persisted = Persisted {
            parent: genesis.digest(),
            balances,
            payouts: genesis.payouts.root,
            matrices: Vec::new(),
            held: A::ZERO,
            deposits: VecDeque::new(),
            required_deposits: 0,
            forced_withdrawals: VecDeque::new(),
            required_forced_withdrawals: 0,
            ranges: BTreeMap::from([(0, genesis.payouts.size)]),
            halt: None,
            claimed: BTreeSet::new(),
            claimable: BTreeMap::new(),
        };
        Self {
            namespace,
            operator,
            verifier,
            persisted,
        }
    }

    /// Returns the epoch of the close the ledger expects.
    pub const fn epoch(&self) -> Epoch {
        self.persisted.matrices.len() as Epoch + 1
    }

    /// Returns the digest of the last posted summary.
    pub const fn parent(&self) -> &H::Digest {
        &self.persisted.parent
    }

    /// Returns the balances root of the last posted summary.
    pub const fn balances(&self) -> &H::Digest {
        &self.persisted.balances
    }

    /// Returns the matrix root of the posted close of `epoch`.
    pub fn matrix(&self, epoch: Epoch) -> Option<&H::Digest> {
        let index = usize::try_from(epoch.checked_sub(1)?).ok()?;
        self.persisted.matrices.get(index)
    }

    /// Returns the ranges of payout log indices that hold a commit or a paid payout, in order, each
    /// from start to exclusive end.
    pub fn ranges(&self) -> Vec<(u64, u64)> {
        self.persisted
            .ranges
            .iter()
            .map(|(start, end)| (*start, *end))
            .collect()
    }

    /// Returns the funds held. They back the unclaimed balances as of the last post, the unclaimed
    /// deposits no close processed, and the posted payouts not yet paid.
    pub const fn custody(&self) -> A {
        self.persisted.held
    }

    /// Returns why the ledger halted, if it has.
    pub const fn halted(&self) -> Option<Halt> {
        self.persisted.halt
    }

    /// Returns the queues as the close the ledger expects must process them.
    pub fn queue(&self) -> Queue<P, A> {
        let persisted = &self.persisted;
        Queue {
            epoch: self.epoch(),
            deposits: persisted.deposits.iter().cloned().collect(),
            required_deposits: persisted.required_deposits,
            forced_withdrawals: persisted.forced_withdrawals.iter().cloned().collect(),
            required_forced_withdrawals: persisted.required_forced_withdrawals,
        }
    }

    /// Takes custody of a deposit and queues it (L2). It refuses a deposit that would take the
    /// funds held past the largest amount (L3).
    pub fn deposit(&mut self, account: P, amount: A) -> Result<(), Refusal> {
        let persisted = &mut self.persisted;
        if persisted.halt.is_some() {
            return Err(Refusal::Halted);
        }
        if amount == A::ZERO {
            return Err(Refusal::ZeroAmount);
        }
        persisted.held = persisted.held.checked_add(amount).ok_or(Refusal::Custody)?;
        persisted.deposits.push_back(Deposit { account, amount });
        Ok(())
    }

    /// Queues a forced withdrawal `account` requested (L2, L4).
    pub fn withdraw(&mut self, account: P, amount: A) -> Result<(), Refusal> {
        if self.persisted.halt.is_some() {
            return Err(Refusal::Halted);
        }
        if amount == A::ZERO {
            return Err(Refusal::ZeroAmount);
        }
        self.persisted
            .forced_withdrawals
            .push_back(ForcedWithdrawal { account, amount });
        Ok(())
    }

    /// Posts a certified summary of the close it expects (L5). The post transfers nothing, and the
    /// close's payouts become withdrawable.
    pub fn post<R: CryptoRng>(
        &mut self,
        rng: &mut R,
        summary: &Summary<H>,
        certificate: &V::Certificate,
    ) -> Result<(), Refusal> {
        if self.persisted.halt.is_some() {
            return Err(Refusal::Halted);
        }
        let epoch = self.epoch();
        let persisted = &self.persisted;
        summary.verify(
            rng,
            &self.verifier,
            certificate,
            epoch,
            &persisted.parent,
            persisted.required_deposits as u64..=persisted.deposits.len() as u64,
            persisted.required_forced_withdrawals as u64
                ..=persisted.forced_withdrawals.len() as u64,
        )?;

        // The counts lie within the queues, and the certificate vouches that the payouts size
        // counts this close's commit, so the commit position is the size less one.
        let deposits =
            usize::try_from(summary.deposits.count).expect("a count within the queue must fit");
        let forced_withdrawals = usize::try_from(summary.forced_withdrawals.count)
            .expect("a count within the queue must fit");
        let commit = summary.payouts.size - 1;

        // One state change claims the commit position, drops the processed requests, requires
        // the rest, and records the summary (L5).
        self.fold(commit);
        let persisted = &mut self.persisted;
        persisted.deposits.drain(..deposits);
        persisted.forced_withdrawals.drain(..forced_withdrawals);
        persisted.required_deposits = persisted.deposits.len();
        persisted.required_forced_withdrawals = persisted.forced_withdrawals.len();
        persisted.payouts = summary.payouts.root;
        persisted.matrices.push(summary.matrix);
        persisted.balances = summary.balances;
        persisted.parent = summary.digest();
        Ok(())
    }

    /// Pays the payout `proof` proves under the last posted payouts root, once per index, before or
    /// after a halt (L6). Returns the account paid and the amount.
    pub fn withdraw_payout(
        &mut self,
        proof: &PayoutProof<P, H::Digest, A>,
    ) -> Result<(P, A), Refusal> {
        if !proof.verify::<H>(&self.persisted.payouts) {
            return Err(Refusal::InvalidProof);
        }
        if self.covers(proof.index) {
            return Err(Refusal::Withdrawn);
        }
        self.transfer(proof.payout.amount)?;
        self.fold(proof.index);
        Ok((proof.payout.account.clone(), proof.payout.amount))
    }

    /// Takes `amount` from the funds held for a transfer, or returns [Refusal::Custody] and changes
    /// nothing if the ledger holds less.
    fn transfer(&mut self, amount: A) -> Result<(), Refusal> {
        let held = &mut self.persisted.held;
        *held = held.checked_sub(amount).ok_or(Refusal::Custody)?;
        Ok(())
    }

    /// Returns whether a range covers `index`.
    fn covers(&self, index: u64) -> bool {
        self.persisted
            .ranges
            .range(..=index)
            .next_back()
            .is_some_and(|(_, end)| index < *end)
    }

    /// Adds `index` to the ranges, merging it with each range it touches.
    fn fold(&mut self, index: u64) {
        let ranges = &mut self.persisted.ranges;
        let (mut start, mut end) = (index, index + 1);
        if let Some((&before, &until)) = ranges.range(..=index).next_back()
            && until >= index
        {
            ranges.remove(&before);
            start = before;
            end = end.max(until);
        }
        if let Some(after) = ranges.remove(&end) {
            end = after;
        }
        ranges.insert(start, end);
    }

    /// Halts on a challenge to a posted close (L7).
    pub fn challenge(&mut self, challenge: &Challenge<P, O, H::Digest, A>) -> Result<(), Refusal> {
        if self.persisted.halt.is_some() {
            return Err(Refusal::Halted);
        }
        let epoch = challenge.receipt.state.epoch;
        let matrix = self.matrix(epoch).ok_or(Refusal::NotPosted)?;
        challenge.verify::<H>(&self.namespace, &self.operator, epoch, matrix)?;
        self.stop(Halt::Challenge { epoch });
        Ok(())
    }

    /// Halts as the deployment's own policy requires. Halting again keeps the first reason.
    pub fn halt(&mut self) {
        if self.persisted.halt.is_none() {
            self.stop(Halt::Fault);
        }
    }

    /// Records the halt, makes every queued deposit claimable, and drops the queued forced
    /// withdrawals and the required counts (L8).
    fn stop(&mut self, halt: Halt) {
        let persisted = &mut self.persisted;
        persisted.halt = Some(halt);
        for deposit in persisted.deposits.drain(..) {
            let claimable = persisted
                .claimable
                .entry(deposit.account)
                .or_insert(A::ZERO);
            *claimable = claimable
                .checked_add(deposit.amount)
                .expect("claimable deposits must not exceed the funds held");
        }
        persisted.forced_withdrawals.clear();
        persisted.required_deposits = 0;
        persisted.required_forced_withdrawals = 0;
    }

    /// Pays `account` its balance as of the last post, proven by `balance`, and its claimable
    /// deposits, each at most once (L9).
    pub fn claim(
        &mut self,
        account: &P,
        balance: Option<&BalanceProof<H::Digest, A>>,
    ) -> Result<A, Refusal> {
        let persisted = &self.persisted;
        if persisted.halt.is_none() {
            return Err(Refusal::NotHalted);
        }
        let balance = match balance {
            Some(proof) if !proof.verify::<H, P>(&persisted.balances, account) => {
                return Err(Refusal::InvalidProof);
            }
            Some(proof) if !persisted.claimed.contains(account) => proof.balance,
            _ => A::ZERO,
        };
        let deposits = persisted.claimable.get(account).copied().unwrap_or(A::ZERO);
        if balance == A::ZERO && deposits == A::ZERO {
            return Err(Refusal::NothingToClaim);
        }
        let paid = balance.checked_add(deposits).ok_or(Refusal::Custody)?;

        self.transfer(paid)?;
        let persisted = &mut self.persisted;
        if balance != A::ZERO {
            persisted.claimed.insert(account.clone());
        }
        persisted.claimable.remove(account);
        Ok(paid)
    }
}
