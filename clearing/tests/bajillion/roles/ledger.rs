//! A reference ledger that holds deposited funds, posts certified summaries, pays out posted
//! payouts, and pays claims after a halt.

use commonware_clearing::bajillion::{
    Amount, BalanceProof, Challenge, Deposit, Epoch, Error, ForcedWithdrawal, Namespace,
    PayoutProof, Queue, Summary,
};
use commonware_cryptography::{Hasher, PublicKey, certificate::Verifier};
use rand_core::CryptoRng;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

/// Why the ledger halted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Halt {
    /// A challenge showed that the posted close of `epoch` credits a receiver less than a receipt
    /// promised.
    Challenge { epoch: Epoch },
    /// The deployment's own policy halted it.
    Fault,
}

/// Why the ledger refused a call.
#[derive(Debug)]
pub enum Refusal {
    /// The ledger halted.
    Halted,
    /// The ledger has not halted.
    NotHalted,
    /// The account has nothing left to claim.
    NothingToClaim,
    /// The call would take more than the ledger holds or can hold.
    Custody,
    /// No close of the challenged epoch has posted.
    NotPosted,
    /// The payout at the proven index was already paid.
    Withdrawn,
    /// The balance or payout proof does not verify under the last posted root.
    InvalidProof,
    /// A helper refused it.
    Error(Error),
}

impl From<Error> for Refusal {
    fn from(error: Error) -> Self {
        Self::Error(error)
    }
}

/// A ledger following L1-L11 that counts the funds it holds as one amount and tracks paid payouts
/// by ranges of payout log indices.
///
/// Every transfer goes to the account it pays (L10). The amount returned by a payout withdrawal
/// or a claim stands for that transfer.
pub struct Ledger<P: PublicKey, O: PublicKey, V: Verifier, H: Hasher, A: Amount> {
    /// Signature namespaces of the deployment.
    namespace: Namespace,
    /// Key the operator countersigns states with.
    operator: O,
    /// Verifier of the validators' certificates.
    verifier: V,
    /// Digest of the last posted summary.
    parent: H::Digest,
    /// Balances root of the last posted summary.
    balances: H::Digest,
    /// Payouts root of the last posted summary.
    log: H::Digest,
    /// Matrix root of each posted close, in epoch order.
    matrices: Vec<H::Digest>,
    /// Funds the ledger holds. A deposit adds to them and every transfer takes from them.
    held: A,
    /// Queued deposits, oldest first.
    deposits: VecDeque<Deposit<P, A>>,
    /// Number of queued deposits the next close must process.
    required_deposits: usize,
    /// Queued forced withdrawals, oldest first.
    forced_withdrawals: VecDeque<ForcedWithdrawal<P, A>>,
    /// Number of queued forced withdrawals the next close must process.
    required_forced_withdrawals: usize,
    /// Payout log indices that hold a commit or a paid payout, as ranges from start to exclusive
    /// end. No two ranges overlap or touch.
    ranges: BTreeMap<u64, u64>,
    /// Why the ledger halted, if it has.
    halt: Option<Halt>,
    /// Accounts that claimed their balance after the halt.
    claimed: HashSet<P>,
    /// Deposits no close processed that each account can still claim after the halt.
    claimable: HashMap<P, A>,
}

impl<P, O, V, H, A> Ledger<P, O, V, H, A>
where
    P: PublicKey,
    O: PublicKey,
    V: for<'a> Verifier<Subject<'a, H::Digest> = &'a Summary<H::Digest>>,
    H: Hasher,
    A: Amount,
{
    /// Returns a ledger whose validators start from the empty balances database with root
    /// `balances` (L1).
    pub fn new(namespace: Namespace, operator: O, verifier: V, balances: H::Digest) -> Self {
        let genesis = Summary::genesis::<H, P, A>(balances);
        Self {
            namespace,
            operator,
            verifier,
            parent: genesis.digest::<H>(),
            balances,
            log: genesis.payouts.root,
            matrices: Vec::new(),
            held: A::ZERO,
            deposits: VecDeque::new(),
            required_deposits: 0,
            forced_withdrawals: VecDeque::new(),
            required_forced_withdrawals: 0,
            ranges: BTreeMap::from([(0, genesis.payouts.size)]),
            halt: None,
            claimed: HashSet::new(),
            claimable: HashMap::new(),
        }
    }

    /// Returns the epoch of the close the ledger expects.
    pub const fn epoch(&self) -> Epoch {
        self.matrices.len() as Epoch + 1
    }

    /// Returns the digest of the last posted summary.
    pub const fn parent(&self) -> &H::Digest {
        &self.parent
    }

    /// Returns the balances root of the last posted summary.
    pub const fn balances(&self) -> &H::Digest {
        &self.balances
    }

    /// Returns the matrix root of the posted close of `epoch`.
    pub fn matrix(&self, epoch: Epoch) -> Option<&H::Digest> {
        let index = usize::try_from(epoch.checked_sub(1)?).ok()?;
        self.matrices.get(index)
    }

    /// Returns the ranges of payout log indices that hold a commit or a paid payout, in order, each
    /// from start to exclusive end.
    pub fn ranges(&self) -> Vec<(u64, u64)> {
        self.ranges
            .iter()
            .map(|(start, end)| (*start, *end))
            .collect()
    }

    /// Returns the funds held. They back the unclaimed balances as of the last post, the unclaimed
    /// deposits no close processed, and the posted payouts not yet paid.
    pub const fn custody(&self) -> A {
        self.held
    }

    /// Returns why the ledger halted, if it has.
    pub const fn halted(&self) -> Option<Halt> {
        self.halt
    }

    /// Returns the queues as the close the ledger expects must process them.
    pub fn queue(&self) -> Queue<P, A> {
        Queue {
            epoch: self.epoch(),
            deposits: self.deposits.iter().cloned().collect(),
            required_deposits: self.required_deposits,
            forced_withdrawals: self.forced_withdrawals.iter().cloned().collect(),
            required_forced_withdrawals: self.required_forced_withdrawals,
        }
    }

    /// Takes custody of a deposit and queues it (L2). It refuses a deposit that would take the
    /// funds held past the largest amount (L3).
    pub fn deposit(&mut self, account: P, amount: A) -> Result<(), Refusal> {
        if self.halt.is_some() {
            return Err(Refusal::Halted);
        }
        if amount == A::ZERO {
            return Err(Error::ZeroAmount.into());
        }
        self.held = self.held.checked_add(amount).ok_or(Refusal::Custody)?;
        self.deposits.push_back(Deposit { account, amount });
        Ok(())
    }

    /// Queues a forced withdrawal `account` requested (L2, L4).
    pub fn withdraw(&mut self, account: P, amount: A) -> Result<(), Refusal> {
        if self.halt.is_some() {
            return Err(Refusal::Halted);
        }
        if amount == A::ZERO {
            return Err(Error::ZeroAmount.into());
        }
        self.forced_withdrawals
            .push_back(ForcedWithdrawal { account, amount });
        Ok(())
    }

    /// Posts a certified summary of the close it expects (L5). The post transfers nothing, and the
    /// close's payouts become withdrawable.
    pub fn post<R: CryptoRng>(
        &mut self,
        rng: &mut R,
        summary: &Summary<H::Digest>,
        certificate: &V::Certificate,
    ) -> Result<(), Refusal> {
        if self.halt.is_some() {
            return Err(Refusal::Halted);
        }
        summary.verify(
            rng,
            &self.verifier,
            certificate,
            self.epoch(),
            &self.parent,
            self.required_deposits as u64..=self.deposits.len() as u64,
            self.required_forced_withdrawals as u64..=self.forced_withdrawals.len() as u64,
        )?;

        // The counts lie within the queues, and the certificate vouches that the payouts size
        // counts this close's commit, so the commit position is the size less one.
        let deposits =
            usize::try_from(summary.deposits.count).expect("a count within the queue must fit");
        let forced_withdrawals = usize::try_from(summary.forced_withdrawals.count)
            .expect("a count within the queue must fit");
        let commit = summary.payouts.size - 1;

        // One state change drops the processed requests, requires the rest, claims the commit
        // position, and records the summary (L5).
        self.deposits.drain(..deposits);
        self.forced_withdrawals.drain(..forced_withdrawals);
        self.required_deposits = self.deposits.len();
        self.required_forced_withdrawals = self.forced_withdrawals.len();
        self.fold(commit);
        self.log = summary.payouts.root;
        self.matrices.push(summary.matrix);
        self.balances = summary.balances;
        self.parent = summary.digest::<H>();
        Ok(())
    }

    /// Pays the payout `proof` proves under the last posted payouts root, once per index, before or
    /// after a halt (L6). Returns the account paid and the amount.
    pub fn withdraw_payout(
        &mut self,
        proof: &PayoutProof<P, H::Digest, A>,
    ) -> Result<(P, A), Refusal> {
        if !proof.verify::<H>(&self.log) {
            return Err(Refusal::InvalidProof);
        }
        if self.covers(proof.index) {
            return Err(Refusal::Withdrawn);
        }
        self.transfer(proof.payout.amount)?;
        self.fold(proof.index);
        Ok((proof.payout.account.clone(), proof.payout.amount))
    }

    /// Takes `amount` from the funds held for a transfer. If the ledger holds less, the chain would
    /// refuse the transfer, so this returns Custody and changes nothing.
    fn transfer(&mut self, amount: A) -> Result<(), Refusal> {
        self.held = self.held.checked_sub(amount).ok_or(Refusal::Custody)?;
        Ok(())
    }

    /// Returns whether a range covers `index`.
    fn covers(&self, index: u64) -> bool {
        self.ranges
            .range(..=index)
            .next_back()
            .is_some_and(|(_, end)| index < *end)
    }

    /// Adds `index` to the ranges, merging it with each range it touches.
    fn fold(&mut self, index: u64) {
        let (mut start, mut end) = (index, index + 1);
        if let Some((&before, &until)) = self.ranges.range(..=index).next_back()
            && until >= index
        {
            self.ranges.remove(&before);
            start = before;
            end = end.max(until);
        }
        if let Some(after) = self.ranges.remove(&end) {
            end = after;
        }
        self.ranges.insert(start, end);
    }

    /// Halts on a challenge to a posted close (L7).
    pub fn challenge(&mut self, challenge: &Challenge<P, O, H::Digest, A>) -> Result<(), Refusal> {
        if self.halt.is_some() {
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
        if self.halt.is_none() {
            self.stop(Halt::Fault);
        }
    }

    /// Records the halt, makes every queued deposit claimable, and drops the queued forced
    /// withdrawals and the required counts (L8).
    fn stop(&mut self, halt: Halt) {
        self.halt = Some(halt);
        for deposit in self.deposits.drain(..) {
            let claimable = self.claimable.entry(deposit.account).or_insert(A::ZERO);
            *claimable = claimable
                .checked_add(deposit.amount)
                .expect("claimable deposits must not exceed the funds held");
        }
        self.forced_withdrawals.clear();
        self.required_deposits = 0;
        self.required_forced_withdrawals = 0;
    }

    /// Pays `account` its balance as of the last post, proven by `balance`, and its claimable
    /// deposits, each at most once (L9).
    pub fn claim(
        &mut self,
        account: &P,
        balance: Option<&BalanceProof<H::Digest, A>>,
    ) -> Result<A, Refusal> {
        if self.halt.is_none() {
            return Err(Refusal::NotHalted);
        }
        let balance = match balance {
            Some(proof) if !proof.verify::<H, P>(&self.balances, account) => {
                return Err(Refusal::InvalidProof);
            }
            Some(proof) if !self.claimed.contains(account) => proof.balance,
            _ => A::ZERO,
        };
        let deposits = self.claimable.get(account).copied().unwrap_or(A::ZERO);
        if balance == A::ZERO && deposits == A::ZERO {
            return Err(Refusal::NothingToClaim);
        }
        let paid = balance.checked_add(deposits).ok_or(Refusal::Custody)?;

        self.transfer(paid)?;
        if balance != A::ZERO {
            self.claimed.insert(account.clone());
        }
        self.claimable.remove(account);
        Ok(paid)
    }
}
