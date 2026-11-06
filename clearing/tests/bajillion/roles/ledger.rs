//! A reference ledger that holds deposited funds, posts certified summaries, and pays out after a
//! halt.

use commonware_clearing::bajillion::{
    Amount, Amounts, BalanceProof, Challenge, Deposit, Epoch, Error, ForcedWithdrawal, Namespace,
    Queue, Summary,
};
use commonware_cryptography::{Hasher, PublicKey, certificate::Verifier};
use rand_core::CryptoRng;
use std::collections::{HashMap, HashSet, VecDeque};

/// Why the ledger halted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Halt {
    /// A challenge showed that the posted close of `epoch` omitted a preconfirmed payment.
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
    /// The account is owed no payout.
    NothingOwed,
    /// The balance proof does not verify under the last posted balances root.
    InvalidProof,
    /// A helper refused it.
    Error(Error),
}

impl From<Error> for Refusal {
    fn from(error: Error) -> Self {
        Self::Error(error)
    }
}

/// A ledger following L1-L11, with owed payouts held as per-account credits.
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
    /// Matrix root of each posted close, in epoch order.
    matrices: Vec<H::Digest>,
    /// Sum of the balances as of the last post.
    liability: A,
    /// Sum of the deposits that no close processed and no claim paid out.
    unprocessed: A,
    /// Queued deposits, oldest first.
    deposits: VecDeque<Deposit<P, A>>,
    /// Number of queued deposits the next close must process.
    required_deposits: usize,
    /// Queued forced withdrawals, oldest first.
    forced_withdrawals: VecDeque<ForcedWithdrawal<P, A>>,
    /// Number of queued forced withdrawals the next close must process.
    required_forced_withdrawals: usize,
    /// Payout each account can withdraw.
    owed: HashMap<P, A>,
    /// Sum of the owed payouts not yet withdrawn.
    payable: A,
    /// Why the ledger halted, if it has.
    halt: Option<Halt>,
    /// Accounts that claimed their balance after the halt.
    claimed: HashSet<P>,
    /// Unprocessed deposits each account can still claim after the halt.
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
        Self {
            namespace,
            operator,
            verifier,
            parent: Summary::genesis::<H>(balances).digest::<H>(),
            balances,
            matrices: Vec::new(),
            liability: A::ZERO,
            unprocessed: A::ZERO,
            deposits: VecDeque::new(),
            required_deposits: 0,
            forced_withdrawals: VecDeque::new(),
            required_forced_withdrawals: 0,
            owed: HashMap::new(),
            payable: A::ZERO,
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

    /// Returns the payout `account` can withdraw.
    pub fn owed(&self, account: &P) -> A {
        self.owed.get(account).copied().unwrap_or(A::ZERO)
    }

    /// Returns the funds held. They are the liability, the unprocessed deposits, and the owed
    /// payouts not yet withdrawn.
    pub fn custody(&self) -> A {
        self.held()
            .expect("the funds held must fit an amount, because deposits are bounded by it")
    }

    /// Returns the funds held, or `None` if they exceed the largest amount.
    fn held(&self) -> Option<A> {
        self.liability
            .checked_add(self.unprocessed)?
            .checked_add(self.payable)
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
    /// funds held, owed payouts included, past the largest amount (L3).
    pub fn deposit(&mut self, account: P, amount: A) -> Result<(), Refusal> {
        if self.halt.is_some() {
            return Err(Refusal::Halted);
        }
        if amount == A::ZERO {
            return Err(Error::ZeroAmount.into());
        }
        self.held()
            .and_then(|held| held.checked_add(amount))
            .ok_or(Refusal::Custody)?;
        self.unprocessed = self
            .unprocessed
            .checked_add(amount)
            .expect("unprocessed deposits must not exceed the funds held");
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

    /// Posts a certified summary of the close it expects, and owes each of its payouts (L5).
    pub fn post<R: CryptoRng>(
        &mut self,
        rng: &mut R,
        summary: &Summary<H::Digest>,
        payouts: &Amounts<P, A>,
        certificate: &V::Certificate,
    ) -> Result<(), Refusal> {
        if self.halt.is_some() {
            return Err(Refusal::Halted);
        }
        summary.verify::<H, P, A, V, R>(
            rng,
            &self.verifier,
            certificate,
            self.epoch(),
            &self.parent,
            self.required_deposits as u64..=self.deposits.len() as u64,
            self.required_forced_withdrawals as u64..=self.forced_withdrawals.len() as u64,
            payouts,
        )?;
        let deposits =
            usize::try_from(summary.deposits).expect("a count within the queue must fit");
        let forced_withdrawals =
            usize::try_from(summary.forced_withdrawals).expect("a count within the queue must fit");
        let deposited = self
            .deposits
            .iter()
            .take(deposits)
            .try_fold(A::ZERO, |total, deposit| total.checked_add(deposit.amount))
            .expect("processed deposits must not exceed the unprocessed deposits");
        let paid = payouts.total().ok_or(Refusal::Custody)?;
        let liability = self
            .liability
            .checked_add(deposited)
            .expect("processed deposits must fit next to the liability")
            .checked_sub(paid)
            .ok_or(Refusal::Custody)?;

        self.deposits.drain(..deposits);
        self.forced_withdrawals.drain(..forced_withdrawals);
        self.required_deposits = self.deposits.len();
        self.required_forced_withdrawals = self.forced_withdrawals.len();
        self.liability = liability;
        self.unprocessed = self
            .unprocessed
            .checked_sub(deposited)
            .expect("processed deposits must not exceed the unprocessed deposits");
        for (account, amount) in payouts.iter() {
            let owed = self.owed.entry(account.clone()).or_insert(A::ZERO);
            *owed = owed
                .checked_add(amount)
                .expect("owed payouts must not exceed the funds held");
        }
        self.payable = self
            .payable
            .checked_add(paid)
            .expect("owed payouts must not exceed the funds held");
        self.matrices.push(summary.matrix);
        self.balances = summary.balances;
        self.parent = summary.digest::<H>();
        Ok(())
    }

    /// Pays `account` everything it is owed, before or after a halt (L6).
    pub fn withdraw_payout(&mut self, account: &P) -> Result<A, Refusal> {
        let owed = self.owed.remove(account).ok_or(Refusal::NothingOwed)?;
        self.payable = self
            .payable
            .checked_sub(owed)
            .expect("an account's payout must not exceed the owed payouts");
        Ok(owed)
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
        let liability = self
            .liability
            .checked_sub(balance)
            .ok_or(Refusal::Custody)?;

        if balance != A::ZERO {
            self.claimed.insert(account.clone());
        }
        self.claimable.remove(account);
        self.liability = liability;
        self.unprocessed = self
            .unprocessed
            .checked_sub(deposits)
            .expect("claimable deposits must not exceed the unprocessed deposits");
        Ok(balance
            .checked_add(deposits)
            .expect("a claim must not exceed the funds held"))
    }
}
