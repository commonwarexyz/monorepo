//! Holding funds and posting closes.

use super::{
    Amounts, BalanceProof, Challenge, Deposit, Epoch, Error, ForcedWithdrawal, Namespace, Queue,
    Summary, close::processed,
};
use commonware_cryptography::{Hasher, PublicKey, certificate::Verifier};
use commonware_parallel::Sequential;
use rand_core::CryptoRng;
use std::collections::{HashMap, HashSet, VecDeque};

/// Why a ledger halted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Halt {
    /// The deployment's policy halted the ledger, for example because the operator stopped
    /// closing epochs.
    Fault,
    /// A challenge showed that the posted close of `epoch` credits a receiver less than a receipt
    /// promised.
    Challenge {
        /// Epoch of the contradicted close.
        epoch: Epoch,
    },
}

/// Holds deposited funds, queues deposits and forced withdrawals, and posts closes.
///
/// The ledger stores only commitments to the state validators keep. These are the digest of the
/// last posted summary, the balances root it certifies, and each posted close's payment matrix
/// root. The funds it holds are the balances as of the last posted close plus the deposits no
/// close has processed.
///
/// Until it halts, the ledger posts each epoch's close once a certificate verifies over its
/// summary. After it halts, it rejects everything but refunds. Every account then recovers its
/// balance as of the last posted close, proven against that close's balances root, and the
/// deposits no close processed.
///
/// The application must apply each state change together with the transfers it implies. A posted
/// close pays its payouts, and a refund pays the amount it returns. The ledger is deterministic,
/// so replaying its operations in order rebuilds it.
pub struct Ledger<P: PublicKey, O: PublicKey, V: Verifier, H: Hasher> {
    namespace: Namespace,
    operator: O,
    verifier: V,
    /// Epoch whose close the ledger expects next.
    epoch: Epoch,
    /// Digest of the last posted summary.
    parent: H::Digest,
    /// Root of the balances as of the last posted close.
    balances: H::Digest,
    /// Payment matrix roots of the posted closes, in epoch order from the first.
    matrices: Vec<H::Digest>,
    /// Sum of the balances as of the last posted close.
    liability: u64,
    /// Sum of the deposits no close has processed.
    unprocessed: u64,
    deposits: VecDeque<Deposit<P>>,
    required_deposits: usize,
    forced_withdrawals: VecDeque<ForcedWithdrawal<P>>,
    required_forced_withdrawals: usize,
    halt: Option<Halt>,
    /// Accounts whose balance has been refunded since the halt.
    refunded: HashSet<P>,
    /// Unprocessed deposits per account not yet refunded since the halt.
    refundable: HashMap<P, u64>,
}

impl<P, O, V, H> Ledger<P, O, V, H>
where
    P: PublicKey,
    O: PublicKey,
    V: for<'a> Verifier<Subject<'a, H::Digest> = &'a Summary<H::Digest>>,
    H: Hasher,
{
    /// Creates a ledger before the first close, holding no funds.
    ///
    /// `balances` is the root of the validators' empty balances database, and `verifier` checks
    /// their certificates.
    pub fn new(namespace: Namespace, operator: O, verifier: V, balances: H::Digest) -> Self {
        let genesis = Summary::genesis::<H>(balances);
        Self {
            namespace,
            operator,
            verifier,
            epoch: genesis.epoch + 1,
            parent: genesis.digest::<H>(),
            balances,
            matrices: Vec::new(),
            liability: 0,
            unprocessed: 0,
            deposits: VecDeque::new(),
            required_deposits: 0,
            forced_withdrawals: VecDeque::new(),
            required_forced_withdrawals: 0,
            halt: None,
            refunded: HashSet::new(),
            refundable: HashMap::new(),
        }
    }

    /// Returns the epoch whose close the ledger expects next.
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the digest of the last posted summary.
    pub const fn parent(&self) -> &H::Digest {
        &self.parent
    }

    /// Returns the root of the balances as of the last posted close.
    pub const fn balances(&self) -> &H::Digest {
        &self.balances
    }

    /// Returns the payment matrix root of the posted close of `epoch`.
    pub fn matrix(&self, epoch: Epoch) -> Option<&H::Digest> {
        let index = usize::try_from(epoch.checked_sub(1)?).ok()?;
        self.matrices.get(index)
    }

    /// Returns the funds the ledger holds.
    pub const fn custody(&self) -> u64 {
        self.liability + self.unprocessed
    }

    /// Returns why the ledger halted, if it has.
    pub const fn halted(&self) -> Option<Halt> {
        self.halt
    }

    /// Returns the queues as the close of the expected epoch sees them.
    pub fn queue(&self) -> Queue<P> {
        Queue {
            epoch: self.epoch,
            deposits: self.deposits.iter().cloned().collect(),
            required_deposits: self.required_deposits,
            forced_withdrawals: self.forced_withdrawals.iter().cloned().collect(),
            required_forced_withdrawals: self.required_forced_withdrawals,
        }
    }

    /// Takes a deposit of `amount` for `account`. The account can spend it once a close processes
    /// it.
    ///
    /// Returns an error if the ledger halted, the amount is zero, or the funds held would exceed
    /// `u64::MAX`.
    pub fn deposit(&mut self, account: P, amount: u64) -> Result<(), Error> {
        if self.halt.is_some() {
            return Err(Error::Halted);
        }
        if amount == 0 {
            return Err(Error::ZeroAmount);
        }
        self.custody().checked_add(amount).ok_or(Error::Custody)?;
        self.unprocessed += amount;
        self.deposits.push_back(Deposit { account, amount });
        Ok(())
    }

    /// Queues a forced withdrawal of up to `amount` from `account`.
    ///
    /// Returns an error if the ledger halted or the amount is zero.
    pub fn withdraw(&mut self, account: P, amount: u64) -> Result<(), Error> {
        if self.halt.is_some() {
            return Err(Error::Halted);
        }
        if amount == 0 {
            return Err(Error::ZeroAmount);
        }
        self.forced_withdrawals
            .push_back(ForcedWithdrawal { account, amount });
        Ok(())
    }

    /// Posts the close of the expected epoch, finalizing it.
    ///
    /// `payouts` must be the close's payouts, and the application transfers them together with
    /// this state change. Every request queued before the next epoch opens must be processed by
    /// the next close.
    ///
    /// Returns an error if the ledger halted, the summary is not for the expected epoch or does not
    /// follow the last posted one, its counts are out of bounds, the payouts do not match it or
    /// exceed the funds held, or the certificate does not verify.
    pub fn post<R: CryptoRng>(
        &mut self,
        rng: &mut R,
        summary: &Summary<H::Digest>,
        payouts: &Amounts<P>,
        certificate: &V::Certificate,
    ) -> Result<(), Error> {
        if self.halt.is_some() {
            return Err(Error::Halted);
        }
        if summary.epoch != self.epoch {
            return Err(Error::WrongEpoch {
                expected: self.epoch,
                found: summary.epoch,
            });
        }
        if summary.parent != self.parent {
            return Err(Error::WrongParent);
        }
        let deposits = processed(
            self.required_deposits,
            self.deposits.len(),
            summary.deposits,
        )?;
        let forced_withdrawals = processed(
            self.required_forced_withdrawals,
            self.forced_withdrawals.len(),
            summary.forced_withdrawals,
        )?;
        if payouts.root::<H>() != summary.payouts {
            return Err(Error::InvalidPayouts);
        }

        // Processed deposits move into the balances, and payouts leave them.
        let deposited: u64 = self
            .deposits
            .iter()
            .take(deposits)
            .map(|deposit| deposit.amount)
            .sum();
        let paid = u64::try_from(payouts.total()).map_err(|_| Error::Custody)?;
        let liability = (self.liability + deposited)
            .checked_sub(paid)
            .ok_or(Error::Custody)?;
        if !self
            .verifier
            .verify_certificate::<_, H::Digest>(rng, summary, certificate, &Sequential)
        {
            return Err(Error::InvalidCertificate);
        }

        self.deposits.drain(..deposits);
        self.forced_withdrawals.drain(..forced_withdrawals);
        self.required_deposits = self.deposits.len();
        self.required_forced_withdrawals = self.forced_withdrawals.len();
        self.liability = liability;
        self.unprocessed -= deposited;
        self.matrices.push(summary.matrix);
        self.balances = summary.balances;
        self.parent = summary.digest::<H>();
        self.epoch += 1;
        Ok(())
    }

    /// Halts the ledger if `challenge` shows that a posted close credits a receiver less than a
    /// receipt promised.
    ///
    /// Returns an error if the ledger halted, the receipt's epoch has no posted close, the receipt
    /// or opening does not verify, or the close credits at least the receipt's amount.
    pub fn challenge(&mut self, challenge: &Challenge<P, O, H::Digest>) -> Result<(), Error> {
        if self.halt.is_some() {
            return Err(Error::Halted);
        }
        let receipt = &challenge.receipt;
        let epoch = receipt.state.epoch;
        let root = self.matrix(epoch).ok_or(Error::NotClosed)?;
        receipt.verify::<H>(&self.namespace, &self.operator)?;
        let credited =
            challenge
                .opening
                .verify::<H>(root, &receipt.state.account, &receipt.receiver)?;
        if credited >= receipt.amount {
            return Err(Error::NoContradiction);
        }
        self.stop(Halt::Challenge { epoch });
        Ok(())
    }

    /// Halts the ledger, for example because the operator stopped closing epochs.
    ///
    /// Halting an already halted ledger has no effect.
    pub fn halt(&mut self) {
        if self.halt.is_none() {
            self.stop(Halt::Fault);
        }
    }

    /// Halts the ledger and makes the unprocessed deposits refundable.
    fn stop(&mut self, halt: Halt) {
        self.halt = Some(halt);
        for deposit in self.deposits.drain(..) {
            *self.refundable.entry(deposit.account).or_default() += deposit.amount;
        }
        self.forced_withdrawals.clear();
        self.required_deposits = 0;
        self.required_forced_withdrawals = 0;
    }

    /// Refunds `account` after a halt and returns the amount to transfer to it.
    ///
    /// The refund includes the account's balance as of the last posted close, if `balance` proves
    /// it and it was not refunded yet, and every unprocessed deposit of the account not refunded
    /// yet.
    ///
    /// Returns an error if the ledger has not halted, the balance proof does not verify, or nothing
    /// remains to refund.
    pub fn refund(
        &mut self,
        account: &P,
        balance: Option<&BalanceProof<H::Digest>>,
    ) -> Result<u64, Error> {
        if self.halt.is_none() {
            return Err(Error::NotHalted);
        }
        let balance = match balance {
            Some(_) if self.refunded.contains(account) => 0,
            Some(proof) => {
                if !proof.verify::<H, P>(&self.balances, account) {
                    return Err(Error::InvalidBalanceProof);
                }
                proof.balance.get()
            }
            None => 0,
        };
        let deposits = self.refundable.get(account).copied().unwrap_or(0);
        if balance == 0 && deposits == 0 {
            return Err(Error::NothingToRefund);
        }
        let liability = self.liability.checked_sub(balance).ok_or(Error::Custody)?;

        if balance > 0 {
            self.refunded.insert(account.clone());
        }
        self.refundable.remove(account);
        self.liability = liability;
        self.unprocessed -= deposits;
        Ok(balance + deposits)
    }
}
