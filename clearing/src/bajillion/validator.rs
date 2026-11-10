//! Checking closes, settling them on the validators' balances and payout log, and applying posted
//! closes.

use super::{
    Amount, Amounts, Close, Epoch, FlowError, Matrix, Namespace, Processed, Queue, State, Summary,
    settlement::Flows,
};
use bytes::BufMut;
use commonware_codec::{Buf, EncodeSize, Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_cryptography::{Digest, Digestible, Hasher, PublicKey};
use commonware_macros::boxed;
use commonware_parallel::Strategy;
use commonware_storage::{
    Context,
    index::Unordered,
    journal::contiguous::fixed::Journal,
    merkle::{Location, MAX_PROOF_DIGESTS_PER_ELEMENT, Proof, mmb, mmr},
    qmdb::{
        self, ProofExt as _,
        any::unordered::{Update, fixed::Operation},
        current::{
            batch::{MerkleizedBatch, Slot},
            unordered::{db::Db, proof::constant::KeyValueProof},
        },
        keyless,
        value::FixedEncoding,
    },
};
use commonware_utils::iter::zip_eq;
use core::fmt::{self, Debug, Formatter};
use std::sync::Arc;
use thiserror::Error;

/// Why a close fails its check.
#[derive(Debug, Error)]
pub enum CheckError {
    /// The checkpoint's matrix is not its summary's.
    #[error("invalid checkpoint")]
    InvalidCheckpoint,
    /// The next epoch does not fit.
    #[error("arithmetic overflow")]
    Overflow,
    /// The close, the queue, or a soft withdrawal is for another epoch.
    #[error("wrong epoch: expected {expected}, found {found}")]
    WrongEpoch {
        /// The epoch after the checkpoint's.
        expected: Epoch,
        /// The epoch found.
        found: Epoch,
    },
    /// A count is outside the queue's bounds.
    #[error("invalid number of queued requests")]
    InvalidCount,
    /// The operator's signature does not verify.
    #[error("invalid operator signature")]
    InvalidOperatorSignature,
    /// A sender did not sign its row's map on top of the map the parent settled for it, or a soft
    /// withdrawal does not verify.
    #[error("invalid user signature")]
    InvalidSignature,
}

/// Why a checked close does not settle.
#[derive(Debug, Error)]
pub enum SettleError {
    /// The databases are not at the parent's roots.
    #[error("invalid checkpoint")]
    InvalidCheckpoint,
    /// A flow does not settle on its account's balance.
    #[error(transparent)]
    Flow(#[from] FlowError),
    /// The balances database failed.
    #[error("balances: {0}")]
    Balances(#[from] qmdb::Error<mmb::Family>),
    /// The payout log failed.
    #[error("payout log: {0}")]
    Log(#[from] qmdb::Error<mmr::Family>),
}

/// Why a proposal does not apply.
#[derive(Debug, Error)]
pub enum ApplyError {
    /// The summary did not post, or the databases are not at the parent's roots.
    #[error("invalid checkpoint")]
    InvalidCheckpoint,
    /// The balances database failed.
    #[error("balances: {0}")]
    Balances(#[from] qmdb::Error<mmb::Family>),
    /// The payout log failed.
    #[error("payout log: {0}")]
    Log(#[from] qmdb::Error<mmr::Family>),
}

/// Bytes per chunk of the balances database's activity bitmap.
const CHUNK: usize = 32;

/// The validators' balances database, over any unordered index `I`.
///
/// It maps each account with a positive balance to that balance. Its root after each posted close
/// is the balances root that close's summary certifies. The size of `H`'s digests must divide 32.
pub type Balances<E, P, H, I, S, A> = Db<
    mmb::Family,
    E,
    Journal<E, Operation<mmb::Family, P, A>>,
    P,
    FixedEncoding<A>,
    I,
    H,
    CHUNK,
    S,
>;

/// A batch of balance writes with its resulting root.
type Batch<P, D, S, A> = MerkleizedBatch<mmb::Family, D, Update<P, FixedEncoding<A>>, CHUNK, S>;

/// The validators' payout log, an append-only log of every payout since genesis.
///
/// Each posted close appends its payouts in account order and then a commit ([Payout::stage]).
/// Its size and root after each posted close are the payouts size and root that close's summary
/// certifies, and each payout keeps its index for good.
pub type Payouts<E, P, H, S, A> = keyless::fixed::Db<mmr::Family, E, Payout<P, A>, H, S>;

/// A batch of payouts and a commit staged on the payout log.
pub type PayoutBatch<P, D, S, A> =
    keyless::batch::MerkleizedBatch<mmr::Family, D, FixedEncoding<Payout<P, A>>, S>;

/// A payout a posted close owes an account.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Payout<P: PublicKey, A: Amount> {
    /// Account paid.
    pub account: P,
    /// Amount paid.
    pub amount: A,
}

impl<P: PublicKey, A: Amount> Payout<P, A> {
    /// Stages the payout log's batch for one posted close. It appends `payouts` in account order,
    /// then a commit with no metadata that keeps the inactivity floor at zero, so no payout is
    /// ever pruned.
    ///
    /// Fails if the log fails, for example because it already raised its floor.
    pub async fn stage<E, H, S>(
        log: &Payouts<E, P, H, S, A>,
        payouts: &Amounts<P, A>,
    ) -> Result<Arc<PayoutBatch<P, H::Digest, S, A>>, qmdb::Error<mmr::Family>>
    where
        E: Context,
        H: Hasher,
        S: Strategy,
    {
        let mut batch = log.new_batch().with_inactivity_floor(Location::new(0));
        for (account, amount) in payouts.iter() {
            batch = batch.append(Self {
                account: account.clone(),
                amount,
            });
        }
        batch.merkleize(log).await
    }
}

impl<P: PublicKey, A: Amount> Write for Payout<P, A> {
    fn write(&self, buf: &mut impl BufMut) {
        self.account.write(buf);
        self.amount.write(buf);
    }
}

impl<P: PublicKey, A: Amount> FixedSize for Payout<P, A> {
    const SIZE: usize = P::SIZE + A::SIZE;
}

impl<P: PublicKey, A: Amount> Read for Payout<P, A> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            account: P::read(buf)?,
            amount: A::read(buf)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<P: PublicKey, A: Amount> arbitrary::Arbitrary<'_> for Payout<P, A>
where
    P: for<'a> arbitrary::Arbitrary<'a>,
    A: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            account: u.arbitrary()?,
            amount: u.arbitrary()?,
        })
    }
}

/// Proof of an account's balance under a balances root.
///
/// A proof reveals the balance, and verifies only for a positive one, because [Balances] holds no
/// zero balance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BalanceProof<D: Digest, A: Amount> {
    /// The account's balance.
    pub balance: A,
    /// Opening of the balance under the balances root.
    pub proof: KeyValueProof<mmb::Family, D, CHUNK>,
}

impl<D: Digest, A: Amount> BalanceProof<D, A> {
    /// Returns whether `account` has `self.balance` under the balances root `root`.
    pub fn verify<H: Hasher<Digest = D>, P: PublicKey>(&self, root: &D, account: &P) -> bool {
        self.proof
            .verify::<H, FixedEncoding<A>, P>(account.clone(), self.balance, root)
    }
}

impl<D: Digest, A: Amount> Write for BalanceProof<D, A> {
    fn write(&self, buf: &mut impl BufMut) {
        self.balance.write(buf);
        self.proof.write(buf);
    }
}

impl<D: Digest, A: Amount> EncodeSize for BalanceProof<D, A> {
    fn encode_size(&self) -> usize {
        A::SIZE + self.proof.encode_size()
    }
}

impl<D: Digest, A: Amount> Read for BalanceProof<D, A> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            balance: A::read(buf)?,
            proof: KeyValueProof::read_cfg(buf, &MAX_PROOF_DIGESTS_PER_ELEMENT)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<D: Digest, A: Amount> arbitrary::Arbitrary<'_> for BalanceProof<D, A>
where
    KeyValueProof<mmb::Family, D, CHUNK>: for<'a> arbitrary::Arbitrary<'a>,
    A: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let balance = u.arbitrary()?;
        let mut proof: KeyValueProof<mmb::Family, D, CHUNK> = u.arbitrary()?;
        proof
            .proof
            .range_proof
            .proof
            .digests
            .truncate(MAX_PROOF_DIGESTS_PER_ELEMENT);
        Ok(Self { balance, proof })
    }
}

/// Proof that the payout log holds a payout at an index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayoutProof<P: PublicKey, D: Digest, A: Amount> {
    /// Index of the payout in the log.
    pub index: Location<mmr::Family>,
    /// The payout.
    pub payout: Payout<P, A>,
    /// Opening of the payout's operation under the log's root.
    pub proof: Proof<mmr::Family, D>,
}

impl<P: PublicKey, D: Digest, A: Amount> PayoutProof<P, D, A> {
    /// Returns whether the payout log with root `root` holds `self.payout` at `self.index`.
    ///
    /// An index no log can hold returns false. A commit never verifies as a payout, because the log
    /// encodes commits with another tag.
    pub fn verify<H: Hasher<Digest = D>>(&self, root: &D) -> bool {
        let operation =
            keyless::fixed::Operation::<mmr::Family, Payout<P, A>>::Append(self.payout.clone());
        self.proof.verify::<H, _>(self.index, &[operation], root)
    }
}

impl<P: PublicKey, D: Digest, A: Amount> Write for PayoutProof<P, D, A> {
    fn write(&self, buf: &mut impl BufMut) {
        self.index.write(buf);
        self.payout.write(buf);
        self.proof.write(buf);
    }
}

impl<P: PublicKey, D: Digest, A: Amount> EncodeSize for PayoutProof<P, D, A> {
    fn encode_size(&self) -> usize {
        self.index.encode_size() + Payout::<P, A>::SIZE + self.proof.encode_size()
    }
}

impl<P: PublicKey, D: Digest, A: Amount> Read for PayoutProof<P, D, A> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            index: Location::read(buf)?,
            payout: Payout::read(buf)?,
            proof: Proof::read_cfg(buf, &MAX_PROOF_DIGESTS_PER_ELEMENT)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<P: PublicKey, D: Digest, A: Amount> arbitrary::Arbitrary<'_> for PayoutProof<P, D, A>
where
    P: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
    A: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let index = u.arbitrary()?;
        let payout = u.arbitrary()?;
        let mut proof: Proof<mmr::Family, D> = u.arbitrary()?;
        proof.digests.truncate(MAX_PROOF_DIGESTS_PER_ELEMENT);
        Ok(Self {
            index,
            payout,
            proof,
        })
    }
}

/// The summary and payment matrix of a posted close.
///
/// Before the first close, it is [Summary::genesis] of the empty balances database's root with
/// [Matrix::empty].
pub struct Checkpoint<P: PublicKey, H: Hasher, A: Amount> {
    /// The close's summary.
    pub summary: Summary<H>,
    /// The close's payment matrix.
    pub matrix: Matrix<P, H, A>,
}

// The hasher is a type parameter only, so the derived traits would bound it.
impl<P: PublicKey, H: Hasher, A: Amount> Clone for Checkpoint<P, H, A> {
    fn clone(&self) -> Self {
        Self {
            summary: self.summary,
            matrix: self.matrix.clone(),
        }
    }
}

impl<P: PublicKey, H: Hasher, A: Amount> Debug for Checkpoint<P, H, A> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Checkpoint")
            .field("summary", &self.summary)
            .field("matrix", &self.matrix)
            .finish()
    }
}

impl<P: PublicKey, O: PublicKey, A: Amount> Close<P, O, A> {
    /// Checks the close as the successor of the posted close `parent` against the ledger's `queue`.
    /// It checks the operator's signature before any user's, and chains each queue's running hash
    /// from `parent`'s summary over the prefix of `queue` that the close's counts select.
    pub fn check<H: Hasher>(
        self,
        namespace: &Namespace,
        operator: &O,
        parent: &Checkpoint<P, H, A>,
        queue: &Queue<P, A>,
        strategy: &impl Strategy,
    ) -> Result<Checked<P, H, A>, CheckError> {
        if parent.matrix.root() != parent.summary.matrix {
            return Err(CheckError::InvalidCheckpoint);
        }
        let epoch = parent
            .summary
            .epoch
            .checked_add(1)
            .ok_or(CheckError::Overflow)?;
        let Self {
            epoch: closed,
            rows,
            withdrawals,
            deposits,
            forced_withdrawals,
            signature,
        } = self;
        if let Some(found) = [closed, queue.epoch]
            .into_iter()
            .chain(withdrawals.iter().map(|withdrawal| withdrawal.epoch))
            .find(|&other| other != epoch)
        {
            return Err(CheckError::WrongEpoch {
                expected: epoch,
                found,
            });
        }
        let (queued_deposits, queued_forced_withdrawals) = queue
            .prefix(deposits, forced_withdrawals)
            .ok_or(CheckError::InvalidCount)?;

        // Check the operator's signature over the matrix root before any user signature, so a
        // close the operator did not sign costs only hashing.
        let (rows, signatures): (Vec<_>, Vec<_>) = strategy
            .map_collect_vec(rows, |row| {
                let root = row.payments.root::<H>();
                ((row.account, row.payments, root), row.signature)
            })
            .into_iter()
            .unzip();
        let matrix = Matrix::from_sorted(rows);
        let message = Self::message(
            epoch,
            &matrix.root(),
            &withdrawals,
            deposits,
            forced_withdrawals,
        );
        if !operator.verify(&namespace.close, &message, &signature) {
            return Err(CheckError::InvalidOperatorSignature);
        }

        // Each sender must have signed exactly its row's payment map on top of the map the parent
        // close settled for it, and each account its soft withdrawal.
        let empty = Amounts::<P, A>::empty().root::<H>();
        strategy.try_map_collect_vec(
            zip_eq(matrix.rows(), &signatures),
            |((account, payments), signature)| {
                let state = State {
                    epoch,
                    account: account.clone(),
                    payments: *payments,
                    previous: parent.matrix.payments_root(account).unwrap_or(empty),
                };
                state
                    .verify(namespace, signature)
                    .then_some(())
                    .ok_or(CheckError::InvalidSignature)
            },
        )?;
        strategy.try_map_collect_vec(&withdrawals, |withdrawal| {
            withdrawal
                .verify(namespace)
                .then_some(())
                .ok_or(CheckError::InvalidSignature)
        })?;

        let flows = Flows::new(
            epoch,
            matrix.iter(),
            &withdrawals,
            queued_deposits,
            queued_forced_withdrawals,
        );
        Ok(Checked {
            epoch,
            parent: parent.summary,
            matrix,
            flows,
            deposits: parent.summary.deposits.next::<H, _>(queued_deposits),
            forced_withdrawals: parent
                .summary
                .forced_withdrawals
                .next::<H, _>(queued_forced_withdrawals),
        })
    }
}

/// A close whose epoch, counts, and signatures checked, awaiting settlement on the balances.
pub struct Checked<P: PublicKey, H: Hasher, A: Amount> {
    /// Epoch of the close.
    epoch: Epoch,
    /// Summary of the parent close.
    parent: Summary<H>,
    /// Payment matrix of the close.
    matrix: Matrix<P, H, A>,
    /// Flow of every account the close touches.
    flows: Flows<P, A>,
    /// The deposits the close processes, as their count and the queue's running hash.
    deposits: Processed<H::Digest>,
    /// The forced withdrawals the close processes, as their count and the queue's running hash.
    forced_withdrawals: Processed<H::Digest>,
}

impl<P: PublicKey, H: Hasher, A: Amount> Checked<P, H, A> {
    /// Settles the close on top of `balances` and `log` and stages a batch on each. The balances
    /// batch writes exactly the balances that change, with a zero balance written as a delete, and
    /// commits with metadata zero, so a balances database with no metadata has applied no close.
    /// The log batch is the one [Payout::stage] builds from the close's payouts.
    pub async fn settle<E, I, S>(
        &self,
        balances: &Balances<E, P, H, I, S, A>,
        log: &Payouts<E, P, H, S, A>,
    ) -> Result<Proposal<P, H, S, A>, SettleError>
    where
        E: Context,
        I: Unordered<Value = Location<mmb::Family>> + 'static,
        S: Strategy,
    {
        if balances.root() != self.parent.balances || log.root() != self.parent.payouts.root {
            return Err(SettleError::InvalidCheckpoint);
        }

        // Staging the accounts keeps the location each balance was read from, so writing an
        // account does not look it up again.
        let accounts: Vec<&P> = self.flows.accounts().collect();
        let (staged, previous) = balances
            .new_batch()
            .with_metadata(A::ZERO)
            .stage(&accounts, balances)
            .await?;
        let settlement = self.flows.settle(
            previous
                .into_iter()
                .map(|balance| balance.unwrap_or(A::ZERO)),
        )?;
        let slots = settlement
            .balances
            .into_iter()
            .map(|balance| match balance {
                None => Slot::Keep,
                Some(balance) if balance == A::ZERO => Slot::Delete,
                Some(balance) => Slot::Put(balance),
            })
            .collect();
        let batch = staged.merkleize(slots, Vec::new(), balances).await?;
        let appends = Payout::stage(log, &settlement.payouts).await?;
        let summary = Summary {
            epoch: self.epoch,
            parent: self.parent.digest(),
            matrix: self.matrix.root(),
            balances: batch.root(),
            payouts: appends.bounds().tip,
            deposits: self.deposits,
            forced_withdrawals: self.forced_withdrawals,
        };
        Ok(Proposal {
            summary,
            parent: self.parent,
            matrix: self.matrix.clone(),
            payouts: settlement.payouts,
            batch,
            appends,
        })
    }
}

/// A settled close with its summary, payment matrix, payouts, and the batches staged on the
/// balances and the payout log.
pub struct Proposal<P: PublicKey, H: Hasher, S: Strategy, A: Amount> {
    /// Summary to certify.
    summary: Summary<H>,
    /// Summary of the parent close. Both batches apply on top of its roots.
    parent: Summary<H>,
    /// Payment matrix of the close.
    matrix: Matrix<P, H, A>,
    /// Payouts the close appends to the payout log.
    payouts: Amounts<P, A>,
    /// The balance writes.
    batch: Arc<Batch<P, H::Digest, S, A>>,
    /// The payouts and commit appended to the payout log.
    appends: Arc<PayoutBatch<P, H::Digest, S, A>>,
}

impl<P: PublicKey, H: Hasher, S: Strategy, A: Amount> Proposal<P, H, S, A> {
    /// Returns the summary to certify.
    pub const fn summary(&self) -> &Summary<H> {
        &self.summary
    }

    /// Returns the payment matrix the close settles.
    pub const fn matrix(&self) -> &Matrix<P, H, A> {
        &self.matrix
    }

    /// Returns the payouts the close appends to the payout log, in account order. With p the
    /// parent's payouts size and s this summary's, they take the indices [p, s - 1) before the
    /// commit at s - 1, so an account's payout sits at p plus the account's [Amounts::position].
    pub const fn payouts(&self) -> &Amounts<P, A> {
        &self.payouts
    }

    /// Applies the staged batches to `balances` and `log` once the summary posts with digest
    /// `posted`, and returns both databases with this close's checkpoint. The log's appends are
    /// durable before the balances change, so after any crash the log is at or past the close the
    /// balances hold. The balance writes are not yet durable.
    ///
    /// Every error drops both handles, and they must be reopened as after a restart (V2). A refusal
    /// writes to neither database.
    #[allow(clippy::type_complexity)]
    #[boxed]
    pub async fn apply<E, I>(
        self,
        balances: Balances<E, P, H, I, S, A>,
        log: Payouts<E, P, H, S, A>,
        posted: &H::Digest,
    ) -> Result<
        (
            Balances<E, P, H, I, S, A>,
            Payouts<E, P, H, S, A>,
            Checkpoint<P, H, A>,
        ),
        ApplyError,
    >
    where
        E: Context,
        I: Unordered<Value = Location<mmb::Family>> + 'static,
    {
        if *posted != self.summary.digest()
            || balances.root() != self.parent.balances
            || log.root() != self.parent.payouts.root
        {
            return Err(ApplyError::InvalidCheckpoint);
        }
        let log = log.apply_batch(self.appends).await?.commit().await?;
        let balances = balances.apply_batch(self.batch).await?;
        let checkpoint = Checkpoint {
            summary: self.summary,
            matrix: self.matrix,
        };
        Ok((balances, log, checkpoint))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bajillion::{
        Withdrawal,
        tests::{
            Store, TestBalances, TestCheckpoint, TestClose, TestDb, TestLog, TestProposal,
            TestQueue, account, amounts, chain, check, config, empty_root, genesis, namespace,
            open, open_log, operator_key, post, queue, row, sign_close, user,
        },
    };
    use commonware_codec::{DecodeExt as _, Encode as _};
    use commonware_cryptography::{
        Digest as _, Sha256, Signer as _, ed25519::PublicKey, sha256::Digest,
    };
    use commonware_runtime::{
        Runner as _, Supervisor as _,
        deterministic::{self, FaultConfig},
        telemetry::metrics::MetricsExt as _,
    };
    use commonware_storage::{
        index::partitioned::unordered::Index as Partitioned,
        qmdb::{self, current::unordered::fixed},
        translator::{EightCap, OneCap},
    };
    use commonware_utils::{NZU64, NZUsize, Probability, Widen};

    /// Returns the checkpoint `proposal`'s close leaves once it posts.
    fn checkpoint(proposal: &TestProposal) -> TestCheckpoint {
        Checkpoint {
            summary: *proposal.summary(),
            matrix: proposal.matrix().clone(),
        }
    }

    /// Returns closes that credit, pay out, and empty the balances of 13 accounts over `epochs`
    /// epochs, each with the queue it processes in full. The accounts of users 42, 46, and 51
    /// share their first byte.
    fn churn(epochs: u64) -> Vec<(TestClose, TestQueue)> {
        (1..=epochs)
            .map(|epoch| {
                let deposits: Vec<_> = (0..6)
                    .map(|index| (40 + (index + epoch) % 13, 1 + epoch * 3 + index))
                    .collect();
                let forced: Vec<_> = if epoch % 4 == 0 {
                    (0..3)
                        .map(|index| (40 + (index * 5 + epoch) % 13, u64::MAX))
                        .collect()
                } else {
                    Vec::new()
                };
                let close = sign_close(
                    &operator_key(),
                    epoch,
                    Vec::new(),
                    Vec::new(),
                    Widen::widen(deposits.len()),
                    Widen::widen(forced.len()),
                );
                (close, queue(epoch, &deposits, &forced))
            })
            .collect()
    }

    /// Posts `closes` in order on `store` from `parent`, committing after each, and returns the
    /// databases with the last checkpoint and the balances root after each close.
    async fn replay<I: Unordered<Value = Location<mmb::Family>> + 'static>(
        mut store: Store<I>,
        mut parent: TestCheckpoint,
        closes: &[(TestClose, TestQueue)],
    ) -> (Store<I>, TestCheckpoint, Vec<Digest>) {
        let mut roots = Vec::with_capacity(closes.len());
        for (close, queue) in closes {
            (store, parent) = post(store, &parent, close.clone(), queue).await;
            store = store.commit().await;
            roots.push(store.balances.root());
        }
        (store, parent, roots)
    }

    /// Returns the proof of the one operation at `index` in `log` under its current root.
    async fn prove(
        log: &TestLog,
        index: Location<mmr::Family>,
    ) -> (Proof<mmr::Family, Digest>, Option<Payout<PublicKey, u64>>) {
        let (proof, operations) = log.proof(index, NZU64!(1)).await.unwrap();
        let payout = match &operations[..] {
            [keyless::fixed::Operation::Append(payout)] => Some(payout.clone()),
            _ => None,
        };
        (proof, payout)
    }

    /// Validators check the close of the next epoch against the queue, and refuse a wrong epoch,
    /// count, signature, row predecessor, soft withdrawal, or checkpoint. A close that overdrafts
    /// checks but does not settle.
    #[test]
    fn test_validators_reject_invalid_closes() {
        deterministic::Runner::default().start(|context| async move {
            let store = open(context.child("opened"), "invalid").await;
            let operator = operator_key();
            let funded = sign_close(&operator, 1, Vec::new(), Vec::new(), 1, 0);
            let parent = genesis(store.balances.root());
            let (store, parent) = post(store, &parent, funded, &queue(1, &[(0, 10)], &[])).await;
            let queued = queue(2, &[(1, 5)], &[(0, 1)]);
            let valid = row(2, 0, amounts(&[(1, 10)]), empty_root());

            // A close of the next epoch processing the queue is valid.
            let close = sign_close(&operator, 2, vec![valid.clone()], Vec::new(), 1, 1);
            let checked = check(close, &parent, &queued).unwrap();
            store.settle(&checked).await.unwrap();

            // It must be the next epoch and process the queue within its bounds.
            let close = sign_close(&operator, 3, vec![valid.clone()], Vec::new(), 1, 1);
            assert!(matches!(
                check(close, &parent, &queued),
                Err(CheckError::WrongEpoch {
                    expected: 2,
                    found: 3
                })
            ));
            for (deposits, forced) in [(2, 1), (1, 2)] {
                let close = sign_close(&operator, 2, Vec::new(), Vec::new(), deposits, forced);
                assert!(matches!(
                    check(close, &parent, &queued),
                    Err(CheckError::InvalidCount)
                ));
            }
            let required = Queue {
                required_deposits: 1,
                required_forced_withdrawals: 1,
                ..queued.clone()
            };
            for (deposits, forced) in [(0, 1), (1, 0)] {
                let close = sign_close(&operator, 2, Vec::new(), Vec::new(), deposits, forced);
                assert!(matches!(
                    check(close, &parent, &required),
                    Err(CheckError::InvalidCount)
                ));
            }

            // Validators reject a close the operator did not sign before checking any user
            // signature.
            let mut forged = valid.clone();
            forged.signature = user(5).sign(b"forged", b"forged");
            let close = sign_close(&user(5), 2, vec![forged], Vec::new(), 1, 1);
            assert!(matches!(
                check(close, &parent, &queued),
                Err(CheckError::InvalidOperatorSignature)
            ));
            let signed = sign_close(&operator, 2, vec![valid.clone()], Vec::new(), 1, 1);
            let mut altered = signed.clone();
            altered.deposits = 0;
            assert!(matches!(
                check(altered, &parent, &queued),
                Err(CheckError::InvalidOperatorSignature)
            ));

            // The signature also covers every row and soft withdrawal, so adding one its account
            // signed breaks it.
            let mut rows = vec![valid.clone(), row(2, 1, amounts(&[(0, 1)]), empty_root())];
            rows.sort_by(|a, b| a.account.cmp(&b.account));
            let withdrawals = vec![Withdrawal::sign(&user(0), &namespace(), 2, 1, 0)];
            for (rows, withdrawals) in [(rows, Vec::new()), (vec![valid.clone()], withdrawals)] {
                let mut altered = signed.clone();
                altered.rows = rows;
                altered.withdrawals = withdrawals;
                assert!(matches!(
                    check(altered, &parent, &queued),
                    Err(CheckError::InvalidOperatorSignature)
                ));
            }

            // The queue must be the ledger's while it expects this close.
            let stale = Queue {
                epoch: 3,
                ..queued.clone()
            };
            let close = sign_close(&operator, 2, vec![valid.clone()], Vec::new(), 1, 1);
            assert!(matches!(
                check(close, &parent, &stale),
                Err(CheckError::WrongEpoch {
                    expected: 2,
                    found: 3
                })
            ));

            // Every sender must sign its row for this epoch on top of its row in the parent close.
            let mut altered = valid.clone();
            altered.payments = amounts(&[(1, 9)]);
            let stale = row(1, 0, amounts(&[(1, 10)]), empty_root());
            let elsewhere = amounts(&[(1, 1)]).root::<Sha256>();
            let unanchored = row(2, 0, amounts(&[(1, 10)]), elsewhere);
            for row in [altered, stale, unanchored] {
                let close = sign_close(&operator, 2, vec![row], Vec::new(), 1, 1);
                assert!(matches!(
                    check(close, &parent, &queued),
                    Err(CheckError::InvalidSignature)
                ));
            }

            // Soft withdrawals must be for this epoch and signed by their account.
            let wrong_epoch = Withdrawal::sign(&user(0), &namespace(), 3, 1, 0);
            let close = sign_close(&operator, 2, Vec::new(), vec![wrong_epoch], 1, 1);
            assert!(matches!(
                check(close, &parent, &queued),
                Err(CheckError::WrongEpoch {
                    expected: 2,
                    found: 3
                })
            ));
            let mut forged = Withdrawal::sign(&user(0), &namespace(), 2, 1, 0);
            forged.amount = 2;
            let close = sign_close(&operator, 2, Vec::new(), vec![forged], 1, 1);
            assert!(matches!(
                check(close, &parent, &queued),
                Err(CheckError::InvalidSignature)
            ));

            // No balance may go negative, even when the sender signed the payment.
            let overdraft = row(2, 1, amounts(&[(0, 6)]), empty_root());
            let close = sign_close(&operator, 2, vec![overdraft], Vec::new(), 1, 1);
            let checked = check(close, &parent, &queued).unwrap();
            assert!(matches!(
                store.settle(&checked).await,
                Err(SettleError::Flow(FlowError::Overdraft))
            ));

            // A sender's next row builds on the map the posted close settled for it, not on the
            // empty map.
            let paying = row(2, 0, amounts(&[(1, 5)]), empty_root());
            let close = sign_close(&operator, 2, vec![paying], Vec::new(), 1, 1);
            let (store, parent) = post(store, &parent, close, &queued).await;
            let next = queue(3, &[], &[]);
            let unanchored = row(3, 0, amounts(&[(1, 1)]), empty_root());
            let close = sign_close(&operator, 3, vec![unanchored], Vec::new(), 0, 0);
            assert!(matches!(
                check(close, &parent, &next),
                Err(CheckError::InvalidSignature)
            ));
            let settled = amounts(&[(1, 5)]).root::<Sha256>();
            let anchored = row(3, 0, amounts(&[(1, 1)]), settled);
            let close = sign_close(&operator, 3, vec![anchored], Vec::new(), 0, 0);
            let checked = check(close, &parent, &next).unwrap();
            store.settle(&checked).await.unwrap();

            // A checkpoint whose matrix is not the one its summary commits to is refused.
            let mismatched = Checkpoint {
                matrix: Matrix::empty(),
                ..parent
            };
            let close = sign_close(&operator, 3, Vec::new(), Vec::new(), 0, 0);
            assert!(matches!(
                check(close, &mismatched, &next),
                Err(CheckError::InvalidCheckpoint)
            ));
        });
    }

    /// A posted close appends exactly its payouts to the payout log, in account order from the
    /// parent's payouts size up to its commit. Settling refuses a log not at the parent's payouts
    /// root.
    #[test]
    fn test_settle_appends_the_payouts_in_account_order() {
        deterministic::Runner::default().start(|context| async move {
            let operator = operator_key();
            let store = open(context.child("opened"), "appends").await;
            let parent = genesis(store.balances.root());
            assert_eq!(parent.summary.payouts.root, store.log.root());
            assert_eq!(store.log.bounds().end, parent.summary.payouts.size);

            // The close of epoch 1 credits three accounts and pays two of them out.
            let queued = queue(1, &[(0, 10), (1, 20), (2, 30)], &[(2, 30), (0, 4)]);
            let close = sign_close(&operator, 1, Vec::new(), Vec::new(), 3, 2);
            let checked = check(close, &parent, &queued).unwrap();
            let proposal = store.settle(&checked).await.unwrap();
            let expected = amounts(&[(0, 4), (2, 30)]);
            assert_eq!(proposal.payouts(), &expected);
            let summary = *proposal.summary();
            assert_eq!(summary.payouts.size, parent.summary.payouts.size + 3);
            let posted = proposal.summary().digest();
            let (store, first) = store.apply(proposal, &posted).await.unwrap();
            assert_eq!(store.log.root(), summary.payouts.root);
            assert_eq!(store.log.bounds().end, summary.payouts.size);

            // Each payout sits at the parent's payouts size plus its account's position in the
            // close's payouts, and the commit follows them.
            let start = parent.summary.payouts.size;
            for (account, amount) in expected.iter() {
                let position: u64 = Widen::widen(expected.position(account).unwrap());
                let payout = store.log.get(start + position).await.unwrap();
                let expected = Payout {
                    account: account.clone(),
                    amount,
                };
                assert_eq!(payout, Some(expected));
            }
            assert_eq!(expected.position(&account(1)), None);
            let commit = summary.payouts.size - 1;
            assert_eq!(store.log.get(commit).await.unwrap(), None);

            // A close with no payouts appends only its commit.
            let close = sign_close(&operator, 2, Vec::new(), Vec::new(), 0, 0);
            let checked = check(close, &first, &queue(2, &[], &[])).unwrap();
            let idle = store.settle(&checked).await.unwrap();
            assert!(idle.payouts().is_empty());
            assert_eq!(idle.summary().payouts.size, summary.payouts.size + 1);

            // A log at another root refuses the close, even with the balances at the parent's.
            let other = open(context.child("other"), "other").await;
            assert!(matches!(
                checked.settle(&store.balances, &other.log).await,
                Err(SettleError::InvalidCheckpoint)
            ));
        });
    }

    /// A proposal applies only as the posted close, on the databases it settled on. A refused apply
    /// leaves both databases as they were.
    #[test]
    fn test_validator_applies_only_the_posted_close() {
        deterministic::Runner::default().start(|context| async move {
            let reopen = |label| open(context.child(label), "competing");
            let store = reopen("opened").await;
            let parent = genesis(store.balances.root());
            let operator = operator_key();
            let queued = queue(1, &[(0, 10), (1, 20)], &[(0, 3)]);

            // Two closes for epoch 1 differ in how many deposits they process.
            let [first, second] = [1, 2].map(|deposits| {
                let close = sign_close(&operator, 1, Vec::new(), Vec::new(), deposits, 1);
                check(close, &parent, &queued).unwrap()
            });
            let first = store.settle(&first).await.unwrap();
            let duplicate = store.settle(&second).await.unwrap();
            let second = store.settle(&second).await.unwrap();
            assert_ne!(first.summary(), second.summary());
            assert_eq!(duplicate.summary(), second.summary());

            // A proposal that did not post is refused before either database changes.
            let posted = second.summary().digest();
            let before = store.roots();
            assert!(matches!(
                store.apply(first, &posted).await,
                Err(ApplyError::InvalidCheckpoint)
            ));
            let store = reopen("refused").await;
            assert_eq!(store.roots(), before);

            // The posted one applies once. A second copy of it is stale on top of it, and the
            // refusal leaves the committed roots.
            let (store, applied) = store.apply(second, &posted).await.unwrap();
            let store = store.commit().await;
            let after = (applied.summary.balances, applied.summary.payouts.root);
            assert_eq!(store.roots(), after);
            assert_eq!(store.balances.get(&account(1)).await.unwrap(), Some(20));
            assert!(matches!(
                store.apply(duplicate, &posted).await,
                Err(ApplyError::InvalidCheckpoint)
            ));
            let store = reopen("stale").await;
            assert_eq!(store.roots(), after);

            // The other candidate does not settle on it.
            let close = sign_close(&operator, 1, Vec::new(), Vec::new(), 1, 1);
            let checked = check(close, &parent, &queued).unwrap();
            assert!(matches!(
                store.settle(&checked).await,
                Err(SettleError::InvalidCheckpoint)
            ));
        });
    }

    /// Apply checks the posted digest and both databases' roots before it touches either
    /// database. Each refusal leaves both databases where they were, including a payout log at
    /// the parent's root beside balances elsewhere.
    #[test]
    fn test_apply_refuses_before_touching_either_database() {
        deterministic::Runner::default().start(|context| async move {
            let operator = operator_key();
            let reopen = |label, name| open(context.child(label), name);
            let here = reopen("here", "here").await;
            let parent = genesis(here.balances.root());
            let queued = queue(1, &[(0, 10)], &[(0, 4)]);
            let close = sign_close(&operator, 1, Vec::new(), Vec::new(), 1, 1);
            let checked = check(close.clone(), &parent, &queued).unwrap();
            let elsewhere = reopen("elsewhere", "elsewhere").await;
            let (elsewhere, _) = post(elsewhere, &parent, close, &queued).await;
            let elsewhere = elsewhere.commit().await;
            let (at_parent, moved) = (here.roots(), elsewhere.roots());

            // The posted digest is not the proposal's.
            let proposal = here.settle(&checked).await.unwrap();
            assert!(matches!(
                here.apply(proposal, &Digest::EMPTY).await,
                Err(ApplyError::InvalidCheckpoint)
            ));
            let here = reopen("digest", "here").await;
            assert_eq!(here.roots(), at_parent);

            // The balances are elsewhere, so the log beside them must not advance.
            let proposal = here.settle(&checked).await.unwrap();
            let posted = proposal.summary().digest();
            assert!(matches!(
                proposal.apply(elsewhere.balances, here.log, &posted).await,
                Err(ApplyError::InvalidCheckpoint)
            ));
            drop((here.balances, elsewhere.log));
            let (here, elsewhere) = (
                reopen("balances", "here").await,
                reopen("balances_elsewhere", "elsewhere").await,
            );
            assert_eq!(here.roots(), at_parent);
            assert_eq!(elsewhere.roots(), moved);

            // The log is elsewhere.
            let proposal = here.settle(&checked).await.unwrap();
            assert!(matches!(
                proposal.apply(here.balances, elsewhere.log, &posted).await,
                Err(ApplyError::InvalidCheckpoint)
            ));
            drop((here.log, elsewhere.balances));
            let (here, elsewhere) = (
                reopen("log", "here").await,
                reopen("log_elsewhere", "elsewhere").await,
            );
            assert_eq!(here.roots(), at_parent);
            assert_eq!(elsewhere.roots(), moved);
        });
    }

    /// A validator that applies several posted closes before committing its balances may stop
    /// with the balances holding any of them, because applied writes can reach disk before a
    /// commit, and with the log at the last one. Reopening the log at the payouts size of the
    /// close the balances hold discards the rest, and replaying from that close reaches the roots
    /// of a validator that committed after every close.
    #[test]
    fn test_log_rewinds_past_several_closes() {
        deterministic::Runner::default().start(|context| async move {
            let closes = churn(6);
            let store = open(context.child("opened"), "ahead").await;
            let start = genesis(store.balances.root());
            let (mut store, mut parent, _) = replay(store, start.clone(), &closes[..1]).await;

            // The closes of epochs 2 to 4 apply without a balances commit. The close of epoch 4
            // pays forced withdrawals out, so the log gains payouts and not only commits.
            let mut applied = vec![parent.clone()];
            for (close, queue) in &closes[1..4] {
                (store, parent) = post(store, &parent, close.clone(), queue).await;
                applied.push(parent.clone());
            }
            assert!(parent.summary.payouts.size > applied[0].summary.payouts.size + 3);
            drop(store);

            // The balances hold one of the applied closes, and the log is past it.
            let crashed = open(context.child("crashed"), "ahead").await;
            let held = applied
                .iter()
                .position(|checkpoint| checkpoint.summary.balances == crashed.balances.root())
                .expect("the balances must hold an applied close");
            assert_eq!(crashed.log.root(), parent.summary.payouts.root);
            assert!(applied[held].summary.payouts.size < parent.summary.payouts.size);

            // The log reopens at that close's payouts size, and the replay converges with a
            // validator that committed after every close.
            let Store { balances, log } = crashed;
            drop(log);
            let size = Some(applied[held].summary.payouts.size);
            let log = open_log(context.child("rewound"), "ahead", size).await;
            assert_eq!(log.root(), applied[held].summary.payouts.root);
            let (store, rewound_parent, rewound) = replay(
                Store { balances, log },
                applied[held].clone(),
                &closes[held + 1..],
            )
            .await;
            let fresh = open(context.child("fresh"), "fresh").await;
            let (fresh, fresh_parent, expected) = replay(fresh, start, &closes).await;
            assert_eq!(rewound, expected[held + 1..]);
            assert_eq!(rewound_parent.summary, fresh_parent.summary);
            assert_eq!(store.roots(), fresh.roots());
        });
    }

    /// Settling stages a batch without applying it, and when the payout log then cannot be made
    /// durable, apply fails before it applies anything to the balances.
    #[test]
    fn test_apply_writes_no_balance_before_the_log_is_durable() {
        deterministic::Runner::default().start(|context| async move {
            let operator = operator_key();
            let store = open(context.child("opened"), "ordered").await;

            // A second handle to the counter the balances database registered shares its count,
            // so it counts the balances batch of the close of epoch 1 and keeps counting after
            // apply drops the database.
            let apply_calls = context
                .child("opened")
                .child("balances")
                .counter("apply_batch_calls", "Number of apply-batch calls");
            let parent = genesis(store.balances.root());
            let queued = queue(1, &[(0, 10)], &[]);
            let close = sign_close(&operator, 1, Vec::new(), Vec::new(), 1, 0);
            let (store, parent) = post(store, &parent, close, &queued).await;
            assert_eq!(apply_calls.metric().get(), 1);

            // The close of epoch 2 pays out a forced withdrawal. Every sync fails, so the log's
            // commit fails and apply drops both handles.
            let queued = queue(2, &[], &[(0, 4)]);
            let close = sign_close(&operator, 2, Vec::new(), Vec::new(), 0, 1);
            let checked = check(close, &parent, &queued).unwrap();
            let proposal = store.settle(&checked).await.unwrap();
            let posted = proposal.summary().digest();
            *context.storage_fault_config().write() = FaultConfig {
                sync_rate: Some(Probability::new(1, 1).unwrap()),
                ..Default::default()
            };
            assert!(matches!(
                store.apply(proposal, &posted).await,
                Err(ApplyError::Log(_))
            ));
            assert_eq!(apply_calls.metric().get(), 1);
        });
    }

    /// Settling needs the databases at the parent's roots. The successor of a candidate that did
    /// not post settles on the posted databases when the candidate wrote the same balances and
    /// payouts, because the roots are the same.
    #[test]
    fn test_settle_needs_the_parent_roots() {
        deterministic::Runner::default().start(|context| async move {
            let operator = operator_key();
            let queued = queue(1, &[(0, 10), (1, 20)], &[(1, 2)]);
            let posted = open(context.child("posted"), "posted").await;
            let parent = genesis(posted.balances.root());

            // Alice also pays herself in the second candidate, so it writes the same balances and
            // payouts as the first under another matrix.
            let candidate = |rows| sign_close(&operator, 1, rows, Vec::new(), 1, 1);
            let alike = vec![row(1, 0, amounts(&[(0, 5)]), empty_root())];
            let checked = check(candidate(alike), &parent, &queued).unwrap();
            let proposal = posted.settle(&checked).await.unwrap();
            let (posted, applied) = post(posted, &parent, candidate(Vec::new()), &queued).await;
            assert_ne!(proposal.summary(), &applied.summary);
            assert_eq!(proposal.summary().balances, applied.summary.balances);
            assert_eq!(
                proposal.summary().payouts.size,
                applied.summary.payouts.size
            );
            assert_eq!(
                proposal.summary().payouts.root,
                applied.summary.payouts.root
            );

            // The successor of the candidate settles on the posted databases, but not on balances
            // that applied a close with other writes or none, nor beside a log at another root.
            let successor = || {
                let close = sign_close(&operator, 2, Vec::new(), Vec::new(), 0, 0);
                check(close, &checkpoint(&proposal), &queue(2, &[], &[])).unwrap()
            };
            posted.settle(&successor()).await.unwrap();
            let other = open(context.child("other"), "other").await;
            let more = sign_close(&operator, 1, Vec::new(), Vec::new(), 2, 1);
            let (other, _) = post(other, &parent, more, &queued).await;
            let empty = open(context.child("empty"), "empty").await;
            for balances in [&other.balances, &empty.balances] {
                assert!(matches!(
                    successor().settle(balances, &posted.log).await,
                    Err(SettleError::InvalidCheckpoint)
                ));
            }
            assert!(matches!(
                successor().settle(&posted.balances, &empty.log).await,
                Err(SettleError::InvalidCheckpoint)
            ));
        });
    }

    /// Checking a close chains each queue's running hash from the parent summary over the prefix
    /// the close processes. A close that processes none of a queue carries its parent's hash, and
    /// two closes chain to one fold over everything they processed.
    #[test]
    fn test_check_chains_the_running_hashes() {
        deterministic::Runner::default().start(|context| async move {
            let operator = operator_key();
            let store = open(context.child("opened"), "chained").await;
            let parent = genesis(store.balances.root());

            // The close of epoch 1 processes two of three deposits and the forced withdrawal.
            let queued = queue(1, &[(0, 10), (1, 20), (2, 30)], &[(0, 3)]);
            let all = queued.deposits.clone();
            let close = sign_close(&operator, 1, Vec::new(), Vec::new(), 2, 1);
            let (store, first) = post(store, &parent, close, &queued).await;
            let expected = Processed {
                count: 2,
                hash: chain(Digest::EMPTY, &all[..2]),
            };
            assert_eq!(first.summary.deposits, expected);
            let expected = Processed {
                count: 1,
                hash: chain(Digest::EMPTY, &queued.forced_withdrawals),
            };
            assert_eq!(first.summary.forced_withdrawals, expected);

            // The close of epoch 2 processes the remaining deposit and no forced withdrawal.
            let queued = Queue {
                required_deposits: 1,
                ..queue(2, &[(2, 30)], &[])
            };
            let close = sign_close(&operator, 2, Vec::new(), Vec::new(), 1, 0);
            let (_, second) = post(store, &first, close, &queued).await;
            let deposits = second.summary.deposits;
            assert_eq!(deposits.count, 1);
            assert_eq!(
                deposits.hash,
                chain(first.summary.deposits.hash, &queued.deposits)
            );
            assert_eq!(deposits.hash, chain(Digest::EMPTY, &all));
            let expected = Processed {
                count: 0,
                hash: first.summary.forced_withdrawals.hash,
            };
            assert_eq!(second.summary.forced_withdrawals, expected);
        });
    }

    /// The balances root commits to every batch the database applied, not only to the balances it
    /// holds, so validators must apply exactly the posted closes.
    #[test]
    fn test_balances_root_depends_on_history() {
        deterministic::Runner::default().start(|context| async move {
            let operator = operator_key();
            let deposits = [(0, 10), (1, 5)];

            // One database credits both deposits in one close, the other in two.
            let once = open(context.child("once"), "once").await;
            let parent = genesis(once.balances.root());
            let close = sign_close(&operator, 1, Vec::new(), Vec::new(), 2, 0);
            let (once, _) = post(once, &parent, close, &queue(1, &deposits, &[])).await;
            let twice = open(context.child("twice"), "twice").await;
            let close = sign_close(&operator, 1, Vec::new(), Vec::new(), 1, 0);
            let (twice, parent) = post(twice, &parent, close, &queue(1, &deposits, &[])).await;
            let close = sign_close(&operator, 2, Vec::new(), Vec::new(), 1, 0);
            let (twice, parent) = post(twice, &parent, close, &queue(2, &deposits[1..], &[])).await;
            for index in [0, 1] {
                assert_eq!(
                    once.balances.get(&account(index)).await.unwrap(),
                    twice.balances.get(&account(index)).await.unwrap()
                );
            }
            assert_ne!(once.balances.root(), twice.balances.root());

            // A close writes only the balances it changes. Alice paying herself changes the matrix
            // but no balance, so it stages the same balances root as an empty close.
            let next = queue(3, &[], &[]);
            let idle = sign_close(&operator, 3, Vec::new(), Vec::new(), 0, 0);
            let paying = vec![row(3, 0, amounts(&[(0, 5)]), empty_root())];
            let paying = sign_close(&operator, 3, paying, Vec::new(), 0, 0);
            let paying = twice
                .settle(&check(paying, &parent, &next).unwrap())
                .await
                .unwrap();
            let staged = twice
                .settle(&check(idle.clone(), &parent, &next).unwrap())
                .await
                .unwrap();
            assert_ne!(paying.summary().matrix, staged.summary().matrix);
            assert_eq!(paying.summary().balances, staged.summary().balances);

            // Alice withdrawing exactly what a deposit credits her keeps her balance, so the close
            // stages the same balances root as an empty close while it owes her the payout.
            let funded = queue(3, &[(0, 4)], &[(0, 4)]);
            let withdrawing = sign_close(&operator, 3, Vec::new(), Vec::new(), 1, 1);
            let withdrawing = twice
                .settle(&check(withdrawing, &parent, &funded).unwrap())
                .await
                .unwrap();
            assert_eq!(withdrawing.payouts(), &amounts(&[(0, 4)]));
            assert_eq!(withdrawing.summary().balances, staged.summary().balances);

            // A close that changes no balance still changes the root.
            let (idle, _) = post(twice, &parent, idle, &next).await;
            assert_ne!(idle.balances.root(), parent.summary.balances);
            assert_eq!(idle.balances.get(&account(0)).await.unwrap(), Some(10));
        });
    }

    /// The index and its translator do not affect the balances root, so validators may choose
    /// them freely.
    #[test]
    fn test_index_does_not_affect_the_balances_root() {
        deterministic::Runner::default().start(|context| async move {
            let closes = churn(40);

            // Three of the accounts share their first byte, so they collide in the plain index
            // under OneCap.
            let colliding = [42, 46, 51].map(|index| account(index).encode()[0]);
            assert!(colliding.iter().all(|first| *first == colliding[0]));
            let eight = open(context.child("eight"), "eight").await;
            let parent = genesis(eight.balances.root());
            let (_, _, expected) = replay(eight, parent.clone(), &closes).await;

            let balances =
                TestBalances::<OneCap>::init(context.child("one"), config("one", OneCap), None)
                    .await
                    .unwrap();
            assert_eq!(balances.root(), parent.summary.balances);
            let log = open_log(context.child("one_log"), "one", None).await;
            let (_, _, roots) = replay(Store { balances, log }, parent.clone(), &closes).await;
            assert_eq!(roots, expected);

            let base = config("partitioned", OneCap);
            let partitioned = fixed::partitioned::Config {
                merkle: base.merkle,
                log: base.log,
                grafted_metadata_partition: base.grafted_metadata_partition,
                translator: base.translator,
                init_cache: base.init_cache,
                init_buffer: base.init_buffer,
                init_concurrency: NZUsize!(1),
            };
            let balances = TestDb::<Partitioned<OneCap, Location<mmb::Family>, 1>>::init(
                context.child("partitioned"),
                partitioned,
                None,
            )
            .await
            .unwrap();
            assert_eq!(balances.root(), parent.summary.balances);
            let log = open_log(context.child("partitioned_log"), "partitioned", None).await;
            let (_, _, roots) = replay(Store { balances, log }, parent, &closes).await;
            assert_eq!(roots, expected);
        });
    }

    /// Databases that applied a close that did not post rewind by reopening at the last posted
    /// close's commit, while the balances retain that commit's inactivity floor. The payout log
    /// rewinds to the payouts size that close certifies.
    #[test]
    fn test_bounded_reopen_rewinds_to_a_posted_close() {
        deterministic::Runner::default().start(|context| async move {
            let closes = churn(12);
            let store = open(context.child("opened"), "rewind").await;
            let start = genesis(store.balances.root());
            let (store, parent, _) = replay(store, start.clone(), &closes[..3]).await;
            let size = store.balances.bounds().end;

            // A close of epoch 4 that did not post is applied and committed by mistake.
            let candidate = sign_close(&operator_key(), 4, Vec::new(), Vec::new(), 1, 1);
            let queued = queue(4, &[(7, 999)], &[(7, 1)]);
            let (store, _) = post(store, &parent, candidate, &queued).await;
            let store = store.commit().await;
            assert_ne!(store.balances.root(), parent.summary.balances);
            assert_ne!(store.log.root(), parent.summary.payouts.root);
            drop(store);

            // Reopened at the commits of epoch 3, they apply the posted closes as if they never
            // applied the candidate.
            let balances = TestBalances::init(
                context.child("rewound"),
                config("rewind", EightCap),
                Some(size),
            )
            .await
            .unwrap();
            let log = open_log(
                context.child("rewound_log"),
                "rewind",
                Some(parent.summary.payouts.size),
            )
            .await;
            let store = Store { balances, log };
            assert_eq!(
                store.roots(),
                (parent.summary.balances, parent.summary.payouts.root)
            );
            let (store, rewound_parent, rewound) = replay(store, parent, &closes[3..]).await;
            let fresh = open(context.child("fresh"), "fresh").await;
            let (fresh, fresh_parent, expected) = replay(fresh, start, &closes).await;
            assert_eq!(rewound, expected[3..]);
            assert_eq!(rewound_parent.summary, fresh_parent.summary);
            assert_eq!(store.log.root(), fresh.log.root());
        });
    }

    /// Balances pruned to their sync boundary reopen at an earlier posted close only while that
    /// close's inactivity floor is retained. The payout log is never pruned, so it always reopens
    /// at the payouts size that close certifies.
    #[test]
    fn test_bounded_reopen_fails_once_the_floor_is_pruned() {
        deterministic::Runner::default().start(|context| async move {
            let reopen = |size| {
                TestBalances::init(context.child("reopened"), config("pruned", EightCap), size)
            };
            let balances = reopen(None).await.unwrap();
            let log = open_log(context.child("log"), "pruned", None).await;
            let mut store = Store { balances, log };
            let mut parent = genesis(store.balances.root());
            let (mut rewound, mut refused) = (0, 0);
            for (close, queue) in churn(60) {
                let (size, previous) = (store.balances.bounds().end, parent.clone());
                (store, parent) = post(store, &parent, close.clone(), &queue).await;
                store = store.commit().await;
                let boundary = store.balances.sync_boundary();
                store.balances = store.balances.prune(boundary).await.unwrap();
                if previous.summary.epoch == 0 {
                    continue;
                }

                // Reopen at the commits of the previous close, then return to the latest one.
                let Store { balances, log } = store;
                drop(balances);
                match reopen(Some(size)).await {
                    Ok(balances) => {
                        rewound += 1;
                        drop(log);
                        let size = Some(previous.summary.payouts.size);
                        let log = open_log(context.child("rewound"), "pruned", size).await;
                        let earlier = Store { balances, log };
                        assert_eq!(
                            earlier.roots(),
                            (previous.summary.balances, previous.summary.payouts.root)
                        );
                        (store, _) = post(earlier, &previous, close, &queue).await;
                        store = store.commit().await;
                    }
                    Err(qmdb::Error::HistoricalFloorPruned(_)) => {
                        refused += 1;
                        let balances = reopen(None).await.unwrap();
                        store = Store { balances, log };
                    }
                    Err(error) => {
                        panic!("a bounded reopen must succeed or find the floor pruned: {error}")
                    }
                }
                assert_eq!(
                    store.roots(),
                    (parent.summary.balances, parent.summary.payouts.root)
                );
            }
            assert!(rewound > 0 && refused > 0);
        });
    }

    /// A payout proof verifies only the payout the log holds at its index, under the log's
    /// current root. A wrong index, account, or amount, a commit position, a later root, and
    /// indices no log can hold all fail without panicking.
    #[test]
    fn test_payout_proof_verifies_only_the_logged_payout() {
        deterministic::Runner::default().start(|context| async move {
            let operator = operator_key();
            let store = open(context.child("opened"), "proofs").await;
            let parent = genesis(store.balances.root());
            let queued = queue(1, &[(0, 10), (1, 20)], &[(0, 3), (1, 4)]);
            let close = sign_close(&operator, 1, Vec::new(), Vec::new(), 2, 2);
            let (store, first) = post(store, &parent, close, &queued).await;
            let root = first.summary.payouts.root;

            // The payout at index 1 proves, and its proof round-trips.
            let (proof, payout) = prove(&store.log, Location::new(1)).await;
            let payout = payout.unwrap();
            let valid = PayoutProof {
                index: Location::new(1),
                payout: payout.clone(),
                proof,
            };
            assert!(valid.verify::<Sha256>(&root));
            assert_eq!(PayoutProof::decode(valid.encode()).unwrap(), valid);

            // Another index, account, or amount does not verify, and neither does an index past
            // the log or one no log can hold.
            let other = [account(0), account(1)]
                .into_iter()
                .find(|account| *account != payout.account)
                .unwrap();
            let forged = [
                (2, payout.clone()),
                (
                    1,
                    Payout {
                        account: other,
                        ..payout.clone()
                    },
                ),
                (
                    1,
                    Payout {
                        amount: payout.amount + 1,
                        ..payout.clone()
                    },
                ),
                (100, payout.clone()),
                (u64::MAX, payout.clone()),
            ];
            for (index, payout) in forged {
                let forged = PayoutProof {
                    index: Location::new(index),
                    payout,
                    ..valid.clone()
                };
                assert!(!forged.verify::<Sha256>(&root));
            }

            // The root binds the log's size and its count of inactive peaks, so a proof claiming
            // another size or another count of inactive peaks does not verify either.
            let mut resized = valid.clone();
            resized.proof.leaves = valid.proof.leaves + 1;
            assert!(!resized.verify::<Sha256>(&root));
            let mut inactive = valid.clone();
            inactive.proof.inactive_peaks = 1;
            assert!(!inactive.verify::<Sha256>(&root));

            // The commit position does not verify as a payout.
            let commit = first.summary.payouts.size - 1;
            let (proof, logged) = prove(&store.log, commit).await;
            assert_eq!(logged, None);
            let at_commit = PayoutProof {
                index: commit,
                payout: payout.clone(),
                proof,
            };
            assert!(!at_commit.verify::<Sha256>(&root));

            // After a later close, the proof fails under the new root and a fresh one verifies.
            let close = sign_close(&operator, 2, Vec::new(), Vec::new(), 0, 0);
            let (store, second) = post(store, &first, close, &queue(2, &[], &[])).await;
            let root = second.summary.payouts.root;
            assert!(!valid.verify::<Sha256>(&root));
            let (proof, _) = prove(&store.log, valid.index).await;
            let fresh = PayoutProof { proof, ..valid };
            assert!(fresh.verify::<Sha256>(&root));
        });
    }

    /// A commit whose metadata is a payout never verifies as that payout, because the log encodes
    /// a commit with another tag than an appended payout.
    #[test]
    fn test_payout_proof_distinguishes_payouts_from_commits() {
        deterministic::Runner::default().start(|context| async move {
            let log = open_log(context.child("log"), "tagged", None).await;
            let payout = Payout {
                account: account(0),
                amount: 7,
            };
            let batch = log
                .new_batch()
                .append(payout.clone())
                .with_metadata(payout.clone())
                .with_inactivity_floor(Location::new(0))
                .merkleize(&log)
                .await
                .unwrap();
            let log = log
                .apply_batch(batch)
                .await
                .unwrap()
                .commit()
                .await
                .unwrap();
            assert_eq!(log.get_metadata().await.unwrap(), Some(payout.clone()));
            for index in [1, 2].map(Location::new) {
                let (proof, _) = prove(&log, index).await;
                let claimed = PayoutProof {
                    index,
                    payout: payout.clone(),
                    proof,
                };
                assert_eq!(claimed.verify::<Sha256>(&log.root()), index == 1);
            }
        });
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<BalanceProof<Digest, u64>>,
            CodecConformance<Payout<PublicKey, u64>>,
            CodecConformance<PayoutProof<PublicKey, Digest, u64>>,
        }
    }
}
