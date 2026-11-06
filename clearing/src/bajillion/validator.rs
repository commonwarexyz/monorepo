//! Checking closes, settling them on the validators' balances, and applying posted closes.

use super::{
    Amount, Amounts, Close, Epoch, Error, Matrix, Namespace, Processed, Queue, State, Summary,
    settlement::Flows,
};
use bytes::BufMut;
use commonware_codec::{Buf, EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_parallel::Strategy;
use commonware_storage::{
    Context,
    index::Unordered,
    journal::contiguous::fixed::Journal,
    merkle::{Location, MAX_PROOF_DIGESTS_PER_ELEMENT, mmb},
    qmdb::{
        any::{
            unordered::{Update, fixed::Operation},
            value::FixedEncoding,
        },
        current::{
            batch::MerkleizedBatch,
            unordered::{db::Db, proof::constant::KeyValueProof},
        },
    },
};
use commonware_utils::iter::zip_eq;
use std::sync::Arc;

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

/// Proof of an account's balance under a balances root.
///
/// A deployment builds one from the [Balances] database's `key_value_proof`, and a zero balance has
/// none. A proof reveals the account's balance to whoever receives it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BalanceProof<D: Digest, A: Amount> {
    /// The account's balance. A proof verifies only for a positive balance, because validators
    /// store no zero balance.
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
        Ok(Self {
            balance: u.arbitrary()?,
            proof: u.arbitrary()?,
        })
    }
}

/// The summary of a posted close and that close's matrix, both needed to check its successor.
///
/// Before the first close, it is [Summary::genesis] of the empty database's root with
/// [Matrix::empty].
#[derive(Clone, Debug)]
pub struct Checkpoint<P: PublicKey, D: Digest, A: Amount> {
    /// The close's summary.
    pub summary: Summary<D>,
    /// The close's payment matrix.
    pub matrix: Matrix<P, D, A>,
}

impl<P: PublicKey, O: PublicKey, A: Amount> Close<P, O, A> {
    /// Checks the close as the successor of the posted close `parent` against the ledger's `queue`.
    /// It reads no storage, checks the operator's signature before any user's, and parallelizes the
    /// checks with `strategy`. It chains each queue's running hash from `parent`'s summary over the
    /// prefix of `queue` that the close's counts select.
    ///
    /// Returns InvalidCheckpoint if `parent`'s matrix is not its summary's, WrongEpoch unless the
    /// close, `queue`, and every soft withdrawal are for the next epoch, InvalidCount unless each
    /// count is within `queue`'s bounds, InvalidOperatorSignature unless the operator signed the
    /// close, InvalidSignature unless every row's state builds on its row in `parent` and every
    /// soft withdrawal verifies, and Overflow if the next epoch or a flow does not fit.
    pub fn check<H: Hasher, S: Strategy>(
        self,
        namespace: &Namespace,
        operator: &O,
        strategy: &S,
        parent: &Checkpoint<P, H::Digest, A>,
        queue: &Queue<P, A>,
    ) -> Result<Checked<P, H::Digest, A>, Error> {
        if parent.matrix.root() != parent.summary.matrix {
            return Err(Error::InvalidCheckpoint);
        }
        let epoch = parent.summary.epoch.checked_add(1).ok_or(Error::Overflow)?;
        let Self {
            epoch: closed,
            rows,
            withdrawals,
            deposits,
            forced_withdrawals,
            signature,
        } = self;
        let found = [closed, queue.epoch]
            .into_iter()
            .chain(withdrawals.iter().map(|withdrawal| withdrawal.epoch))
            .find(|found| *found != epoch);
        if let Some(found) = found {
            return Err(Error::WrongEpoch {
                expected: epoch,
                found,
            });
        }
        let (queued_deposits, queued_forced_withdrawals) =
            queue.prefix(deposits, forced_withdrawals)?;

        // Check the operator's signature over the matrix root before any user signature, so a
        // close the operator did not sign costs only hashing.
        let (rows, signatures): (Vec<_>, Vec<_>) = strategy
            .map_collect_vec(rows, |row| {
                let root = row.payments.root::<H>();
                ((row.account, row.payments, root), row.signature)
            })
            .into_iter()
            .unzip();
        let matrix = Matrix::from_sorted::<H>(rows);
        let message = Self::message(
            epoch,
            &matrix.root(),
            &withdrawals,
            deposits,
            forced_withdrawals,
        );
        if !operator.verify(&namespace.close, &message, &signature) {
            return Err(Error::InvalidOperatorSignature);
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
                    .ok_or(Error::InvalidSignature)
            },
        )?;
        strategy.try_map_collect_vec(&withdrawals, |withdrawal| {
            withdrawal
                .verify(namespace)
                .then_some(())
                .ok_or(Error::InvalidSignature)
        })?;

        let flows = Flows::new(
            epoch,
            matrix.iter(),
            &withdrawals,
            queued_deposits,
            queued_forced_withdrawals,
        )?;
        Ok(Checked {
            epoch,
            parent: parent.summary.digest::<H>(),
            base: parent.summary.balances,
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
pub struct Checked<P: PublicKey, D: Digest, A: Amount> {
    /// Epoch of the close.
    epoch: Epoch,
    /// Digest of the parent close's summary.
    parent: D,
    /// Balances root of the parent close.
    base: D,
    /// Payment matrix of the close.
    matrix: Matrix<P, D, A>,
    /// Flow of every account the close touches.
    flows: Flows<P, A>,
    /// The queued deposits the close processes.
    deposits: Processed<D>,
    /// The queued forced withdrawals the close processes.
    forced_withdrawals: Processed<D>,
}

impl<P: PublicKey, D: Digest, A: Amount> Checked<P, D, A> {
    /// Settles the close on top of `balances` and stages one batch with metadata zero. The batch
    /// writes exactly the balances that change, with a zero balance written as a delete. It borrows
    /// the close, so a failed settle can be retried without checking the signatures again.
    ///
    /// Returns InvalidCheckpoint unless `balances` is at the parent's balances root, Overdraft or
    /// Overflow if a balance goes negative or does not fit, and Storage if the database fails.
    pub async fn settle<E, H, I, S>(
        &self,
        balances: &Balances<E, P, H, I, S, A>,
    ) -> Result<Proposal<P, H, S, A>, Error>
    where
        E: Context,
        H: Hasher<Digest = D>,
        I: Unordered<Value = Location<mmb::Family>> + 'static,
        S: Strategy,
    {
        if balances.root() != self.base {
            return Err(Error::InvalidCheckpoint);
        }
        let accounts: Vec<&P> = self.flows.accounts().collect();
        let previous = balances.get_many(&accounts).await?;
        let settlement = self.flows.settle(
            previous
                .into_iter()
                .map(|balance| balance.unwrap_or(A::ZERO)),
        )?;
        let mut batch = balances.new_batch().with_metadata(A::ZERO);
        for (account, balance) in settlement.balances {
            batch = batch.write(account, (balance != A::ZERO).then_some(balance));
        }
        let batch = batch.merkleize(balances).await?;
        let summary = Summary {
            epoch: self.epoch,
            parent: self.parent,
            matrix: self.matrix.root(),
            balances: batch.root(),
            payouts: settlement.payouts.root::<H>(),
            deposits: self.deposits,
            forced_withdrawals: self.forced_withdrawals,
        };
        Ok(Proposal {
            summary,
            matrix: self.matrix.clone(),
            payouts: settlement.payouts,
            base: self.base,
            batch,
        })
    }
}

/// A settled close with its summary, payment matrix, payouts, and staged balance writes.
pub struct Proposal<P: PublicKey, H: Hasher, S: Strategy, A: Amount> {
    /// Summary to certify.
    summary: Summary<H::Digest>,
    /// Payment matrix of the close.
    matrix: Matrix<P, H::Digest, A>,
    /// Payouts the ledger owes once the close posts.
    payouts: Amounts<P, A>,
    /// Balances root of the parent close. The writes apply on top of it.
    base: H::Digest,
    /// The balance writes.
    batch: Arc<Batch<P, H::Digest, S, A>>,
}

impl<P: PublicKey, H: Hasher, S: Strategy, A: Amount> Proposal<P, H, S, A> {
    /// Returns the summary to certify.
    pub const fn summary(&self) -> &Summary<H::Digest> {
        &self.summary
    }

    /// Returns the payment matrix the close settles.
    pub const fn matrix(&self) -> &Matrix<P, H::Digest, A> {
        &self.matrix
    }

    /// Returns the payouts the ledger owes once it posts the close.
    pub const fn payouts(&self) -> &Amounts<P, A> {
        &self.payouts
    }

    /// Applies the staged writes to `balances` once the summary posts with digest `posted`, and
    /// returns the database with this close's checkpoint. The writes are not yet durable.
    ///
    /// Returns InvalidCheckpoint, before touching `balances`, if `posted` is not this summary's
    /// digest or `balances` is not at the parent's balances root, and Storage if the batch does not
    /// apply. Any error drops the database's handle, and the deployment reopens the database at its
    /// last commit.
    #[allow(clippy::type_complexity)]
    pub async fn apply<E, I>(
        self,
        balances: Balances<E, P, H, I, S, A>,
        posted: &H::Digest,
    ) -> Result<(Balances<E, P, H, I, S, A>, Checkpoint<P, H::Digest, A>), Error>
    where
        E: Context,
        I: Unordered<Value = Location<mmb::Family>> + 'static,
    {
        if *posted != self.summary.digest::<H>() || balances.root() != self.base {
            return Err(Error::InvalidCheckpoint);
        }
        let balances = balances.apply_batch(self.batch).await?;
        let checkpoint = Checkpoint {
            summary: self.summary,
            matrix: self.matrix,
        };
        Ok((balances, checkpoint))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bajillion::{
        Withdrawal,
        tests::{
            TestBalances, TestCheckpoint, TestClose, TestDb, TestProposal, account, amounts, chain,
            check, config, empty_root, genesis, namespace, open, operator_key, post, queue, row,
            sign_close, user,
        },
    };
    use commonware_cryptography::{
        Digest as _, Sha256, Signer as _, ed25519::PublicKey, sha256::Digest,
    };
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use commonware_storage::{
        index::partitioned::unordered::Index as Partitioned,
        qmdb::{self, current::unordered::fixed},
        translator::{EightCap, OneCap},
    };
    use commonware_utils::NZUsize;

    type TestQueue = Queue<PublicKey, u64>;

    /// Returns the checkpoint `proposal`'s close leaves once it posts.
    fn checkpoint(proposal: &TestProposal) -> TestCheckpoint {
        Checkpoint {
            summary: *proposal.summary(),
            matrix: proposal.matrix().clone(),
        }
    }

    /// Returns closes that credit, pay out, and empty the balances of 13 accounts over `epochs`
    /// epochs, each with the queue it processes in full.
    fn churn(epochs: u64) -> Vec<(TestClose, TestQueue)> {
        (1..=epochs)
            .map(|epoch| {
                let deposits: Vec<_> = (0..6)
                    .map(|index| (10 + (index + epoch) % 13, 1 + epoch * 3 + index))
                    .collect();
                let forced: Vec<_> = if epoch % 4 == 0 {
                    (0..3)
                        .map(|index| (10 + (index * 5 + epoch) % 13, u64::MAX))
                        .collect()
                } else {
                    Vec::new()
                };
                let close = sign_close(
                    &operator_key(),
                    epoch,
                    Vec::new(),
                    Vec::new(),
                    deposits.len() as u64,
                    forced.len() as u64,
                );
                (close, queue(epoch, &deposits, &forced))
            })
            .collect()
    }

    /// Posts `closes` in order on `balances` from `parent`, committing after each, and returns the
    /// database with the last checkpoint and the balances root after each close.
    async fn replay<I: Unordered<Value = Location<mmb::Family>> + 'static>(
        mut balances: TestDb<I>,
        mut parent: TestCheckpoint,
        closes: &[(TestClose, TestQueue)],
    ) -> (TestDb<I>, TestCheckpoint, Vec<Digest>) {
        let mut roots = Vec::with_capacity(closes.len());
        for (close, queue) in closes {
            (balances, parent) = post(balances, &parent, close.clone(), queue).await;
            balances = balances.commit().await.unwrap();
            roots.push(balances.root());
        }
        (balances, parent, roots)
    }

    #[test]
    fn test_validators_reject_invalid_closes() {
        deterministic::Runner::default().start(|context| async move {
            let balances = open(context.child("balances"), "invalid").await;
            let operator = operator_key();
            let funded = sign_close(&operator, 1, Vec::new(), Vec::new(), 1, 0);
            let parent = genesis(balances.root());
            let (balances, parent) =
                post(balances, &parent, funded, &queue(1, &[(0, 10)], &[])).await;
            let queued = queue(2, &[(1, 5)], &[(0, 1)]);
            let valid = row(0, 2, amounts(&[(1, 10)]), empty_root());

            // A close of the next epoch processing the queue is valid.
            let close = sign_close(&operator, 2, vec![valid.clone()], Vec::new(), 1, 1);
            check(close, &parent, &queued)
                .unwrap()
                .settle(&balances)
                .await
                .unwrap();

            // It must be the next epoch and process the queue within its bounds.
            let close = sign_close(&operator, 3, vec![valid.clone()], Vec::new(), 1, 1);
            assert!(matches!(
                check(close, &parent, &queued),
                Err(Error::WrongEpoch {
                    expected: 2,
                    found: 3
                })
            ));
            for (deposits, forced) in [(2, 1), (1, 2)] {
                let close = sign_close(&operator, 2, Vec::new(), Vec::new(), deposits, forced);
                assert!(matches!(
                    check(close, &parent, &queued),
                    Err(Error::InvalidCount)
                ));
            }

            // Validators reject a close the operator did not sign before checking any user
            // signature.
            let mut forged = valid.clone();
            forged.signature = user(5).sign(b"forged", b"forged");
            let close = sign_close(&user(5), 2, vec![forged], Vec::new(), 1, 1);
            assert!(matches!(
                check(close, &parent, &queued),
                Err(Error::InvalidOperatorSignature)
            ));
            let signed = sign_close(&operator, 2, vec![valid.clone()], Vec::new(), 1, 1);
            let altered = Close::new(
                2,
                signed.rows().to_vec(),
                Vec::new(),
                0,
                1,
                signed.signature().clone(),
            );
            assert!(matches!(
                check(altered, &parent, &queued),
                Err(Error::InvalidOperatorSignature)
            ));

            // The signature also covers every row and soft withdrawal, so adding one its account
            // signed breaks it.
            let mut rows = vec![valid.clone(), row(1, 2, amounts(&[(0, 1)]), empty_root())];
            rows.sort_by(|a, b| a.account.cmp(&b.account));
            let withdrawals = vec![Withdrawal::sign(&user(0), &namespace(), 2, 1, 0)];
            for (rows, withdrawals) in [(rows, Vec::new()), (vec![valid.clone()], withdrawals)] {
                let altered = Close::new(2, rows, withdrawals, 1, 1, signed.signature().clone());
                assert!(matches!(
                    check(altered, &parent, &queued),
                    Err(Error::InvalidOperatorSignature)
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
                Err(Error::WrongEpoch {
                    expected: 2,
                    found: 3
                })
            ));

            // Every sender must sign its row for this epoch on top of its row in the parent close.
            let mut altered = valid.clone();
            altered.payments = amounts(&[(1, 9)]);
            let stale = row(0, 1, amounts(&[(1, 10)]), empty_root());
            let elsewhere = amounts(&[(1, 1)]).root::<Sha256>();
            let unanchored = row(0, 2, amounts(&[(1, 10)]), elsewhere);
            for row in [altered, stale, unanchored] {
                let close = sign_close(&operator, 2, vec![row], Vec::new(), 1, 1);
                assert!(matches!(
                    check(close, &parent, &queued),
                    Err(Error::InvalidSignature)
                ));
            }

            // Soft withdrawals must be for this epoch and signed by their account.
            let wrong_epoch = Withdrawal::sign(&user(0), &namespace(), 3, 1, 0);
            let close = sign_close(&operator, 2, Vec::new(), vec![wrong_epoch], 1, 1);
            assert!(matches!(
                check(close, &parent, &queued),
                Err(Error::WrongEpoch {
                    expected: 2,
                    found: 3
                })
            ));
            let mut forged = Withdrawal::sign(&user(0), &namespace(), 2, 1, 0);
            forged.amount = 2;
            let close = sign_close(&operator, 2, Vec::new(), vec![forged], 1, 1);
            assert!(matches!(
                check(close, &parent, &queued),
                Err(Error::InvalidSignature)
            ));

            // No balance may go negative, even when the sender signed the payment.
            let overdraft = row(1, 2, amounts(&[(0, 6)]), empty_root());
            let close = sign_close(&operator, 2, vec![overdraft], Vec::new(), 1, 1);
            let checked = check(close, &parent, &queued).unwrap();
            assert!(matches!(
                checked.settle(&balances).await,
                Err(Error::Overdraft)
            ));

            // A sender's next row builds on the map the posted close settled for it, not on the
            // empty map.
            let paying = row(0, 2, amounts(&[(1, 5)]), empty_root());
            let close = sign_close(&operator, 2, vec![paying], Vec::new(), 1, 1);
            let (balances, parent) = post(balances, &parent, close, &queued).await;
            let next = queue(3, &[], &[]);
            let unanchored = row(0, 3, amounts(&[(1, 1)]), empty_root());
            let close = sign_close(&operator, 3, vec![unanchored], Vec::new(), 0, 0);
            assert!(matches!(
                check(close, &parent, &next),
                Err(Error::InvalidSignature)
            ));
            let settled = amounts(&[(1, 5)]).root::<Sha256>();
            let anchored = row(0, 3, amounts(&[(1, 1)]), settled);
            let close = sign_close(&operator, 3, vec![anchored], Vec::new(), 0, 0);
            check(close, &parent, &next)
                .unwrap()
                .settle(&balances)
                .await
                .unwrap();

            // A checkpoint whose matrix is not the one its summary commits to is refused.
            let mismatched = Checkpoint {
                matrix: Matrix::empty::<Sha256>(),
                ..parent
            };
            let close = sign_close(&operator, 3, Vec::new(), Vec::new(), 0, 0);
            assert!(matches!(
                check(close, &mismatched, &next),
                Err(Error::InvalidCheckpoint)
            ));
        });
    }

    /// A proposal applies only as the posted close, on the database it settled on. A refused apply
    /// leaves the database as it was.
    #[test]
    fn test_validator_applies_only_the_posted_close() {
        deterministic::Runner::default().start(|context| async move {
            let reopen = |label| {
                TestBalances::init(context.child(label), config("competing", EightCap), None)
            };
            let balances = reopen("opened").await.unwrap();
            let parent = genesis(balances.root());
            let operator = operator_key();
            let queued = queue(1, &[(0, 10), (1, 20)], &[]);

            // Two closes for epoch 1 differ in how many deposits they process.
            let [first, second] = [1, 2].map(|deposits| {
                let close = sign_close(&operator, 1, Vec::new(), Vec::new(), deposits, 0);
                check(close, &parent, &queued).unwrap()
            });
            let first = first.settle(&balances).await.unwrap();
            let duplicate = second.settle(&balances).await.unwrap();
            let second = second.settle(&balances).await.unwrap();
            assert_ne!(first.summary(), second.summary());
            assert_eq!(duplicate.summary(), second.summary());

            // A proposal that did not post is refused before the database changes.
            let posted = second.summary().digest::<Sha256>();
            let root = balances.root();
            assert!(matches!(
                first.apply(balances, &posted).await,
                Err(Error::InvalidCheckpoint)
            ));
            let balances = reopen("refused").await.unwrap();
            assert_eq!(balances.root(), root);

            // The posted one applies once. A second copy of it is stale on top of it, and the
            // refusal leaves the committed root.
            let (balances, applied) = second.apply(balances, &posted).await.unwrap();
            let balances = balances.commit().await.unwrap();
            assert_eq!(balances.root(), applied.summary.balances);
            assert_eq!(balances.get(&account(1)).await.unwrap(), Some(20));
            assert!(matches!(
                duplicate.apply(balances, &posted).await,
                Err(Error::InvalidCheckpoint)
            ));
            let balances = reopen("stale").await.unwrap();
            assert_eq!(balances.root(), applied.summary.balances);

            // The other candidate does not settle on it.
            let close = sign_close(&operator, 1, Vec::new(), Vec::new(), 1, 0);
            let checked = check(close, &parent, &queued).unwrap();
            assert!(matches!(
                checked.settle(&balances).await,
                Err(Error::InvalidCheckpoint)
            ));
        });
    }

    /// Settling needs the database at the parent's balances root. The successor of a candidate that
    /// did not post settles on the posted database when the candidate wrote the same balances,
    /// because the root is the same.
    #[test]
    fn test_settle_needs_the_parent_balances() {
        deterministic::Runner::default().start(|context| async move {
            let operator = operator_key();
            let queued = queue(1, &[(0, 10), (1, 20)], &[]);
            let posted = open(context.child("posted"), "posted").await;
            let parent = genesis(posted.root());

            // Alice also pays herself in the second candidate, so it writes the same balance as
            // the first under another matrix.
            let candidate = |rows| sign_close(&operator, 1, rows, Vec::new(), 1, 0);
            let alike = vec![row(0, 1, amounts(&[(0, 5)]), empty_root())];
            let proposal = check(candidate(alike), &parent, &queued)
                .unwrap()
                .settle(&posted)
                .await
                .unwrap();
            let (posted, applied) = post(posted, &parent, candidate(Vec::new()), &queued).await;
            assert_ne!(proposal.summary(), &applied.summary);
            assert_eq!(proposal.summary().balances, applied.summary.balances);

            // The successor of the candidate settles on the posted database, but not on one that
            // applied a close with other writes or none.
            let successor = || {
                let close = sign_close(&operator, 2, Vec::new(), Vec::new(), 0, 0);
                check(close, &checkpoint(&proposal), &queue(2, &[], &[])).unwrap()
            };
            successor().settle(&posted).await.unwrap();
            let other = open(context.child("other"), "other").await;
            let more = sign_close(&operator, 1, Vec::new(), Vec::new(), 2, 0);
            let (other, _) = post(other, &parent, more, &queued).await;
            let empty = open(context.child("empty"), "empty").await;
            for balances in [&other, &empty] {
                assert!(matches!(
                    successor().settle(balances).await,
                    Err(Error::InvalidCheckpoint)
                ));
            }
        });
    }

    /// Settling borrows the checked close, so a refused or repeated settle leaves it usable, and
    /// every settle of it on the same database stages the same writes.
    #[test]
    fn test_settle_can_be_retried() {
        deterministic::Runner::default().start(|context| async move {
            let operator = operator_key();
            let balances = open(context.child("opened"), "retry").await;
            let parent = genesis(balances.root());
            let funded = sign_close(&operator, 1, Vec::new(), Vec::new(), 2, 0);
            let queued = queue(1, &[(0, 10), (1, 20)], &[]);
            let (balances, parent) = post(balances, &parent, funded, &queued).await;

            // A database at another root refuses the close, and the right one settles it as a
            // fresh check would, as often as asked.
            let paying = row(0, 2, amounts(&[(1, 3)]), empty_root());
            let close = sign_close(&operator, 2, vec![paying], Vec::new(), 0, 0);
            let checked = check(close.clone(), &parent, &queue(2, &[], &[])).unwrap();
            let other = open(context.child("other"), "other").await;
            assert!(matches!(
                checked.settle(&other).await,
                Err(Error::InvalidCheckpoint)
            ));
            let fresh = check(close, &parent, &queue(2, &[], &[]))
                .unwrap()
                .settle(&balances)
                .await
                .unwrap();
            for _ in 0..2 {
                let retried = checked.settle(&balances).await.unwrap();
                assert_eq!(retried.summary(), fresh.summary());
                assert_eq!(retried.payouts(), fresh.payouts());
            }
        });
    }

    /// Checking a close chains each queue's running hash from the parent summary over the prefix
    /// the close processes. A close that processes none of a queue carries its parent's hash, and
    /// two closes chain to one fold over everything they processed.
    #[test]
    fn test_check_chains_the_running_hashes() {
        deterministic::Runner::default().start(|context| async move {
            let operator = operator_key();
            let balances = open(context.child("opened"), "chained").await;
            let parent = genesis(balances.root());

            // The close of epoch 1 processes two of three deposits and the forced withdrawal.
            let queued = queue(1, &[(0, 10), (1, 20), (2, 30)], &[(0, 3)]);
            let all = queued.deposits.clone();
            let close = sign_close(&operator, 1, Vec::new(), Vec::new(), 2, 1);
            let (balances, first) = post(balances, &parent, close, &queued).await;
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
            let (_, second) = post(balances, &first, close, &queued).await;
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
            let parent = genesis(once.root());
            let close = sign_close(&operator, 1, Vec::new(), Vec::new(), 2, 0);
            let (once, _) = post(once, &parent, close, &queue(1, &deposits, &[])).await;
            let twice = open(context.child("twice"), "twice").await;
            let close = sign_close(&operator, 1, Vec::new(), Vec::new(), 1, 0);
            let (twice, parent) = post(twice, &parent, close, &queue(1, &deposits, &[])).await;
            let close = sign_close(&operator, 2, Vec::new(), Vec::new(), 1, 0);
            let (twice, parent) = post(twice, &parent, close, &queue(2, &deposits[1..], &[])).await;
            for index in [0, 1] {
                assert_eq!(
                    once.get(&account(index)).await.unwrap(),
                    twice.get(&account(index)).await.unwrap()
                );
            }
            assert_ne!(once.root(), twice.root());

            // A close writes only the balances it changes. Alice paying herself changes the matrix
            // but no balance, so it stages the same balances root as an empty close.
            let next = queue(3, &[], &[]);
            let idle = sign_close(&operator, 3, Vec::new(), Vec::new(), 0, 0);
            let paying = vec![row(0, 3, amounts(&[(0, 5)]), empty_root())];
            let paying = sign_close(&operator, 3, paying, Vec::new(), 0, 0);
            let paying = check(paying, &parent, &next)
                .unwrap()
                .settle(&twice)
                .await
                .unwrap();
            let staged = check(idle.clone(), &parent, &next)
                .unwrap()
                .settle(&twice)
                .await
                .unwrap();
            assert_ne!(paying.summary().matrix, staged.summary().matrix);
            assert_eq!(paying.summary().balances, staged.summary().balances);

            // A close that changes no balance still changes the root.
            let (idle, _) = post(twice, &parent, idle, &next).await;
            assert_ne!(idle.root(), parent.summary.balances);
            assert_eq!(idle.get(&account(0)).await.unwrap(), Some(10));
        });
    }

    /// The index and its translator do not affect the balances root, so validators may choose
    /// them freely.
    #[test]
    fn test_index_does_not_affect_the_balances_root() {
        deterministic::Runner::default().start(|context| async move {
            let closes = churn(40);
            let eight = open(context.child("eight"), "eight").await;
            let parent = genesis(eight.root());
            let (_, _, expected) = replay(eight, parent.clone(), &closes).await;

            let one =
                TestBalances::<OneCap>::init(context.child("one"), config("one", OneCap), None)
                    .await
                    .unwrap();
            assert_eq!(one.root(), parent.summary.balances);
            let (_, _, roots) = replay(one, parent.clone(), &closes).await;
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
            let partitioned = TestDb::<Partitioned<OneCap, Location<mmb::Family>, 1>>::init(
                context.child("partitioned"),
                partitioned,
                None,
            )
            .await
            .unwrap();
            assert_eq!(partitioned.root(), parent.summary.balances);
            let (_, _, roots) = replay(partitioned, parent, &closes).await;
            assert_eq!(roots, expected);
        });
    }

    /// A database that applied a close that did not post rewinds by reopening at the last posted
    /// close's commit, while that commit's inactivity floor is retained.
    #[test]
    fn test_bounded_reopen_rewinds_to_a_posted_close() {
        deterministic::Runner::default().start(|context| async move {
            let closes = churn(12);
            let balances = open(context.child("opened"), "rewind").await;
            let start = genesis(balances.root());
            let (balances, parent, _) = replay(balances, start.clone(), &closes[..3]).await;
            let size = balances.bounds().end;

            // A close of epoch 4 that did not post is applied and committed by mistake.
            let candidate = sign_close(&operator_key(), 4, Vec::new(), Vec::new(), 1, 0);
            let (balances, _) =
                post(balances, &parent, candidate, &queue(4, &[(7, 999)], &[])).await;
            let balances = balances.commit().await.unwrap();
            assert_ne!(balances.root(), parent.summary.balances);
            drop(balances);

            // Reopened at the commit of epoch 3, it applies the posted closes as if it never
            // applied the candidate.
            let balances = TestBalances::init(
                context.child("rewound"),
                config("rewind", EightCap),
                Some(size),
            )
            .await
            .unwrap();
            assert_eq!(balances.root(), parent.summary.balances);
            let (_, _, rewound) = replay(balances, parent, &closes[3..]).await;
            let fresh = open(context.child("fresh"), "fresh").await;
            let (_, _, expected) = replay(fresh, start, &closes).await;
            assert_eq!(rewound, expected[3..]);
        });
    }

    /// A database pruned to its sync boundary reopens at an earlier posted close only while that
    /// close's inactivity floor is retained.
    #[test]
    fn test_bounded_reopen_fails_once_the_floor_is_pruned() {
        deterministic::Runner::default().start(|context| async move {
            let reopen = |size| {
                TestBalances::init(context.child("reopened"), config("pruned", EightCap), size)
            };
            let mut balances = reopen(None).await.unwrap();
            let mut parent = genesis(balances.root());
            let (mut rewound, mut refused) = (0, 0);
            for (close, queue) in churn(60) {
                let (size, previous) = (balances.bounds().end, parent.clone());
                (balances, parent) = post(balances, &parent, close.clone(), &queue).await;
                balances = balances.commit().await.unwrap();
                let boundary = balances.sync_boundary();
                balances = balances.prune(boundary).await.unwrap();
                if previous.summary.epoch == 0 {
                    continue;
                }

                // Reopen at the commit of the previous close, then return to the latest one.
                drop(balances);
                match reopen(Some(size)).await {
                    Ok(earlier) => {
                        rewound += 1;
                        assert_eq!(earlier.root(), previous.summary.balances);
                        (balances, _) = post(earlier, &previous, close, &queue).await;
                        balances = balances.commit().await.unwrap();
                    }
                    Err(qmdb::Error::HistoricalFloorPruned(_)) => {
                        refused += 1;
                        balances = reopen(None).await.unwrap();
                    }
                    Err(error) => {
                        panic!("a bounded reopen must succeed or find the floor pruned: {error}")
                    }
                }
                assert_eq!(balances.root(), parent.summary.balances);
            }
            assert!(rewound > 0 && refused > 0);
        });
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::super::*;
        use commonware_codec::conformance::CodecConformance;
        use commonware_cryptography::sha256::Digest;

        commonware_conformance::conformance_tests! {
            CodecConformance<BalanceProof<Digest, u64>>,
        }
    }
}
