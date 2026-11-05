//! Checking closes and certifying their effects.

use super::{
    Amounts, Close, Error, Matrix, Namespace, Queue, Scheme, State, Summary, settlement::Flows,
};
use bytes::BufMut;
use commonware_codec::{Buf, EncodeSize, Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_cryptography::{Digest, Hasher, PublicKey, certificate::Attestation};
use commonware_parallel::Strategy;
use commonware_runtime::Spawner;
use commonware_storage::{
    Context,
    merkle::{MAX_PROOF_DIGESTS_PER_ELEMENT, mmb},
    qmdb::{
        self,
        any::{unordered::Update, value::FixedEncoding},
        current::{
            batch::MerkleizedBatch,
            unordered::{fixed, proof::constant::KeyValueProof},
        },
    },
    translator::Translator,
};
use commonware_utils::iter::zip_eq;
use std::{num::NonZeroU64, sync::Arc};

/// Bytes per chunk of the balances database's activity bitmap.
const CHUNK: usize = 32;

/// The balances database. It maps each account with a positive balance to that balance.
type Balances<E, P, H, T, S> = fixed::Db<mmb::Family, E, P, NonZeroU64, H, T, CHUNK, S>;

/// A batch of balance writes with its resulting root.
type Batch<P, D, S> =
    MerkleizedBatch<mmb::Family, D, Update<P, FixedEncoding<NonZeroU64>>, CHUNK, S>;

/// Proof of an account's balance under a balances root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BalanceProof<D: Digest> {
    /// The account's balance.
    pub balance: NonZeroU64,
    /// Opening of the balance under the balances root.
    pub proof: KeyValueProof<mmb::Family, D, CHUNK>,
}

impl<D: Digest> BalanceProof<D> {
    /// Returns whether `account` has `self.balance` under the balances root `root`.
    pub fn verify<H: Hasher<Digest = D>, P: PublicKey>(&self, root: &D, account: &P) -> bool {
        self.proof
            .verify::<H, FixedEncoding<NonZeroU64>, P>(account.clone(), self.balance, root)
    }
}

impl<D: Digest> Write for BalanceProof<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.balance.write(buf);
        self.proof.write(buf);
    }
}

impl<D: Digest> EncodeSize for BalanceProof<D> {
    fn encode_size(&self) -> usize {
        NonZeroU64::SIZE + self.proof.encode_size()
    }
}

impl<D: Digest> Read for BalanceProof<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            balance: NonZeroU64::read(buf)?,
            proof: KeyValueProof::read_cfg(buf, &MAX_PROOF_DIGESTS_PER_ELEMENT)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<D: Digest> arbitrary::Arbitrary<'_> for BalanceProof<D>
where
    KeyValueProof<mmb::Family, D, CHUNK>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            balance: u.arbitrary()?,
            proof: u.arbitrary()?,
        })
    }
}

/// Configuration for a [Validator].
#[derive(Clone)]
pub struct Config<O: PublicKey, T: Translator, S: Strategy> {
    /// The deployment's signature namespaces.
    pub namespace: Namespace,
    /// The operator's public key.
    pub operator: O,
    /// The balances database. Its strategy also parallelizes signature checks.
    pub balances: fixed::Config<T, S>,
}

/// A posted close as a validator needs it to resume after a restart.
#[derive(Clone, Debug)]
pub struct Checkpoint<P: PublicKey, D: Digest> {
    /// The close's summary.
    pub summary: Summary<D>,
    /// The close's payment matrix.
    pub matrix: Matrix<P, D>,
}

impl<P: PublicKey, D: Digest> Checkpoint<P, D> {
    /// Rebuilds the checkpoint of the posted close `close` with summary `summary`.
    ///
    /// Returns an error if the close does not settle the matrix the summary commits to.
    pub fn new<H: Hasher<Digest = D>, O: PublicKey>(
        summary: Summary<D>,
        close: &Close<P, O>,
    ) -> Result<Self, Error> {
        let matrix = close.matrix::<H>();
        if close.epoch() != summary.epoch || matrix.root() != summary.matrix {
            return Err(Error::InvalidCheckpoint);
        }
        Ok(Self { summary, matrix })
    }
}

/// A checked close with its summary, payment matrix, payouts, and balance writes.
pub struct Proposal<P: PublicKey, H: Hasher, S: Strategy> {
    summary: Summary<H::Digest>,
    matrix: Matrix<P, H::Digest>,
    payouts: Amounts<P>,
    batch: Arc<Batch<P, H::Digest, S>>,
}

impl<P: PublicKey, H: Hasher, S: Strategy> Proposal<P, H, S> {
    /// Returns the summary to certify.
    pub const fn summary(&self) -> &Summary<H::Digest> {
        &self.summary
    }

    /// Returns the payment matrix the close settles.
    pub const fn matrix(&self) -> &Matrix<P, H::Digest> {
        &self.matrix
    }

    /// Returns the payouts the ledger makes when it posts the close.
    pub const fn payouts(&self) -> &Amounts<P> {
        &self.payouts
    }

    /// Returns the checkpoint a validator resumes from after applying the close.
    pub fn checkpoint(&self) -> Checkpoint<P, H::Digest> {
        Checkpoint {
            summary: self.summary,
            matrix: self.matrix.clone(),
        }
    }

    /// Signs the summary with `scheme`, or returns `None` if the scheme cannot sign.
    pub fn sign<C: Scheme<H::Digest>>(&self, scheme: &C) -> Option<Attestation<C>> {
        scheme.sign::<H::Digest>(&self.summary)
    }
}

/// Checks closes against the finalized balances and certifies their effects.
///
/// A validator keeps the balances as of the last posted close in QMDB, and that close's payment
/// matrix. [Validator::verify] checks a close and computes its effects without changing any
/// state, so a validator can check several candidate closes for the same epoch. Once the ledger
/// posts one of them, [Validator::apply] commits its effects.
///
/// Every honest validator must apply exactly the posted closes, in order, starting from an empty
/// database, because the balances root depends on the database's whole history. The balances
/// database stores its activity bitmap in 32-byte chunks, so the size of `H`'s digests must
/// divide 32.
///
/// A validator that certifies a close must keep it available. Receivers open the matrix of every
/// posted close to check their receipts, and validators that did not check the posted close need
/// it to apply it.
pub struct Validator<E, P, O, H, T, S>
where
    E: Context + Spawner,
    P: PublicKey,
    O: PublicKey,
    H: Hasher,
    T: Translator,
    S: Strategy,
{
    balances: Balances<E, P, H, T, S>,
    namespace: Namespace,
    operator: O,
    strategy: S,
    summary: Summary<H::Digest>,
    matrix: Matrix<P, H::Digest>,
}

impl<E, P, O, H, T, S> Validator<E, P, O, H, T, S>
where
    E: Context + Spawner,
    P: PublicKey,
    O: PublicKey,
    H: Hasher,
    T: Translator,
    S: Strategy,
{
    /// Opens the validator's balances.
    ///
    /// A new database starts before the first close. A database that has applied a close resumes
    /// from that close's checkpoint, and `checkpoints` must include it. Passing the checkpoints
    /// of the last close the application knows the database applied and of the close it was
    /// applying covers a crash in between.
    ///
    /// Returns an error if no checkpoint matches the database.
    pub async fn init(
        context: E,
        config: Config<O, T, S>,
        checkpoints: Vec<Checkpoint<P, H::Digest>>,
    ) -> Result<Self, Error> {
        let strategy = config.balances.merkle.strategy.clone();
        let balances = Balances::init(context, config.balances, None).await?;
        let applied = balances.get_metadata().await?.map_or(0, NonZeroU64::get);
        let root = balances.root();
        let checkpoint = checkpoints
            .into_iter()
            .find(|checkpoint| checkpoint.summary.epoch == applied)
            .or_else(|| {
                (applied == 0).then(|| Checkpoint {
                    summary: Summary::genesis::<H>(root),
                    matrix: Matrix::empty::<H>(),
                })
            })
            .filter(|checkpoint| {
                checkpoint.summary.balances == root
                    && checkpoint.summary.matrix == checkpoint.matrix.root()
            })
            .ok_or(Error::InvalidCheckpoint)?;
        Ok(Self {
            balances,
            namespace: config.namespace,
            operator: config.operator,
            strategy,
            summary: checkpoint.summary,
            matrix: checkpoint.matrix,
        })
    }

    /// Returns the summary of the last close applied.
    pub const fn summary(&self) -> &Summary<H::Digest> {
        &self.summary
    }

    /// Returns the payment matrix of the last close applied.
    pub const fn matrix(&self) -> &Matrix<P, H::Digest> {
        &self.matrix
    }

    /// Returns `account`'s balance as of the last close applied.
    pub async fn balance(&self, account: &P) -> Result<u64, Error> {
        Ok(self.balances.get(account).await?.map_or(0, NonZeroU64::get))
    }

    /// Proves `account`'s balance as of the last close applied, or returns `None` if it is zero.
    pub async fn prove(&self, account: &P) -> Result<Option<BalanceProof<H::Digest>>, Error> {
        match self.balances.key_value_proof(account).await {
            Ok((proof, balance)) => Ok(Some(BalanceProof { balance, proof })),
            Err(qmdb::Error::KeyNotFound) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// Checks the close of the epoch after the last close applied and computes its effects.
    ///
    /// `queue` holds the ledger's queues while it expects this close. Checking changes no state.
    ///
    /// The close is valid if:
    /// - It is for that epoch and processes at least the queued requests it must and no more than
    ///   are queued.
    /// - The operator signed it.
    /// - Every row's sender signed its state for the epoch on top of the payment map the last
    ///   close settled for it.
    /// - Every soft withdrawal is for the epoch and signed by its account.
    /// - No balance goes negative.
    ///
    /// Returns the proposal to certify.
    pub async fn verify(
        &self,
        close: Close<P, O>,
        queue: &Queue<P>,
    ) -> Result<Proposal<P, H, S>, Error> {
        let epoch = self.summary.epoch.checked_add(1).ok_or(Error::Overflow)?;
        let Close {
            epoch: closed,
            rows,
            withdrawals,
            deposits,
            forced_withdrawals,
            signature,
        } = close;
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
        let (rows, signatures): (Vec<_>, Vec<_>) = self
            .strategy
            .map_collect_vec(rows, |row| {
                let root = row.payments.root::<H>();
                ((row.account, row.payments, root), row.signature)
            })
            .into_iter()
            .unzip();
        let matrix = Matrix::from_sorted::<H>(rows);
        let message = Close::<P, O>::message(
            epoch,
            &matrix.root(),
            &withdrawals,
            deposits,
            forced_withdrawals,
        );
        if !self
            .operator
            .verify(&self.namespace.close, &message, &signature)
        {
            return Err(Error::InvalidOperatorSignature);
        }

        // Each sender must have signed exactly its row's payment map on top of the map the last
        // close settled for it, and each account its soft withdrawal.
        let empty = Amounts::<P>::empty().root::<H>();
        self.strategy.try_map_collect_vec(
            zip_eq(matrix.rows(), &signatures),
            |((account, payments), signature)| {
                let state = State {
                    epoch,
                    account: account.clone(),
                    payments: *payments,
                    previous: self.matrix.payments_root(account).unwrap_or(empty),
                };
                state
                    .verify(&self.namespace, signature)
                    .then_some(())
                    .ok_or(Error::InvalidSignature)
            },
        )?;
        self.strategy
            .try_map_collect_vec(&withdrawals, |withdrawal| {
                withdrawal
                    .verify(&self.namespace)
                    .then_some(())
                    .ok_or(Error::InvalidSignature)
            })?;

        // Settle on top of the balances of every account the close touches.
        let flows = Flows::new(
            matrix.iter(),
            &withdrawals,
            queued_deposits,
            queued_forced_withdrawals,
        )?;
        let accounts: Vec<&P> = flows.accounts().collect();
        let balances = self.balances.get_many(&accounts).await?;
        drop(accounts);
        let settlement = flows.settle(
            balances
                .into_iter()
                .map(|balance| balance.map_or(0, NonZeroU64::get)),
        )?;

        // Every validator writes the same balances with the same metadata, so they all derive the
        // same root.
        let mut batch = self
            .balances
            .new_batch()
            .with_metadata(NonZeroU64::new(epoch));
        for (account, balance) in settlement.balances {
            batch = batch.write(account, NonZeroU64::new(balance));
        }
        let batch = batch.merkleize(&self.balances).await?;
        let summary = Summary {
            epoch,
            parent: self.summary.digest::<H>(),
            matrix: matrix.root(),
            balances: batch.root(),
            payouts: settlement.payouts.root::<H>(),
            deposits,
            forced_withdrawals,
        };
        Ok(Proposal {
            summary,
            matrix,
            payouts: settlement.payouts,
            batch,
        })
    }

    /// Commits the effects of the posted close `proposal` checked.
    ///
    /// The application must persist the posted close before applying it, and must apply only the
    /// proposal whose summary the ledger posted. Any error destroys the validator.
    pub async fn apply(self, proposal: Proposal<P, H, S>) -> Result<Self, Error> {
        if proposal.summary.parent != self.summary.digest::<H>() {
            return Err(Error::StaleProposal);
        }
        let Self {
            balances,
            namespace,
            operator,
            strategy,
            ..
        } = self;
        let balances = balances.apply_batch(proposal.batch).await?;
        let balances = balances.commit().await?;
        let boundary = balances.sync_boundary();
        let balances = balances.prune(boundary).await?;
        Ok(Self {
            balances,
            namespace,
            operator,
            strategy,
            summary: proposal.summary,
            matrix: proposal.matrix,
        })
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::super::*;
        use commonware_codec::conformance::CodecConformance;
        use commonware_cryptography::sha256::Digest;

        commonware_conformance::conformance_tests! {
            CodecConformance<BalanceProof<Digest>>,
        }
    }
}
