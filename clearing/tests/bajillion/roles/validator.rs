//! A reference validator that checks closes, applies the posted ones to its balances and payout
//! log, and serves the closes it attested and the payouts they owe.

use bytes::Bytes;
use commonware_clearing::bajillion::{
    Amount, ApplyError, BalanceProof, Balances, CheckError, Checkpoint, Close, Deposit, Epoch,
    ForcedWithdrawal, Limits, Matrix, Namespace, Opening, PayoutProof, Payouts, Proposal, Queue,
    SettleError, Summary,
};
use commonware_codec::{Decode as _, DecodeExt as _, Encode as _, RangeCfg};
use commonware_cryptography::{Digest, Digestible, Hasher, PublicKey};
use commonware_parallel::Strategy;
use commonware_runtime::Spawner;
use commonware_storage::{
    Context,
    index::unordered::Index,
    merkle::{Location, mmb, mmr},
    qmdb::{self, current::unordered::fixed, keyless},
    translator::Translator,
};
use commonware_utils::NZU64;
use std::{cmp::Ordering, collections::HashMap};

/// Why the validator refused a close, a restart, or a proof.
#[derive(Debug, thiserror::Error)]
pub enum Refusal {
    /// The databases and the persisted records do not agree on a posted close.
    #[error("the databases and the records do not agree on a posted close")]
    InvalidCheckpoint,
    /// The close fails its check.
    #[error(transparent)]
    Check(#[from] CheckError),
    /// The close does not settle.
    #[error(transparent)]
    Settle(#[from] SettleError),
    /// The proposal does not apply.
    #[error(transparent)]
    Apply(#[from] ApplyError),
    /// The balances database failed.
    #[error("balances: {0}")]
    Balances(#[from] qmdb::Error<mmb::Family>),
    /// The payout log failed.
    #[error("payout log: {0}")]
    Log(#[from] qmdb::Error<mmr::Family>),
}

/// The balances database over the plain unordered index.
type Database<E, P, H, T, S, A> = Balances<E, P, H, Index<T, Location<mmb::Family>>, S, A>;

/// Configuration of a [Validator].
#[derive(Clone)]
pub struct Config<O: PublicKey, T: Translator, S: Strategy> {
    /// Signature namespaces of the deployment.
    pub namespace: Namespace,
    /// Key the operator signs closes with.
    pub operator: O,
    /// Limits the validator decodes closes with (V7).
    pub limits: Limits,
    /// Configuration of the balances database. Its strategy also parallelizes checking.
    pub balances: fixed::Config<T, S>,
    /// Configuration of the payout log.
    pub payouts: keyless::fixed::Config<S>,
}

/// A close the validator attested, with the deposits and forced withdrawals it processes and its
/// summary, each in its encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Record {
    close: Bytes,
    deposits: Bytes,
    forced_withdrawals: Bytes,
    summary: Bytes,
}

/// What a validator persists besides its databases. It holds every close the validator attested, by
/// the digest of its summary, written before the attestation is released (V4).
///
/// With the ledger's last posted digest, it suffices to recover after a restart and to serve
/// earlier posted closes (V6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Persisted<D: Digest> {
    attested: HashMap<D, Record>,
}

impl<D: Digest> Default for Persisted<D> {
    fn default() -> Self {
        Self {
            attested: HashMap::new(),
        }
    }
}

/// A validator holding the balances database, the payout log, what it persisted, and the checkpoint
/// of the last close it applied.
pub struct Validator<E, P, O, H, T, S, A>
where
    E: Context + Spawner,
    P: PublicKey,
    O: PublicKey,
    H: Hasher,
    T: Translator,
    S: Strategy,
    A: Amount,
{
    /// Configuration the validator opened with.
    config: Config<O, T, S>,
    /// Balances database, absent once a failed apply left it unusable until a restart.
    balances: Option<Database<E, P, H, T, S, A>>,
    /// Payout log, absent once a failed apply left it unusable until a restart.
    log: Option<Payouts<E, P, H, S, A>>,
    /// Closes the validator attested (V4).
    persisted: Persisted<H::Digest>,
    /// Checkpoint of the last close applied.
    parent: Checkpoint<P, H, A>,
}

impl<E, P, O, H, T, S, A> Validator<E, P, O, H, T, S, A>
where
    E: Context + Spawner,
    P: PublicKey,
    O: PublicKey,
    H: Hasher,
    T: Translator,
    S: Strategy,
    A: Amount,
{
    /// Opens the payout log at `summary`'s payouts size (V2). The log is durable before the
    /// balances change, so it is at or past the close the balances hold, and the bounded reopen
    /// discards any later close.
    ///
    /// Returns [Refusal::InvalidCheckpoint] unless the log then has `summary`'s payouts root.
    async fn log(
        context: &E,
        config: &Config<O, T, S>,
        summary: &Summary<H>,
    ) -> Result<Payouts<E, P, H, S, A>, Refusal> {
        let size = Some(summary.payouts.size);
        let log = Payouts::init(context.child("payouts"), config.payouts.clone(), size).await?;
        if log.root() != summary.payouts.root {
            return Err(Refusal::InvalidCheckpoint);
        }
        Ok(log)
    }

    /// Opens the databases and resumes from what the validator persisted (V2). `posted` is the
    /// digest of the ledger's last post, or `None` before the first.
    ///
    /// It resumes from the persisted summary on the chain ending at `posted` whose balances root
    /// the database holds, or from genesis if the database has applied no close. A close that did
    /// not post is off that chain, so it is never chosen even when it shares the root.
    pub async fn init(
        context: E,
        config: Config<O, T, S>,
        persisted: Persisted<H::Digest>,
        posted: Option<&H::Digest>,
    ) -> Result<Self, Refusal> {
        let balances: Database<E, P, H, T, S, A> =
            Database::init(context.child("balances"), config.balances.clone(), None).await?;
        let applied = balances.get_metadata().await?.is_some();
        let root = balances.root();

        // Walk the persisted summaries back from the last post to the first whose balances root
        // the database holds.
        let mut parent = None;
        let mut digest = posted.copied();
        while let Some(record) = digest.and_then(|digest| persisted.attested.get(&digest)) {
            let summary = Self::summary_of(record);
            if summary.balances == root {
                let matrix =
                    Self::close_of(&config, record).matrix::<H>(&config.balances.merkle.strategy);
                parent = Some(Checkpoint { summary, matrix });
                break;
            }
            digest = Some(summary.parent);
        }

        // Only a database that applied no close falls back to genesis, and the payout log reopens
        // at the chosen summary's payouts size.
        let parent = parent
            .or_else(|| {
                (!applied).then(|| Checkpoint {
                    summary: Summary::<H>::genesis::<P, A>(root),
                    matrix: Matrix::empty(),
                })
            })
            .ok_or(Refusal::InvalidCheckpoint)?;
        let log = Self::log(&context, &config, &parent.summary).await?;
        Ok(Self {
            config,
            balances: Some(balances),
            log: Some(log),
            persisted,
            parent,
        })
    }

    /// Decodes the summary of `record`.
    fn summary_of(record: &Record) -> Summary<H> {
        Summary::decode(record.summary.clone()).expect("a persisted summary must decode")
    }

    /// Decodes the close of `record` with the validator's limits.
    fn close_of(config: &Config<O, T, S>, record: &Record) -> Close<P, O, A> {
        Close::decode_cfg(record.close.clone(), &config.limits)
            .expect("a persisted close must decode with the validator's limits")
    }

    /// Returns the balances database.
    const fn balances(&self) -> &Database<E, P, H, T, S, A> {
        self.balances
            .as_ref()
            .expect("a validator must restart after a failed apply")
    }

    /// Returns the payout log.
    const fn payout_log(&self) -> &Payouts<E, P, H, S, A> {
        self.log
            .as_ref()
            .expect("a validator must restart after a failed apply")
    }

    /// Returns what the validator persisted besides its databases.
    pub const fn persisted(&self) -> &Persisted<H::Digest> {
        &self.persisted
    }

    /// Returns the summary of the last close applied.
    pub const fn summary(&self) -> &Summary<H> {
        &self.parent.summary
    }

    /// Returns the matrix of the last close applied.
    pub const fn matrix(&self) -> &Matrix<P, H, A> {
        &self.parent.matrix
    }

    /// Returns the balance of `account` as of the last close applied.
    pub async fn balance(&self, account: &P) -> Result<A, Refusal> {
        Ok(self.balances().get(account).await?.unwrap_or(A::ZERO))
    }

    /// Proves the balance of `account` as of the last close applied, or returns `None` if it is
    /// zero.
    pub async fn prove(&self, account: &P) -> Result<Option<BalanceProof<H::Digest, A>>, Refusal> {
        match self.balances().key_value_proof(account).await {
            Ok((proof, balance)) => Ok(Some(BalanceProof { balance, proof })),
            Err(qmdb::Error::KeyNotFound) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// Returns the persisted record of the posted close of `epoch`, at or before the last close
    /// applied.
    fn record(&self, epoch: Epoch) -> Option<&Record> {
        let mut digest = self.parent.summary.digest();
        while let Some(record) = self.persisted.attested.get(&digest) {
            let summary = Self::summary_of(record);
            if summary.epoch == epoch {
                return Some(record);
            }
            digest = summary.parent;
        }
        None
    }

    /// Opens what `sender` paid `receiver` in the posted close of `epoch`, at or before the last
    /// close applied, from the close the validator persisted (V6).
    pub fn open(&self, epoch: Epoch, sender: &P, receiver: &P) -> Option<Opening<P, H::Digest, A>> {
        let record = self.record(epoch)?;
        let matrix =
            Self::close_of(&self.config, record).matrix::<H>(&self.config.balances.merkle.strategy);
        Some(matrix.open(sender, receiver))
    }

    /// Proves the payout the posted close of `epoch` owes `account` under the payouts root of the
    /// last close applied, or returns `None` if no applied close of `epoch` owes it one (V6). A
    /// withdrawal names the epoch of [Self::summary]. The ledger keeps that epoch's payouts root
    /// after later posts.
    ///
    /// The close's payouts sit in account order from its parent's payouts size up to its commit, so
    /// a binary search over them finds the account's.
    pub async fn prove_payout(
        &self,
        epoch: Epoch,
        account: &P,
    ) -> Result<Option<PayoutProof<P, H::Digest, A>>, Refusal> {
        let Some(record) = self.record(epoch) else {
            return Ok(None);
        };
        let summary = Self::summary_of(record);

        // The close's payouts start at its parent's payouts size. The parent of epoch 1 is the
        // genesis summary.
        let start = match self.persisted.attested.get(&summary.parent) {
            Some(parent) => Self::summary_of(parent).payouts.size,
            None if epoch == 1 => Summary::<H>::genesis::<P, A>(H::Digest::EMPTY).payouts.size,
            None => return Err(Refusal::InvalidCheckpoint),
        };
        let log = self.payout_log();
        let (mut low, mut high) = (start, summary.payouts.size - 1);
        while low < high {
            let index = low + (*high - *low) / 2;
            let payout = log
                .get(index)
                .await?
                .expect("a close's payouts must precede its commit");
            match payout.account.cmp(account) {
                Ordering::Less => low = index + 1,
                Ordering::Greater => high = index,
                Ordering::Equal => {
                    let (proof, _) = log.proof(index, NZU64!(1)).await?;
                    return Ok(Some(PayoutProof {
                        index,
                        payout,
                        proof,
                    }));
                }
            }
        }
        Ok(None)
    }

    /// Checks the close of the epoch after the last close applied while the ledger's queues are
    /// `queue` (V3), and settles it on the balances. Before returning the proposal whose summary
    /// it attests (V1), it persists the close, the requests it processes, and the summary (V4).
    /// Checking and settling depend only on the close, the checkpoint, and the queues, so asking
    /// again for a close already persisted yields the same proposal and writes nothing.
    pub async fn verify(
        &mut self,
        close: Close<P, O, A>,
        queue: &Queue<P, A>,
    ) -> Result<Proposal<P, H, S, A>, Refusal> {
        let encoded = close.encode();
        let (deposited, forced) = (close.deposits(), close.forced_withdrawals());
        let checked = close.check::<H>(
            &self.config.namespace,
            &self.config.operator,
            &self.parent,
            queue,
            &self.config.balances.merkle.strategy,
        )?;
        let proposal = checked.settle(self.balances(), self.payout_log()).await?;

        // The close, the requests it processes, and its summary are persisted before the
        // attestation is released (V4).
        let (deposits, forced_withdrawals) = queue
            .prefix(deposited, forced)
            .expect("a checked close must process a prefix of its queue");
        let record = Record {
            close: encoded,
            deposits: deposits.encode(),
            forced_withdrawals: forced_withdrawals.encode(),
            summary: proposal.summary().encode(),
        };
        self.persisted
            .attested
            .entry(proposal.summary().digest())
            .or_insert(record);
        Ok(proposal)
    }

    /// Applies the proposal of the posted close whose summary has digest `posted` to both
    /// databases, and makes it durable (V5).
    ///
    /// Any error leaves the validator unusable until it restarts (V2).
    pub async fn apply(
        &mut self,
        proposal: Proposal<P, H, S, A>,
        posted: &H::Digest,
    ) -> Result<(), Refusal> {
        let (Some(balances), Some(log)) = (self.balances.take(), self.log.take()) else {
            panic!("a validator must restart after a failed apply");
        };
        let (balances, log, checkpoint) = proposal.apply(balances, log, posted).await?;

        // The log is durable once the close applies, so committing the balances makes the close
        // durable. The balances then prune their history up to the sync boundary.
        let balances = balances.commit().await?;
        let boundary = balances.sync_boundary();
        self.balances = Some(balances.prune(boundary).await?);
        self.log = Some(log);
        self.parent = checkpoint;
        Ok(())
    }

    /// Applies every posted close after the last one applied, up to the ledger's last post
    /// `posted`, from the persisted closes and the requests they process alone (V4, V5). Returns
    /// how many it applied.
    ///
    /// Returns [Refusal::InvalidCheckpoint] if a posted close in between was not persisted.
    pub async fn catch_up(&mut self, posted: &H::Digest) -> Result<usize, Refusal> {
        // Collect the persisted closes from the ledger's last post back to the last close applied.
        let applied = self.parent.summary.digest();
        let mut missing = Vec::new();
        let mut digest = *posted;
        while digest != applied {
            let record = self
                .persisted
                .attested
                .get(&digest)
                .ok_or(Refusal::InvalidCheckpoint)?;
            let summary = Self::summary_of(record);
            if summary.epoch <= self.parent.summary.epoch {
                return Err(Refusal::InvalidCheckpoint);
            }
            missing.push((digest, record.clone()));
            digest = summary.parent;
        }

        // A queue holding exactly the persisted prefix, each required count equal to its length,
        // checks a posted close as the ledger's queues did.
        let count = missing.len();
        for (digest, record) in missing.into_iter().rev() {
            let summary = Self::summary_of(&record);
            let deposits =
                Vec::<Deposit<P, A>>::decode_cfg(record.deposits.clone(), &(RangeCfg::new(..), ()))
                    .expect("persisted deposits must decode");
            let forced_withdrawals = Vec::<ForcedWithdrawal<P, A>>::decode_cfg(
                record.forced_withdrawals.clone(),
                &(RangeCfg::new(..), ()),
            )
            .expect("persisted forced withdrawals must decode");
            let queue = Queue {
                epoch: summary.epoch,
                required_deposits: deposits.len(),
                deposits,
                required_forced_withdrawals: forced_withdrawals.len(),
                forced_withdrawals,
            };
            let close = Self::close_of(&self.config, &record);
            let proposal = self.verify(close, &queue).await?;
            if proposal.summary() != &summary {
                return Err(Refusal::InvalidCheckpoint);
            }
            self.apply(proposal, &digest).await?;
        }
        Ok(count)
    }
}
