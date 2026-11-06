//! A reference validator that checks closes, applies the posted ones to its balances and payout
//! log, and serves the closes it attested and the payouts they owe.

use bytes::Bytes;
use commonware_clearing::bajillion::{
    Amount, BalanceProof, Balances, Checkpoint, Close, Deposit, Epoch, Error, ForcedWithdrawal,
    Limits, Matrix, Namespace, Opening, PayoutLog, PayoutProof, Proposal, Queue, Summary,
};
use commonware_codec::{Decode as _, DecodeExt as _, Encode as _, RangeCfg, Write as _};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_parallel::Strategy;
use commonware_runtime::Spawner;
use commonware_storage::{
    Context,
    index::unordered::Index,
    merkle::{Location, mmb},
    qmdb::{self, current::unordered::fixed, keyless},
    translator::Translator,
};
use commonware_utils::NZU64;
use std::{cmp::Ordering, collections::HashMap};

/// The balances database over the plain unordered index.
type Database<E, P, H, T, S, A> = Balances<E, P, H, Index<T, Location<mmb::Family>>, S, A>;

/// Configuration of a [Validator].
#[derive(Clone)]
pub struct Config<O: PublicKey, T: Translator, S: Strategy> {
    pub namespace: Namespace,
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
#[derive(Clone, Debug)]
struct Record {
    close: Bytes,
    deposits: Bytes,
    forced_withdrawals: Bytes,
    summary: Bytes,
}

/// What a validator persists besides its databases. It holds every close the validator attested, by
/// the digest of its summary, written before the attestation is released (V4).
///
/// A restart recovers from it and the ledger's last posted digest alone, and the validator serves
/// earlier posted closes from it (V6).
#[derive(Clone, Debug)]
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

/// Encodes queued requests as a validator persists them.
fn encode<T: commonware_codec::Write>(requests: &[T]) -> Bytes {
    let mut encoded = Vec::new();
    requests.write(&mut encoded);
    Bytes::from(encoded)
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
    context: E,
    config: Config<O, T, S>,
    opened: u64,

    /// Absent once a storage failure left the databases unusable until a restart.
    balances: Option<Database<E, P, H, T, S, A>>,
    log: Option<PayoutLog<E, P, H, S, A>>,

    persisted: Persisted<H::Digest>,
    parent: Checkpoint<P, H::Digest, A>,
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
    async fn database(
        context: &E,
        config: &Config<O, T, S>,
        opened: u64,
    ) -> Result<Database<E, P, H, T, S, A>, Error> {
        let context = context.child("balances").with_attribute("opened", opened);
        Ok(Database::init(context, config.balances.clone(), None).await?)
    }

    /// Opens the payout log at the close of `summary` (V2). The log is durable before the balances
    /// change, so it is at or past the close the balances hold, and the bounded reopen discards
    /// any later close.
    ///
    /// Returns InvalidCheckpoint unless the log then has `summary`'s payouts root.
    async fn log(
        context: &E,
        config: &Config<O, T, S>,
        opened: u64,
        summary: &Summary<H::Digest, A>,
    ) -> Result<PayoutLog<E, P, H, S, A>, Error> {
        let context = context.child("payouts").with_attribute("opened", opened);
        let size = Some(Location::new(summary.payouts.size));
        let log = PayoutLog::init(context, config.payouts.clone(), size).await?;
        if log.root() != summary.payouts.root {
            return Err(Error::InvalidCheckpoint);
        }
        Ok(log)
    }

    /// Opens the databases and resumes from what the validator persisted (V2). `posted` is the
    /// digest of the ledger's last post, or `None` before the first.
    ///
    /// The validator walks the persisted summaries back from `posted` along their parents, and
    /// resumes from the first one with the balances database's root. A close that did not post is
    /// off that chain, so it is never chosen even when it shares the root. A balances database with
    /// no commit metadata has applied no close and starts from genesis. The payout log then reopens
    /// at that summary's payouts size.
    pub async fn init(
        context: E,
        config: Config<O, T, S>,
        persisted: Persisted<H::Digest>,
        posted: Option<&H::Digest>,
    ) -> Result<Self, Error> {
        let balances = Self::database(&context, &config, 0).await?;
        let applied = balances.get_metadata().await?.is_some();
        let root = balances.root();
        let mut parent = None;
        let mut digest = posted.copied();
        while let Some(record) = digest.and_then(|digest| persisted.attested.get(&digest)) {
            let summary = Self::summary_of(record);
            if summary.balances == root {
                let matrix = Self::close_of(&config, record).matrix::<H>();
                parent = Some(Checkpoint { summary, matrix });
                break;
            }
            digest = Some(summary.parent);
        }
        let parent = parent
            .or_else(|| {
                (!applied).then(|| Checkpoint {
                    summary: Summary::genesis::<H, P>(root),
                    matrix: Matrix::empty::<H>(),
                })
            })
            .ok_or(Error::InvalidCheckpoint)?;
        let log = Self::log(&context, &config, 0, &parent.summary).await?;
        Ok(Self {
            context,
            config,
            opened: 0,
            balances: Some(balances),
            log: Some(log),
            persisted,
            parent,
        })
    }

    fn summary_of(record: &Record) -> Summary<H::Digest, A> {
        Summary::decode(record.summary.clone()).expect("a persisted summary must decode")
    }

    fn close_of(config: &Config<O, T, S>, record: &Record) -> Close<P, O, A> {
        Close::decode_cfg(record.close.clone(), &config.limits)
            .expect("a persisted close must decode with the validator's limits")
    }

    const fn balances(&self) -> &Database<E, P, H, T, S, A> {
        self.balances
            .as_ref()
            .expect("a validator whose storage failed must restart")
    }

    const fn payout_log(&self) -> &PayoutLog<E, P, H, S, A> {
        self.log
            .as_ref()
            .expect("a validator whose storage failed must restart")
    }

    /// Returns what the validator persisted besides its databases.
    pub const fn persisted(&self) -> &Persisted<H::Digest> {
        &self.persisted
    }

    /// Returns the summary of the last close applied.
    pub const fn summary(&self) -> &Summary<H::Digest, A> {
        &self.parent.summary
    }

    /// Returns the matrix of the last close applied.
    pub const fn matrix(&self) -> &Matrix<P, H::Digest, A> {
        &self.parent.matrix
    }

    /// Returns the balance of `account` as of the last close applied.
    pub async fn balance(&self, account: &P) -> Result<A, Error> {
        Ok(self.balances().get(account).await?.unwrap_or(A::ZERO))
    }

    /// Proves the balance of `account` as of the last close applied, or returns `None` if it is
    /// zero.
    pub async fn prove(&self, account: &P) -> Result<Option<BalanceProof<H::Digest, A>>, Error> {
        match self.balances().key_value_proof(account).await {
            Ok((proof, balance)) => Ok(Some(BalanceProof { balance, proof })),
            Err(qmdb::Error::KeyNotFound) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// Returns the persisted record of the posted close of `epoch`, at or before the last close
    /// applied.
    fn record(&self, epoch: Epoch) -> Option<&Record> {
        let mut digest = self.parent.summary.digest::<H>();
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
        let matrix = Self::close_of(&self.config, record).matrix::<H>();
        Some(matrix.open(sender, receiver))
    }

    /// Proves the payout the posted close of `epoch` owes `account` under the payouts root of the
    /// last close applied, or returns `None` if no applied close of `epoch` owes it one (V6).
    ///
    /// The close's payouts sit in account order from its parent's payouts size up to its commit, so
    /// a binary search over them finds the account's.
    pub async fn prove_payout(
        &self,
        epoch: Epoch,
        account: &P,
    ) -> Result<Option<PayoutProof<P, H::Digest, A>>, Error> {
        let Some(record) = self.record(epoch) else {
            return Ok(None);
        };
        let summary = Self::summary_of(record);
        let start = match self.persisted.attested.get(&summary.parent) {
            Some(parent) => Self::summary_of(parent).payouts.size,
            None if epoch == 1 => {
                Summary::<H::Digest, A>::genesis::<H, P>(H::Digest::EMPTY)
                    .payouts
                    .size
            }
            None => return Err(Error::InvalidCheckpoint),
        };
        let log = self.payout_log();
        let (mut low, mut high) = (start, summary.payouts.size - 1);
        while low < high {
            let index = low + (high - low) / 2;
            let payout = log
                .get(Location::new(index))
                .await?
                .expect("a close's payouts must precede its commit");
            match payout.account.cmp(account) {
                Ordering::Less => low = index + 1,
                Ordering::Greater => high = index,
                Ordering::Equal => {
                    let (proof, _) = log.proof(Location::new(index), NZU64!(1)).await?;
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
    pub async fn verify(
        &mut self,
        close: Close<P, O, A>,
        queue: &Queue<P, A>,
    ) -> Result<Proposal<P, H, S, A>, Error> {
        let encoded = close.encode();
        let counts = (close.deposits(), close.forced_withdrawals());
        let checked = close.check::<H, S>(
            &self.config.namespace,
            &self.config.operator,
            &self.config.balances.merkle.strategy,
            &self.parent,
            queue,
        )?;
        let proposal = checked.settle(self.balances(), self.payout_log()).await?;
        let (deposits, forced_withdrawals) = queue.prefix(counts.0, counts.1)?;
        let record = Record {
            close: encoded,
            deposits: encode(deposits),
            forced_withdrawals: encode(forced_withdrawals),
            summary: proposal.summary().encode(),
        };
        self.persisted
            .attested
            .insert(proposal.summary().digest::<H>(), record);
        Ok(proposal)
    }

    /// Applies the proposal of the posted close whose summary has digest `posted` to both
    /// databases, and makes it durable (V5).
    ///
    /// A refusal leaves both databases at the last close, reopened. A storage failure while
    /// applying the close or making it durable leaves the validator unusable until it restarts.
    pub async fn apply(
        &mut self,
        proposal: Proposal<P, H, S, A>,
        posted: &H::Digest,
    ) -> Result<(), Error> {
        let (Some(balances), Some(log)) = (self.balances.take(), self.log.take()) else {
            panic!("a validator whose storage failed must restart");
        };
        let (balances, log, checkpoint) = match proposal.apply(balances, log, posted).await {
            Ok(applied) => applied,
            Err(error) => {
                // A refusal touches neither database. After a storage failure the balances may
                // hold either close, so only a restart realigns the log with them (V2).
                if matches!(error, Error::InvalidCheckpoint) {
                    self.opened += 1;
                    let (context, config) = (&self.context, &self.config);
                    self.balances = Some(Self::database(context, config, self.opened).await?);
                    let log = Self::log(context, config, self.opened, &self.parent.summary).await?;
                    self.log = Some(log);
                }
                return Err(error);
            }
        };
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
    /// Returns InvalidCheckpoint if a posted close in between was not persisted.
    pub async fn catch_up(&mut self, posted: &H::Digest) -> Result<usize, Error> {
        let applied = self.parent.summary.digest::<H>();
        let mut missing = Vec::new();
        let mut digest = *posted;
        while digest != applied {
            let record = self
                .persisted
                .attested
                .get(&digest)
                .ok_or(Error::InvalidCheckpoint)?;
            let summary = Self::summary_of(record);
            if summary.epoch <= self.parent.summary.epoch {
                return Err(Error::InvalidCheckpoint);
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
                return Err(Error::InvalidCheckpoint);
            }
            self.apply(proposal, &digest).await?;
        }
        Ok(count)
    }
}
