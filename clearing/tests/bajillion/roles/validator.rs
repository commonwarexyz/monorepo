//! A reference validator that checks closes, applies the posted ones to its balances, and serves
//! the closes it attested.

use bytes::Bytes;
use commonware_clearing::bajillion::{
    Amount, BalanceProof, Balances, Checkpoint, Close, Deposit, Epoch, Error, ForcedWithdrawal,
    Limits, Matrix, Namespace, Opening, Proposal, Queue, Summary,
};
use commonware_codec::{Decode as _, DecodeExt as _, Encode as _, RangeCfg, Write as _};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_parallel::Strategy;
use commonware_runtime::Spawner;
use commonware_storage::{
    Context,
    index::unordered::Index,
    merkle::{Location, mmb},
    qmdb::{self, current::unordered::fixed},
    translator::Translator,
};
use std::collections::HashMap;

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

/// What a validator persists besides its balances database. It holds every close the validator
/// attested, by the digest of its summary, written before the attestation is released (V4).
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

/// A validator holding the balances database, what it persisted, and the checkpoint of the last
/// close it applied.
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

    /// Absent once a storage failure left the database unusable until a restart.
    balances: Option<Database<E, P, H, T, S, A>>,

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

    /// Opens the balances database and resumes from what the validator persisted (V2). `posted`
    /// is the digest of the ledger's last post, or `None` before the first.
    ///
    /// The validator walks the persisted summaries back from `posted` along their parents, and
    /// resumes from the first one with the database's balances root. A close that did not post is
    /// off that chain, so it is never chosen even when it shares the root. A database with no
    /// commit metadata has applied no close and starts from genesis.
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
                    summary: Summary::genesis::<H>(root),
                    matrix: Matrix::empty::<H>(),
                })
            })
            .ok_or(Error::InvalidCheckpoint)?;
        Ok(Self {
            context,
            config,
            opened: 0,
            balances: Some(balances),
            persisted,
            parent,
        })
    }

    fn summary_of(record: &Record) -> Summary<H::Digest> {
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

    /// Returns what the validator persisted besides its balances database.
    pub const fn persisted(&self) -> &Persisted<H::Digest> {
        &self.persisted
    }

    /// Returns the summary of the last close applied.
    pub const fn summary(&self) -> &Summary<H::Digest> {
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

    /// Opens what `sender` paid `receiver` in the posted close of `epoch`, at or before the last
    /// close applied, from the close the validator persisted (V6).
    pub fn open(&self, epoch: Epoch, sender: &P, receiver: &P) -> Option<Opening<P, H::Digest, A>> {
        let mut digest = self.parent.summary.digest::<H>();
        while let Some(record) = self.persisted.attested.get(&digest) {
            let summary = Self::summary_of(record);
            if summary.epoch == epoch {
                let matrix = Self::close_of(&self.config, record).matrix::<H>();
                return Some(matrix.open(sender, receiver));
            }
            digest = summary.parent;
        }
        None
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
        let proposal = checked.settle(self.balances()).await?;
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

    /// Applies the proposal of the posted close whose summary has digest `posted`, and makes it
    /// durable (V5).
    ///
    /// A refusal leaves the database at its last close, reopened. A storage failure while making
    /// the close durable leaves the validator unusable until it restarts.
    pub async fn apply(
        &mut self,
        proposal: Proposal<P, H, S, A>,
        posted: &H::Digest,
    ) -> Result<(), Error> {
        let balances = self
            .balances
            .take()
            .expect("a validator whose storage failed must restart");
        let (balances, checkpoint) = match proposal.apply(balances, posted).await {
            Ok(applied) => applied,
            Err(error) => {
                self.opened += 1;
                self.balances =
                    Some(Self::database(&self.context, &self.config, self.opened).await?);
                return Err(error);
            }
        };
        let balances = balances.commit().await?;
        let boundary = balances.sync_boundary();
        self.balances = Some(balances.prune(boundary).await?);
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
