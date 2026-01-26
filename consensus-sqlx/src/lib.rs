//! SQLx-backed implementations of consensus storage traits.
//!
//! This crate provides database-backed storage for consensus primitives,
//! enabling durable persistence of votes and certificates using SQLx.

use commonware_codec::{Decode, Encode, Read as CodecRead};
use commonware_consensus::{
    simplex::{store::Votes, types::Artifact},
    types::{Epoch, View},
};
use commonware_cryptography::{certificate::Scheme, Digest};
use futures::Stream;
use sqlx::{Error, PgPool};
use std::{marker::PhantomData, pin::Pin};
use tracing::instrument;

pub struct Config<C> {
    /// Codec configuration.
    pub codec_config: C,

    /// The connection to the Postgres database (pool of clients).
    pub pg_pool: PgPool,
}

/// SQLx-backed storage for consensus artifacts.
///
/// Stores [Artifact]s keyed by view, backed by a PostgreSQL database.
/// Artifacts are serialized using `commonware-codec` before storage.
///
/// # Table Schema
///
/// The implementation expects a table with the following schema:
///
/// ```sql
/// CREATE TABLE IF NOT EXISTS consensus_votes (
///     id BIGSERIAL PRIMARY KEY,
///     epoch BIGINT NOT NULL,
///     view BIGINT NOT NULL,
///     artifact BYTEA NOT NULL
/// );
/// CREATE INDEX IF NOT EXISTS idx_consensus_votes_epoch_view ON consensus_votes(epoch, view);
/// ```
pub struct VotesSqlx<E, S, D>
where
    S: Scheme,
{
    _context: E,
    _lock_id: i64,
    pg_pool: PgPool,
    codec_config: <S::Certificate as CodecRead>::Cfg,
    _marker: PhantomData<D>,
}

impl<E, S, D> VotesSqlx<E, S, D>
where
    E: commonware_runtime::Metrics,
    S: Scheme,
    D: Digest,
{
    /// Creates a new SQLx-backed votes store.
    ///
    /// Acquires an exclusive session-level advisory lock to ensure only one
    /// writer can access the votes table at a time. The lock is held for the
    /// lifetime of the connection pool.
    ///
    /// Note that the lock ID is derived from the context label: if another
    /// part of the system wants to create a lock, it needs to have a different
    /// label than the one provided here.
    ///
    /// # Arguments
    ///
    /// * `context` - the runtime context.
    /// * `cfg` - the [`Config`].
    ///
    /// # Errors
    ///
    /// Returns an error if the exclusive lock cannot be acquired (another
    /// instance already holds it).
    #[instrument(skip_all, err)]
    pub async fn init(
        context: E,
        cfg: Config<<S::Certificate as CodecRead>::Cfg>,
    ) -> Result<Self, Error> {
        let Config {
            codec_config,
            pg_pool,
        } = cfg;

        // Derive lock ID from table name to make it table-specific.
        // Blake3 was present in the dependencies and this is a one-time hash.
        // Considerations of performance or cryptographic resistance are not important.
        let lock_id = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(context.label().as_bytes());
            let hash: [u8; _] = hasher.finalize().into();
            i64::from_be_bytes([
                hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
            ])
        };
        let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
            .bind(lock_id)
            .fetch_one(&pg_pool)
            .await?;

        if !acquired {
            return Err(Error::Protocol(format!(
                "failed to acquire exclusive write lock with ID `{lock_id}`: another instance holds the lock"
            )));
        }

        Ok(Self {
            _context: context,
            _lock_id: lock_id,
            pg_pool,
            codec_config,
            _marker: PhantomData,
        })
    }
}

impl<E, S, D> Votes for VotesSqlx<E, S, D>
where
    E: commonware_runtime::Metrics,
    S: Scheme,
    S::Certificate: Unpin,
    S::Signature: Unpin,
    <S::Certificate as CodecRead>::Cfg: Clone,
    D: Digest + Unpin,
{
    type Scheme = S;
    type Digest = D;
    type Error = Error;
    type ReplayStream<'a>
        = Pin<Box<dyn Stream<Item = Result<Artifact<S, D>, Self::Error>> + Send + 'a>>
    where
        Self: 'a;

    async fn append(
        &mut self,
        epoch: Epoch,
        view: View,
        artifact: Artifact<Self::Scheme, Self::Digest>,
    ) -> Result<(), Self::Error> {
        let data = artifact.encode();
        let query =
            format!("INSERT INTO consensus_votes (epoch, view, artifact) VALUES ($1, $2, $3)",);
        sqlx::query(&query)
            .bind(epoch.get() as i64)
            .bind(view.get() as i64)
            .bind(data.as_ref())
            .execute(&self.pg_pool)
            .await?;
        Ok(())
    }

    async fn sync(&mut self, _epoch: Epoch, _view: View) -> Result<(), Self::Error> {
        // PostgreSQL provides durability guarantees after successful INSERT,
        // so no additional sync operation is required.
        Ok(())
    }

    async fn sync_all(&mut self) -> Result<(), Self::Error> {
        // PostgreSQL provides durability guarantees after successful INSERT,
        // so no additional sync operation is required.
        Ok(())
    }

    async fn prune(&mut self, epoch: Epoch, min: View) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM consensus_votes WHERE epoch = $1 AND view < $2 ")
            .bind(epoch.get() as i64)
            .bind(min.get() as i64)
            .execute(&self.pg_pool)
            .await?;
        Ok(())
    }

    async fn replay(&mut self, epoch: Epoch) -> Result<Self::ReplayStream<'_>, Self::Error> {
        use sqlx::Row as _;

        let cfg = self.codec_config.clone();
        let stream = sqlx::query(
            "SELECT artifact FROM consensus_votes WHERE epoch = $1 ORDER BY view ASC, id ASC",
        )
        .bind(epoch.get() as i64)
        .try_map(move |row: sqlx::postgres::PgRow| {
            let bytes: Vec<u8> = row.try_get("artifact")?;
            Artifact::decode_cfg(&mut &bytes[..], &cfg)
                .map_err(|err| sqlx::Error::Decode(err.into()))
        })
        .fetch(&self.pg_pool);
        Ok(Box::pin(stream))
    }
}
