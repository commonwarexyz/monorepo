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
pub struct VotesSqlx<S, D>
where
    S: Scheme,
{
    pool: PgPool,
    cfg: <S::Certificate as CodecRead>::Cfg,
    _marker: PhantomData<D>,
}

impl<S, D> VotesSqlx<S, D>
where
    S: Scheme,
    D: Digest,
{
    /// Creates a new SQLx-backed votes store.
    ///
    /// # Arguments
    ///
    /// * `pool` - The SQLx PostgreSQL connection pool.
    /// * `table` - The name of the table to use for storage.
    /// * `cfg` - The codec configuration for decoding certificates.
    pub fn new(pool: PgPool, cfg: <S::Certificate as CodecRead>::Cfg) -> Self {
        Self {
            pool,
            cfg,
            _marker: PhantomData,
        }
    }
}

impl<S, D> Votes for VotesSqlx<S, D>
where
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
            .execute(&self.pool)
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
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn replay(&mut self, epoch: Epoch) -> Result<Self::ReplayStream<'_>, Self::Error> {
        use sqlx::Row as _;

        let cfg = self.cfg.clone();
        let stream = sqlx::query(
            "SELECT artifact FROM consensus_votes WHERE epoch = $1 ORDER BY view ASC, id ASC",
        )
        .bind(epoch.get() as i64)
        .try_map(move |row: sqlx::postgres::PgRow| {
            let bytes: Vec<u8> = row.try_get("artifact")?;
            Artifact::decode_cfg(&mut &bytes[..], &cfg)
                .map_err(|err| sqlx::Error::Decode(err.into()))
        })
        .fetch(&self.pool);
        Ok(Box::pin(stream))
    }
}
