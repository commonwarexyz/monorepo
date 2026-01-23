use std::pin::Pin;

use commonware_consensus::{
    simplex::{
        store::{Votes, VotesJournal},
        types::Artifact,
    },
    types::{Epoch, View},
};
use commonware_consensus_sqlx::VotesSqlx;
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_runtime::{Metrics, Storage};
use commonware_storage::journal;
use futures::{Stream, TryStreamExt as _};

pub enum DatabaseOrJournal<E, S, D>
where
    E: Storage + Metrics,
    S: Scheme,
    D: Digest,
{
    Journal(VotesJournal<E, S, D>),
    Database(VotesSqlx<S, D>),
}

impl<E, S, D> From<VotesJournal<E, S, D>> for DatabaseOrJournal<E, S, D>
where
    E: Storage + Metrics,
    S: Scheme,
    D: Digest,
{
    fn from(value: VotesJournal<E, S, D>) -> Self {
        Self::Journal(value)
    }
}

impl<E, S, D> From<VotesSqlx<S, D>> for DatabaseOrJournal<E, S, D>
where
    E: Storage + Metrics,
    S: Scheme,
    D: Digest,
{
    fn from(value: VotesSqlx<S, D>) -> Self {
        Self::Database(value)
    }
}

#[derive(Debug)]
pub enum Error {
    Journal(journal::Error),
    Database(sqlx::Error),
}

impl From<journal::Error> for Error {
    fn from(value: journal::Error) -> Self {
        Self::Journal(value)
    }
}

impl From<sqlx::Error> for Error {
    fn from(value: sqlx::Error) -> Self {
        Self::Database(value)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Self::Journal(e) => e.fmt(formatter),
            Self::Database(e) => e.fmt(formatter),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Journal(e) => e.source(),
            Self::Database(e) => e.source(),
        }
    }
}

impl<E, S, D> Votes for DatabaseOrJournal<E, S, D>
where
    E: Storage + Metrics,
    S: Scheme,
    S::Certificate: Unpin,
    S::Signature: Unpin,
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
        match self {
            Self::Journal(this) => this.append(epoch, view, artifact).await?,
            Self::Database(this) => this.append(epoch, view, artifact).await?,
        };
        Ok(())
    }
    async fn sync(&mut self, epoch: Epoch, view: View) -> Result<(), Self::Error> {
        match self {
            Self::Journal(this) => this.sync(epoch, view).await?,
            Self::Database(this) => this.sync(epoch, view).await?,
        };
        Ok(())
    }
    async fn sync_all(&mut self) -> Result<(), Self::Error> {
        match self {
            Self::Journal(this) => this.sync_all().await?,
            Self::Database(this) => this.sync_all().await?,
        };
        Ok(())
    }
    async fn prune(&mut self, epoch: Epoch, min: View) -> Result<(), Self::Error> {
        match self {
            Self::Journal(this) => this.prune(epoch, min).await?,
            Self::Database(this) => this.prune(epoch, min).await?,
        };
        Ok(())
    }
    async fn replay(&mut self, epoch: Epoch) -> Result<Self::ReplayStream<'_>, Self::Error> {
        let stream = match self {
            Self::Journal(this) => Box::pin(this.replay(epoch).await?.map_err(Self::Error::from))
                as Self::ReplayStream<'_>,
            Self::Database(this) => Box::pin(this.replay(epoch).await?.map_err(Self::Error::from))
                as Self::ReplayStream<'_>,
        };
        Ok(stream)
    }
}
