//! Shared compact QMDB helpers.

pub(crate) mod batch;
pub(crate) mod witness;

use crate::{
    Context,
    journal::contiguous::variable,
    merkle::{Family, Location},
    qmdb::{
        Error,
        sync::{Journal as _, Target, journal::Memory},
    },
};
use commonware_cryptography::Digest;
use commonware_parallel::Strategy;
use commonware_utils::range::NonEmptyRange;

/// Configuration for a compact authenticated db.
#[derive(Clone)]
pub struct Config<C, S: Strategy> {
    /// Strategy used to parallelize merkleization.
    pub strategy: S,

    /// Configuration for the journal that persists the witness.
    pub witness: variable::Config<()>,

    /// Codec config used to decode the persisted last commit operation on reopen.
    pub commit_codec_config: C,
}

/// Open the sync journal for `target`. Compact databases keep no operations to reuse, and nothing
/// is pinned at genesis.
#[allow(clippy::type_complexity)]
pub(crate) async fn open_sync_journal<E, F, D, Op>(
    context: &E,
    target: &Target<F, D>,
) -> Result<((), Memory<F, E, Op>, Option<Vec<D>>), Error<F>>
where
    E: Context,
    F: Family,
    D: Digest,
    Op: Send + Sync,
{
    let start = target.range.start();
    let journal = Memory::clear(context.child("journal"), (), start).await?;
    Ok(((), journal, (start == Location::new(0)).then(Vec::new)))
}

/// Build a compact db from state fetched by the sync engine.
/// Returns [`Error::UnexpectedData`] if the log has more than the commit operation.
pub(crate) async fn from_sync_result<E, F, D, C, S, Op, DB>(
    context: E,
    config: Config<C, S>,
    log: Memory<F, E, Op>,
    pinned_nodes: Option<Vec<D>>,
    range: NonEmptyRange<Location<F>>,
    init: impl FnOnce(S, witness::Journal<E, F, D>, C, Location<F>, Vec<D>, Op) -> Result<DB, Error<F>>,
) -> Result<DB, Error<F>>
where
    E: Context,
    F: Family,
    D: Digest,
    S: Strategy,
{
    let last_commit_loc = range.start();
    let (start, ops) = log.into_parts();
    let (Ok([op]), true) = (<[Op; 1]>::try_from(ops), start == last_commit_loc) else {
        return Err(Error::UnexpectedData(last_commit_loc));
    };

    let journal = variable::Journal::init(context.child("witness"), config.witness).await?;
    init(
        config.strategy,
        journal,
        config.commit_codec_config,
        last_commit_loc,
        // None only happens at genesis, where nothing is pinned.
        pinned_nodes.unwrap_or_default(),
        op,
    )
}
