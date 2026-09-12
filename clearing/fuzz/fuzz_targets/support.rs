#![allow(dead_code)]

use commonware_clearing::bajillion::{
    boundary::{DepositBatch, WithdrawalBatch},
    qmdb::{self, State, account_key},
    transition::{CloseContext, CloseLimits, EpochContext},
};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_cryptography_curve25519::signing::StrictVerifyingKey as VerifyingKey;
use commonware_parallel::Sequential;
use commonware_runtime::{BufferPooler, deterministic, utils::buffer::paged::CacheRef};
use commonware_storage::{
    journal::contiguous::fixed::Config as JournalConfig, merkle::full::Config as MerkleConfig,
    qmdb::current::FixedConfig, translator::EightCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize};
use core::num::NonZeroU64;

pub type TestState = State<deterministic::Context, Sha256>;

pub fn config(context: &impl BufferPooler, prefix: &str) -> qmdb::Config<Sequential> {
    let page_cache = CacheRef::from_pooler(context, NZU16!(4092), NZUsize!(16));
    FixedConfig {
        merkle_config: MerkleConfig {
            journal_partition: format!("{prefix}-merkle"),
            metadata_partition: format!("{prefix}-merkle-meta"),
            items_per_blob: NZU64!(64),
            write_buffer: NZUsize!(4096),
            strategy: Sequential,
            page_cache: page_cache.clone(),
        },
        journal_config: JournalConfig {
            partition: format!("{prefix}-operations"),
            items_per_blob: NZU64!(64),
            write_buffer: NZUsize!(4096),
            page_cache,
        },
        grafted_metadata_partition: format!("{prefix}-grafted"),
        translator: EightCap,
        init_cache_size: Some(NZUsize!(1024)),
        init_buffer: NZUsize!(4096),
        init_concurrency: (),
    }
}

pub async fn new_state(
    context: deterministic::Context,
    prefix: &str,
    balances: Vec<(VerifyingKey, u64)>,
) -> TestState {
    let mut genesis = balances
        .into_iter()
        .map(|(key, balance)| {
            (
                account_key(&key).unwrap(),
                NonZeroU64::new(balance).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    genesis.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    let config = config(&context, prefix);
    State::init(context, config, genesis).await.unwrap()
}

#[allow(clippy::too_many_arguments)]
pub async fn close_context(
    deployment: Digest,
    epoch: u64,
    operator: VerifyingKey,
    state: &TestState,
    deposits: &DepositBatch<VerifyingKey>,
    withdrawals: &WithdrawalBatch<VerifyingKey, Digest>,
    admission: u64,
    challenge: u64,
    limits: CloseLimits,
    committee: Digest,
) -> CloseContext<VerifyingKey, Digest> {
    EpochContext::new::<Sha256>(
        deployment,
        epoch,
        operator,
        deposits,
        withdrawals,
        state.liability(),
        admission,
        challenge,
        limits,
        committee,
    )
    .unwrap()
    .bind::<Sha256, _, _>(state, deposits, withdrawals)
    .await
    .unwrap()
}
