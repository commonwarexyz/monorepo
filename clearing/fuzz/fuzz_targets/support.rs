#![allow(dead_code)]

use commonware_clearing::bajillion::{
    boundary::{DepositBatch, WithdrawalBatch},
    logs::{self, Floors, Logs},
    qmdb::{self, State, account_key},
    replica::{self, Replica},
    transition::{CloseContext, CloseLimits, EpochContext},
};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_cryptography_curve25519::signing::StrictVerifyingKey as VerifyingKey;
use commonware_parallel::Sequential;
use commonware_runtime::{
    BufferPooler, Supervisor as _, deterministic, utils::buffer::paged::CacheRef,
};
use commonware_storage::{
    journal::contiguous::fixed::Config as JournalConfig, merkle::full::Config as MerkleConfig,
    qmdb::current::FixedConfig, translator::EightCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize};
use core::num::NonZeroU64;

pub type TestState = Replica<deterministic::Context, Sha256, VerifyingKey>;

pub fn config(context: &impl BufferPooler, prefix: &str) -> qmdb::Config<Sequential> {
    let page_cache = CacheRef::from_pooler(context, NZU16!(4092), NZUsize!(16));
    FixedConfig {
        merkle_config: MerkleConfig {
            journal_partition: format!("{prefix}-merkle"),
            metadata_partition: format!("{prefix}-merkle-meta"),
            items_per_blob: NZU64!(64),
            write_buffer: NZUsize!(4096),
            replay_buffer: NZUsize!(4096),
            strategy: Sequential,
            page_cache: page_cache.clone(),
        },
        journal_config: JournalConfig {
            partition: format!("{prefix}-operations"),
            items_per_blob: NZU64!(64),
            write_buffer: NZUsize!(4096),
            replay_buffer: NZUsize!(4096),
            page_cache,
        },
        grafted_metadata_partition: format!("{prefix}-grafted"),
        translator: EightCap,
        init_cache_size: Some(NZUsize!(1024)),
        init_buffer: NZUsize!(4096),
        init_concurrency: (),
    }
}

pub fn logs_config(context: &impl BufferPooler, prefix: &str) -> logs::Config<Sequential> {
    let activity = config(context, &format!("{prefix}-activity"));
    let payouts = config(context, &format!("{prefix}-payouts"));
    logs::Config {
        activity: commonware_storage::qmdb::keyless::Config {
            merkle: activity.merkle_config,
            log: commonware_storage::journal::contiguous::variable::Config {
                partition: activity.journal_config.partition,
                items_per_section: commonware_utils::NZU64!(4096),
                compression: None,
                codec_config: commonware_codec::RangeCfg::new(..=16 * 1024 * 1024),
                page_cache: activity.journal_config.page_cache,
                write_buffer: commonware_utils::NZUsize!(4096),
                replay_buffer: commonware_utils::NZUsize!(4096),
            },
        },
        payouts: commonware_storage::qmdb::keyless::Config {
            merkle: payouts.merkle_config,
            log: commonware_storage::journal::contiguous::variable::Config {
                partition: payouts.journal_config.partition,
                items_per_section: NZU64!(64),
                compression: None,
                codec_config: commonware_codec::RangeCfg::new(0..=1024),
                page_cache: payouts.journal_config.page_cache,
                write_buffer: NZUsize!(4096),
                replay_buffer: NZUsize!(4096),
            },
        },
    }
}

pub async fn open_state(
    context: deterministic::Context,
    prefix: &str,
) -> Result<TestState, replica::Error> {
    let cfg = replica::Config {
        state: config(&context, prefix),
        logs: logs_config(&context, prefix),
    };
    Replica::open(context, cfg).await
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
    let log_config = logs_config(&context, prefix);
    let state = State::init(context.child("state"), config, genesis)
        .await
        .unwrap();
    let logs = Logs::open(context, log_config).await.unwrap();
    Replica::from_parts(state, logs)
}

#[allow(clippy::too_many_arguments)]
pub fn close_context(
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
    floors: Floors,
) -> CloseContext<VerifyingKey, Digest> {
    EpochContext::new::<Sha256>(
        deployment,
        epoch,
        operator,
        deposits,
        withdrawals,
        state.state().liability(),
        admission,
        challenge,
        limits,
        committee,
    )
    .unwrap()
    .bind::<Sha256, _, _>(state, deposits, withdrawals, floors)
    .unwrap()
}
