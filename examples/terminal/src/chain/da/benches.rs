//! Filesystem measurements through the production durable-vote boundary.

#[cfg(test)]
mod tests;

use super::{
    Ballot, Lane, NativeReplica, checkpoint,
    config::{LOG_MERKLE_NODES_PER_BLOB, LOG_OPERATIONS_PER_SECTION},
    persist_candidate, recover, replica_config,
};
use crate::{
    chain::validator::{IO_BUFFER_SIZE, PAGE_SIZE, PHYSICAL_PAGE_SIZE},
    protocol::{
        Account, Deployment, MAX_ACCEPTED_PAYMENTS, MAX_ACTIVITY_ROWS, MAX_GENESIS_ACCOUNTS,
        MAX_WITHDRAWALS, STATE_MERKLE_NODES_PER_BLOB, STATE_OPERATIONS_PER_BLOB, genesis_balances,
        limits,
    },
};
use anyhow::{Context as _, Result, ensure};
use bytes::Bytes;
use clap::Parser;
use commonware_clearing::bajillion::{
    admission::{Committee, bls12381, seal},
    benchmark_workload as workload,
    replica::Replica,
    transition::{CloseLimits, ProposalId},
};
use commonware_codec::Encode as _;
use commonware_cryptography::{
    Hasher as _, Sha256, Signer as _,
    bls12381::primitives::{
        group::{Private, Scalar},
        ops::compute_public,
        variant::MinSig,
    },
    sha256::Digest,
};
use commonware_cryptography_curve25519::signing::BatchVerifier;
use commonware_parallel::Rayon;
use commonware_runtime::{
    Runner as _, Spawner, Strategizer as _, Supervisor as _, buffer::paged::CacheRef, tokio,
};
use commonware_storage::Context as StorageContext;
use rand_core::CryptoRng;
use serde_json::{Value, json};
use std::{
    fs,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const PREFIX: &str = "ack-benchmark";
const VALIDATORS: usize = 100;

// Each state/activity writer holds a complete million-payer batch before its durable commit.
const BATCH_WRITE_BUFFER: NonZeroUsize = NonZeroUsize::new(256 * 1024 * 1024).unwrap();

// Physical-page budget for the million-account durability workloads.
const PAGE_CACHE_BUDGET: usize = 1 << 30;
const PAGE_CACHE_SIZE: NonZeroUsize =
    NonZeroUsize::new(PAGE_CACHE_BUDGET / PHYSICAL_PAGE_SIZE as usize)
        .expect("page-cache budget must hold at least one complete page");

#[derive(Parser)]
struct Options {
    /// Parent directory on the filesystem being measured.
    #[arg(long)]
    storage_directory: PathBuf,
    #[arg(long, default_value_t = 1_000_000)]
    accounts: usize,
    #[arg(long, default_value_t = 1_000)]
    senders: usize,
    #[arg(long, default_value_t = 512)]
    recipients: usize,
    #[arg(long, default_value_t = 1)]
    out_degree: usize,
    #[arg(long, default_value_t = 0)]
    withdrawals: usize,
    /// Prior activity rows, produced by durable self-transfer epochs.
    #[arg(long, default_value_t = 0)]
    history: usize,
    #[arg(long, default_value_t = 3)]
    samples: usize,
    #[arg(long, default_value_t = 0)]
    warmup: usize,
    #[arg(long, default_value_t = 2)]
    runtime_workers: usize,
    /// Workers in the adaptive pool shared by validation and the three public QMDBs.
    #[arg(long, default_value = "16")]
    workers: NonZeroUsize,
    /// Use explicit large fixture limits instead of the deployed terminal policy.
    #[arg(long)]
    benchmark_limits: bool,
}

impl Options {
    const fn case(&self) -> workload::Case {
        workload::Case {
            n: self.accounts,
            a: self.senders,
            b: self.recipients,
            k: self.out_degree,
            w: self.withdrawals,
            h: self.history,
        }
    }

    fn validate(&self) -> Result<()> {
        self.case().validate();
        ensure!(
            self.samples > 0 && self.runtime_workers > 0,
            "samples and workers must be positive"
        );
        self.samples
            .checked_add(self.warmup)
            .context("sample count overflow")?;
        if !self.benchmark_limits {
            ensure!(
                self.accounts <= MAX_GENESIS_ACCOUNTS
                    && self
                        .senders
                        .checked_mul(self.out_degree)
                        .is_some_and(|n| n <= MAX_ACCEPTED_PAYMENTS)
                    && self
                        .senders
                        .checked_add(self.recipients)
                        .and_then(|n| n.checked_add(self.withdrawals))
                        .is_some_and(|n| n <= MAX_ACTIVITY_ROWS)
                    && self.withdrawals <= MAX_WITHDRAWALS,
                "this fixture exceeds terminal policy; explicitly select --benchmark-limits"
            );
        }
        Ok(())
    }

    const fn close_limits(&self) -> CloseLimits {
        if self.benchmark_limits {
            CloseLimits::protocol_maximum()
        } else {
            limits()
        }
    }

    fn runner(&self, directory: &Path) -> tokio::Runner {
        tokio::Runner::new(
            tokio::Config::default()
                .with_storage_directory(directory)
                .with_worker_threads(self.runtime_workers),
        )
    }
}

fn config(
    deployment: &Digest,
    page_cache: CacheRef,
    strategy: Rayon,
) -> commonware_clearing::bajillion::replica::Config<Rayon> {
    let mut config = replica_config(
        &format!("{PREFIX}-replica-{deployment}-0"),
        page_cache,
        strategy,
    );
    config.state.journal_config.write_buffer = BATCH_WRITE_BUFFER;
    config.state.merkle_config.write_buffer = BATCH_WRITE_BUFFER;
    config.logs.activity.log.write_buffer = BATCH_WRITE_BUFFER;
    config.logs.activity.merkle.write_buffer = BATCH_WRITE_BUFFER;
    config
}

fn signer() -> bls12381::Scheme {
    let keys = (0..VALIDATORS)
        .map(|index| Private::new(Scalar::from(1_000_001 + index as u64)))
        .collect::<Vec<_>>();
    let committee = Committee::new(keys.iter().map(compute_public::<MinSig>).collect()).unwrap();
    bls12381::Scheme::signer(committee, keys[0].clone()).unwrap()
}

struct Sample {
    elapsed: Duration,
    manifest: Bytes,
    rows: usize,
    mutations: usize,
    deletions: usize,
    before: Value,
    after: Value,
}

#[commonware_macros::boxed]
async fn measure<E: StorageContext + Spawner + CryptoRng>(
    runtime: &mut E,
    lane: &mut Lane<E>,
    input: &workload::Built,
    scheme: &bls12381::Scheme,
    strategy: &Rayon,
) -> Result<Sample> {
    let parent = lane.manifest();
    ensure!(
        parent.candidate.is_none() && parent.decision.is_none(),
        "sample has a saved vote"
    );
    ensure!(
        lane.state.as_ref().unwrap().head() == parent.canonical.checkpoint.head,
        "sample is not at its canonical predecessor"
    );
    ensure!(
        lane.next() == input.context.payment().epoch(),
        "sample epoch mismatch"
    );
    let encoded = input.encoded_dealing.clone();
    let before = process_snapshot();

    let start = Instant::now();
    let (vote, prepared) = seal::<Sha256, _, _, _, _, BatchVerifier, _>(
        scheme,
        lane.state.as_ref().unwrap(),
        &input.context,
        &lane.deployment.operator_ack,
        &input.deposits,
        &input.withdrawals,
        encoded.clone(),
        runtime,
        strategy,
    )
    .await?;
    let close = prepared.close();
    let rows = close.rows.len();
    let mutations = prepared.state().mutations().len();
    let deletions = usize::try_from(
        parent.canonical.checkpoint.head.state.live_accounts()
            - prepared.state().head().live_accounts(),
    )?;
    let ballot = Ballot {
        deployment: *lane.deployment.digest(),
        epoch: input.context.payment().epoch(),
        proposal: *ProposalId::for_dealing::<Sha256, _>(input.context.epoch_context(), &encoded)
            .digest(),
        context: input.context.clone(),
        header: close.header,
        roots: close.roots,
        withdrawal_total: close.withdrawal_total,
        vote,
    };
    ballot.check()?;
    persist_candidate(lane, prepared.into_parts().1, ballot).await?;
    let elapsed = start.elapsed();

    let after = process_snapshot();
    let manifest = lane.manifest();
    let decision = manifest
        .decision
        .as_ref()
        .context("missing persisted ballot")?;
    ensure!(
        scheme.verify_vote(&decision.header, &decision.vote),
        "persisted vote is invalid"
    );
    ensure!(
        decision.header == input.header && decision.roots == input.roots,
        "measured candidate differs from the fixture"
    );
    ensure!(
        decision.context == input.context && decision.withdrawal_total == input.withdrawal_total,
        "measured registration differs from the fixture"
    );
    ensure!(
        lane.state.as_ref().unwrap().head() == input.expected_head,
        "measured native head mismatch"
    );
    ensure!(
        manifest.canonical.encode() == parent.canonical.encode(),
        "candidate changed canonical authority"
    );
    ensure!(
        manifest.candidate.as_ref().unwrap().checkpoint.head == input.expected_head,
        "private candidate mismatch"
    );
    ensure!(
        rows == input.rows && mutations == input.mutations && deletions == input.deletions,
        "measured logical work differs from the fixture"
    );
    ensure!(
        input.expected_head.state.operations()
            > parent.canonical.checkpoint.head.state.operations()
            && input.expected_head.logs.activity.operations
                > parent.canonical.checkpoint.head.logs.activity.operations
            && input.expected_head.logs.payouts.operations
                > parent.canonical.checkpoint.head.logs.payouts.operations,
        "sample did not advance every public QMDB"
    );
    Ok(Sample {
        elapsed,
        manifest: manifest.encode(),
        rows,
        mutations,
        deletions,
        before,
        after,
    })
}

#[commonware_macros::boxed]
async fn open<E: StorageContext + Spawner>(
    context: E,
    deployment: Deployment,
    page_cache: CacheRef,
    strategy: Rayon,
) -> Result<Lane<E>> {
    let state = NativeReplica::open(
        context.child("replica"),
        config(deployment.digest(), page_cache.clone(), strategy),
    )
    .await?;
    let checkpoint = checkpoint::Store::open(
        context.child("checkpoint"),
        PREFIX,
        deployment.digest(),
        page_cache,
    )
    .await?;
    Ok(Lane {
        deployment,
        pending: None,
        state: Some(state),
        checkpoint: Some(checkpoint),
    })
}

#[commonware_macros::boxed]
async fn setup<E: StorageContext + Spawner + CryptoRng>(
    mut context: E,
    options: &Options,
    scheme: &bls12381::Scheme,
    strategy: &Rayon,
    page_cache: CacheRef,
) -> Result<(Deployment, workload::Built)> {
    let keys = workload::keys(options.accounts, strategy);
    let digest = Sha256::hash(&[b"clearing-benchmark-deployment"]);
    let accounts = keys
        .accounts
        .iter()
        .map(|(key, _)| Account {
            key: key.clone(),
            balance: workload::OPENING_BALANCE,
        })
        .collect();
    let initial = Deployment::new(
        digest,
        keys.operator.public_key(),
        keys.operator_bls,
        accounts,
    );
    let replica = NativeReplica::open(
        context.child("bootstrap"),
        config(&digest, page_cache.clone(), strategy.clone()),
    )
    .await?;
    let (state, logs) = replica.into_parts();
    let prepared = state
        .prepare(
            state.head(),
            genesis_balances(&initial)?
                .into_iter()
                .map(|(key, balance)| (key, Some(balance)))
                .collect(),
        )
        .await?;
    let replica = Replica::from_parts(state.apply(prepared).await?, logs)
        .commit()
        .await?;
    let deployment = Deployment::configured(
        digest,
        initial.operator,
        initial.operator_ack,
        initial.accounts,
        replica.state().root(),
        replica.state().head().operations(),
    )?;
    let checkpoint = checkpoint::Store::open(
        context.child("bootstrap_checkpoint"),
        PREFIX,
        &digest,
        page_cache,
    )
    .await?;
    let (replica, checkpoint) = recover(replica, &deployment, checkpoint).await?;
    let mut lane = Lane {
        deployment: deployment.clone(),
        pending: None,
        state: Some(replica),
        checkpoint: Some(checkpoint),
    };
    let mut remaining = options.history;
    while remaining > 0 {
        let rows = remaining.min(options.accounts);
        let case = workload::Case {
            n: options.accounts,
            a: rows,
            b: rows,
            k: 1,
            w: 0,
            h: 0,
        };
        let input = workload::build_close(
            lane.state.as_ref().unwrap(),
            case,
            &keys,
            digest,
            scheme.committee().commitment::<Sha256>(),
            lane.next(),
            options.close_limits(),
            strategy,
        )
        .await;
        measure(&mut context, &mut lane, &input, scheme, strategy).await?;

        // Fixture history advances through complete, validated epochs before sampling begins.
        let mut manifest = lane.manifest().as_ref().clone();
        manifest.canonical = manifest.candidate.take().unwrap();
        manifest.decision = None;
        lane.checkpoint = Some(lane.checkpoint.take().unwrap().put(manifest).await?);
        remaining -= rows;
    }
    let input = workload::build_close(
        lane.state.as_ref().unwrap(),
        options.case(),
        &keys,
        digest,
        scheme.committee().commitment::<Sha256>(),
        lane.next(),
        options.close_limits(),
        strategy,
    )
    .await;
    ensure!(
        lane.state.as_ref().unwrap().state().live_accounts() == options.accounts as u64,
        "baseline live-account count mismatch"
    );
    Ok((deployment, input))
}

fn verify_reopened<E: StorageContext + Spawner>(
    lane: &Lane<E>,
    input: &workload::Built,
    sample: &Sample,
    scheme: &bls12381::Scheme,
) -> Result<()> {
    // Inspect raw recovered owners before application recovery can align their heads.
    ensure!(
        lane.state.as_ref().unwrap().head() == input.expected_head,
        "raw reopened native head mismatch"
    );
    let manifest = lane.manifest();
    manifest.check(&lane.deployment)?;
    ensure!(
        manifest.encode() == sample.manifest,
        "raw reopened private decision mismatch"
    );
    let ballot = manifest
        .decision
        .as_ref()
        .context("reopened candidate lost its vote")?;
    ensure!(
        scheme.verify_vote(&ballot.header, &ballot.vote),
        "reopened vote signature mismatch"
    );
    ensure!(
        manifest.complete().checkpoint.head == input.expected_head,
        "reopened checkpoint/head mismatch"
    );
    Ok(())
}

fn copy_directory(source: &Path, target: &Path) -> Result<()> {
    fs::create_dir(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let path = target.join(entry.file_name());
        if kind.is_dir() {
            copy_directory(&entry.path(), &path)?;
        } else {
            ensure!(
                kind.is_file(),
                "benchmark storage contains a non-file entry"
            );
            fs::copy(entry.path(), &path)?;
            fs::File::open(path)?.sync_all()?;
        }
    }
    fs::File::open(target)?.sync_all()?;
    Ok(())
}

fn process_snapshot() -> Value {
    let stat = fs::read_to_string("/proc/self/stat").ok();
    let fields = stat
        .as_deref()
        .and_then(|s| s.rsplit_once(')'))
        .map(|(_, s)| s.split_whitespace().collect::<Vec<_>>());
    let ticks = |index: usize| {
        fields
            .as_ref()
            .and_then(|f| f.get(index))
            .and_then(|s| s.parse::<u64>().ok())
    };
    let status = fs::read_to_string("/proc/self/status").ok();
    let io = fs::read_to_string("/proc/self/io").ok();
    let field = |text: &Option<String>, name: &str| {
        text.as_deref().and_then(|s| {
            s.lines().find_map(|line| {
                line.strip_prefix(name)
                    .and_then(|rest| rest.split_whitespace().next()?.parse::<u64>().ok())
            })
        })
    };
    json!({
        "user_ticks": ticks(11), "system_ticks": ticks(12),
        "rss_kib": field(&status, "VmRSS:"), "process_hwm_kib": field(&status, "VmHWM:"),
        "read_bytes": field(&io, "read_bytes:"), "write_bytes": field(&io, "write_bytes:"),
    })
}

/// Executes explicitly configured filesystem samples and writes raw JSONL results.
pub fn run() -> Result<()> {
    let options = Options::parse();
    options.validate()?;
    fs::create_dir_all(&options.storage_directory)?;
    let root = options.storage_directory.canonicalize()?.join(format!(
        "ack-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    fs::create_dir(&root)?;
    let baseline = root.join("baseline");
    let scheme = signer();
    let (setup_options, setup_scheme) = (&options, &scheme);
    let (deployment, input, strategy) = options.runner(&baseline).start(|context| async move {
        let strategy = context.strategy(setup_options.workers);
        let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
        let (deployment, input) =
            setup(context, setup_options, setup_scheme, &strategy, page_cache).await?;
        Ok::<_, anyhow::Error>((deployment, input, strategy))
    })?;
    let name = format!("{}::durable_ack/{}", module_path!(), options.case().label());
    println!(
        "{}",
        json!({
            "record": "ack_metadata", "name": name, "storage_directory": root,
            "backend": "tokio_filesystem", "reset": "isolated_durable_four_owner_predecessor",
            "boundary": "encoded_dealing_to_seal_and_production_persist_candidate_return",
            "native_strategy": "rayon_adaptive", "workers": options.workers.get(),
            "native_worker_pools": 1, "public_store_concurrency": 3,
            "private_control_after_public_commit": true, "runtime_workers": options.runtime_workers,
            "validators": VALIDATORS, "samples": options.samples, "warmup": options.warmup,
            "benchmark_limits": options.benchmark_limits,
            "context_limits": format!("{:?}", input.context.limits()),
            "row_count": input.row_count,
            "activity_append_operations": input.activity_append_operations,
            "activity_append_bytes": input.activity_append_bytes,
            "payout_output_operations": input.payout_output_operations,
            "payout_output_bytes": input.payout_output_bytes,
            "withdrawal_output_bytes": input.withdrawal_output_bytes,
            "encoded_dealing_bytes": input.encoded_dealing.len(), "encoded_dealing_sha256": Sha256::hash(&[&input.encoded_dealing]).to_string(),
            "native_logical_page_bytes": PAGE_SIZE.get(),
            "native_physical_page_bytes": PHYSICAL_PAGE_SIZE,
            "native_cache_pages": PAGE_CACHE_SIZE.get(),
            "native_cache_budget_bytes": PAGE_CACHE_BUDGET,
            "native_cache_instances": 1,
            "native_state_activity_write_buffer_bytes": BATCH_WRITE_BUFFER.get(),
            "native_payout_write_buffer_bytes": IO_BUFFER_SIZE.get(),
            "native_replay_buffer_bytes": IO_BUFFER_SIZE.get(),
            "native_private_write_replay_buffer_bytes": IO_BUFFER_SIZE.get(),
            "native_log_operations_per_section": LOG_OPERATIONS_PER_SECTION.get(),
            "native_log_merkle_nodes_per_blob": LOG_MERKLE_NODES_PER_BLOB.get(),
            "native_state_operations_per_blob": STATE_OPERATIONS_PER_BLOB.get(),
            "native_state_merkle_nodes_per_blob": STATE_MERKLE_NODES_PER_BLOB.get(),
            "n": options.accounts, "a": options.senders, "b": options.recipients,
            "k": options.out_degree, "w": options.withdrawals, "h": options.history,
        })
    );
    let (options, deployment, input, scheme, strategy) =
        (&options, &deployment, &input, &scheme, &strategy);
    for index in 0..options.warmup + options.samples {
        let directory = root.join(format!("sample-{index}"));
        copy_directory(&baseline, &directory)?;
        fs::File::open(&root)?.sync_all()?;
        let sample = options.runner(&directory).start(|mut context| async move {
            let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
            let mut lane = open(
                context.child("sample"),
                deployment.clone(),
                page_cache.clone(),
                strategy.clone(),
            )
            .await?;
            let sample = measure(&mut context, &mut lane, input, scheme, strategy).await?;
            drop(lane);

            // Reopening in the running context keeps startup filesystem flushes outside this
            // verification. Native initialization owns recovery of the committed journals.
            let lane = open(
                context.child("reopen"),
                deployment.clone(),
                page_cache,
                strategy.clone(),
            )
            .await?;
            verify_reopened(&lane, input, &sample, scheme)?;
            Ok::<_, anyhow::Error>(sample)
        })?;
        println!(
            "{}",
            json!({
                "record": "ack_sample", "name": name, "sample": index,
                "warmup": index < options.warmup, "ns": sample.elapsed.as_nanos(),
                "rows": sample.rows, "mutations": sample.mutations, "deletions": sample.deletions,
                "live_accounts_after": input.expected_head.state.live_accounts(),
                "state_operations": input.expected_head.state.operations(),
                "activity_operations": input.expected_head.logs.activity.operations,
                "payout_operations": input.expected_head.logs.payouts.operations,
                "public_head_sha256": Sha256::hash(&[&input.expected_head.encode()]).to_string(),
                "private_manifest_sha256": Sha256::hash(&[&sample.manifest]).to_string(),
                "reopen_verified": true, "before": sample.before, "after": sample.after,
            })
        );
        // The Tokio runner has drained its blocking I/O before the sample directory is removed.
        fs::remove_dir_all(directory)?;
    }
    fs::remove_dir_all(root)?;
    Ok(())
}
