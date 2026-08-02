use super::fabric;
use crate::multimmit::{
    config::Limits,
    machine::{
        Artifact, Cursor, DomainEventCodecConfig, Input, Machine, PersistJob, Profile, Role,
        Tuning, ViewProof,
    },
    mocks::Committee,
    storage::{JournalConfig, SafetyJournal},
};
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk, sha256::Digest};
use commonware_runtime::{
    Handle, Storage as _, Supervisor as _, benchmarks::context, buffer::paged::CacheRef,
    tokio::Context as TokioContext,
};
use commonware_utils::{NZU16, NZUsize};
use std::{
    num::NonZeroUsize,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

const APPEND_RECORDS: usize = 256;

static PARTITION_SEQ: AtomicU64 = AtomicU64::new(0);

fn unique_partition(label: &str) -> String {
    format!(
        "multimmit-journal-{label}-{}",
        PARTITION_SEQ.fetch_add(1, Ordering::SeqCst)
    )
}

struct Harvest {
    profile: Profile<Sha256, MinPk>,
    jobs: Vec<PersistJob<MinPk, Digest>>,
}

/// Drives a live single-participant observer through `views` nullified views, collecting the
/// exact contiguous persistence jobs the machine stages. `PersistJob` and `DomainEvent` are
/// machine-issued only, so real machine output is the only public source of journal input.
fn harvest(views: u64, seed: u64) -> Harvest {
    let committee = Committee::<MinPk>::new(seed, 1, Limits::new(2, 1).unwrap());
    let profile: Profile<Sha256, MinPk> =
        Profile::new(committee.config.clone(), Role::Observer, Tuning::default()).unwrap();
    let mut jobs = Vec::new();
    let mut machine = Machine::new(profile.clone());
    let step = machine.step(Input::Start).unwrap();
    fabric::drain_with(
        &mut machine,
        step.into_capabilities(),
        NonZeroUsize::MIN,
        &mut |key| panic!("startup requires no resolution: {key:?}"),
        &mut |job| jobs.push(job.clone()),
    );
    for view in 1..=views {
        let staged = fabric::absorb(
            &mut machine,
            vec![Artifact::Nullification(committee.nullification(view))],
        );
        fabric::drain_with(
            &mut machine,
            staged,
            NonZeroUsize::MIN,
            &mut |job| {
                ViewProof::Nullification(Box::new(committee.nullification(job.view().get())))
            },
            &mut |job| jobs.push(job.clone()),
        );
    }
    Harvest { profile, jobs }
}

fn journal_config(
    pooler: &TokioContext,
    profile: &Profile<Sha256, MinPk>,
    partition: String,
) -> JournalConfig {
    JournalConfig {
        partition,
        epoch: profile.protocol().epoch(),
        event_codec: DomainEventCodecConfig::from_profile(profile),
        max_events_per_record: NZUsize!(64),
        max_record_bytes: NZUsize!(4 * 1024 * 1024),
        page_cache: CacheRef::from_pooler(pooler, NZU16!(4096), NZUsize!(256)),
        write_buffer: NZUsize!(64 * 1024),
    }
}

async fn open_journal(
    context: &TokioContext,
    config: JournalConfig,
) -> SafetyJournal<TokioContext, MinPk, Digest> {
    let mut recovery = SafetyJournal::open(context.child("journal"), config, Cursor::zero())
        .await
        .unwrap();
    while recovery.next().await.unwrap().is_some() {}
    recovery.finish().unwrap()
}

/// Appends `jobs` awaiting the previous sync just before the next append (depth-one pipeline).
async fn append_pipelined(
    mut journal: SafetyJournal<TokioContext, MinPk, Digest>,
    jobs: &[PersistJob<MinPk, Digest>],
) -> SafetyJournal<TokioContext, MinPk, Digest> {
    let mut previous: Option<Handle<()>> = None;
    for job in jobs {
        if let Some(handle) = previous.take() {
            handle.await.unwrap();
        }
        let (next, _, sync) = journal.start_persist(job).await.unwrap();
        journal = next;
        previous = Some(sync);
    }
    if let Some(handle) = previous {
        handle.await.unwrap();
    }
    journal
}

// The harvest is lazy so filtered runs of the other bench groups do not pay for it. Each
// nullified view currently stages two records, so 500 views cover the
// largest record slice used below.
static HARVEST: LazyLock<Arc<Harvest>> = LazyLock::new(|| Arc::new(harvest(500, 99)));

/// Fixed real-store journal workloads.
#[derive(Clone, Copy, Debug)]
pub enum JournalScenario {
    AppendSerial256,
    AppendPipelined256,
    Replay1000,
}

/// Executes one journal workload in the benchmark runtime and returns only its measured region.
pub async fn run_journal(scenario: JournalScenario) -> Duration {
    let harvest = HARVEST.clone();
    let ctx = context::get::<TokioContext>();
    match scenario {
        JournalScenario::AppendSerial256 | JournalScenario::AppendPipelined256 => {
            let pipelined = matches!(scenario, JournalScenario::AppendPipelined256);
            let mode = if pipelined { "pipelined" } else { "serial" };
            let partition = unique_partition(mode);
            let config = journal_config(&ctx, &harvest.profile, partition.clone());
            let journal = open_journal(&ctx, config).await;
            let jobs = &harvest.jobs[..APPEND_RECORDS];
            let started = Instant::now();
            let journal = if pipelined {
                append_pipelined(journal, jobs).await
            } else {
                let mut journal = journal;
                for job in jobs {
                    let (next, _, sync) = journal.start_persist(job).await.unwrap();
                    sync.await.unwrap();
                    journal = next;
                }
                journal
            };
            let elapsed = started.elapsed();
            drop(journal);
            ctx.remove(&partition, None).await.unwrap();
            elapsed
        }
        JournalScenario::Replay1000 => {
            const RECORDS: usize = 1_000;
            let partition = format!("multimmit-journal-replay-{RECORDS}");
            let populated = ctx
                .scan(&partition)
                .await
                .map(|blobs| !blobs.is_empty())
                .unwrap_or(false);
            if !populated {
                let config = journal_config(&ctx, &harvest.profile, partition.clone());
                let journal = open_journal(&ctx, config).await;
                let journal = append_pipelined(journal, &harvest.jobs[..RECORDS]).await;
                drop(journal);
            }

            let config = journal_config(&ctx, &harvest.profile, partition);
            let started = Instant::now();
            let mut recovery = SafetyJournal::<_, MinPk, Digest>::open(
                ctx.child("journal"),
                config,
                crate::multimmit::machine::Cursor::zero(),
            )
            .await
            .unwrap();
            let mut replayed = 0usize;
            while recovery.next().await.unwrap().is_some() {
                replayed += 1;
            }
            let journal = recovery.finish().unwrap();
            let elapsed = started.elapsed();
            assert_eq!(replayed, RECORDS, "replay must cover every record");
            drop(journal);
            elapsed
        }
    }
}
