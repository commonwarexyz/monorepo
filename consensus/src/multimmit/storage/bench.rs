//! Journal benchmarks: appending and replaying machine-issued persistence jobs on a real store.

use crate::{
    Epochable as _,
    multimmit::{
        config::{Profile, Role, Tuning},
        machine::{Cursor, DomainEventCodecConfig, Input, Machine, PersistJob},
        mocks::Committee,
        storage::{JournalConfig, SafetyJournal},
        test_utils::bench::fabric,
        types::{Artifact, ViewProof},
    },
    types::View,
};
use commonware_cryptography::{bls12381::primitives::variant::MinPk, sha256::Digest};
use commonware_runtime::{
    Handle, Storage as _, Supervisor as _, buffer::paged::CacheRef, tokio::Context as TokioContext,
};
use commonware_utils::{NZU16, NZUsize};
use core::fmt;
use std::{
    num::NonZeroUsize,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

const APPEND_RECORDS: usize = 256;

const REPLAY_RECORDS: usize = 1_000;

static PARTITION_SEQ: AtomicU64 = AtomicU64::new(0);

fn unique_partition(label: &str) -> String {
    format!(
        "multimmit-journal-{label}-{}",
        PARTITION_SEQ.fetch_add(1, Ordering::SeqCst)
    )
}

struct Harvest {
    profile: Profile<Digest>,
    jobs: Vec<PersistJob<MinPk, Digest>>,
}

/// Drives a live single-participant observer through nullified views until it has collected at
/// least `records` contiguous persistence jobs. `PersistJob` and `DomainEvent` are machine-issued
/// only, so real machine output is the only public source of journal input.
fn harvest(records: usize, seed: u64) -> Harvest {
    let committee = Committee::<MinPk>::builder(seed, 1).build();
    let profile: Profile<Digest> =
        Profile::new::<MinPk>(committee.config.clone(), Role::Observer, Tuning::default()).unwrap();
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
    for view in 1.. {
        if jobs.len() >= records {
            break;
        }
        let staged = fabric::absorb(
            &mut machine,
            vec![Artifact::Nullification(
                committee.nullification(View::new(view)),
            )],
        );
        fabric::drain_with(
            &mut machine,
            staged,
            NonZeroUsize::MIN,
            &mut |job| ViewProof::Nullification(Box::new(committee.nullification(job.view()))),
            &mut |job| jobs.push(job.clone()),
        );
    }
    Harvest { profile, jobs }
}

fn journal_config(
    pooler: &TokioContext,
    profile: &Profile<Digest>,
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
        replay_buffer: NZUsize!(64 * 1024),
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

// The harvest is lazy so filtered runs of the other bench groups do not pay for it.
static HARVEST: LazyLock<Arc<Harvest>> =
    LazyLock::new(|| Arc::new(harvest(APPEND_RECORDS.max(REPLAY_RECORDS), 99)));

/// Fixed real-store journal workloads.
///
/// Each workload's [`Display`](fmt::Display) form is its `operation/key=value` benchmark label.
#[derive(Clone, Copy, Debug)]
pub enum JournalScenario {
    /// Appends `records` jobs, waiting for each sync before the next append.
    AppendSerial {
        /// Jobs appended.
        records: usize,
    },
    /// Appends `records` jobs, starting each append before the previous sync completes.
    AppendPipelined {
        /// Jobs appended.
        records: usize,
    },
    /// Replays a freshly written journal of `records` records.
    Replay {
        /// Records replayed.
        records: usize,
    },
}

impl JournalScenario {
    /// Every workload the benchmark target measures.
    pub const ALL: [Self; 3] = [
        Self::AppendSerial {
            records: APPEND_RECORDS,
        },
        Self::AppendPipelined {
            records: APPEND_RECORDS,
        },
        Self::Replay {
            records: REPLAY_RECORDS,
        },
    ];
}

impl fmt::Display for JournalScenario {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AppendSerial { records } => write!(f, "append_serial/records={records}"),
            Self::AppendPipelined { records } => write!(f, "append_pipelined/records={records}"),
            Self::Replay { records } => write!(f, "replay/records={records}"),
        }
    }
}

/// Executes one journal workload in the benchmark runtime and returns only its measured region.
///
/// # Panics
///
/// Panics if a workload asks for more records than the shared harvest holds.
pub async fn run_journal(ctx: &TokioContext, scenario: JournalScenario) -> Duration {
    let harvest = HARVEST.clone();
    match scenario {
        JournalScenario::AppendSerial { records }
        | JournalScenario::AppendPipelined { records } => {
            let pipelined = matches!(scenario, JournalScenario::AppendPipelined { .. });
            let mode = if pipelined { "pipelined" } else { "serial" };
            let partition = unique_partition(mode);
            let config = journal_config(ctx, &harvest.profile, partition.clone());
            let journal = open_journal(ctx, config).await;
            let jobs = &harvest.jobs[..records];
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
        JournalScenario::Replay { records } => {
            let partition = unique_partition("replay");
            let config = journal_config(ctx, &harvest.profile, partition.clone());
            let journal = open_journal(ctx, config).await;
            let journal = append_pipelined(journal, &harvest.jobs[..records]).await;
            drop(journal);

            let config = journal_config(ctx, &harvest.profile, partition.clone());
            let started = Instant::now();
            let mut recovery = SafetyJournal::<_, MinPk, Digest>::open(
                ctx.child("journal"),
                config,
                Cursor::zero(),
            )
            .await
            .unwrap();
            let mut replayed = 0usize;
            while recovery.next().await.unwrap().is_some() {
                replayed += 1;
            }
            let journal = recovery.finish().unwrap();
            let elapsed = started.elapsed();
            assert_eq!(replayed, records, "replay must cover every record");
            drop(journal);
            ctx.remove(&partition, None).await.unwrap();
            elapsed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harvest_collects_the_requested_contiguous_records() {
        let records = 16;
        let harvest = harvest(records, 99);
        assert!(harvest.jobs.len() >= records);
        for pair in harvest.jobs.windows(2) {
            assert_eq!(pair[1].previous(), pair[0].last_cursor());
        }
    }
}
