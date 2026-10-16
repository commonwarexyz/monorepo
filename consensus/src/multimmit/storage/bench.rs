//! Journal benchmarks: appending and replaying persistence jobs on a real store.

use crate::{
    Epochable as _,
    multimmit::{
        config::{Profile, Role, Tuning},
        machine::{BatchId, Change, Cursor, DomainEvent, Generation, PersistJob},
        mocks::Committee,
        storage::{JournalConfig, SafetyJournal},
        types::Artifact,
    },
    types::View,
};
use commonware_cryptography::{bls12381::primitives::variant::MinPk, sha256::Digest};
use commonware_runtime::{
    Handle, Storage as _, Supervisor as _,
    buffer::paged::{self, CacheRef},
    tokio::Context as TokioContext,
};
use commonware_utils::NZUsize;
use core::fmt;
use std::{
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

/// Builds `records` contiguous persistence jobs, each retaining one V-QC.
///
/// A V-QC is the largest artifact a barrier routinely carries, so the jobs exercise the journal
/// with realistic record sizes without driving a machine.
fn harvest(records: usize, seed: u64) -> Harvest {
    let committee = Committee::<MinPk>::builder(seed, 6).build();
    let profile: Profile<Digest> =
        Profile::new::<MinPk>(committee.config.clone(), Role::Observer, Tuning::default()).unwrap();
    let epoch = profile.protocol().epoch();
    let certificate = Arc::new(Artifact::Vqc(committee.vqc(View::new(1))));
    let generation = Generation::new(1);
    let jobs = (0..records as u64)
        .map(|index| {
            let event = DomainEvent::new(
                epoch,
                Cursor::new(index + 1),
                Change::CertificateCreated {
                    artifact: certificate.clone(),
                },
            );
            PersistJob::new(
                BatchId::new(index + 1),
                generation,
                Cursor::new(index),
                vec![event],
                false,
            )
        })
        .collect();
    Harvest { profile, jobs }
}

fn journal_config(
    pooler: &TokioContext,
    profile: &Profile<Digest>,
    partition: String,
) -> JournalConfig {
    let page_cache = CacheRef::from_pooler(pooler, paged::page_size(4_096), NZUsize!(256));
    JournalConfig::from_profile(profile, partition, page_cache)
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

/// Appends `jobs` keeping one sync in flight: each job is appended and its sync started before
/// the previous job's sync is awaited.
async fn append_pipelined(
    mut journal: SafetyJournal<TokioContext, MinPk, Digest>,
    jobs: &[PersistJob<MinPk, Digest>],
) -> SafetyJournal<TokioContext, MinPk, Digest> {
    let mut previous: Option<Handle<()>> = None;
    for job in jobs {
        let (next, _, sync) = journal.start_persist(job).await.unwrap();
        journal = next;
        if let Some(handle) = previous.replace(sync) {
            handle.await.unwrap();
        }
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
    fn harvest_builds_the_requested_contiguous_records() {
        let records = 16;
        let harvest = harvest(records, 99);
        assert_eq!(harvest.jobs.len(), records);
        for pair in harvest.jobs.windows(2) {
            assert_eq!(pair[1].previous(), pair[0].last_cursor());
        }
    }
}
