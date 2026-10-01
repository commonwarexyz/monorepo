//! Engine progress shared by the headless log and the terminal UI.

use crate::LOG_TARGET;
use commonware_consensus::multimmit::{Inspection, Inspector};
use commonware_cryptography::Digest;
use commonware_runtime::Clock;
use std::time::Duration;
use tracing::info;

/// How often headless mode inspects the engine and logs one progress line.
const PROGRESS_INTERVAL: Duration = Duration::from_secs(1);

/// The local producer's build state.
#[derive(Clone, Copy, Debug)]
pub struct Producer {
    /// The local producer chain.
    pub chain: u32,
    /// Latest locally produced height.
    pub produced: u64,
    /// Latest locally held DA-certified height.
    pub certified: u64,
    /// DA shares needed for a certificate.
    pub da_quorum: usize,
    /// Whether the DA pipeline window blocks another build.
    pub pipeline_blocked: bool,
    /// Whether durable-effect capacity permits another build.
    pub production_credit: bool,
}

/// One producer chain's local progress.
#[derive(Clone, Copy, Debug)]
pub struct Chain {
    /// The producer chain.
    pub chain: u32,
    /// Greatest height established by retained local finality.
    pub finalized: u64,
    /// Greatest height backed by a retained DA certificate.
    pub certified: u64,
    /// Greatest locally usable, certified, or finalized height.
    pub known: u64,
}

/// Engine state reported by the headless log and the terminal UI.
#[derive(Clone, Debug)]
pub struct Summary {
    /// Current view.
    pub view: u64,
    /// Durable consensus signing floor.
    pub finality_floor: u64,
    /// Durable transition floor.
    pub retired: u64,
    /// Whether normal live inputs may be processed.
    pub live: bool,
    /// Retained artifact records.
    pub cached_artifacts: usize,
    /// Durable external actions awaiting acknowledgement.
    pub outbox_effects: usize,
    /// Outstanding verification jobs.
    pub verification_jobs: usize,
    /// Outstanding resolution requests.
    pub resolution_jobs: usize,
    /// The local producer's state, when this node produces.
    pub producer: Option<Producer>,
    /// Every producer chain's progress, in chain order.
    pub chains: Vec<Chain>,
}

impl Summary {
    /// Projects the fields shown to operators from one engine inspection.
    pub fn new<D: Digest>(inspection: &Inspection<D>) -> Self {
        Self {
            view: inspection.view().get(),
            finality_floor: inspection.finality_floor().get(),
            retired: inspection.retired_view().get(),
            live: inspection.is_live(),
            cached_artifacts: inspection.cached_artifacts(),
            outbox_effects: inspection.outbox_len(),
            verification_jobs: inspection.verification_jobs_len(),
            resolution_jobs: inspection.resolution_jobs(),
            producer: inspection.producer().map(|producer| Producer {
                chain: producer.chain().get(),
                produced: producer.produced().get(),
                certified: producer.certified().get(),
                da_quorum: producer.da_quorum(),
                pipeline_blocked: producer.pipeline_blocked(),
                production_credit: producer.production_credit(),
            }),
            chains: inspection
                .chain_progress()
                .iter()
                .map(|progress| Chain {
                    chain: progress.chain().get(),
                    finalized: progress.finalized().get(),
                    certified: progress.certified().get(),
                    known: progress.known().get(),
                })
                .collect(),
        }
    }

    /// Emits one structured progress line.
    ///
    /// External tooling reads these lines to detect frozen views, halted producers, and
    /// unbounded lag.
    fn log(&self) {
        let chains = self
            .chains
            .iter()
            .map(|chain| {
                format!(
                    "C{} known={} certified={} finalized={}",
                    chain.chain, chain.known, chain.certified, chain.finalized,
                )
            })
            .collect::<Vec<_>>()
            .join(" ");
        let producer = self.producer.map(|producer| {
            format!(
                "produced={} certified={} blocked={} credit={}",
                producer.produced,
                producer.certified,
                producer.pipeline_blocked,
                producer.production_credit,
            )
        });
        info!(
            target: LOG_TARGET,
            view = self.view,
            floor = self.finality_floor,
            retired = self.retired,
            live = self.live,
            outbox = self.outbox_effects,
            cached = self.cached_artifacts,
            verify_jobs = self.verification_jobs,
            resolution_jobs = self.resolution_jobs,
            chains = %chains,
            producer = producer.as_deref().unwrap_or("none"),
            "progress"
        );
    }
}

/// Logs one progress line per interval until the engine stops.
pub async fn log<D: Digest>(context: &impl Clock, inspector: Inspector<D>) {
    while let Some(inspection) = inspector.inspect().await {
        Summary::new(&inspection).log();
        context.sleep(PROGRESS_INTERVAL).await;
    }
}
