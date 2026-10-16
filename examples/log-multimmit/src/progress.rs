//! Engine progress shared by the headless log and the terminal UI.

use crate::{LOG_TARGET, application::ProductionStats, bench::FinalityGoal};
use commonware_consensus::multimmit::{
    DeclarationCounts, DeclarationRule, Inspection, Inspector, ViewEnd, ViewEnds,
};
use commonware_cryptography::Digest;
use commonware_runtime::Clock;
use std::time::Duration;
use tracing::info;

/// How often headless mode inspects the engine and logs one progress line.
const PROGRESS_INTERVAL: Duration = Duration::from_secs(1);

/// Views this node sent its final vote for and their summed length.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ViewTotals {
    views: u64,
    millis: u64,
}

impl ViewTotals {
    const fn of(ends: &ViewEnds) -> Self {
        Self {
            views: ends.total(),
            millis: ends.total_millis(),
        }
    }

    /// Returns the totals of the views that ended after `previous`.
    const fn since(self, previous: Self) -> Self {
        Self {
            views: self.views.saturating_sub(previous.views),
            millis: self.millis.saturating_sub(previous.millis),
        }
    }

    /// Returns the mean view length in milliseconds, or zero without views.
    fn mean_millis(self) -> u64 {
        self.millis.checked_div(self.views).unwrap_or(0)
    }
}

/// The local producer's build state.
#[derive(Clone, Copy, Debug)]
pub struct Producer {
    /// The local producer chain.
    pub chain: u32,
    /// Latest locally produced height.
    pub produced: u64,
    /// Whether the application is building a block.
    pub building: bool,
    /// Whether a built block awaits durable custody before its header is signed.
    pub custody_pending: bool,
}

/// One producer chain's local progress.
#[derive(Clone, Copy, Debug)]
pub struct Chain {
    /// The producer chain.
    pub chain: u32,
    /// Greatest height this node knows to be final.
    pub finalized: u64,
    /// Greatest height at least n - 2f validators endorse.
    pub quorum: u64,
    /// Height of the locally accepted tip.
    pub accepted: u64,
}

/// Engine state reported by the headless log and the terminal UI.
#[derive(Clone, Debug)]
pub struct Summary {
    /// Current view.
    pub view: u64,
    /// Newest view whose tips consensus resolved.
    pub resolved: u64,
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
    /// The measured one-way delay `delta_hat` the current view's timers use, in milliseconds.
    pub delay_ms: u64,
    /// The measured per-block production interval `theta_hat`, in milliseconds.
    pub production_ms: u64,
    /// Why each view this node sent a final vote for ended, and their total length.
    pub view_ends: ViewEnds,
    /// Chains declared final per rule since the process started.
    pub declarations: DeclarationCounts,
}

impl Summary {
    /// Projects the fields shown to operators from one engine inspection.
    pub fn new<D: Digest>(inspection: &Inspection<D>) -> Self {
        Self {
            view: inspection.view().get(),
            resolved: inspection.last_resolved().get(),
            retired: inspection.retired_view().get(),
            live: inspection.is_live(),
            cached_artifacts: inspection.cached_artifacts(),
            outbox_effects: inspection.outbox_len(),
            verification_jobs: inspection.verification_jobs_len(),
            resolution_jobs: inspection.resolution_jobs(),
            producer: inspection.producer().map(|producer| Producer {
                chain: producer.chain().get(),
                produced: producer.produced().get(),
                building: producer.building(),
                custody_pending: producer.custody_pending(),
            }),
            chains: inspection
                .chain_progress()
                .iter()
                .map(|progress| Chain {
                    chain: progress.chain().get(),
                    finalized: progress.finalized().get(),
                    quorum: progress.quorum().get(),
                    accepted: progress.accepted().get(),
                })
                .collect(),
            delay_ms: inspection.delay_millis(),
            production_ms: inspection.production_millis(),
            view_ends: inspection.view_ends(),
            declarations: inspection.declarations(),
        }
    }

    /// Emits one structured progress line, with this producer's block latencies from `stats`
    /// and view lengths since the `previous` line's view totals.
    ///
    /// External tooling reads these lines to detect frozen views, halted producers, and
    /// unbounded lag, and to measure view lengths, view-end reasons, and block latencies.
    /// Field names are stable:
    ///
    /// - `view`, `resolved`, `retired`, `live`: current view, newest resolved view, durable
    ///   transition floor, and whether live inputs are processed.
    /// - `outbox`, `cached`, `verify_jobs`, `resolution_jobs`: outstanding engine work.
    /// - `chains`: each chain's accepted, quorum, and finalized heights.
    /// - `producer`: the local producer's height and build state, or `none`.
    /// - `delta_hat_ms`, `theta_hat_ms`: the delay and production interval estimates.
    /// - `views_ended_on_count`, `views_ended_at_bound`, `views_ended_by_declaration`: views
    ///   this node sent its final vote for, by reason, since the process started.
    /// - `mean_view_ms`: mean length of those views since the process started.
    /// - `view_ms_interval`: mean length of the views that ended since the previous line, or
    ///   zero when none did.
    /// - `declarations`: chains declared final per rule since the process started.
    /// - `signed_blocks`: this producer's signed blocks.
    /// - `build_to_signed_ms`, `production_to_ordered_ms`: mean time from the start of an own
    ///   block's construction to its header signature and to its ordered delivery.
    /// - `signed_to_final_ms`, `signed_to_ordered_ms`: mean time from an own block's header
    ///   signature to its first finality and to its ordered delivery, for blocks carrying input.
    /// - `final_within_goal_pct`: percentage of those blocks final within the goal
    ///   `2 * delta_hat + eta` captured at signing, among those with a known goal.
    /// - `final_in_signing_view_pct`, `views_waited_x100`: share of those blocks final in the
    ///   view they were signed in, and the mean views waited in hundredths.
    ///
    /// Latency means and shares are zero until a sample exists.
    fn log(&self, stats: &ProductionStats, previous: ViewTotals) {
        let chains = self
            .chains
            .iter()
            .map(|chain| {
                format!(
                    "C{} accepted={} quorum={} finalized={}",
                    chain.chain, chain.accepted, chain.quorum, chain.finalized,
                )
            })
            .collect::<Vec<_>>()
            .join(" ");
        let producer = self.producer.map(|producer| {
            format!(
                "produced={} building={} custody={}",
                producer.produced, producer.building, producer.custody_pending,
            )
        });
        let ends = &self.view_ends;
        let totals = ViewTotals::of(ends);
        let mean_view_ms = totals.mean_millis();
        let view_ms_interval = totals.since(previous).mean_millis();
        let declared = |rule| self.declarations.get(rule);
        let (final_in_signing_view_pct, views_waited_x100) =
            stats.views_waited().unwrap_or_default();
        let declarations = format!(
            "stopped={} late={} bound={} view_change={} split={} grace={} silent_leader={}",
            declared(DeclarationRule::Stopped),
            declared(DeclarationRule::Late),
            declared(DeclarationRule::Bound),
            declared(DeclarationRule::ViewChange),
            declared(DeclarationRule::Split),
            declared(DeclarationRule::Grace),
            declared(DeclarationRule::SilentLeader),
        );
        info!(
            target: LOG_TARGET,
            view = self.view,
            resolved = self.resolved,
            retired = self.retired,
            live = self.live,
            outbox = self.outbox_effects,
            cached = self.cached_artifacts,
            verify_jobs = self.verification_jobs,
            resolution_jobs = self.resolution_jobs,
            chains = %chains,
            producer = producer.as_deref().unwrap_or("none"),
            delta_hat_ms = self.delay_ms,
            theta_hat_ms = self.production_ms,
            views_ended_on_count = ends.get(ViewEnd::Count),
            views_ended_at_bound = ends.get(ViewEnd::Bound),
            views_ended_by_declaration = ends.get(ViewEnd::Declared),
            mean_view_ms,
            view_ms_interval,
            declarations = %declarations,
            signed_blocks = stats.signed_blocks(),
            build_to_signed_ms = stats.mean_signed().unwrap_or(0),
            production_to_ordered_ms = stats.mean_ordered().unwrap_or(0),
            signed_to_final_ms = stats.mean_signed_finalized().unwrap_or(0),
            signed_to_ordered_ms = stats.mean_signed_ordered().unwrap_or(0),
            final_within_goal_pct = stats.within_goal_pct().unwrap_or(0),
            final_in_signing_view_pct,
            views_waited_x100,
            "progress"
        );
    }
}

/// Logs one progress line per interval until the engine stops, refreshing `goal` from each
/// inspection.
pub async fn log<D: Digest>(
    context: &impl Clock,
    inspector: Inspector<D>,
    stats: ProductionStats,
    goal: FinalityGoal,
) {
    let mut previous = ViewTotals::default();
    while let Some(inspection) = inspector.inspect().await {
        let summary = Summary::new(&inspection);
        goal.refresh(summary.delay_ms);
        summary.log(&stats, previous);
        previous = ViewTotals::of(&summary.view_ends);
        context.sleep(PROGRESS_INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interval_view_length_covers_only_views_since_the_previous_line() {
        let previous = ViewTotals {
            views: 10,
            millis: 100_000,
        };
        let current = ViewTotals {
            views: 14,
            millis: 102_000,
        };
        assert_eq!(current.mean_millis(), 7_285);
        assert_eq!(current.since(previous).mean_millis(), 500);
        assert_eq!(current.since(current).mean_millis(), 0);
        assert_eq!(current.since(ViewTotals::default()), current);
    }
}
