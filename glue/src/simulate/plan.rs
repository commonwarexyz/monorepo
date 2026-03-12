//! Simulation plan: declarative test configuration with select-loop orchestration.

use super::{
    engine::EngineDefinition,
    exit::{ExitCondition, MinimumFinalizations},
    fault::{Crash, Fault, Schedule},
    property::{FinalizationProperty, Property},
    team::Team,
    tracker::{FinalizationUpdate, ProgressTracker},
};
use commonware_cryptography::PublicKey;
use commonware_macros::select_loop;
use commonware_p2p::{
    simulated::{self, Link, LinkSelector, Network},
    Manager as _,
};
use commonware_runtime::{deterministic, Clock, Metrics, Runner as _, Spawner};
use commonware_utils::{channel::mpsc, TryCollect};
use rand::seq::SliceRandom;
use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tracing::{error, info};

/// Command sent from the fault scheduler to the select loop.
enum ScheduleCmd<P: PublicKey> {
    Crash(P),
    Restart(P),
}

/// Result of a simulation run.
pub struct PlanResult<D: EngineDefinition> {
    /// Auditor state (deterministic hash) at simulation end.
    pub state: String,

    /// Final progress tracker state.
    pub tracker: ProgressTracker<D::PublicKey>,

    /// Number of validator crashes that occurred during the simulation.
    pub crashes: u64,

    /// Number of scheduled fault events that were applied.
    pub scheduled_faults: u64,

    /// Whether delayed validators were started (if Delay was configured).
    pub delayed_started: bool,
}

/// Declarative configuration for a simulation run.
///
/// All parameters needed to reproduce a test deterministically.
pub struct Plan<D: EngineDefinition> {
    /// Deterministic seed. Same seed produces identical execution.
    pub seed: u64,

    /// Participant public keys in order. The caller is responsible for
    /// generating these (e.g. via `PrivateKey::from_seed`).
    pub participants: Vec<D::PublicKey>,

    /// Network link configuration.
    pub link: Link,

    /// Maximum size of a p2p message (bytes).
    pub max_message_size: u32,

    /// Engine definition (how to wire up each validator).
    pub engine: D,

    /// Crash/fault injection strategies.
    pub faults: Vec<Crash<D::PublicKey>>,

    /// Number of finalizations required before the simulation stops.
    ///
    /// Used by the default exit condition when no custom condition is set.
    pub required_finalizations: u64,

    /// Exit condition that determines when the simulation should terminate.
    pub exit_condition: Box<dyn ExitCondition<D::PublicKey, D::State>>,

    /// Maximum simulation wall-clock time (deterministic time).
    pub timeout: Duration,

    /// Properties checked after each finalization.
    pub finalization_property: Vec<Box<dyn FinalizationProperty<D::State>>>,

    /// Properties checked once at simulation end with state and tracker access.
    pub property: Vec<Box<dyn Property<D::PublicKey, D::State>>>,
}

/// Builder for constructing a [`Plan`] with sensible defaults.
///
/// Only the engine is required. Everything else has defaults suitable
/// for quick tests.
pub struct PlanBuilder<D: EngineDefinition> {
    seed: u64,
    participants: Vec<D::PublicKey>,
    link: Link,
    max_message_size: u32,
    engine: D,
    faults: Vec<Crash<D::PublicKey>>,
    required_finalizations: u64,
    exit_condition: Option<Box<dyn ExitCondition<D::PublicKey, D::State>>>,
    timeout: Duration,
    finalization_property: Vec<Box<dyn FinalizationProperty<D::State>>>,
    property: Vec<Box<dyn Property<D::PublicKey, D::State>>>,
}

impl<D: EngineDefinition> PlanBuilder<D> {
    /// Create a builder with the required engine and sensible defaults.
    ///
    /// Participants are derived from the engine via
    /// [`EngineDefinition::participants`].
    ///
    /// Defaults: seed 0, 1MB max message size, good links (10ms latency,
    /// 5ms jitter, 100% success), no faults, 10 required finalizations,
    /// 120s timeout.
    pub fn new(engine: D) -> Self {
        let participants = engine.participants();
        Self {
            seed: 0,
            participants,
            link: Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(5),
                success_rate: 1.0,
            },
            max_message_size: 1024 * 1024,
            engine,
            faults: vec![],
            required_finalizations: 10,
            exit_condition: None,
            timeout: Duration::from_secs(120),
            finalization_property: vec![],
            property: vec![],
        }
    }

    pub const fn seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    pub const fn link(mut self, link: Link) -> Self {
        self.link = link;
        self
    }

    pub const fn max_message_size(mut self, size: u32) -> Self {
        self.max_message_size = size;
        self
    }

    pub fn crash(mut self, crash: Crash<D::PublicKey>) -> Self {
        match crash {
            Crash::Delay { .. } => assert!(
                !self
                    .faults
                    .iter()
                    .any(|fault| matches!(fault, Crash::Delay { .. })),
                "only one Crash::Delay fault may be configured"
            ),
            Crash::Random { .. } => assert!(
                !self
                    .faults
                    .iter()
                    .any(|fault| matches!(fault, Crash::Random { .. })),
                "only one Crash::Random fault may be configured"
            ),
            Crash::Schedule(_) => {}
        }
        self.faults.push(crash);
        self
    }

    pub const fn required_finalizations(mut self, n: u64) -> Self {
        self.required_finalizations = n;
        self
    }

    /// Override the default exit condition.
    pub fn exit_condition(
        mut self,
        condition: impl ExitCondition<D::PublicKey, D::State> + 'static,
    ) -> Self {
        self.exit_condition = Some(Box::new(condition));
        self
    }

    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn finalization_property(
        mut self,
        property: impl FinalizationProperty<D::State> + 'static,
    ) -> Self {
        self.finalization_property.push(Box::new(property));
        self
    }

    pub fn property(mut self, property: impl Property<D::PublicKey, D::State> + 'static) -> Self {
        self.property.push(Box::new(property));
        self
    }

    /// Build the [`Plan`].
    pub fn build(self) -> Plan<D> {
        let exit_condition = self
            .exit_condition
            .unwrap_or_else(|| Box::new(MinimumFinalizations::new(self.required_finalizations)));
        Plan {
            seed: self.seed,
            participants: self.participants,
            link: self.link,
            max_message_size: self.max_message_size,
            engine: self.engine,
            faults: self.faults,
            required_finalizations: self.required_finalizations,
            exit_condition,
            timeout: self.timeout,
            finalization_property: self.finalization_property,
            property: self.property,
        }
    }

    /// Build and run the plan in one step.
    pub fn run(self) -> Result<PlanResult<D>, String> {
        self.build().run()
    }
}

impl<D: EngineDefinition> Plan<D> {
    fn delay_fault(&self) -> Option<(usize, u64)> {
        self.faults.iter().find_map(|fault| match fault {
            Crash::Delay { count, after } => Some((*count, *after)),
            _ => None,
        })
    }

    fn random_fault(&self) -> Option<(Duration, Duration, usize)> {
        self.faults.iter().find_map(|fault| match fault {
            Crash::Random {
                frequency,
                downtime,
                count,
            } => Some((*frequency, *downtime, *count)),
            _ => None,
        })
    }

    fn schedules(&self) -> impl Iterator<Item = &Schedule<D::PublicKey>> {
        self.faults.iter().filter_map(|fault| match fault {
            Crash::Schedule(schedule) => Some(schedule),
            _ => None,
        })
    }

    /// Determine which participants should be delayed at startup.
    fn delayed_participants(&self) -> HashSet<D::PublicKey> {
        if let Some((count, _)) = self.delay_fault() {
            self.participants.iter().take(count).cloned().collect()
        } else {
            HashSet::new()
        }
    }

    /// Run the simulation. This is the main async entry point.
    async fn run_inner(self, mut ctx: deterministic::Context) -> Result<PlanResult<D>, String> {
        let (network, oracle) = Network::<_, D::PublicKey>::new(
            ctx.with_label("network"),
            simulated::Config {
                max_size: self.max_message_size,
                disconnect_on_block: true,
                tracked_peer_sets: Some(3),
            },
        );
        network.start();

        // Seed initial peers so resolver subscriptions can reconcile immediately.
        let mut manager = oracle.manager();
        manager
            .track(
                0,
                self.participants
                    .iter()
                    .cloned()
                    .try_collect()
                    .expect("participants must be unique"),
            )
            .await;

        let total = self.participants.len();
        let mut team = Team::new(self.engine.clone(), self.participants.clone());
        let (monitor_tx, mut monitor_rx) = mpsc::channel::<FinalizationUpdate<D::PublicKey>>(1024);
        let (restart_tx, mut restart_rx) = mpsc::channel::<D::PublicKey>(10);
        let (crash_tx, mut crash_rx) = mpsc::channel::<()>(1);
        let (schedule_tx, mut schedule_rx) = mpsc::channel::<ScheduleCmd<D::PublicKey>>(10);
        let scheduled_faults = Arc::new(AtomicU64::new(0));

        let delayed = self.delayed_participants();
        team.start(
            &ctx,
            &oracle,
            self.link.clone(),
            monitor_tx.clone(),
            &delayed,
        )
        .await;

        // Spawn crash ticker for Random crashes.
        if let Some((frequency, _, _)) = self.random_fault() {
            let crash_tx = crash_tx.clone();
            ctx.clone().spawn(move |ctx| async move {
                loop {
                    ctx.sleep(frequency).await;
                    if crash_tx.send(()).await.is_err() {
                        break;
                    }
                }
            });
        }

        // Spawn fault schedule actors.
        for schedule in self.schedules() {
            let schedule = schedule.clone();
            let oracle_clone = oracle.clone();
            let participants = self.participants.clone();
            let schedule_tx_clone = schedule_tx.clone();
            let scheduled_faults_clone = scheduled_faults.clone();
            ctx.clone().spawn(move |ctx| async move {
                Self::run_fault_scheduler(
                    ctx,
                    schedule,
                    &oracle_clone,
                    &participants,
                    schedule_tx_clone,
                    scheduled_faults_clone,
                )
                .await;
            });
        }

        let mut tracker = ProgressTracker::default();
        let mut delayed_started = false;
        let active_count = total - delayed.len();
        let mut crashes: u64 = 0;
        let mut result: Result<PlanResult<D>, String> =
            Err("simulation stopped before completion".into());
        const EXIT_POLL: Duration = Duration::from_millis(25);

        select_loop! {
            ctx,
            on_stopped => {
                result = Err("simulation stopped".into());
            },
            Some(update) = monitor_rx.recv() else {
                result = Err("monitor channel closed".into());
                break;
            } => {
                tracker.observe(update)?;

                // Check finalization properties
                let states = team.active_states();
                for prop in &self.finalization_property {
                    match prop.check(&states).await {
                        Ok(()) => {
                            info!(
                                target: "simulator",
                                property = prop.name(),
                                "finalization property passed"
                            );
                        }
                        Err(e) => {
                            error!(
                                target: "simulator",
                                property = prop.name(),
                                error = %e,
                                "finalization property failed"
                            );
                            return Err(format!(
                                "finalization property violation ({}): {e}",
                                prop.name()
                            ));
                        }
                    }
                }

                // Check termination.
                let target_count = if delayed_started {
                    total
                } else {
                    active_count
                };
                let states = team.active_states();
                let done = self
                    .exit_condition
                    .reached(&tracker, &states, target_count)
                    .await
                    .map_err(|e| {
                        format!(
                            "exit condition evaluation failed ({}): {e}",
                            self.exit_condition.name()
                        )
                    })?;
                if done {
                    // Check post-run properties
                    for prop in &self.property {
                        match prop.check(&tracker, &states).await {
                            Ok(()) => {
                                info!(
                                    target: "simulator",
                                    property = prop.name(),
                                    "post-run property passed"
                                );
                            }
                            Err(e) => {
                                error!(
                                    target: "simulator",
                                    property = prop.name(),
                                    error = %e,
                                    "post-run property failed"
                                );
                                return Err(format!(
                                    "post-run property violation ({}): {e}",
                                    prop.name()
                                ));
                            }
                        }
                    }
                    let scheduled_faults_applied = scheduled_faults.load(Ordering::Relaxed);

                    info!(
                        target: "simulator",
                        required = self.required_finalizations,
                        exit_condition = self.exit_condition.name(),
                        crashes,
                        scheduled_faults = scheduled_faults_applied,
                        delayed_started,
                        "all validators reached required progress"
                    );
                    result = Ok(PlanResult {
                        state: ctx.auditor().state(),
                        tracker,
                        crashes,
                        scheduled_faults: scheduled_faults_applied,
                        delayed_started,
                    });
                    break;
                }

                // Start delayed validators after enough progress
                if !delayed_started {
                    if let Some((_, after)) = self.delay_fault() {
                        if tracker.min_view() >= after {
                            info!(target: "simulator", "starting delayed participants");
                            for pk in &delayed {
                                team.start_one(
                                    &ctx,
                                    &oracle,
                                    pk.clone(),
                                    monitor_tx.clone(),
                                )
                                .await;
                            }
                            delayed_started = true;
                        }
                    }
                }
            },
            _ = ctx.sleep(EXIT_POLL) => {
                if !self.exit_condition.requires_polling() {
                    continue;
                }
                let target_count = if delayed_started {
                    total
                } else {
                    active_count
                };
                let states = team.active_states();
                let done = self
                    .exit_condition
                    .reached(&tracker, &states, target_count)
                    .await
                    .map_err(|e| {
                        format!(
                            "exit condition evaluation failed ({}): {e}",
                            self.exit_condition.name()
                        )
                    })?;
                if !done {
                    continue;
                }

                // Check post-run properties
                for prop in &self.property {
                    match prop.check(&tracker, &states).await {
                        Ok(()) => {
                            info!(
                                target: "simulator",
                                property = prop.name(),
                                "post-run property passed"
                            );
                        }
                        Err(e) => {
                            error!(
                                target: "simulator",
                                property = prop.name(),
                                error = %e,
                                "post-run property failed"
                            );
                            return Err(format!(
                                "post-run property violation ({}): {e}",
                                prop.name()
                            ));
                        }
                    }
                }
                let scheduled_faults_applied = scheduled_faults.load(Ordering::Relaxed);

                info!(
                    target: "simulator",
                    required = self.required_finalizations,
                    exit_condition = self.exit_condition.name(),
                    crashes,
                    scheduled_faults = scheduled_faults_applied,
                    delayed_started,
                    "all validators reached required progress"
                );
                result = Ok(PlanResult {
                    state: ctx.auditor().state(),
                    tracker,
                    crashes,
                    scheduled_faults: scheduled_faults_applied,
                    delayed_started,
                });
                break;
            },
            Some(pk) = restart_rx.recv() else break => {
                team.restart(&ctx, &oracle, pk, monitor_tx.clone()).await;
            },
            Some(cmd) = schedule_rx.recv() else break => {
                match cmd {
                    ScheduleCmd::Crash(pk) => {
                        team.crash(&pk);
                        crashes += 1;
                    }
                    ScheduleCmd::Restart(pk) => {
                        team.restart(&ctx, &oracle, pk, monitor_tx.clone()).await;
                    }
                }
            },
            _ = crash_rx.recv() => {
                let Some((_, downtime, count)) = self.random_fault() else {
                    continue;
                };
                let active = team.active_keys();
                let crash_count = count.min(active.len());
                let to_crash: Vec<D::PublicKey> = active
                    .choose_multiple(&mut ctx, crash_count)
                    .cloned()
                    .collect();
                for pk in to_crash {
                    if !team.crash(&pk) {
                        continue;
                    }
                    crashes += 1;
                    let restart_tx = restart_tx.clone();
                    ctx.clone().spawn(move |ctx| async move {
                        if downtime > Duration::ZERO {
                            ctx.sleep(downtime).await;
                        }
                        let _ = restart_tx.send(pk).await;
                    });
                }
            },
        }

        // Assert that configured faults were actually exercised.
        if let Ok(ref r) = result {
            if self.random_fault().is_some() {
                assert!(
                    r.crashes > 0,
                    "Crash::Random configured but no crashes occurred. \
                     Increase required_finalizations or decrease crash frequency."
                );
            }

            let scheduled_events: usize =
                self.schedules().map(|schedule| schedule.events.len()).sum();
            if scheduled_events > 0 {
                assert!(
                    r.scheduled_faults > 0,
                    "Crash::Schedule configured with {} events but none were applied. \
                     Schedule events may be timed after consensus completes.",
                    scheduled_events
                );
            }

            if self.delay_fault().is_some() {
                assert!(
                    r.delayed_started,
                    "Crash::Delay configured but delayed validators were never started. \
                     Increase required_finalizations or decrease the `after` threshold."
                );
            }
        }

        result
    }

    /// Fault schedule executor -- sleeps until each scheduled time and
    /// applies the fault. Network faults are applied directly via the
    /// oracle; node faults (crash/restart) are sent as commands to the
    /// select loop which owns the team.
    async fn run_fault_scheduler(
        ctx: deterministic::Context,
        schedule: Schedule<D::PublicKey>,
        oracle: &simulated::Oracle<D::PublicKey, deterministic::Context>,
        participants: &[D::PublicKey],
        cmd_tx: mpsc::Sender<ScheduleCmd<D::PublicKey>>,
        faults_applied: Arc<AtomicU64>,
    ) {
        let start = ctx.current();
        for (time, fault) in schedule.events {
            let elapsed = ctx
                .current()
                .duration_since(start)
                .unwrap_or(Duration::ZERO);
            if time > elapsed {
                ctx.sleep(time - elapsed).await;
            }
            match fault {
                Fault::Partition { ref a, ref b } => {
                    for pa in a {
                        for pb in b {
                            let _ = oracle.remove_link(pa.clone(), pb.clone()).await;
                            let _ = oracle.remove_link(pb.clone(), pa.clone()).await;
                        }
                    }
                    faults_applied.fetch_add(1, Ordering::Relaxed);
                    info!(target: "simulator", "partition applied");
                }
                Fault::Heal(ref link) => {
                    for v1 in participants {
                        for v2 in participants {
                            if v1 == v2 {
                                continue;
                            }
                            let _ = oracle.remove_link(v1.clone(), v2.clone()).await;
                            let _ = oracle.add_link(v1.clone(), v2.clone(), link.clone()).await;
                        }
                    }
                    faults_applied.fetch_add(1, Ordering::Relaxed);
                    info!(target: "simulator", "partition healed");
                }
                Fault::UpdateLink {
                    ref from,
                    ref to,
                    ref link,
                } => {
                    let _ = oracle.remove_link(from.clone(), to.clone()).await;
                    let _ = oracle
                        .add_link(from.clone(), to.clone(), link.clone())
                        .await;
                    faults_applied.fetch_add(1, Ordering::Relaxed);
                    info!(target: "simulator", ?from, ?to, "link updated");
                }
                Fault::UpdateChannelLink {
                    ref from,
                    ref to,
                    channel,
                    ref link,
                } => {
                    let _ = oracle
                        .remove_link_selected(
                            from.clone(),
                            to.clone(),
                            LinkSelector::Channel(channel),
                        )
                        .await;
                    let _ = oracle
                        .add_link_selected(
                            from.clone(),
                            to.clone(),
                            LinkSelector::Channel(channel),
                            link.clone(),
                        )
                        .await;
                    faults_applied.fetch_add(1, Ordering::Relaxed);
                    info!(target: "simulator", ?from, ?to, channel, "channel link updated");
                }
                Fault::Crash(ref pk) => {
                    if cmd_tx.send(ScheduleCmd::Crash(pk.clone())).await.is_err() {
                        break;
                    }
                    faults_applied.fetch_add(1, Ordering::Relaxed);
                }
                Fault::Restart(ref pk) => {
                    if cmd_tx.send(ScheduleCmd::Restart(pk.clone())).await.is_err() {
                        break;
                    }
                    faults_applied.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// Run the simulation synchronously.
    ///
    /// Creates a deterministic runner with the plan's seed and timeout,
    /// then executes the simulation.
    pub fn run(self) -> Result<PlanResult<D>, String> {
        let seed = self.seed;
        let timeout = self.timeout;
        let cfg = deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(timeout));
        let runner = deterministic::Runner::new(cfg);
        runner.start(|ctx| self.run_inner(ctx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_consensus::types::View;
    use commonware_cryptography::{ed25519, Signer as _};
    use commonware_runtime::{Clock, Handle, Quota, Spawner};
    use std::{future::Future, pin::Pin};

    #[derive(Clone)]
    struct FinalizingEngine {
        participants: Vec<ed25519::PublicKey>,
        finalize_after: Duration,
        finalizations: u64,
    }

    struct FinalizingNode {
        context: deterministic::Context,
        monitor: mpsc::Sender<FinalizationUpdate<ed25519::PublicKey>>,
        pk: ed25519::PublicKey,
        finalize_after: Duration,
        finalizations: u64,
    }

    impl FinalizingEngine {
        fn new(num_validators: u64, finalize_after: Duration, finalizations: u64) -> Self {
            let participants = (0..num_validators)
                .map(|seed| ed25519::PrivateKey::from_seed(seed).public_key())
                .collect();
            Self {
                participants,
                finalize_after,
                finalizations,
            }
        }
    }

    impl EngineDefinition for FinalizingEngine {
        type PublicKey = ed25519::PublicKey;
        type Engine = FinalizingNode;
        type State = ();

        fn participants(&self) -> Vec<Self::PublicKey> {
            self.participants.clone()
        }

        fn channels(&self) -> Vec<(u64, Quota)> {
            vec![]
        }

        fn init(
            &self,
            ctx: super::super::engine::InitContext<'_, Self::PublicKey>,
        ) -> impl Future<Output = (Self::Engine, Self::State)> + Send {
            let finalize_after = self.finalize_after;
            let finalizations = self.finalizations;
            async move {
                (
                    FinalizingNode {
                        context: ctx.context,
                        monitor: ctx.monitor,
                        pk: ctx.public_key.clone(),
                        finalize_after,
                        finalizations,
                    },
                    (),
                )
            }
        }

        fn start(engine: Self::Engine) -> Handle<()> {
            let pk = engine.pk;
            let monitor = engine.monitor;
            let finalize_after = engine.finalize_after;
            let finalizations = engine.finalizations;
            engine.context.spawn(move |ctx| async move {
                if finalize_after > Duration::ZERO {
                    ctx.sleep(finalize_after).await;
                }
                for view in 1..=finalizations {
                    let _ = monitor
                        .send(FinalizationUpdate {
                            pk: pk.clone(),
                            view: View::new(view),
                            block_digest: vec![view as u8],
                        })
                        .await;
                }
            })
        }
    }

    struct AtLeastTrackedValidators {
        min: usize,
    }

    impl ExitCondition<ed25519::PublicKey, ()> for AtLeastTrackedValidators {
        fn name(&self) -> &str {
            "at_least_tracked_validators"
        }

        fn reached<'a>(
            &'a self,
            tracker: &'a ProgressTracker<ed25519::PublicKey>,
            _states: &'a [&'a ()],
            _target_count: usize,
        ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + 'a>> {
            Box::pin(async move { Ok(tracker.tracked_count() >= self.min) })
        }
    }

    #[test]
    fn schedule_fault_applied_before_completion_is_counted() {
        let link = Link {
            latency: Duration::from_millis(10),
            jitter: Duration::from_millis(0),
            success_rate: 1.0,
        };
        let result = PlanBuilder::new(FinalizingEngine::new(1, Duration::from_millis(100), 1))
            .required_finalizations(1)
            .timeout(Duration::from_secs(2))
            .crash(Crash::Schedule(
                Schedule::new()
                    .at(Duration::from_millis(1), Fault::Heal(link.clone()))
                    .at(Duration::from_secs(5), Fault::Heal(link)),
            ))
            .run()
            .expect("simulation should complete");
        assert!(
            result.scheduled_faults >= 1,
            "expected at least one applied fault before completion, got {}",
            result.scheduled_faults
        );
    }

    #[test]
    fn delay_and_schedule_faults_compose() {
        let link = Link {
            latency: Duration::from_millis(10),
            jitter: Duration::from_millis(0),
            success_rate: 1.0,
        };
        let result = PlanBuilder::new(FinalizingEngine::new(2, Duration::from_millis(100), 2))
            .required_finalizations(2)
            .timeout(Duration::from_secs(2))
            .crash(Crash::Delay { count: 1, after: 1 })
            .crash(Crash::Schedule(
                Schedule::new().at(Duration::from_millis(1), Fault::Heal(link)),
            ))
            .run()
            .expect("simulation should complete");
        assert!(
            result.delayed_started,
            "delayed validator should still start when schedule faults are also configured"
        );
        assert!(
            result.scheduled_faults >= 1,
            "scheduled faults should still run when delay faults are also configured"
        );
    }

    #[test]
    fn custom_exit_condition_overrides_required_finalizations() {
        let result = PlanBuilder::new(FinalizingEngine::new(2, Duration::from_millis(10), 1))
            .required_finalizations(100)
            .exit_condition(AtLeastTrackedValidators { min: 2 })
            .timeout(Duration::from_secs(2))
            .run()
            .expect("simulation should complete with custom exit condition");

        assert_eq!(
            result.tracker.tracked_count(),
            2,
            "custom exit condition should see both validators"
        );
    }
}
