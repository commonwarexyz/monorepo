//! Simulation plan: declarative test configuration with select-loop orchestration.

use super::{
    action::{Action, Crash, Schedule},
    engine::EngineDefinition,
    exit::{ExitCondition, MinimumFinalizations},
    property::{FinalizationProperty, Property},
    team::Team,
    tracker::{FinalizationUpdate, ProgressTracker},
};
use commonware_cryptography::PublicKey;
use commonware_macros::select_loop;
use commonware_p2p::{
    simulated::{self, Link, Network},
    Manager as _,
};
use commonware_runtime::{deterministic, Clock, Metrics, Runner as _, Spawner};
use commonware_utils::{channel::mpsc, ordered::Set, NZUsize, TryCollect};
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

/// Command sent from the action scheduler to the select loop.
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

    /// Number of scheduled actions that were applied.
    pub scheduled_actions: u64,

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

    /// Crash/action injection strategies.
    pub crashes: Vec<Crash<D::PublicKey>>,

    /// Number of finalizations required before the simulation stops.
    ///
    /// Used by the default exit condition when no custom condition is set.
    pub required_finalizations: u64,

    /// Exit condition that determines when the simulation should terminate.
    pub exit_condition: Box<dyn ExitCondition<D::PublicKey, D::State>>,

    /// Maximum simulation wall-clock time (deterministic time).
    pub timeout: Option<Duration>,

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
    seeds: Vec<u64>,
    participants: Vec<D::PublicKey>,
    link: Link,
    max_message_size: u32,
    engine: D,
    crashes: Vec<Crash<D::PublicKey>>,
    required_finalizations: u64,
    exit_condition: Option<ExitConditionFactory<D>>,
    timeout: Option<Duration>,
    finalization_property: Vec<FinalizationPropertyFactory<D>>,
    property: Vec<PropertyFactory<D>>,
}

type ExitConditionFactory<D> = Box<
    dyn Fn() -> Box<
        dyn ExitCondition<<D as EngineDefinition>::PublicKey, <D as EngineDefinition>::State>,
    >,
>;

type FinalizationPropertyFactory<D> =
    Box<dyn Fn() -> Box<dyn FinalizationProperty<<D as EngineDefinition>::State>>>;

type PropertyFactory<D> = Box<
    dyn Fn()
        -> Box<dyn Property<<D as EngineDefinition>::PublicKey, <D as EngineDefinition>::State>>,
>;

impl<D: EngineDefinition> PlanBuilder<D> {
    /// Create a builder with the required engine and sensible defaults.
    ///
    /// Participants are derived from the engine via
    /// [`EngineDefinition::participants`].
    ///
    /// Defaults: seed 0, 1MB max message size, good links (10ms latency,
    /// 5ms jitter, 100% success), no crashes, 10 required finalizations,
    /// no timeout.
    pub fn new(engine: D) -> Self {
        let participants = engine.participants();
        Self {
            seeds: vec![0],
            participants,
            link: Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(5),
                success_rate: 1.0,
            },
            max_message_size: 1024 * 1024,
            engine,
            crashes: vec![],
            required_finalizations: 10,
            exit_condition: None,
            timeout: None,
            finalization_property: vec![],
            property: vec![],
        }
    }

    /// Set the deterministic seeds used by [`Self::run`].
    ///
    /// At least one seed must be provided.
    pub fn seeds(mut self, seeds: impl IntoIterator<Item = u64>) -> Self {
        let seeds: Vec<u64> = seeds.into_iter().collect();
        assert!(!seeds.is_empty(), "at least one seed must be configured");
        self.seeds = seeds;
        self
    }

    /// Convenience method for configuring a single seed.
    pub fn seed(self, seed: u64) -> Self {
        self.seeds([seed])
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
                    .crashes
                    .iter()
                    .any(|crash| matches!(crash, Crash::Delay { .. })),
                "only one Crash::Delay strategy may be configured"
            ),
            Crash::Random { .. } => assert!(
                !self
                    .crashes
                    .iter()
                    .any(|crash| matches!(crash, Crash::Random { .. })),
                "only one Crash::Random strategy may be configured"
            ),
            Crash::Schedule(_) => {}
        }
        self.crashes.push(crash);
        self
    }

    pub const fn required_finalizations(mut self, n: u64) -> Self {
        self.required_finalizations = n;
        self
    }

    /// Override the default exit condition.
    pub fn exit_condition(
        mut self,
        condition: impl ExitCondition<D::PublicKey, D::State> + Clone + 'static,
    ) -> Self {
        self.exit_condition = Some(Box::new(move || Box::new(condition.clone())));
        self
    }

    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn finalization_property(
        mut self,
        property: impl FinalizationProperty<D::State> + Clone + 'static,
    ) -> Self {
        self.finalization_property
            .push(Box::new(move || Box::new(property.clone())));
        self
    }

    pub fn property(
        mut self,
        property: impl Property<D::PublicKey, D::State> + Clone + 'static,
    ) -> Self {
        self.property
            .push(Box::new(move || Box::new(property.clone())));
        self
    }

    /// Build the [`Plan`].
    pub fn build(self) -> Plan<D> {
        let seed = self
            .seeds
            .first()
            .copied()
            .expect("at least one seed must be configured");
        self.build_with_seed(seed)
    }

    fn build_with_seed(&self, seed: u64) -> Plan<D> {
        let exit_condition = self.exit_condition.as_ref().map_or_else(
            || Box::new(MinimumFinalizations::new(self.required_finalizations)) as _,
            |factory| factory(),
        );
        let finalization_property = self
            .finalization_property
            .iter()
            .map(|factory| factory())
            .collect();
        let property = self.property.iter().map(|factory| factory()).collect();
        Plan {
            seed,
            participants: self.participants.clone(),
            link: self.link.clone(),
            max_message_size: self.max_message_size,
            engine: self.engine.clone(),
            crashes: self.crashes.clone(),
            required_finalizations: self.required_finalizations,
            exit_condition,
            timeout: self.timeout,
            finalization_property,
            property,
        }
    }

    /// Build a fresh plan per seed and run each simulation.
    pub fn run(self) -> Result<Vec<PlanResult<D>>, String> {
        let mut results = Vec::with_capacity(self.seeds.len());
        for &seed in &self.seeds {
            let plan = self.build_with_seed(seed);
            let result = plan.run().map_err(|e| format!("seed {seed}: {e}"))?;
            results.push(result);
        }
        Ok(results)
    }
}

impl<D: EngineDefinition> Plan<D> {
    fn delay_crash(&self) -> Option<(usize, u64)> {
        self.crashes.iter().find_map(|crash| match crash {
            Crash::Delay { count, after } => Some((*count, *after)),
            _ => None,
        })
    }

    fn random_crash(&self) -> Option<(Duration, Duration, usize)> {
        self.crashes.iter().find_map(|crash| match crash {
            Crash::Random {
                frequency,
                downtime,
                count,
            } => Some((*frequency, *downtime, *count)),
            _ => None,
        })
    }

    fn schedules(&self) -> impl Iterator<Item = &Schedule<D::PublicKey>> {
        self.crashes.iter().filter_map(|crash| match crash {
            Crash::Schedule(schedule) => Some(schedule),
            _ => None,
        })
    }

    /// Determine which participants should be delayed at startup.
    fn delayed_participants(&self) -> HashSet<D::PublicKey> {
        if let Some((count, _)) = self.delay_crash() {
            self.participants.iter().take(count).cloned().collect()
        } else {
            HashSet::new()
        }
    }

    /// Check post-run properties, log completion, and build the result.
    async fn finish(
        &self,
        ctx: &deterministic::Context,
        tracker: ProgressTracker<D::PublicKey>,
        team: &Team<D>,
        crashes: u64,
        scheduled_actions: &AtomicU64,
        delayed_started: bool,
    ) -> Result<PlanResult<D>, String> {
        let states = team.active_states();
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
        let scheduled_actions_applied = scheduled_actions.load(Ordering::Relaxed);
        info!(
            target: "simulator",
            required = self.required_finalizations,
            exit_condition = self.exit_condition.name(),
            crashes,
            scheduled_actions = scheduled_actions_applied,
            delayed_started,
            "all validators reached required progress"
        );
        Ok(PlanResult {
            state: ctx.auditor().state(),
            tracker,
            crashes,
            scheduled_actions: scheduled_actions_applied,
            delayed_started,
        })
    }

    /// Run the simulation. This is the main async entry point.
    async fn run_inner(&self, mut ctx: deterministic::Context) -> Result<PlanResult<D>, String> {
        let (network, oracle) = Network::<_, D::PublicKey>::new(
            ctx.with_label("network"),
            simulated::Config {
                max_size: self.max_message_size,
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(3),
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
                    .try_collect::<Set<D::PublicKey>>()
                    .expect("participants must be unique"),
            )
            .await;

        let total = self.participants.len();
        let mut team = Team::new(self.engine.clone(), self.participants.clone());
        let (monitor_tx, mut monitor_rx) = mpsc::channel::<FinalizationUpdate<D::PublicKey>>(1024);
        let (restart_tx, mut restart_rx) = mpsc::channel::<D::PublicKey>(10);
        let (crash_tx, mut crash_rx) = mpsc::channel::<()>(1);
        let (schedule_tx, mut schedule_rx) = mpsc::channel::<ScheduleCmd<D::PublicKey>>(10);
        let scheduled_actions = Arc::new(AtomicU64::new(0));

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
        if let Some((frequency, _, _)) = self.random_crash() {
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

        // Spawn action schedule actors.
        for schedule in self.schedules() {
            let schedule = schedule.clone();
            let oracle_clone = oracle.clone();
            let participants = self.participants.clone();
            let schedule_tx_clone = schedule_tx.clone();
            let scheduled_actions_clone = scheduled_actions.clone();
            ctx.clone().spawn(move |ctx| async move {
                Self::run_action_scheduler(
                    ctx,
                    schedule,
                    &oracle_clone,
                    &participants,
                    schedule_tx_clone,
                    scheduled_actions_clone,
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
                    result = self.finish(
                        &ctx, tracker, &team, crashes, &scheduled_actions, delayed_started,
                    ).await;
                    break;
                }

                // Start delayed validators after enough progress
                if !delayed_started {
                    if let Some((_, after)) = self.delay_crash() {
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

                result = self.finish(
                    &ctx, tracker, &team, crashes, &scheduled_actions, delayed_started,
                ).await;
                break;
            },
            Some(pk) = restart_rx.recv() else break => {
                team.restart(&ctx, &oracle, pk, monitor_tx.clone()).await;
            },
            Some(cmd) = schedule_rx.recv() else break => {
                match cmd {
                    ScheduleCmd::Crash(pk) => {
                        if team.crash(&pk) {
                            crashes += 1;
                        }
                    }
                    ScheduleCmd::Restart(pk) => {
                        team.restart(&ctx, &oracle, pk, monitor_tx.clone()).await;
                    }
                }
            },
            _ = crash_rx.recv() => {
                let Some((_, downtime, count)) = self.random_crash() else {
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

        // Assert that configured crashes were actually exercised.
        if let Ok(ref r) = result {
            if self.random_crash().is_some() {
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
                    r.scheduled_actions > 0,
                    "Crash::Schedule configured with {} events but none were applied. \
                     Schedule events may be timed after consensus completes.",
                    scheduled_events
                );
            }

            if self.delay_crash().is_some() {
                assert!(
                    r.delayed_started,
                    "Crash::Delay configured but delayed validators were never started. \
                     Increase required_finalizations or decrease the `after` threshold."
                );
            }
        }

        result
    }

    /// Schedule executor -- sleeps until each scheduled time and
    /// applies the action. Network actions are applied directly via the
    /// oracle; node actions (crash/restart) are sent as commands to the
    /// select loop which owns the team.
    async fn run_action_scheduler(
        ctx: deterministic::Context,
        schedule: Schedule<D::PublicKey>,
        oracle: &simulated::Oracle<D::PublicKey, deterministic::Context>,
        participants: &[D::PublicKey],
        cmd_tx: mpsc::Sender<ScheduleCmd<D::PublicKey>>,
        actions_applied: Arc<AtomicU64>,
    ) {
        let start = ctx.current();
        for (time, action) in schedule.events {
            let elapsed = ctx
                .current()
                .duration_since(start)
                .unwrap_or(Duration::ZERO);
            if time > elapsed {
                ctx.sleep(time - elapsed).await;
            }
            match action {
                Action::Heal(ref link) => {
                    for v1 in participants {
                        for v2 in participants {
                            if v1 == v2 {
                                continue;
                            }
                            let _ = oracle.remove_link(v1.clone(), v2.clone()).await;
                            let _ = oracle.add_link(v1.clone(), v2.clone(), link.clone()).await;
                        }
                    }
                    actions_applied.fetch_add(1, Ordering::Relaxed);
                    info!(target: "simulator", "links reset");
                }
                Action::UpdateLink {
                    ref from,
                    ref to,
                    ref link,
                } => {
                    let _ = oracle.remove_link(from.clone(), to.clone()).await;
                    let _ = oracle
                        .add_link(from.clone(), to.clone(), link.clone())
                        .await;
                    actions_applied.fetch_add(1, Ordering::Relaxed);
                    info!(target: "simulator", ?from, ?to, "link updated");
                }
                Action::Crash(ref pk) => {
                    if cmd_tx.send(ScheduleCmd::Crash(pk.clone())).await.is_err() {
                        break;
                    }
                    actions_applied.fetch_add(1, Ordering::Relaxed);
                }
                Action::Restart(ref pk) => {
                    if cmd_tx.send(ScheduleCmd::Restart(pk.clone())).await.is_err() {
                        break;
                    }
                    actions_applied.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// Run the simulation synchronously using [`Self::seed`].
    ///
    /// Creates a deterministic runner with the plan's seed and timeout,
    /// then executes the simulation.
    pub fn run(&self) -> Result<PlanResult<D>, String> {
        self.run_with_seed(self.seed)
    }

    /// Run the simulation synchronously with an explicit seed.
    pub fn run_with_seed(&self, seed: u64) -> Result<PlanResult<D>, String> {
        let cfg = deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(self.timeout);
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
    use std::{
        future::Future,
        pin::Pin,
        sync::atomic::{AtomicUsize, Ordering},
    };

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

    #[derive(Clone)]
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

    #[derive(Default)]
    struct SingleUseProperty {
        calls: AtomicUsize,
    }

    impl Clone for SingleUseProperty {
        fn clone(&self) -> Self {
            Self::default()
        }
    }

    impl Property<ed25519::PublicKey, ()> for SingleUseProperty {
        fn name(&self) -> &str {
            "single_use_property"
        }

        fn check<'a>(
            &'a self,
            _tracker: &'a ProgressTracker<ed25519::PublicKey>,
            _states: &'a [&'a ()],
        ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
            Box::pin(async move {
                let previous = self.calls.fetch_add(1, Ordering::Relaxed);
                if previous == 0 {
                    return Ok(());
                }
                Err(format!(
                    "property reused across runs: call {}",
                    previous + 1
                ))
            })
        }
    }

    #[test]
    fn schedule_action_applied_before_completion_is_counted() {
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
                    .at(Duration::from_millis(1), Action::Heal(link.clone()))
                    .at(Duration::from_secs(5), Action::Heal(link)),
            ))
            .run()
            .expect("simulation should complete")
            .into_iter()
            .next()
            .expect("expected one result for the default seed");
        assert!(
            result.scheduled_actions >= 1,
            "expected at least one applied action before completion, got {}",
            result.scheduled_actions
        );
    }

    #[test]
    fn delay_and_schedule_actions_compose() {
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
                Schedule::new().at(Duration::from_millis(1), Action::Heal(link)),
            ))
            .run()
            .expect("simulation should complete")
            .into_iter()
            .next()
            .expect("expected one result for the default seed");
        assert!(
            result.delayed_started,
            "delayed validator should still start when schedule crashes are also configured"
        );
        assert!(
            result.scheduled_actions >= 1,
            "scheduled crashes should still run when delay crashes are also configured"
        );
    }

    #[test]
    fn schedule_double_crash_before_restart_counts_one_crash() {
        let pk = ed25519::PrivateKey::from_seed(0).public_key();
        let result = PlanBuilder::new(FinalizingEngine::new(1, Duration::from_millis(50), 1))
            .required_finalizations(1)
            .timeout(Duration::from_secs(2))
            .crash(Crash::Schedule(
                Schedule::new()
                    .at(Duration::from_millis(1), Action::Crash(pk.clone()))
                    .at(Duration::from_millis(2), Action::Crash(pk.clone()))
                    .at(Duration::from_millis(3), Action::Restart(pk)),
            ))
            .run()
            .expect("simulation should complete")
            .into_iter()
            .next()
            .expect("expected one result for the default seed");

        assert_eq!(
            result.crashes, 1,
            "second crash before restart should be a no-op and not counted"
        );
    }

    #[test]
    fn custom_exit_condition_overrides_required_finalizations() {
        let result = PlanBuilder::new(FinalizingEngine::new(2, Duration::from_millis(10), 1))
            .required_finalizations(100)
            .exit_condition(AtLeastTrackedValidators { min: 2 })
            .timeout(Duration::from_secs(2))
            .run()
            .expect("simulation should complete with custom exit condition")
            .into_iter()
            .next()
            .expect("expected one result for the default seed");

        assert_eq!(
            result.tracker.tracked_count(),
            2,
            "custom exit condition should see both validators"
        );
    }

    #[test]
    fn multi_seed_run_reconstructs_properties_per_seed() {
        PlanBuilder::new(FinalizingEngine::new(1, Duration::from_millis(10), 1))
            .seeds([0, 1])
            .timeout(Duration::from_secs(1))
            .required_finalizations(1)
            .property(SingleUseProperty::default())
            .run()
            .expect("stateful properties should not be reused across seed runs");
    }
}
