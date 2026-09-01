//! The voter before its startup barrier is durable.
//!
//! [`Starting`] builds the live state from the configuration, stages the fresh start or recovery
//! transition, and runs core work until the startup barrier is acknowledged. It then seeds the
//! resolver and submits the initial producer wake, returning the [`Live`] voter.

use super::{
    AtRoot as _, ConfigOf, DigestOf, Failure, Planes, VoterTypes,
    app::AppExecutor,
    chains::ChainTasks,
    crypto::CryptoExecutor,
    live::Live,
    persist::{Ledger, Persistence},
    timers::Timers,
    verification::VerificationQueue,
};
use crate::{
    Epochable as _,
    multimmit::{
        actors::{
            ingress, resolver, verifier,
            voter::{
                egress::Egress,
                mailbox::Inbox,
                persistence,
                tasks::{TaskLimits, TaskReservations},
                telemetry::{Correlation, PeerActivity, Telemetry, metrics::Metrics},
            },
        },
        config::Role,
        machine::Input,
        storage::Recovered,
    },
};
use commonware_actor::mailbox;
use commonware_p2p::Sender;
use commonware_runtime::{Clock as _, Supervisor as _};
use commonware_utils::SystemTimeExt as _;
use std::{collections::BTreeMap, num::NonZeroUsize, sync::Arc};

/// The voter from construction until its startup barrier is acknowledged.
pub(crate) struct Starting<T: VoterTypes, S> {
    live: Live<T, S>,
    recovered: bool,
}

/// What [`Starting::new`] builds the live voter from.
pub(crate) struct Parts<T: VoterTypes, S> {
    pub(crate) context: T::Context,
    pub(crate) config: ConfigOf<T>,
    pub(crate) inbox: Inbox<T::PublicKey, T::Variant, DigestOf<T>>,
    pub(crate) planes: Planes<S>,
    pub(crate) ingress: ingress::Mailbox,
    pub(crate) verifier: verifier::Mailbox<T::Variant, DigestOf<T>>,
    pub(crate) resolver: resolver::Mailbox<T::Variant, DigestOf<T>>,
    pub(crate) metrics: Metrics,
    pub(crate) hooks: T::Hooks,
    pub(crate) journal_capacity: Option<NonZeroUsize>,
    pub(crate) flushes: persistence::Flushes,
}

impl<T, S> Starting<T, S>
where
    T: VoterTypes,
    S: Sender<PublicKey = T::PublicKey>,
{
    /// Builds the voter's live state and starts its persistence actor.
    pub(crate) fn new(parts: Parts<T, S>) -> Self {
        let Parts {
            context,
            config,
            inbox,
            planes,
            ingress,
            verifier,
            resolver,
            metrics,
            hooks,
            journal_capacity,
            flushes,
        } = parts;
        let Recovered {
            core: machine,
            journal: storage_journal,
            checkpoints,
            replayed,
        } = config.recovered;
        let recovered = replayed.is_some();
        let profile = machine.machine().profile();
        let protocol = profile.protocol();
        let epoch = protocol.epoch();
        let leaders = protocol.leaders().clone();
        let participant = match profile.role() {
            Role::Validator(participant) => Some(participant),
            Role::Observer => None,
        };
        let initial_view = machine.machine().view();
        let tasks =
            TaskReservations::new(machine.machine().generation(), TaskLimits::derive(profile))
                .expect("validated profiles admit every task class");
        let persistence_capacity = journal_capacity.unwrap_or_else(|| {
            NonZeroUsize::new(profile.resources().max_outbox_effects())
                .expect("validated resources reserve journal commands")
        });
        let now = context.current();
        let verification_queue_limit = profile.resources().max_inflight_verifications();
        let observation_batch = profile.resources().max_verification_batch();
        let driver_context = context.child("driver");
        let (output, persisted) =
            mailbox::new(driver_context.child("persisted"), persistence_capacity);
        let persistence_config = persistence::Config {
            journal: storage_journal,
            checkpoints,
            capacity: persistence_capacity,
            output,
            snapshot_tasks: context.child("driver"),
            flushes,
            hooks: hooks.clone(),
        };
        let (persistence, persistence_mailbox) =
            persistence::Actor::new(driver_context.child("journal"), persistence_config);
        persistence.start();

        let scheme = Arc::new(config.scheme);
        let activity = PeerActivity::new(
            scheme.participants().len(),
            participant,
            config.limits.skip_timeout,
            scheme.codec_config().view_quorum(),
        );
        let chains = ChainTasks::new(
            &driver_context,
            profile,
            &scheme,
            config.strategy,
            &config.automaton,
            &metrics,
            config.mailbox_size,
        );
        let crypto = CryptoExecutor::new(
            scheme,
            config.critical_strategy,
            driver_context.child("crypto"),
            &metrics,
        );
        let app = AppExecutor::new(config.automaton, epoch);
        let telemetry = Telemetry::new(metrics, epoch, initial_view, (!recovered).then_some(now));
        let live = Live {
            context: driver_context,
            machine,
            tasks,
            epoch,
            leaders,
            participant,
            limits: config.limits,
            inbox,
            carried_observation: None,
            observation_batch,
            pending_inspection: None,
            persistence: Persistence::new(
                persistence_mailbox,
                persisted,
                Ledger::new(replayed.unwrap_or(0), config.limits.checkpoint_interval),
            ),
            crypto,
            app,
            verification: VerificationQueue::new(verification_queue_limit),
            verification_tasks: BTreeMap::new(),
            timers: Timers::new(now.saturating_add_ext(config.limits.heartbeat)),
            egress: Egress::new(epoch, config.limits.into()),
            relay: config.relay,
            planes,
            ingress,
            verifier,
            resolver,
            blocker: config.blocker,
            blocked: config.blocked,
            reporter: config.reporter,
            chains,
            telemetry,
            activity,
            correlation: Correlation::default(),
            hooks,
        };
        Self { live, recovered }
    }

    /// Stages startup, waits for its barrier, and returns the live voter.
    ///
    /// Storage waits run on the persistence actor; the voter keeps running core work until the
    /// startup barrier is acknowledged.
    pub(crate) async fn run(self) -> Result<Live<T, S>, Failure> {
        let Self {
            mut live,
            recovered,
        } = self;
        live.update_progress();
        live.telemetry.update_chains(&live.machine);
        let span = live.round_span();
        span.in_scope(|| {
            if recovered {
                live.track_in_round(|core| core.enqueue(Input::RecoveryComplete))
            } else {
                live.track_in_round(|core| core.enqueue(Input::Start))
            }
        })
        .at(&span)?;
        loop {
            if live.persistence.has_capacity() {
                live.drive_core_cycle().await?;
                if live.machine.has_runnable_work() {
                    continue;
                }
            }
            if live.persistence.ledger().outstanding() == 0 {
                break;
            }
            live.persistence.flush().at(live.telemetry.round_span())?;
            let output = live.persistence.output().recv().await;
            let output = output.unwrap_or_else(|| live.persistence_closed());
            live.persisted(output)?;
        }
        let span = live.round_span();
        live.seed_resolver().at(&span)?;
        span.in_scope(|| live.track_in_round(|core| core.enqueue(Input::ProducerWake)))
            .at(&span)?;
        Ok(live)
    }
}
