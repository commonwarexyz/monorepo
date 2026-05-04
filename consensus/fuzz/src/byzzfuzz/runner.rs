//! Run a single ByzzFuzz iteration.
//!
//! Orchestrates the four pieces in this module:
//! - schedule sampling (network faults via [`crate::network_faults`],
//!   process faults via [`process_faults`] over the active strategy);
//! - per-validator setup with vote/cert/resolver `SplitForwarder`s
//!   (partition + procFault filtering, byzantine sender additionally
//!   intercepts to the injector queue);
//! - the [`ByzzFuzzInjector`] consuming the intercept queue and re-emitting
//!   the per-message mutation;
//! - bounded liveness wait + invariant checks with the byzantine identity
//!   excluded from the equivocation invariant.

use crate::{
    byzzfuzz::{
        fault::{self, ProcessFault},
        forwarder,
        injector::ByzzFuzzInjector,
        intercept, log,
    },
    invariants, network_faults,
    simplex::Simplex,
    spawn_honest_validator,
    strategy::{AnyScope, FutureScope, SmallScope, StrategyChoice},
    utils::Partition,
    PublicKeyOf, FAULT_INJECTION_RATIO, MAX_SLEEP_DURATION, N4F0C4,
};
use commonware_consensus::{simplex::mocks::relay, types::View, Monitor as _};
use commonware_cryptography::{
    certificate::Scheme as CertificateScheme, PublicKey as CryptoPublicKey,
};
use commonware_macros::select;
use commonware_runtime::{deterministic, Clock, Metrics, Runner, Spawner};
use commonware_utils::{channel::mpsc::Receiver as ViewReceiver, FuzzRng};
use futures::future::join_all;
use std::{collections::HashSet, sync::Arc, time::Duration};

/// Maximum virtual time `run` waits for finalization before giving up.
/// Adversarial schedules can prevent finalization indefinitely; this bound
/// guarantees `run` always returns so the fuzzer can move on.
const LIVENESS_BUDGET: Duration = Duration::from_secs(60);

/// Sample a process-fault schedule. Number of faults and view range are
/// derived from `strategy` mirroring the network/messaging dispatchers in
/// `lib.rs` so density is consistent across adaptive modes.
fn process_faults<P: CryptoPublicKey>(
    strategy: StrategyChoice,
    required_containers: u64,
    participants: &[P],
    byzantine_idx: usize,
    rng: &mut impl rand::Rng,
) -> Vec<ProcessFault<P>> {
    let (count, min_view, max_view) = match strategy {
        StrategyChoice::SmallScope {
            fault_rounds,
            fault_rounds_bound,
        } => {
            let bound = fault_rounds_bound.min(required_containers).max(1);
            let d = fault_rounds.max(1).min(bound);
            (d, 1, bound)
        }
        StrategyChoice::AnyScope => {
            let max_d = (required_containers / FAULT_INJECTION_RATIO).max(1);
            let d = rng.gen_range(1..=max_d);
            (d, 1, required_containers.max(1))
        }
        StrategyChoice::FutureScope {
            fault_rounds,
            fault_rounds_bound,
        } => {
            let start = fault_rounds_bound
                .saturating_add(1)
                .min(required_containers)
                .max(1);
            let window = required_containers.saturating_sub(start).saturating_add(1);
            let d = fault_rounds.max(1).min(window);
            (d, start, required_containers.max(start))
        }
    };
    fault::sample(count, min_view, max_view, participants, byzantine_idx, rng)
}

/// Closed-set enum over the three strategy-keyed [`ByzzFuzzInjector`]
/// instantiations. Avoids dynamic dispatch / boxing.
//
// Variant names intentionally mirror `StrategyChoice::{SmallScope, AnyScope,
// FutureScope}` so the dispatch reads 1:1 with the strategy it wraps;
// renaming would break that correspondence.
#[allow(clippy::enum_variant_names)]
enum InjectorChoice<P: Simplex> {
    SmallScope(ByzzFuzzInjector<P::Scheme, SmallScope, deterministic::Context>),
    AnyScope(ByzzFuzzInjector<P::Scheme, AnyScope, deterministic::Context>),
    FutureScope(ByzzFuzzInjector<P::Scheme, FutureScope, deterministic::Context>),
}

impl<P: Simplex> InjectorChoice<P> {
    fn build(context: deterministic::Context, scheme: P::Scheme, strategy: StrategyChoice) -> Self {
        match strategy {
            StrategyChoice::SmallScope {
                fault_rounds,
                fault_rounds_bound,
            } => Self::SmallScope(ByzzFuzzInjector::new(
                context,
                scheme,
                SmallScope {
                    fault_rounds,
                    fault_rounds_bound,
                },
            )),
            StrategyChoice::AnyScope => {
                Self::AnyScope(ByzzFuzzInjector::new(context, scheme, AnyScope))
            }
            StrategyChoice::FutureScope {
                fault_rounds,
                fault_rounds_bound,
            } => Self::FutureScope(ByzzFuzzInjector::new(
                context,
                scheme,
                FutureScope {
                    fault_rounds,
                    fault_rounds_bound,
                },
            )),
        }
    }

    fn start(
        self,
        vote_sender: impl commonware_p2p::Sender<PublicKey = PublicKeyOf<P>> + 'static,
        cert_sender: impl commonware_p2p::Sender<PublicKey = PublicKeyOf<P>> + 'static,
        resolver_sender: impl commonware_p2p::Sender<PublicKey = PublicKeyOf<P>> + 'static,
        intercept_rx: commonware_utils::channel::mpsc::UnboundedReceiver<
            intercept::Intercept<PublicKeyOf<P>>,
        >,
    ) {
        match self {
            Self::SmallScope(i) => {
                i.start(vote_sender, cert_sender, resolver_sender, intercept_rx);
            }
            Self::AnyScope(i) => {
                i.start(vote_sender, cert_sender, resolver_sender, intercept_rx);
            }
            Self::FutureScope(i) => {
                i.start(vote_sender, cert_sender, resolver_sender, intercept_rx);
            }
        }
    }
}

/// Run the ByzzFuzz fault model on `input`. 4 *honest* engines plus a
/// per-message strict-replace interception layer (Algorithm 1).
///
/// See [`crate::byzzfuzz`] module docs for the architectural overview.
pub fn run<P: Simplex>(mut input: crate::FuzzInput)
where
    <<P::Scheme as CertificateScheme>::Certificate as commonware_codec::Read>::Cfg:
        Clone + Send + Sync + 'static,
{
    // Force 4-honest topology with no oracle-driven link toggling. Per-channel
    // forwarders own all network-fault behavior in this mode.
    input.configuration = N4F0C4;
    input.partition = Partition::Connected;
    input.degraded_network = false;

    // Reset the on-panic decision log so a dump only contains entries from
    // this run. fuzz()'s panic handler flushes the buffer.
    log::clear();

    let rng = FuzzRng::new(input.raw_bytes.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);

    executor.start(|mut context| async move {
        let network_schedule_vec =
            network_faults(input.strategy, input.required_containers, &mut context);

        let byzantine_idx = 0usize;

        let (oracle, participants, schemes, mut registrations) =
            crate::setup_network::<P>(&mut context, &input).await;

        let proc_faults = process_faults(
            input.strategy,
            input.required_containers,
            &participants,
            byzantine_idx,
            &mut context,
        );

        log::push(format!(
            "byzzfuzz schedule: byzantine_idx={} required_containers={} strategy={:?} network_faults={:?} proc_faults={:?}",
            byzantine_idx,
            input.required_containers,
            input.strategy,
            network_schedule_vec,
            proc_faults,
        ));

        let participants_arc: Arc<[PublicKeyOf<P>]> = Arc::from(participants.clone());
        let network_schedule = Arc::new(network_schedule_vec);
        let proc_schedule_arc = Arc::new(proc_faults);
        let empty_proc_schedule: Arc<Vec<ProcessFault<PublicKeyOf<P>>>> =
            Arc::new(Vec::new());

        // Intercept queue. Forwarders push (sync); injector consumes (async).
        let (intercept_tx, intercept_rx) = intercept::channel::<PublicKeyOf<P>>();

        let relay = Arc::new(relay::Relay::new());
        let mut reporters = Vec::new();
        let config = input.configuration;

        // Cloned byzantine senders for the injector. Grabbed BEFORE
        // split_with so injector emissions bypass the forwarder.
        let mut injector_vote_sender = None;
        let mut injector_cert_sender = None;
        let mut injector_resolver_sender = None;

        for i in 0..config.n as usize {
            let validator = participants[i].clone();
            let (vote_chan, cert_chan, resolver_chan) =
                registrations.remove(&validator).unwrap();
            let (vote_sender, vote_receiver) = vote_chan;
            let (cert_sender, cert_receiver) = cert_chan;
            let (resolver_sender, resolver_receiver) = resolver_chan;

            if i == byzantine_idx {
                injector_vote_sender = Some(vote_sender.clone());
                injector_cert_sender = Some(cert_sender.clone());
                injector_resolver_sender = Some(resolver_sender.clone());
            }

            // Per-sender shared cell implementing rnd(m) per the paper:
            // "max round in which the sender has sent OR received a message".
            // Outgoing forwarders fold transmitted views in;
            // RoundTrackingReceiver wrappers (below) fold received views in.
            // Old-view retransmissions therefore inherit the sender's
            // current round, not their own stale view.
            let sender_view = intercept::SenderViewCell::new();

            // Non-byzantine senders see an empty procFault schedule -> the
            // forwarder degenerates to partition-only filtering. Same closure
            // type for all four senders -> no opaque-type mismatch.
            let proc_for_sender = if i == byzantine_idx {
                proc_schedule_arc.clone()
            } else {
                empty_proc_schedule.clone()
            };
            let intercept_for_sender = if i == byzantine_idx {
                Some(intercept_tx.clone())
            } else {
                None
            };

            let cert_codec = schemes[i].certificate_codec_config();

            let (vote_primary, _vote_secondary) =
                vote_sender.split_with(forwarder::make_vote::<P::Scheme>(
                    participants_arc.clone(),
                    i,
                    network_schedule.clone(),
                    proc_for_sender.clone(),
                    sender_view.clone(),
                    intercept_for_sender.clone(),
                ));
            let (cert_primary, _cert_secondary) =
                cert_sender.split_with(forwarder::make_certificate::<P::Scheme>(
                    cert_codec.clone(),
                    participants_arc.clone(),
                    i,
                    network_schedule.clone(),
                    proc_for_sender.clone(),
                    sender_view.clone(),
                    intercept_for_sender.clone(),
                ));
            let (resolver_primary, _resolver_secondary) =
                resolver_sender.split_with(forwarder::make_resolver::<PublicKeyOf<P>>(
                    participants_arc.clone(),
                    i,
                    network_schedule.clone(),
                    proc_for_sender,
                    sender_view.clone(),
                    intercept_for_sender,
                ));

            // Wrap inbound vote / cert / resolver receivers so received
            // views also raise this sender's round cell. Resolver wire
            // messages carry round-relevant data (Request key = U64 view;
            // Response payload = serialized Certificate), so the resolver
            // path participates in `rnd(m)` just like vote/cert.
            let vote_receiver = intercept::RoundTrackingReceiver::new(
                vote_receiver,
                sender_view.clone(),
                intercept::vote_view_extractor::<P::Scheme>(),
            );
            let cert_receiver = intercept::RoundTrackingReceiver::new(
                cert_receiver,
                sender_view.clone(),
                intercept::certificate_view_extractor::<P::Scheme>(cert_codec.clone()),
            );
            let resolver_receiver = intercept::RoundTrackingReceiver::new(
                resolver_receiver,
                sender_view,
                intercept::resolver_view_extractor::<P::Scheme>(cert_codec),
            );

            let ctx = context.with_label(&format!("validator_{validator}"));
            let reporter = spawn_honest_validator::<P, _, _, _, _, _, _, _>(
                ctx,
                &oracle,
                &participants,
                schemes[i].clone(),
                validator,
                P::Elector::default(),
                relay.clone(),
                Duration::from_secs(1),
                Duration::from_secs(2),
                (vote_primary, vote_receiver),
                (cert_primary, cert_receiver),
                (resolver_primary, resolver_receiver),
            );
            reporters.push(reporter);
        }

        // Drop the local intercept_tx clone so the queue closes once all the
        // forwarder-held clones are dropped at end of run.
        drop(intercept_tx);

        // Spawn the injector. If procFaults are empty, no intercepts will
        // arrive and the injector exits as soon as `intercept_tx` is dropped.
        let injector_ctx = context.with_label("byzzfuzz_injector");
        let injector =
            InjectorChoice::<P>::build(injector_ctx, schemes[byzantine_idx].clone(), input.strategy);
        injector.start(
            injector_vote_sender.expect("byzantine vote sender cloned"),
            injector_cert_sender.expect("byzantine cert sender cloned"),
            injector_resolver_sender.expect("byzantine resolver sender cloned"),
            intercept_rx,
        );

        // Liveness wait, bounded so adversarial schedules cannot block forever.
        if config.is_valid() {
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut() {
                let required_containers = input.required_containers;
                let (mut latest, mut monitor): (View, ViewReceiver<View>) =
                    reporter.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest.get() < required_containers {
                        let Some(next) = monitor.recv().await else {
                            return;
                        };
                        latest = next;
                    }
                }));
            }
            select! {
                _ = join_all(finalizers) => {},
                _ = context.sleep(LIVENESS_BUDGET) => {},
            }
        } else {
            context.sleep(MAX_SLEEP_DURATION).await;
        }

        if config.is_valid() {
            // Index 0 is intentionally byzantine via the injector; exclude it
            // from the equivocation invariant.
            let byzantine: HashSet<usize> = [byzantine_idx].into_iter().collect();
            invariants::check_vote_invariants_with_byzantine(&byzantine, &reporters);
            let states = invariants::extract(reporters, config.n as usize);
            invariants::check::<P>(config.n, states);
        }
    });
}
