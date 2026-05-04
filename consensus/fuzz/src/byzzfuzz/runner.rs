//! Run a single ByzzFuzz iteration.

use super::BYZANTINE_IDX;
use crate::{
    byzzfuzz::{
        fault::ProcessFault, forwarder, injector::ByzzFuzzInjector, intercept, log,
        mutator::ByzzFuzzMutator, observed::ObservedState, ByzzFuzz,
    },
    invariants,
    simplex::Simplex,
    spawn_honest_validator,
    utils::Partition,
    PublicKeyOf, FAULT_INJECTION_RATIO, MAX_SLEEP_DURATION, N4F0C4,
};
use commonware_consensus::{simplex::mocks::relay, types::View, Monitor as _};
use commonware_cryptography::certificate::Scheme as CertificateScheme;
use commonware_macros::select;
use commonware_runtime::{deterministic, Clock, Metrics, Runner, Spawner};
use commonware_utils::{channel::mpsc::Receiver as ViewReceiver, FuzzRng};
use futures::future::join_all;
use rand::Rng;
use std::{collections::HashSet, sync::Arc, time::Duration};

/// Run the ByzzFuzz fault model on `input`. 4 honest engines plus a
/// per-message strict-replace interception layer.
///
/// See [`crate::byzzfuzz`] module docs for the architectural overview.
pub fn run<P: Simplex>(mut input: crate::FuzzInput)
where
    <<P::Scheme as CertificateScheme>::Certificate as commonware_codec::Read>::Cfg:
        Clone + Send + Sync + 'static,
{
    // Per-channel forwarders own all network-fault behavior in this mode;
    // disable oracle-driven topology and do not use `Disrupter` actor.
    input.configuration = N4F0C4;
    input.partition = Partition::Connected;
    input.degraded_network = false;

    log::clear();

    let rng = FuzzRng::new(input.raw_bytes.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);

    executor.start(|mut context| async move {
        // Sample `(c, d, r)` here rather than threading it through `FuzzInput` type.
        let use_required_bound = context.gen_bool(0.5);
        let r_bound = if use_required_bound {
            input.required_containers
        } else {
            let multiplier = context.gen_range(2..=100);
            input.required_containers.saturating_mul(multiplier)
        };

        let r = context.gen_range(1..=r_bound.max(input.required_containers));
        let max_per_fault_type = (r / FAULT_INJECTION_RATIO).max(1);
        let mut c = context.gen_range(0..=max_per_fault_type);
        let mut d = context.gen_range(0..=max_per_fault_type);
        // At least one fault type must be active; otherwise the run is a no-op.
        if c == 0 && d == 0 {
            if context.gen_bool(0.5) {
                c = 1;
            } else {
                d = 1;
            }
        }
        let byzz = ByzzFuzz::new(c, d, r);

        let network_schedule_vec = byzz.network_faults(&mut context);

        let (oracle, participants, schemes, mut registrations) =
            crate::setup_network::<P>(&mut context, &input).await;

        let proc_faults = byzz.process_faults(&participants, &mut context);

        log::push(format!(
            "byzzfuzz schedule: byzantine_idx={} required_containers={} (c,d,r)={:?} network_faults={:?} proc_faults={:?}",
            BYZANTINE_IDX,
            input.required_containers,
            byzz,
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

        // Observed-value pool shared by every extractor (populated by
        // decoded vote/cert/resolver bytes flowing in either direction)
        // and by the byzantine injector's mutator (replays observed
        // payloads / proposals / certs / request views).
        let pool = ObservedState::new();

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

            if i == BYZANTINE_IDX {
                injector_vote_sender = Some(vote_sender.clone());
                injector_cert_sender = Some(cert_sender.clone());
                injector_resolver_sender = Some(resolver_sender.clone());
            }

            let sender_view = intercept::SenderViewCell::new();

            let proc_for_sender = if i == BYZANTINE_IDX {
                proc_schedule_arc.clone()
            } else {
                empty_proc_schedule.clone()
            };
            let intercept_for_sender = if i == BYZANTINE_IDX {
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
                    pool.clone(),
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
                    pool.clone(),
                ));
            let (resolver_primary, _resolver_secondary) =
                resolver_sender.split_with(forwarder::make_resolver::<P::Scheme>(
                    cert_codec.clone(),
                    participants_arc.clone(),
                    i,
                    network_schedule.clone(),
                    proc_for_sender,
                    sender_view.clone(),
                    intercept_for_sender,
                    pool.clone(),
                ));

            let vote_receiver = intercept::RoundTrackingReceiver::new(
                vote_receiver,
                sender_view.clone(),
                intercept::vote_view_extractor::<P::Scheme>(pool.clone()),
            );
            let cert_receiver = intercept::RoundTrackingReceiver::new(
                cert_receiver,
                sender_view.clone(),
                intercept::certificate_view_extractor::<P::Scheme>(cert_codec.clone(), pool.clone()),
            );
            let resolver_receiver = intercept::RoundTrackingReceiver::new(
                resolver_receiver,
                sender_view,
                intercept::resolver_view_extractor::<P::Scheme>(cert_codec, pool.clone()),
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

        // Closes the intercept queue once all forwarder-held clones drop.
        drop(intercept_tx);

        // Mutator: observed-value pool first, SmallScope local edits as
        // fallback. Replays seen payloads / proposals / certs / request
        // views so byzantine messages stay consensus-relevant.
        let injector_ctx = context.with_label("byzzfuzz_injector");
        let injector = ByzzFuzzInjector::new(
            injector_ctx,
            schemes[BYZANTINE_IDX].clone(),
            ByzzFuzzMutator::new(pool.clone()),
        );
        injector.start(
            injector_vote_sender.expect("byzantine vote sender cloned"),
            injector_cert_sender.expect("byzantine cert sender cloned"),
            injector_resolver_sender.expect("byzantine resolver sender cloned"),
            intercept_rx,
        );

        let mut finalizers = Vec::new();
        for reporter in reporters.iter_mut() {
            let required_containers = input.required_containers;
            let (mut latest, mut monitor): (View, ViewReceiver<View>) = reporter.subscribe().await;
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
          _ = context.sleep(MAX_SLEEP_DURATION) => {},
        }

        let byzantine: HashSet<usize> = [BYZANTINE_IDX].into_iter().collect();
        invariants::check_vote_invariants_with_byzantine(&byzantine, &reporters);
        let states = invariants::extract(reporters, config.n as usize);
        invariants::check::<P>(config.n, states);
    });
}
