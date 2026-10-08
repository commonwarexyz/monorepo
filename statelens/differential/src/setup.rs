//! The cluster setup both sides share.
//!
//! [`cluster`] is a verbatim copy of the SETUP block and the harness
//! construction of `scenarios::runner::run@392b116687`
//! (`consensus/fuzz/marshal/src/scenarios/runner.rs:139-264@392b116687`), with
//! the stamping wrappers of [`crate::record`] inserted around the three
//! arguments of `start_with_buffer`, and the fuzz input's configuration passed
//! as `byzantine`. It starts no engine.

use crate::record::{Recorder, StampingBuffer, StampingReporter, StampingResolver};
use commonware_consensus::marshal::{
    Start,
    mocks::{application::Application, harness::NUM_VALIDATORS},
};
use commonware_consensus_fuzz_core::{NetworkChannels, simplex::Simplex};
use commonware_consensus_fuzz_marshal::{
    marshal::end_to_end::{
        app::{
            AlwaysAcceptBlockBuilderApp, BlockContextRegistry, DeliveryReporter, ProgressHandle,
        },
        twins::{
            B, Ctx, PublicKeyOf, SchemeOf,
            stack::{
                DEFAULT_MAX_PENDING_ACKS, MarshalChoice, TwinsMarshal, genesis_block,
                register_engine_networks, setup_network, setup_validator,
            },
        },
    },
    scenarios::{
        environment::{Mb, Node},
        harness::{App, BufferSend, FuzzScenarioStandardHarness, HarnessNode, RecordingBuffer},
        recording_resolver::{RecordingResolver, init_injectable},
    },
};
use commonware_cryptography::Digestible;
use commonware_p2p::simulated::Oracle;
use commonware_runtime::{Supervisor as _, deterministic};
use std::sync::{Arc, atomic::AtomicUsize};

/// Per-node marshal handles produced by setup, for the `M` marshal variant
/// (`runner::MarshalNode`).
pub struct MarshalNode<P: Simplex, M: TwinsMarshal<P, App<P>>> {
    pub mailbox: Mb<P>,
    pub application: Application<B<P>>,
    pub progress: ProgressHandle,
    pub builder: M::Wrapper,
    pub resolver: RecordingResolver<P>,
    pub sends: Arc<commonware_utils::sync::Mutex<Vec<BufferSend<P>>>>,
    pub subscriptions: Arc<AtomicUsize>,
    pub forwarding: Arc<std::sync::atomic::AtomicBool>,
}

/// What setup produced besides the harness.
pub struct Cluster<P: Simplex, M: TwinsMarshal<P, App<P>>> {
    pub oracle: Oracle<PublicKeyOf<P>, deterministic::Context>,
    pub participants: Vec<PublicKeyOf<P>>,
    pub schemes: Vec<SchemeOf<P>>,
    pub genesis: B<P>,
    pub nodes: Vec<Option<MarshalNode<P, M>>>,
    pub engine_channels: Vec<Option<NetworkChannels<PublicKeyOf<P>>>>,
    pub recorder: Recorder,
}

impl<P: Simplex, M: TwinsMarshal<P, App<P>>> Cluster<P, M> {
    /// The marshal handles of `node`, which must have a marshal.
    pub fn node(&self, node: Node) -> &MarshalNode<P, M> {
        self.nodes[node.idx()]
            .as_ref()
            .expect("node without a marshal")
    }
}

/// Builds the four validators and the scenario harness as the runner does. The
/// victim (`Node::B`) gets the stamping wrappers with `recorder`; every other
/// node gets them without one, so they are transparent.
pub async fn cluster<P: Simplex, M: TwinsMarshal<P, App<P>>>(
    context: &mut deterministic::Context,
    byzantine: bool,
    marshal: MarshalChoice,
    recorder: Recorder,
) -> (Cluster<P, M>, FuzzScenarioStandardHarness<P, M>) {
    // === SETUP === (scenarios::runner::run@392b116687)
    let (participants, schemes) = P::setup(
        context,
        commonware_consensus_fuzz_core::NAMESPACE,
        NUM_VALIDATORS,
    );
    let mut oracle = setup_network::<P>(context.child("network"), participants.clone()).await;

    let genesis = genesis_block::<P>(participants[0].clone());
    let genesis_commitment = genesis.digest();
    let block_contexts = BlockContextRegistry::<Ctx<P>>::default();
    block_contexts.record(genesis_commitment, genesis.context.clone());
    let stack_label: Arc<str> = "scenario".into();

    let mut nodes: Vec<Option<MarshalNode<P, M>>> = Vec::with_capacity(NUM_VALIDATORS as usize);
    let mut engine_channels: Vec<Option<NetworkChannels<PublicKeyOf<P>>>> =
        Vec::with_capacity(NUM_VALIDATORS as usize);
    for (idx, validator) in participants.iter().enumerate() {
        let validator_ctx = context.child("validator").with_attribute("index", idx);
        engine_channels.push(Some(
            register_engine_networks::<P>(&oracle, validator.clone()).await,
        ));
        if byzantine && idx == Node::A.idx() {
            nodes.push(None);
            continue;
        }
        // The victim's P2P resolver is built around a handler pair the
        // runner holds, so the prefix can inject the source's armed
        // delivery while the real fetch, deliver, and serve paths stay
        // live for the fuzzing phase.
        let (resolver_override, injection_handler) = if idx == Node::B.idx() {
            let injectable_ctx = validator_ctx.child("injectable");
            let (pair, handler) =
                init_injectable::<P>(&injectable_ctx, &oracle, validator.clone()).await;
            (Some(pair), Some(handler))
        } else {
            (None, None)
        };
        let mut validator_state = setup_validator::<P>(
            validator_ctx.child("marshal"),
            &mut oracle,
            validator.clone(),
            commonware_cryptography::certificate::ConstantProvider::new(schemes[idx].clone()),
            Start::Genesis(genesis.clone().into()),
            resolver_override,
            DEFAULT_MAX_PENDING_ACKS,
            None,
        )
        .await;
        let progress = ProgressHandle::new();
        let application = AlwaysAcceptBlockBuilderApp::<Ctx<P>, SchemeOf<P>>::default()
            .with_block_contexts(block_contexts.clone())
            .with_reporter(
                DeliveryReporter::new(
                    idx,
                    validator_state.application.clone(),
                    None,
                    stack_label.clone(),
                )
                .with_progress(progress.clone()),
            );
        let builder = <M as TwinsMarshal<P, _>>::create(
            marshal,
            &validator_ctx,
            application,
            validator_state.mailbox.clone(),
        );
        // Wrap the real resolver so the prefix can observe exact fetches
        // (and inject deliveries on the victim), and the real broadcast
        // buffer so it can observe dispatched blocks and local waits.
        let (resolver_rx, real_resolver) = validator_state.take_resolver();
        let resolver = match injection_handler {
            Some(handler) => RecordingResolver::<P>::injectable(handler, real_resolver),
            None => RecordingResolver::<P>::observing(real_resolver),
        };
        let sends = Arc::new(commonware_utils::sync::Mutex::new(Vec::new()));
        let subscriptions = Arc::new(AtomicUsize::new(0));
        // Recording-only during the prefix; the runner enables forwarding
        // before the engines start.
        let forwarding = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let buffer = RecordingBuffer::<P>::new(
            validator_state.buffer.clone(),
            sends.clone(),
            forwarding.clone(),
            subscriptions.clone(),
        );
        // [differential] The stamping wrappers: only the victim records.
        let recording = (idx == Node::B.idx()).then(|| recorder.clone());
        validator_state.start_with_buffer(
            StampingReporter::new(builder.clone(), recording.clone()),
            (
                resolver_rx,
                StampingResolver::new(resolver.clone(), recording.clone()),
            ),
            StampingBuffer::new(buffer, recording, sends.clone(), subscriptions.clone()),
        );
        nodes.push(Some(MarshalNode {
            mailbox: validator_state.mailbox.clone(),
            application: validator_state.application.clone(),
            progress,
            builder,
            resolver,
            sends,
            subscriptions,
            forwarding,
        }));
    }

    // === PREFIX === (the harness construction of scenarios::runner::run@392b116687)
    let harness_nodes: Vec<Option<HarnessNode<P, M>>> = nodes
        .iter()
        .map(|node| {
            node.as_ref().map(|node| HarnessNode {
                mailbox: node.mailbox.clone(),
                wrapper: node.builder.clone(),
                resolver: node.resolver.clone(),
                application: node.application.clone(),
                sends: node.sends.clone(),
                subscriptions: node.subscriptions.clone(),
            })
        })
        .collect();
    let harness = FuzzScenarioStandardHarness::<P, M>::new(
        context.child("prefix"),
        participants.clone(),
        schemes.clone(),
        genesis.clone(),
        harness_nodes,
    );
    (
        Cluster {
            oracle,
            participants,
            schemes,
            genesis,
            nodes,
            engine_channels,
            recorder,
        },
        harness,
    )
}
