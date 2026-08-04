//! Scenario-driven multi-node marshal end-to-end harness.
//!
//! One driver runs an `N4F1C3` cluster (`TermLength::ONE`, deferred marshal
//! wrapper, every node a full Simplex engine) and replays a pre-GST program
//! before healing the network and measuring progress.
//!
//! The program is built from two sources:
//!
//! - a [`ScenarioTemplate`], which fixes the topology the engines start under,
//!   the correct-message rules armed for the pre-GST window, and a scripted
//!   sequence of [`PreGstAction`]s split into phase stages;
//! - the fuzzer's own [`PreGstAction`] list, which is spliced into those stages
//!   in round-robin order so a generated program perturbs every pre-GST window
//!   rather than only the last one.
//!
//! [`ScenarioTemplate::SplitNotarization`] scripts the split notarization/block
//! wedge: the victim is inbound-isolated while the byzantine node leads and
//! alone notarizes the attack view, then links come back with holder answers
//! slower than the certificate-backfill timeout, so the byzantine answer to the
//! victim's backfill wins by latency asymmetry. Its scripted program with an
//! empty generated action list reproduces that wedge.
//!
//! The GST boundary is not part of the fuzzed input: [`gst`] always heals every
//! link, advances the phase, and disarms every correct-message rule.
//!
//! Every execution runs the marshal safety invariants over the correct nodes.
//! Liveness is measured against each correct node's height at GST.

use super::{
    MAX_REQUIRED,
    app::{
        AlwaysAcceptBlockBuilderApp, ApplicationChoice, BlockContextRegistry, DeliveryReporter,
        FaultyConfig,
    },
    input::MarshalScenarioInput,
    invariants,
    runner::highest_delivered,
    twins::{
        B, Ctx, PublicKeyOf, SchemeOf,
        stack::{
            DEFAULT_MAX_PENDING_ACKS, DeferredMarshal, MarshalChoice, TwinsBlockBuilder,
            TwinsMarshal, genesis_block, register_engine_networks, setup_network,
            setup_network_links, setup_validator, start_engine,
        },
    },
};
use crate::{
    network::{
        ByzantineFirstReceiver, ByzantinePolicy, Router, Wedge, WedgeChannel, WedgeDrop,
        WedgeEvent, WedgeNode, WedgePhase, WedgeReceiver, WedgeRequest, WedgeRole, drop_rate_cell,
    },
    simplex::Simplex,
    utils::apply_partition,
};
use commonware_consensus::{
    marshal::mocks::{
        application::Application,
        harness::{LINK, NUM_VALIDATORS},
    },
    simplex::ForwardingPolicy,
    types::{Epoch, Round, TermLength, View},
};
use commonware_cryptography::{
    Digestible as _, PublicKey, certificate::ConstantProvider, sha256::Digest as Sha256Digest,
};
use commonware_p2p::simulated::{Link, Oracle};
use commonware_runtime::{Clock, Runner, Supervisor as _, deterministic};
use commonware_utils::FuzzRng;
use std::{collections::BTreeSet, time::Duration};

/// View the byzantine node leads and alone notarizes. The round-robin elector
/// picks `(epoch + view) % n`, so at epoch 0 [`Role::Byzantine`] leads it.
const ATTACK_VIEW: View = View::new(1);

/// Upper bound on generated pre-GST actions.
pub const MAX_ACTIONS: usize = 16;
/// Upper bound on one generated [`PreGstAction::AdvanceTime`], in milliseconds.
pub const MAX_ADVANCE_MILLIS: u16 = 5_000;
/// Upper bound on a generated [`PreGstAction::SetLink`] latency, in
/// milliseconds.
pub const MAX_LATENCY_MILLIS: u16 = 5_000;
/// Upper bound on the simulated time generated actions may add before GST.
const MAX_GENERATED_TIME: Duration = Duration::from_secs(20);
/// Post-GST settling window every correct node is measured over.
pub(super) const SETTLE: Duration = Duration::from_secs(60);

/// A participant of the four-node cluster.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// Correct node that stores the attack block and notarizes it.
    HolderA,
    /// Attack-view leader.
    Byzantine,
    /// The second block holder.
    HolderB,
    /// Correct node the attack wedges.
    Victim,
}

impl Role {
    const ALL: [Self; 4] = [Self::HolderA, Self::Byzantine, Self::HolderB, Self::Victim];

    const fn index(self) -> usize {
        match self {
            Self::HolderA => 0,
            Self::Byzantine => 1,
            Self::HolderB => 2,
            Self::Victim => 3,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::HolderA => "H0",
            Self::Byzantine => "B",
            Self::HolderB => "H1",
            Self::Victim => "V",
        }
    }

    const fn wedge_role(self) -> WedgeRole {
        match self {
            Self::HolderA | Self::HolderB => WedgeRole::Holder,
            Self::Byzantine => WedgeRole::Byzantine,
            Self::Victim => WedgeRole::Victim,
        }
    }

    const fn from_index(index: usize) -> Self {
        match index {
            0 => Self::HolderA,
            1 => Self::Byzantine,
            2 => Self::HolderB,
            _ => Self::Victim,
        }
    }

    const fn is_correct(self) -> bool {
        !matches!(self, Self::Byzantine)
    }
}

/// A correct-message withholding rule the pre-GST program can arm or disarm.
///
/// Only correct-message rules are addressable: the byzantine omissions are
/// fixed for the run by [`ByzantinePolicy`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DropRule {
    /// Neither holder receives the other's attack-view notarize vote.
    HolderNotarizeSplit,
    /// Holders do not receive the victim's attack-view notarization broadcast.
    VictimNotarizationRebroadcast,
}

impl DropRule {
    const fn wedge_drop(self) -> WedgeDrop {
        match self {
            Self::HolderNotarizeSplit => WedgeDrop::HolderNotarizeSplit,
            Self::VictimNotarizationRebroadcast => WedgeDrop::VictimNotarizationRebroadcast,
        }
    }
}

/// One step of the pre-GST program.
#[derive(Clone, Copy, Debug)]
pub enum PreGstAction {
    /// Let the cluster run for this many milliseconds.
    AdvanceTime(u16),
    /// Take down one directed link.
    RemoveLink { from: Role, to: Role },
    /// Bring one directed link up at this latency.
    SetLink {
        from: Role,
        to: Role,
        latency_ms: u16,
    },
    /// Arm a correct-message withholding rule.
    EnableDrop(DropRule),
    /// Disarm a correct-message withholding rule.
    DisableDrop(DropRule),
}

/// The scripted scenario a run starts from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScenarioTemplate {
    /// The split notarization/block wedge.
    SplitNotarization,
    /// A full mesh with no correct-message rule armed.
    Connected,
    /// A quorum-breaking `{H0, B} | {H1, V}` split held across both pre-GST
    /// stages.
    Partitioned,
}

impl ScenarioTemplate {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SplitNotarization => "split-notarization",
            Self::Connected => "connected",
            Self::Partitioned => "partitioned",
        }
    }

    /// Directed links taken down before any engine starts, so nothing is in
    /// flight over them when they go down.
    fn initial_cuts(self) -> Vec<(Role, Role)> {
        match self {
            // The victim is unreachable from its peers. Its outbound links stay
            // up, which is what lets the cluster nullify the attack view
            // without it ever collecting those votes itself.
            Self::SplitNotarization => vec![
                (Role::HolderA, Role::Victim),
                (Role::Byzantine, Role::Victim),
                (Role::HolderB, Role::Victim),
            ],
            Self::Connected => Vec::new(),
            Self::Partitioned => {
                let mut cuts = Vec::new();
                for from in Role::ALL {
                    for to in Role::ALL {
                        let same_side = (from.index() < 2) == (to.index() < 2);
                        if from != to && !same_side {
                            cuts.push((from, to));
                        }
                    }
                }
                cuts
            }
        }
    }

    /// Correct-message rules armed for the pre-GST window.
    const fn armed_rules(self) -> &'static [DropRule] {
        match self {
            Self::SplitNotarization => &[
                DropRule::HolderNotarizeSplit,
                DropRule::VictimNotarizationRebroadcast,
            ],
            Self::Connected | Self::Partitioned => &[],
        }
    }

    /// Scripted pre-GST stages, each labelled with the phase it runs in.
    fn stages(self) -> [(WedgePhase, Vec<PreGstAction>); 2] {
        match self {
            Self::SplitNotarization => [
                (WedgePhase::Isolated, vec![PreGstAction::AdvanceTime(8_000)]),
                (
                    WedgePhase::Asynchronous,
                    vec![
                        // Holder answers now take longer than the certificate
                        // backfill timeout; every message they carry is still
                        // delivered.
                        PreGstAction::SetLink {
                            from: Role::HolderA,
                            to: Role::Victim,
                            latency_ms: 4_000,
                        },
                        PreGstAction::SetLink {
                            from: Role::HolderB,
                            to: Role::Victim,
                            latency_ms: 4_000,
                        },
                        PreGstAction::SetLink {
                            from: Role::Byzantine,
                            to: Role::Victim,
                            latency_ms: 100,
                        },
                        PreGstAction::AdvanceTime(25_000),
                    ],
                ),
            ],
            // Short enough that the cluster is still below the single-epoch
            // height ceiling at GST, so the progress target is not vacuous.
            Self::Connected => [
                (WedgePhase::Isolated, vec![PreGstAction::AdvanceTime(2_000)]),
                (
                    WedgePhase::Asynchronous,
                    vec![PreGstAction::AdvanceTime(3_000)],
                ),
            ],
            Self::Partitioned => [
                (WedgePhase::Isolated, vec![PreGstAction::AdvanceTime(5_000)]),
                (
                    WedgePhase::Asynchronous,
                    vec![PreGstAction::AdvanceTime(10_000)],
                ),
            ],
        }
    }
}

/// The simulated topology, plus the ledger the GST check reads.
///
/// Every link mutation the scenario performs goes through this type, so the
/// recorded state is the state the harness asked the oracle for.
struct Topology<K: PublicKey> {
    oracle: Oracle<K, deterministic::Context>,
    participants: Vec<K>,
    up: BTreeSet<(usize, usize)>,
}

impl<K: PublicKey> Topology<K> {
    /// Wraps an oracle whose links are already a full mesh.
    fn meshed(oracle: Oracle<K, deterministic::Context>, participants: Vec<K>) -> Self {
        let up = Self::pairs(participants.len());
        Self {
            oracle,
            participants,
            up,
        }
    }

    fn pairs(len: usize) -> BTreeSet<(usize, usize)> {
        (0..len)
            .flat_map(|from| (0..len).map(move |to| (from, to)))
            .filter(|(from, to)| from != to)
            .collect()
    }

    async fn remove(&mut self, from: usize, to: usize) {
        if from == to {
            return;
        }
        self.oracle
            .remove_link(
                self.participants[from].clone(),
                self.participants[to].clone(),
            )
            .await
            .ok();
        self.up.remove(&(from, to));
    }

    async fn set(&mut self, from: usize, to: usize, link: Link) {
        if from == to {
            return;
        }
        self.remove(from, to).await;
        if self
            .oracle
            .add_link(
                self.participants[from].clone(),
                self.participants[to].clone(),
                link,
            )
            .await
            .is_ok()
        {
            self.up.insert((from, to));
        }
    }

    /// Heals every link. The ledger is refreshed here and nowhere else, so a
    /// run that skipped this call reports every link the program took down.
    async fn heal(&mut self) {
        apply_partition(&self.oracle, &self.participants, None, &LINK).await;
        self.up = Self::pairs(self.participants.len());
    }

    /// Directed links currently down, as role labels.
    fn down(&self) -> Vec<(&'static str, &'static str)> {
        Self::pairs(self.participants.len())
            .difference(&self.up)
            .map(|(from, to)| {
                (
                    Role::from_index(*from).label(),
                    Role::from_index(*to).label(),
                )
            })
            .collect()
    }
}

/// What one scenario execution produced.
pub struct ScenarioOutcome {
    pub template: ScenarioTemplate,
    /// Generated actions spliced into the template's stages.
    pub actions: usize,
    pub forwarding: ForwardingPolicy,
    pub byzantine_policy: ByzantinePolicy,
    /// Highest finalized height each correct node had delivered at GST.
    pub baselines: Vec<(&'static str, u64)>,
    /// Highest finalized height each node's marshal delivered by the end.
    pub heights: Vec<(&'static str, u64)>,
    /// Directed links still down after GST healed the topology.
    pub unhealed_links: Vec<(&'static str, &'static str)>,
    pub honest_drops_pre_gst: usize,
    pub honest_drops_post_gst: usize,
    pub byzantine_withholds: usize,
    /// Messages the harness withheld on the certificate-backfill channel.
    pub resolver_drops: usize,
    pub ledger: Vec<(WedgeDrop, WedgePhase, usize)>,
    pub events: Vec<WedgeEvent>,
    /// Attack-view certificate requests the victim sent, as seen by the peers
    /// it asked.
    pub requests: Vec<WedgeRequest>,
    /// Attack-view proposal payload, learned from the notarization the victim
    /// was served.
    pub attack_payload: Option<Sha256Digest>,
}

impl ScenarioOutcome {
    /// Highest finalized height one node's marshal delivered by the end.
    pub fn height(&self, label: &str) -> u64 {
        self.heights
            .iter()
            .find(|(node, _)| *node == label)
            .map_or(0, |(_, height)| *height)
    }

    /// Progress target for one correct node: one block past its height at GST,
    /// unless it already sits at the single-epoch boundary this harness can
    /// deliver.
    pub const fn target(baseline: u64) -> u64 {
        if baseline < MAX_REQUIRED {
            baseline + 1
        } else {
            baseline
        }
    }

    /// Observations one node made, in arrival order.
    #[cfg(test)]
    pub fn node_events(&self, label: &str) -> impl Iterator<Item = &WedgeEvent> {
        self.events.iter().filter(move |event| event.node == label)
    }
}

/// Runs one scenario.
///
/// `configure` is applied to the shared scenario state before the engines
/// start; the fuzz entry point passes an empty hook and the recovery tests use
/// it to enable a control.
pub fn run_scenario<P: Simplex>(
    input: &MarshalScenarioInput,
    configure: impl FnOnce(&Wedge<PublicKeyOf<P>, Sha256Digest>) + Send + 'static,
) -> ScenarioOutcome {
    let template = input.template;
    let forwarding = input.forwarding;
    let byzantine_policy = input.byzantine_policy;
    let actions = input.actions.clone();
    let rng = FuzzRng::new(input.raw_bytes.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);
    let fault_bytes = input.raw_bytes.clone();

    executor.start(|mut context| async move {
        let (participants, schemes) = P::setup(&mut context, crate::NAMESPACE, NUM_VALIDATORS);
        let labels: Vec<(PublicKeyOf<P>, String)> = Role::ALL
            .iter()
            .map(|role| (participants[role.index()].clone(), role.label().to_string()))
            .collect();

        let mut oracle = setup_network::<P>(context.child("network"), participants.clone()).await;
        setup_network_links::<P>(&mut oracle, &participants).await;
        let mut topology = Topology::meshed(oracle.clone(), participants.clone());
        for (from, to) in template.initial_cuts() {
            topology.remove(from.index(), to.index()).await;
        }

        let wedge = Wedge::new(
            context.child("wedge"),
            participants[Role::Byzantine.index()].clone(),
            participants[Role::Victim.index()].clone(),
            labels,
            Round::new(Epoch::zero(), ATTACK_VIEW),
            byzantine_policy,
        );
        for rule in template.armed_rules() {
            wedge.set_honest_rule(rule.wedge_drop(), true);
        }
        configure(&wedge);

        let genesis_marshal_block = genesis_block::<P>(participants[0].clone());
        let genesis_commitment = genesis_marshal_block.digest();
        let block_contexts = BlockContextRegistry::<Ctx<P>>::default();
        block_contexts.record(genesis_commitment, genesis_marshal_block.context.clone());
        let mut fault_rng = FuzzRng::new(fault_bytes);
        let faulty_config = FaultyConfig::new(&mut fault_rng, View::new(0));

        // Byzantine-first delivery ordering, cluster-wide: whenever a byzantine
        // message and a correct message are both ready, the byzantine one is
        // serviced first. Ordering is legal at every point in the run, so this
        // is never disarmed.
        let router = Router::new(
            context.child("byzantine_router"),
            [participants[Role::Byzantine.index()].clone()],
            drop_rate_cell(),
        );

        let mut apps: Vec<(usize, &'static str, Application<B<P>>)> = Vec::new();
        for (idx, validator) in participants.iter().enumerate() {
            let scheme = schemes[idx].clone();
            let role = Role::from_index(idx);
            let node = WedgeNode::new(
                wedge.clone(),
                validator.clone(),
                role.wedge_role(),
                scheme.clone(),
            );

            let (vote, certificate, resolver) =
                register_engine_networks::<P>(&oracle, validator.clone()).await;
            let (vote_sender, vote_receiver) = vote;
            let (certificate_sender, certificate_receiver) = certificate;
            let (resolver_sender, resolver_receiver) = resolver;

            let vote_router = router.clone();
            let (vote_primary, vote_secondary) = vote_receiver
                .split_with(context.child("byzantine_first_vote"), move |message| {
                    vote_router.route(message)
                });
            let vote = (
                vote_sender,
                WedgeReceiver::<SchemeOf<P>, Sha256Digest, B<P>, _>::new(
                    ByzantineFirstReceiver::new(vote_primary, vote_secondary),
                    Some(node.clone()),
                    WedgeChannel::Vote,
                ),
            );

            let certificate_router = router.clone();
            let (certificate_primary, certificate_secondary) = certificate_receiver.split_with(
                context.child("byzantine_first_certificate"),
                move |message| certificate_router.route(message),
            );
            let certificate = (
                certificate_sender,
                WedgeReceiver::<SchemeOf<P>, Sha256Digest, B<P>, _>::new(
                    ByzantineFirstReceiver::new(certificate_primary, certificate_secondary),
                    Some(node.clone()),
                    WedgeChannel::Certificate,
                ),
            );

            let resolver_router = router.clone();
            let (resolver_primary, resolver_secondary) = resolver_receiver
                .split_with(context.child("byzantine_first_resolver"), move |message| {
                    resolver_router.route(message)
                });
            let resolver = (
                resolver_sender,
                WedgeReceiver::<SchemeOf<P>, Sha256Digest, B<P>, _>::new(
                    ByzantineFirstReceiver::new(resolver_primary, resolver_secondary),
                    Some(node.clone()),
                    WedgeChannel::Resolver,
                ),
            );

            let validator_ctx = context
                .child("validator")
                .with_attribute("public_key", validator);
            let provider = ConstantProvider::new(scheme.clone());
            let mut marshal_node = setup_validator::<P>(
                validator_ctx.child("marshal"),
                &mut oracle,
                validator.clone(),
                provider,
                genesis_marshal_block.clone(),
                DEFAULT_MAX_PENDING_ACKS,
                Some(node),
            )
            .await;
            apps.push((idx, role.label(), marshal_node.application.clone()));

            let application =
                <AlwaysAcceptBlockBuilderApp<Ctx<P>, SchemeOf<P>> as TwinsBlockBuilder<P>>::create(
                    ApplicationChoice::AlwaysAccept,
                    faulty_config,
                    None,
                    block_contexts.clone(),
                    DeliveryReporter::new(
                        idx,
                        marshal_node.application.clone(),
                        Some(DEFAULT_MAX_PENDING_ACKS),
                        "marshal-scenario".into(),
                    ),
                );
            let builder = <DeferredMarshal as TwinsMarshal<P, _>>::create(
                MarshalChoice::Deferred,
                &validator_ctx,
                application,
                marshal_node.mailbox.clone(),
            );
            marshal_node.start(builder.clone());

            start_engine::<P, _, _, _>(
                validator_ctx,
                &oracle,
                validator.clone(),
                scheme,
                P::elector(TermLength::ONE),
                builder.clone(),
                builder,
                marshal_node.mailbox.clone(),
                genesis_commitment,
                format!("marshal-scenario-{idx}"),
                forwarding,
                vote,
                certificate,
                resolver,
            );
        }

        // The generated actions are spliced into the template's stages in
        // round-robin order, so they perturb every pre-GST window.
        let stages = template.stages();
        let mut generated: Vec<Vec<PreGstAction>> = vec![Vec::new(); stages.len()];
        for (position, action) in actions.iter().enumerate() {
            generated[position % stages.len()].push(*action);
        }
        let mut budget = MAX_GENERATED_TIME;
        for (stage, (phase, script)) in stages.iter().enumerate() {
            wedge.set_phase(*phase);
            for action in script {
                apply_action(&context, &mut topology, &wedge, *action, None).await;
            }
            for action in &generated[stage] {
                apply_action(&context, &mut topology, &wedge, *action, Some(&mut budget)).await;
            }
        }

        gst(&mut topology, &wedge).await;
        let baselines: Vec<(&'static str, u64)> = apps
            .iter()
            .filter(|(idx, _, _)| Role::from_index(*idx).is_correct())
            .map(|(_, label, app)| (*label, highest_delivered(app)))
            .collect();

        context.sleep(SETTLE).await;

        // Safety runs on every execution, before any liveness verdict, so a
        // stalled run still reports an ordering, linkage or agreement failure.
        let correct: Vec<(usize, Application<B<P>>)> = apps
            .iter()
            .filter(|(idx, _, _)| Role::from_index(*idx).is_correct())
            .map(|(idx, _, app)| (*idx, app.clone()))
            .collect();
        invariants::check_all_blocks(&correct, Some("marshal-scenario"));

        ScenarioOutcome {
            template,
            actions: actions.len(),
            forwarding,
            byzantine_policy,
            baselines,
            heights: apps
                .iter()
                .map(|(_, label, app)| (*label, highest_delivered(app)))
                .collect(),
            unhealed_links: topology.down(),
            honest_drops_pre_gst: wedge.honest_drops(WedgePhase::Isolated)
                + wedge.honest_drops(WedgePhase::Asynchronous),
            honest_drops_post_gst: wedge.honest_drops(WedgePhase::PostGst),
            byzantine_withholds: wedge.byzantine_withholds(),
            resolver_drops: wedge.channel_drops(WedgeChannel::Resolver),
            ledger: wedge.drop_ledger(),
            events: wedge.events(),
            requests: wedge.victim_requests(),
            attack_payload: wedge.attack_payload(),
        }
    })
}

/// The GST boundary.
///
/// Nothing generated reaches this: the pre-GST program runs to completion
/// inside the stage loop above, and this heals every link, advances the phase,
/// and disarms every correct-message rule unconditionally.
async fn gst<K: PublicKey, D: commonware_cryptography::Digest>(
    topology: &mut Topology<K>,
    wedge: &Wedge<K, D>,
) {
    topology.heal().await;
    wedge.set_phase(WedgePhase::PostGst);
    wedge.disarm_honest_rules();
}

/// Applies one pre-GST action.
///
/// `budget` caps the simulated time generated actions may add; scripted
/// template actions pass `None` and are not charged.
async fn apply_action<K: PublicKey, D: commonware_cryptography::Digest>(
    context: &deterministic::Context,
    topology: &mut Topology<K>,
    wedge: &Wedge<K, D>,
    action: PreGstAction,
    budget: Option<&mut Duration>,
) {
    match action {
        PreGstAction::AdvanceTime(millis) => {
            let mut advance = Duration::from_millis(millis.min(MAX_ADVANCE_MILLIS).into());
            if let Some(budget) = budget {
                advance = advance.min(*budget);
                *budget -= advance;
            }
            if !advance.is_zero() {
                context.sleep(advance).await;
            }
        }
        PreGstAction::RemoveLink { from, to } => {
            topology.remove(from.index(), to.index()).await;
        }
        PreGstAction::SetLink {
            from,
            to,
            latency_ms,
        } => {
            let link = Link {
                latency: Duration::from_millis(latency_ms.min(MAX_LATENCY_MILLIS).into()),
                jitter: LINK.jitter,
                success_rate: 1.0,
            };
            topology.set(from.index(), to.index(), link).await;
        }
        PreGstAction::EnableDrop(rule) => wedge.set_honest_rule(rule.wedge_drop(), true),
        PreGstAction::DisableDrop(rule) => wedge.set_honest_rule(rule.wedge_drop(), false),
    }
}

/// Crypto: `P` (the target uses `SimplexCertificateMock`). Marshal: standard,
/// deferred. Cluster: `N4F1C3`, one byzantine node, no Twins. App: fixed
/// always-accept.
///
/// Safety invariants run inside every execution. The crash oracle is post-GST
/// liveness measured from each correct node's height at GST.
pub fn fuzz_marshal_standard_scenarios<P: Simplex>(input: MarshalScenarioInput) {
    let outcome = run_scenario::<P>(&input, |_| {});
    invariants::check_scenario_phases(&outcome);
    invariants::check_scenario_progress(&outcome);
}

#[cfg(test)]
mod recovery {
    use super::*;
    use crate::SimplexCertificateMock;

    /// Recovery path enabled after GST.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum WedgeControl {
        /// The byzantine node serves its attack-round block after GST.
        ServeNotarized,
        /// The attack-view nullification is delivered to the victim once after
        /// GST.
        DeliverNullification,
    }

    impl WedgeControl {
        const fn as_str(self) -> &'static str {
            match self {
                Self::ServeNotarized => "control-serve-notarized",
                Self::DeliverNullification => "control-deliver-nullification",
            }
        }
    }

    fn tapes() -> Vec<Vec<u8>> {
        std::env::var("WEDGE_TAPES").map_or_else(
            |_| (0..6u8).map(|tape| vec![tape; 8]).collect(),
            |raw| {
                raw.split(',')
                    .filter_map(|tape| tape.trim().parse::<u8>().ok())
                    .map(|tape| vec![tape; 8])
                    .collect()
            },
        )
    }

    fn report(control: WedgeControl, tape: &[u8], outcome: &ScenarioOutcome, verbose: bool) {
        println!(
            "\n=== tape={tape:?} scenario={} template={} heights={:?} baselines={:?}",
            control.as_str(),
            outcome.template.as_str(),
            outcome.heights,
            outcome.baselines
        );
        println!(
            "    drops honest(pre)={} honest(post)={} byzantine={} resolver-channel={}",
            outcome.honest_drops_pre_gst,
            outcome.honest_drops_post_gst,
            outcome.byzantine_withholds,
            outcome.resolver_drops
        );
        for (drop, phase, count) in &outcome.ledger {
            println!("    ledger {drop:?} {phase:?} = {count}");
        }
        println!("    attack payload = {:?}", outcome.attack_payload);
        println!(
            "    victim attack-view requests ({}):",
            outcome.requests.len()
        );
        for request in &outcome.requests {
            println!(
                "      t={:>8.3}s -> {} id={} view={}",
                request.at.as_secs_f64(),
                request.responder,
                request.id,
                request.view
            );
        }
        let answered_by = outcome
            .node_events("V")
            .find(|event| event.detail.contains("ANSWER notarization view=1"));
        println!(
            "    byzantine answer: {}",
            answered_by.map_or_else(|| "none".to_string(), std::string::ToString::to_string)
        );
        let nullifications: Vec<_> = outcome
            .node_events("V")
            .filter(|event| event.detail.contains("ANSWER nullification view=1"))
            .collect();
        println!(
            "    attack-view nullifications delivered to the victim: {} ({} after GST)",
            nullifications.len(),
            nullifications
                .iter()
                .filter(|event| event.phase == WedgePhase::PostGst)
                .count()
        );
        println!(
            "    attack block arrivals at the victim: {}",
            outcome
                .node_events("V")
                .filter(|event| event.detail.contains("ATTACK BLOCK"))
                .count()
        );
        if verbose {
            println!("    events ({}):", outcome.events.len());
            for event in &outcome.events {
                println!("      {event}");
            }
        }
    }

    /// The wedge is a scenario, not an accident: repairing either of the two
    /// paths that starve the victim lets the cluster recover.
    #[test]
    fn split_notarization_controls() {
        let verbose = std::env::var("WEDGE_VERBOSE").is_ok();
        for control in [
            WedgeControl::ServeNotarized,
            WedgeControl::DeliverNullification,
        ] {
            let tapes = tapes();
            for tape in &tapes {
                let input = MarshalScenarioInput {
                    raw_bytes: tape.clone(),
                    template: ScenarioTemplate::SplitNotarization,
                    actions: Vec::new(),
                    byzantine_policy: ByzantinePolicy::ALL,
                    forwarding: ForwardingPolicy::SilentVoters,
                };
                let outcome =
                    run_scenario::<SimplexCertificateMock>(&input, move |wedge| match control {
                        WedgeControl::ServeNotarized => wedge.enable_serve_after_gst(),
                        WedgeControl::DeliverNullification => {
                            wedge.enable_nullification_injection();
                        }
                    });
                report(control, tape, &outcome, verbose);
                invariants::check_scenario_phases(&outcome);
                invariants::check_scenario_progress(&outcome);
                println!("    VERDICT: recovered");
            }
            println!(
                "\nSUMMARY {} recovered {}/{}",
                control.as_str(),
                tapes.len(),
                tapes.len()
            );
        }
    }
}
