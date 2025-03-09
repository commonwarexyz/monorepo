use super::{Config, Mailbox, Message};
use crate::{
    threshold_simplex::{
        actors::resolver,
        encoder::{
            finalize_namespace, notarize_namespace, nullify_message, nullify_namespace,
            proposal_message, seed_message, seed_namespace,
        },
        metrics,
        prover::Prover,
        verifier::{verify_finalization, verify_notarization, verify_nullification},
        wire, Context, View, CONFLICTING_FINALIZE, CONFLICTING_NOTARIZE, FINALIZE, NOTARIZE,
        NULLIFY_AND_FINALIZE,
    },
    Automaton, Committer, Parsed, Relay, ThresholdSupervisor, LATENCY,
};
use commonware_cryptography::{
    bls12381::primitives::{
        group::{self, Element},
        ops,
        poly::{self, Eval},
    },
    hash,
    sha256::Digest as Sha256Digest,
    Scheme,
};
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Blob, Clock, Handle, Metrics, Spawner, Storage};
use commonware_storage::journal::variable::Journal;
use commonware_utils::{quorum, Array};
use futures::{
    channel::{mpsc, oneshot},
    future::Either,
    pin_mut, StreamExt,
};
use prometheus_client::metrics::{
    counter::Counter, family::Family, gauge::Gauge, histogram::Histogram,
};
use prost::Message as _;
use rand::Rng;
use std::sync::atomic::AtomicI64;
use std::{
    collections::{BTreeMap, HashMap},
    time::{Duration, SystemTime},
};
use tracing::{debug, trace, warn};

const GENESIS_VIEW: View = 0;

struct Round<
    C: Scheme,
    D: Array,
    S: ThresholdSupervisor<
        Seed = group::Signature,
        Index = View,
        Share = group::Share,
        PublicKey = C::PublicKey,
    >,
> {
    start: SystemTime,
    supervisor: S,

    leader: Option<C::PublicKey>,

    view: View,
    leader_deadline: Option<SystemTime>,
    advance_deadline: Option<SystemTime>,
    nullify_retry: Option<SystemTime>,

    // Track one proposal per view (only matters prior to notarization)
    proposal: Option<(Sha256Digest /* proposal */, Parsed<wire::Proposal, D>)>,
    requested_proposal: bool,
    verified_proposal: bool,

    // Track notarizes for all proposals (ensuring any participant only has one recorded notarize)
    notaries: HashMap<u32, Sha256Digest>,
    notarizes: HashMap<Sha256Digest, HashMap<u32, Parsed<wire::Notarize, D>>>,
    notarization: Option<Parsed<wire::Notarization, D>>,
    broadcast_notarize: bool,
    broadcast_notarization: bool,

    // Track nullifies (ensuring any participant only has one recorded nullify)
    nullifies: HashMap<u32, wire::Nullify>,
    nullification: Option<wire::Nullification>,
    broadcast_nullify: bool,
    broadcast_nullification: bool,

    // Track finalizes for all proposals (ensuring any participant only has one recorded finalize)
    finalizers: HashMap<u32, Sha256Digest>,
    finalizes: HashMap<Sha256Digest, HashMap<u32, Parsed<wire::Finalize, D>>>,
    finalization: Option<Parsed<wire::Finalization, D>>,
    broadcast_finalize: bool,
    broadcast_finalization: bool,
}

impl<
        C: Scheme,
        D: Array,
        S: ThresholdSupervisor<
            Seed = group::Signature,
            Index = View,
            Share = group::Share,
            PublicKey = C::PublicKey,
        >,
    > Round<C, D, S>
{
    pub fn new(start: SystemTime, supervisor: S, view: View) -> Self {
        Self {
            start,
            supervisor,

            view,
            leader: None,
            leader_deadline: None,
            advance_deadline: None,
            nullify_retry: None,

            requested_proposal: false,
            proposal: None,
            verified_proposal: false,

            notaries: HashMap::new(),
            notarizes: HashMap::new(),
            notarization: None,
            broadcast_notarize: false,
            broadcast_notarization: false,

            nullifies: HashMap::new(),
            nullification: None,
            broadcast_nullify: false,
            broadcast_nullification: false,

            finalizers: HashMap::new(),
            finalizes: HashMap::new(),
            finalization: None,
            broadcast_finalize: false,
            broadcast_finalization: false,
        }
    }

    pub fn set_leader(&mut self, seed: group::Signature) {
        let leader = ThresholdSupervisor::leader(&self.supervisor, self.view, seed).unwrap();
        self.leader = Some(leader);
    }

    fn add_verified_proposal(&mut self, proposal: Parsed<wire::Proposal, D>) {
        let message = proposal_message(
            proposal.message.view,
            proposal.message.parent,
            &proposal.digest,
        );
        let proposal_digest = hash(&message);
        if self.proposal.is_none() {
            debug!(
                view = proposal.message.view,
                digest = ?proposal_digest,
                "setting unverified proposal in notarization"
            );
            self.proposal = Some((proposal_digest, proposal));
        } else if let Some((previous_digest, _)) = &self.proposal {
            if proposal_digest != *previous_digest {
                warn!(
                    view = proposal.message.view,
                    ?previous_digest,
                    digest = ?proposal_digest,
                    "proposal in notarization does not match stored proposal"
                );
            }
        }
    }

    async fn add_verified_notarize(
        &mut self,
        public_key_index: u32,
        notarize: Parsed<wire::Notarize, D>,
    ) -> bool {
        // Get proposal
        let proposal = notarize.message.proposal.as_ref().unwrap();

        // Compute proposal digest
        let message = proposal_message(proposal.view, proposal.parent, &notarize.digest);
        let proposal_digest = hash(&message);

        // Check if already notarized
        if let Some(previous_notarize) = self.notaries.get(&public_key_index) {
            if previous_notarize == &proposal_digest {
                trace!(
                    view = self.view,
                    signer = public_key_index,
                    ?previous_notarize,
                    "already notarized"
                );
                return false;
            }

            // Create fault
            let previous_notarize = self
                .notarizes
                .get(previous_notarize)
                .unwrap()
                .get(&public_key_index)
                .unwrap();
            let previous_proposal = previous_notarize.message.proposal.as_ref().unwrap();
            let proof = Prover::<D>::serialize_conflicting_notarize(
                self.view,
                previous_proposal.parent,
                &previous_notarize.digest,
                &previous_notarize.message.proposal_signature,
                proposal.parent,
                &notarize.digest,
                &notarize.message.proposal_signature,
            );
            self.supervisor.report(CONFLICTING_NOTARIZE, proof).await;
            warn!(
                view = self.view,
                signer = public_key_index,
                activity = CONFLICTING_NOTARIZE,
                "recorded fault"
            );
            return false;
        }

        // Store the notarize
        if self
            .notaries
            .insert(public_key_index, proposal_digest.clone())
            .is_some()
        {
            return false;
        }
        let entry = self.notarizes.entry(proposal_digest).or_default();
        let proof = Prover::<D>::serialize_proposal(proposal, &notarize.message.proposal_signature);
        entry.insert(public_key_index, notarize);
        self.supervisor.report(NOTARIZE, proof).await;
        true
    }

    async fn add_verified_nullify(
        &mut self,
        public_key_index: u32,
        nullify: wire::Nullify,
    ) -> bool {
        // Check if already issued finalize
        let finalize = self.finalizers.get(&public_key_index);
        if finalize.is_none() {
            // Store the nullify
            return self.nullifies.insert(public_key_index, nullify).is_none();
        }
        let finalize = finalize.unwrap();

        // Create fault
        let finalize = self
            .finalizes
            .get(finalize)
            .unwrap()
            .get(&public_key_index)
            .unwrap();
        let finalize_proposal = finalize.message.proposal.as_ref().unwrap();
        let proof = Prover::<D>::serialize_nullify_finalize(
            self.view,
            finalize_proposal.parent,
            &finalize.digest,
            &finalize.message.proposal_signature,
            &nullify.view_signature,
        );
        self.supervisor.report(NULLIFY_AND_FINALIZE, proof).await;
        warn!(
            view = self.view,
            signer = public_key_index,
            activity = NULLIFY_AND_FINALIZE,
            "recorded fault"
        );
        false
    }

    async fn add_verified_finalize(
        &mut self,
        public_key_index: u32,
        finalize: Parsed<wire::Finalize, D>,
    ) -> bool {
        // Check if also issued nullify
        let proposal = finalize.message.proposal.as_ref().unwrap();
        let null = self.nullifies.get(&public_key_index);
        if let Some(null) = null {
            // Create fault
            let proof = Prover::<D>::serialize_nullify_finalize(
                self.view,
                proposal.parent,
                &finalize.digest,
                &finalize.message.proposal_signature,
                &null.view_signature,
            );
            self.supervisor.report(NULLIFY_AND_FINALIZE, proof).await;
            warn!(
                view = self.view,
                signer = public_key_index,
                activity = NULLIFY_AND_FINALIZE,
                "recorded fault"
            );
            return false;
        }
        // Compute proposal digest
        let message = proposal_message(proposal.view, proposal.parent, &finalize.digest);
        let proposal_digest = hash(&message);

        // Check if already finalized
        if let Some(previous_finalize) = self.finalizers.get(&public_key_index) {
            if previous_finalize == &proposal_digest {
                trace!(
                    view = self.view,
                    signer = public_key_index,
                    ?previous_finalize,
                    "already finalize"
                );
                return false;
            }

            // Create fault
            let previous_finalize = self
                .finalizes
                .get(previous_finalize)
                .unwrap()
                .get(&public_key_index)
                .unwrap();
            let previous_proposal = previous_finalize.message.proposal.as_ref().unwrap();
            let proof = Prover::<D>::serialize_conflicting_finalize(
                self.view,
                previous_proposal.parent,
                &previous_finalize.digest,
                &previous_finalize.message.proposal_signature,
                proposal.parent,
                &finalize.digest,
                &finalize.message.proposal_signature,
            );
            self.supervisor.report(CONFLICTING_FINALIZE, proof).await;
            warn!(
                view = self.view,
                signer = public_key_index,
                activity = CONFLICTING_FINALIZE,
                "recorded fault"
            );
            return false;
        }

        // Store the finalize
        if self
            .finalizers
            .insert(public_key_index, proposal_digest.clone())
            .is_some()
        {
            return false;
        }
        let entry = self.finalizes.entry(proposal_digest).or_default();
        let signature = &finalize.message.proposal_signature;
        let proof = Prover::<D>::serialize_proposal(proposal, signature);
        entry.insert(public_key_index, finalize);
        self.supervisor.report(FINALIZE, proof).await;
        true
    }

    fn add_verified_notarization(&mut self, notarization: Parsed<wire::Notarization, D>) -> bool {
        // If already have notarization, ignore
        if self.notarization.is_some() {
            return false;
        }

        // Clear leader and advance deadlines (if they exist)
        self.leader_deadline = None;
        self.advance_deadline = None;

        // If proposal is missing, set it
        let proposal = notarization.message.proposal.as_ref().unwrap().clone();
        self.add_verified_proposal(Parsed {
            message: proposal,
            digest: notarization.digest.clone(),
        });

        // Store the notarization
        self.notarization = Some(notarization);
        true
    }

    fn add_verified_nullification(&mut self, nullification: wire::Nullification) -> bool {
        // If already have nullification, ignore
        if self.nullification.is_some() {
            return false;
        }

        // Clear leader and advance deadlines (if they exist)
        self.leader_deadline = None;
        self.advance_deadline = None;

        // Store the nullification
        self.nullification = Some(nullification);
        true
    }

    fn add_verified_finalization(&mut self, finalization: Parsed<wire::Finalization, D>) -> bool {
        // If already have finalization, ignore
        if self.finalization.is_some() {
            return false;
        }

        // Clear leader and advance deadlines (if they exist)
        self.leader_deadline = None;
        self.advance_deadline = None;

        // If proposal is missing, set it
        let proposal = finalization.message.proposal.as_ref().unwrap().clone();
        self.add_verified_proposal(Parsed {
            message: proposal,
            digest: finalization.digest.clone(),
        });

        // Store the finalization
        self.finalization = Some(finalization);
        true
    }

    fn notarizable(
        &mut self,
        threshold: u32,
        force: bool,
    ) -> Option<Parsed<wire::Notarization, D>> {
        // Ensure we haven't already broadcast
        if !force && (self.broadcast_notarization || self.broadcast_nullification) {
            // We want to broadcast a notarization, even if we haven't yet verified a proposal.
            return None;
        }

        // If already constructed, return
        if let Some(notarization) = &self.notarization {
            self.broadcast_notarization = true;
            return Some(notarization.clone());
        }

        // Attempt to construct notarization
        for (proposal, notarizes) in self.notarizes.iter() {
            if (notarizes.len() as u32) < threshold {
                continue;
            }

            // There should never exist enough notarizes for multiple proposals, so it doesn't
            // matter which one we choose.
            debug!(
                view = self.view,
                ?proposal,
                verified = self.verified_proposal,
                "broadcasting notarization"
            );

            // Grab the proposal (all will be the same)
            let notarize = notarizes.values().next().unwrap();
            let proposal = notarize.message.proposal.as_ref().unwrap().clone();

            // Recover threshold signature
            let mut notarization = Vec::new();
            let mut seed = Vec::new();
            for notarize in notarizes.values() {
                let eval = Eval::deserialize(&notarize.message.proposal_signature).unwrap();
                notarization.push(eval);
                let eval = Eval::deserialize(&notarize.message.seed_signature).unwrap();
                seed.push(eval);
            }
            let proposal_signature = ops::threshold_signature_recover(threshold, notarization)
                .unwrap()
                .serialize();
            let seed_signature = ops::threshold_signature_recover(threshold, seed)
                .unwrap()
                .serialize();

            // Construct notarization
            let notarization = wire::Notarization {
                proposal: Some(proposal.clone()),
                proposal_signature,
                seed_signature,
            };
            self.broadcast_notarization = true;
            return Some(Parsed {
                message: notarization,
                digest: notarize.digest.clone(),
            });
        }
        None
    }

    fn nullifiable(&mut self, threshold: u32, force: bool) -> Option<wire::Nullification> {
        // Ensure we haven't already broadcast
        if !force && (self.broadcast_nullification || self.broadcast_notarization) {
            return None;
        }

        // If already constructed, return
        if let Some(nullification) = &self.nullification {
            self.broadcast_nullification = true;
            return Some(nullification.clone());
        }

        // Attempt to construct nullification
        if (self.nullifies.len() as u32) < threshold {
            return None;
        }
        debug!(view = self.view, "broadcasting nullification");

        // Recover threshold signature
        let mut nullification = Vec::new();
        let mut seed = Vec::new();
        for nullify in self.nullifies.values() {
            let eval = Eval::deserialize(&nullify.view_signature).unwrap();
            nullification.push(eval);
            let eval = Eval::deserialize(&nullify.seed_signature).unwrap();
            seed.push(eval);
        }
        let view_signature = ops::threshold_signature_recover(threshold, nullification)
            .unwrap()
            .serialize();
        let seed_signature = ops::threshold_signature_recover(threshold, seed)
            .unwrap()
            .serialize();

        // Construct nullification
        let nullification = wire::Nullification {
            view: self.view,
            view_signature,
            seed_signature,
        };
        self.broadcast_nullification = true;
        Some(nullification)
    }

    fn finalizable(
        &mut self,
        threshold: u32,
        force: bool,
    ) -> Option<Parsed<wire::Finalization, D>> {
        // Ensure we haven't already broadcast
        if !force && self.broadcast_finalization {
            // We want to broadcast a finalization, even if we haven't yet verified a proposal.
            return None;
        }

        // If already constructed, return
        if let Some(finalization) = &self.finalization {
            self.broadcast_finalization = true;
            return Some(finalization.clone());
        }

        // Attempt to construct finalization
        for (proposal_digest, finalizes) in self.finalizes.iter() {
            if (finalizes.len() as u32) < threshold {
                continue;
            }

            // Ensure we have a notarization
            let Some(notarization) = &self.notarization else {
                continue;
            };
            let seed_signature = notarization.message.seed_signature.clone();

            // Check notarization and finalization proposal match
            let notarization_proposal = notarization.message.proposal.as_ref().unwrap();
            let message = proposal_message(
                notarization_proposal.view,
                notarization_proposal.parent,
                &notarization.digest,
            );
            let notarization_digest = hash(&message);
            if notarization_digest != *proposal_digest {
                warn!(
                    view = self.view,
                    proposal = ?proposal_digest,
                    notarization = ?notarization_digest,
                    "finalization proposal does not match notarization"
                );
            }

            // There should never exist enough finalizes for multiple proposals, so it doesn't
            // matter which one we choose.
            debug!(
                view = self.view,
                proposal = ?proposal_digest,
                verified = self.verified_proposal,
                "broadcasting finalization"
            );

            // Grab the proposal
            let finalize = finalizes.values().next().unwrap();
            let proposal = finalize.message.proposal.as_ref().unwrap().clone();

            // Recover threshold signature
            let mut finalization = Vec::new();
            for finalize in finalizes.values() {
                let eval = Eval::deserialize(&finalize.message.proposal_signature).unwrap();
                finalization.push(eval);
            }
            let proposal_signature = ops::threshold_signature_recover(threshold, finalization)
                .unwrap()
                .serialize();

            // Construct finalization
            let finalization = wire::Finalization {
                proposal: Some(proposal.clone()),
                proposal_signature,
                seed_signature,
            };
            // self.finalization = Some(finalization.clone());
            self.broadcast_finalization = true;
            return Some(Parsed {
                message: finalization,
                digest: finalize.digest.clone(),
            });
        }
        None
    }

    /// Returns whether at least one honest participant has notarized a proposal.
    pub fn at_least_one_honest(&self) -> Option<View> {
        let participants = self.supervisor.participants(self.view)?;
        let threshold = quorum(participants.len() as u32)?;
        let at_least_one_honest = (threshold - 1) / 2 + 1;
        for (_, notarizes) in self.notarizes.iter() {
            if notarizes.len() < at_least_one_honest as usize {
                continue;
            }
            let parent = notarizes
                .values()
                .next()
                .unwrap()
                .message
                .proposal
                .as_ref()
                .unwrap()
                .parent;
            return Some(parent);
        }
        None
    }
}

pub struct Actor<
    B: Blob,
    E: Clock + Rng + Spawner + Storage<B> + Metrics,
    C: Scheme,
    D: Array,
    A: Automaton<Digest = D, Context = Context<D>>,
    R: Relay,
    F: Committer<Digest = D>,
    S: ThresholdSupervisor<
        Identity = poly::Poly<group::Public>,
        Seed = group::Signature,
        Index = View,
        Share = group::Share,
        PublicKey = C::PublicKey,
    >,
> {
    context: E,
    crypto: C,
    automaton: A,
    relay: R,
    committer: F,
    supervisor: S,

    replay_concurrency: usize,
    journal: Option<Journal<B, E>>,

    genesis: Option<D>,

    seed_namespace: Vec<u8>,
    notarize_namespace: Vec<u8>,
    nullify_namespace: Vec<u8>,
    finalize_namespace: Vec<u8>,

    leader_timeout: Duration,
    notarization_timeout: Duration,
    nullify_retry: Duration,
    activity_timeout: View,

    mailbox_receiver: mpsc::Receiver<Message<D>>,

    last_finalized: View,
    view: View,
    views: BTreeMap<View, Round<C, D, S>>,

    current_view: Gauge,
    tracked_views: Gauge,
    received_messages: Family<metrics::PeerMessage, Counter>,
    broadcast_messages: Family<metrics::Message, Counter>,
    notarization_latency: Histogram,
    finalization_latency: Histogram,
}

impl<
        B: Blob,
        E: Clock + Rng + Spawner + Storage<B> + Metrics,
        C: Scheme,
        D: Array,
        A: Automaton<Digest = D, Context = Context<D>>,
        R: Relay<Digest = D>,
        F: Committer<Digest = D>,
        S: ThresholdSupervisor<
            Identity = poly::Poly<group::Public>,
            Seed = group::Signature,
            Index = View,
            Share = group::Share,
            PublicKey = C::PublicKey,
        >,
    > Actor<B, E, C, D, A, R, F, S>
{
    pub fn new(
        context: E,
        journal: Journal<B, E>,
        cfg: Config<C, D, A, R, F, S>,
    ) -> (Self, Mailbox<D>) {
        // Assert correctness of timeouts
        if cfg.leader_timeout > cfg.notarization_timeout {
            panic!("leader timeout must be less than or equal to notarization timeout");
        }

        // Initialize metrics
        let current_view = Gauge::<i64, AtomicI64>::default();
        let tracked_views = Gauge::<i64, AtomicI64>::default();
        let received_messages = Family::<metrics::PeerMessage, Counter>::default();
        let broadcast_messages = Family::<metrics::Message, Counter>::default();
        let notarization_latency = Histogram::new(LATENCY.into_iter());
        let finalization_latency = Histogram::new(LATENCY.into_iter());
        context.register("current_view", "current view", current_view.clone());
        context.register("tracked_views", "tracked views", tracked_views.clone());
        context.register(
            "received_messages",
            "received messages",
            received_messages.clone(),
        );
        context.register(
            "broadcast_messages",
            "broadcast messages",
            broadcast_messages.clone(),
        );
        context.register(
            "notarization_latency",
            "notarization latency",
            notarization_latency.clone(),
        );
        context.register(
            "finalization_latency",
            "finalization latency",
            finalization_latency.clone(),
        );

        // Initialize store
        let (mailbox_sender, mailbox_receiver) = mpsc::channel(cfg.mailbox_size);
        let mailbox = Mailbox::new(mailbox_sender);
        (
            Self {
                context,
                crypto: cfg.crypto,
                automaton: cfg.automaton,
                relay: cfg.relay,
                committer: cfg.committer,
                supervisor: cfg.supervisor,

                replay_concurrency: cfg.replay_concurrency,
                journal: Some(journal),

                genesis: None,

                seed_namespace: seed_namespace(&cfg.namespace),
                notarize_namespace: notarize_namespace(&cfg.namespace),
                nullify_namespace: nullify_namespace(&cfg.namespace),
                finalize_namespace: finalize_namespace(&cfg.namespace),

                leader_timeout: cfg.leader_timeout,
                notarization_timeout: cfg.notarization_timeout,
                nullify_retry: cfg.nullify_retry,

                activity_timeout: cfg.activity_timeout,

                mailbox_receiver,

                last_finalized: 0,
                view: 0,
                views: BTreeMap::new(),

                current_view,
                tracked_views,
                received_messages,
                broadcast_messages,
                notarization_latency,
                finalization_latency,
            },
            mailbox,
        )
    }

    fn is_notarized(&self, view: View) -> Option<&D> {
        let round = self.views.get(&view)?;
        if let Some(notarization) = &round.notarization {
            return Some(&notarization.digest);
        }
        let (digest, proposal) = round.proposal.as_ref()?;
        let notarizes = round.notarizes.get(digest)?;
        let identity = self.supervisor.identity(view)?;
        let threshold = identity.required();
        if notarizes.len() >= threshold as usize {
            return Some(&proposal.digest);
        }
        None
    }

    fn is_nullified(&self, view: View) -> bool {
        let round = match self.views.get(&view) {
            Some(round) => round,
            None => return false,
        };
        let identity = match self.supervisor.identity(view) {
            Some(identity) => identity,
            None => return false,
        };
        let threshold = identity.required();
        round.nullification.is_some() || round.nullifies.len() >= threshold as usize
    }

    fn is_finalized(&self, view: View) -> Option<&D> {
        let round = self.views.get(&view)?;
        if let Some(finalization) = &round.finalization {
            return Some(&finalization.digest);
        }
        let (digest, proposal) = round.proposal.as_ref()?;
        let finalizes = round.finalizes.get(digest)?;
        let identity = self.supervisor.identity(view)?;
        let threshold = identity.required();
        if finalizes.len() >= threshold as usize {
            return Some(&proposal.digest);
        }
        None
    }

    fn find_parent(&self) -> Result<(View, D), View> {
        let mut cursor = self.view - 1; // self.view always at least 1
        loop {
            if cursor == 0 {
                return Ok((GENESIS_VIEW, self.genesis.as_ref().unwrap().clone()));
            }

            // If have notarization, return
            let parent = self.is_notarized(cursor);
            if let Some(parent) = parent {
                return Ok((cursor, parent.clone()));
            }

            // If have finalization, return
            //
            // We never want to build on some view less than finalized and this prevents that
            let parent = self.is_finalized(cursor);
            if let Some(parent) = parent {
                return Ok((cursor, parent.clone()));
            }

            // If have nullification, continue
            if self.is_nullified(cursor) {
                cursor -= 1;
                continue;
            }

            // We can't find a valid parent, return
            return Err(cursor);
        }
    }

    fn missing_nullifications(&self, parent: View) -> Vec<View> {
        let mut missing = Vec::new();
        for view in (parent + 1)..self.view {
            if !self.is_nullified(view) {
                missing.push(view);
            }
        }
        missing
    }

    #[allow(clippy::question_mark)]
    async fn propose(
        &mut self,
        backfiller: &mut resolver::Mailbox,
    ) -> Option<(Context<D>, oneshot::Receiver<D>)> {
        // Check if we are leader
        {
            let round = self.views.get_mut(&self.view).unwrap();
            let Some(leader) = &round.leader else {
                return None;
            };
            if *leader != self.crypto.public_key() {
                return None;
            }

            // Check if we have already requested a proposal
            if round.requested_proposal {
                return None;
            }

            // Check if we have already proposed
            if round.proposal.is_some() {
                return None;
            }

            // Set that we requested a proposal even if we don't end up finding a parent
            // to prevent frequent scans.
            round.requested_proposal = true;
        }

        // Find best parent
        let (parent_view, parent_payload) = match self.find_parent() {
            Ok(parent) => parent,
            Err(view) => {
                debug!(
                    view = self.view,
                    missing = view,
                    "skipping proposal opportunity"
                );
                backfiller.fetch(vec![view], vec![view]).await;
                return None;
            }
        };

        // Request proposal from application
        debug!(view = self.view, "requested proposal from automaton");
        let context = Context {
            view: self.view,
            parent: (parent_view, parent_payload),
        };
        Some((context.clone(), self.automaton.propose(context).await))
    }

    fn timeout_deadline(&mut self) -> SystemTime {
        // Return the earliest deadline
        let view = self.views.get_mut(&self.view).unwrap();
        if let Some(deadline) = view.leader_deadline {
            return deadline;
        }
        if let Some(deadline) = view.advance_deadline {
            return deadline;
        }

        // If no deadlines are still set (waiting for nullify),
        // return next try for nullify.
        if let Some(deadline) = view.nullify_retry {
            return deadline;
        }

        // Set nullify retry, if none already set
        let null_retry = self.context.current() + self.nullify_retry;
        view.nullify_retry = Some(null_retry);
        null_retry
    }

    async fn timeout(&mut self, sender: &mut impl Sender) {
        // Set timeout fired
        let round = self.views.get_mut(&self.view).unwrap();
        let mut retry = false;
        if round.broadcast_nullify {
            retry = true;
        }
        round.broadcast_nullify = true;

        // Remove deadlines
        round.leader_deadline = None;
        round.advance_deadline = None;
        round.nullify_retry = None;

        // If retry, broadcast notarization that led us to enter this view
        let past_view = self.view - 1;
        if retry && past_view > 0 {
            if let Some(notarization) = self.construct_notarization(past_view, true) {
                let msg = wire::Voter {
                    payload: Some(wire::voter::Payload::Notarization(notarization.message)),
                }
                .encode_to_vec()
                .into();
                sender.send(Recipients::All, msg, true).await.unwrap();
                self.broadcast_messages
                    .get_or_create(&metrics::NOTARIZATION)
                    .inc();
                debug!(view = past_view, "rebroadcast entry notarization");
            } else if let Some(nullification) = self.construct_nullification(past_view, true) {
                let msg = wire::Voter {
                    payload: Some(wire::voter::Payload::Nullification(nullification)),
                }
                .encode_to_vec()
                .into();
                sender.send(Recipients::All, msg, true).await.unwrap();
                self.broadcast_messages
                    .get_or_create(&metrics::NULLIFICATION)
                    .inc();
                debug!(view = past_view, "rebroadcast entry nullification");
            } else {
                warn!(
                    view = past_view,
                    "unable to rebroadcast entry notarization/nullification"
                );
            }
        }

        // Construct nullify
        let share = self.supervisor.share(self.view).unwrap();
        let message = nullify_message(self.view);
        let view_signature =
            ops::partial_sign_message(share, Some(&self.nullify_namespace), &message).serialize();
        let message = seed_message(self.view);
        let seed_signature =
            ops::partial_sign_message(share, Some(&self.seed_namespace), &message).serialize();
        let null = wire::Nullify {
            view: self.view,
            view_signature,
            seed_signature,
        };

        // Handle the nullify
        self.handle_nullify(share.index, null.clone()).await;

        // Sync the journal
        self.journal
            .as_mut()
            .unwrap()
            .sync(self.view)
            .await
            .expect("unable to sync journal");

        // Broadcast nullify
        let msg = wire::Voter {
            payload: Some(wire::voter::Payload::Nullify(null)),
        }
        .encode_to_vec()
        .into();
        sender.send(Recipients::All, msg, true).await.unwrap();
        self.broadcast_messages
            .get_or_create(&metrics::NULLIFY)
            .inc();
        debug!(view = self.view, "broadcasted nullify");
    }

    async fn nullify(&mut self, sender: &C::PublicKey, nullify: wire::Nullify) {
        // Ensure we are in the right view to process this message
        if !self.interesting(nullify.view, false) {
            return;
        }

        // Verify that signer is a validator
        let Some(public_key_index) = self.supervisor.is_participant(nullify.view, sender) else {
            return;
        };
        let Some(identity) = self.supervisor.identity(nullify.view) else {
            return;
        };

        // Verify signature
        let Some(signature) = Eval::deserialize(&nullify.view_signature) else {
            debug!(
                public_key_index,
                "partial signature is not formatted correctly"
            );
            return;
        };
        if signature.index != public_key_index {
            debug!(
                public_key_index,
                partial_signature = signature.index,
                "invalid signature index for nullify"
            );
            return;
        }
        let nullify_message = nullify_message(nullify.view);
        if ops::partial_verify_message(
            identity,
            Some(&self.nullify_namespace),
            &nullify_message,
            &signature,
        )
        .is_err()
        {
            return;
        }

        // Verify seed
        let Some(seed) = Eval::deserialize(&nullify.seed_signature) else {
            return;
        };
        if seed.index != public_key_index {
            return;
        }
        let seed_message = seed_message(nullify.view);
        if ops::partial_verify_message(identity, Some(&self.seed_namespace), &seed_message, &seed)
            .is_err()
        {
            return;
        }

        // Handle nullify
        self.handle_nullify(public_key_index, nullify).await;
    }

    async fn handle_nullify(&mut self, public_key_index: u32, nullify: wire::Nullify) {
        // Check to see if nullify is for proposal in view
        let view = nullify.view;
        let round = self
            .views
            .entry(view)
            .or_insert_with(|| Round::new(self.context.current(), self.supervisor.clone(), view));

        // Handle nullify
        let nullify_bytes = wire::Voter {
            payload: Some(wire::voter::Payload::Nullify(nullify.clone())),
        }
        .encode_to_vec()
        .into();
        if round.add_verified_nullify(public_key_index, nullify).await && self.journal.is_some() {
            self.journal
                .as_mut()
                .unwrap()
                .append(view, nullify_bytes)
                .await
                .expect("unable to append nullify");
        }
    }

    async fn our_proposal(
        &mut self,
        proposal_digest: Sha256Digest,
        proposal: Parsed<wire::Proposal, D>,
    ) -> bool {
        // Store the proposal
        let round = self
            .views
            .get_mut(&proposal.message.view)
            .expect("view missing");

        // Check if view timed out
        if round.broadcast_nullify {
            debug!(
                view = proposal.message.view,
                reason = "view timed out",
                "dropping our proposal"
            );
            return false;
        }

        // Store the proposal
        debug!(
            view = proposal.message.view,
            parent = proposal.message.parent,
            digest = ?proposal_digest,
            "generated proposal"
        );
        round.proposal = Some((proposal_digest, proposal));
        round.verified_proposal = true;
        round.leader_deadline = None;
        true
    }

    // Attempt to set proposal from each message received over the wire
    #[allow(clippy::question_mark)]
    async fn peer_proposal(&mut self) -> Option<(Context<D>, oneshot::Receiver<bool>)> {
        // Get round
        let (proposal_digest, proposal) = {
            // Get view or exit
            let round = self.views.get(&self.view)?;

            // If we are the leader, drop peer proposals
            let Some(leader) = &round.leader else {
                debug!(
                    view = self.view,
                    "dropping peer proposal because leader is not set"
                );
                return None;
            };
            if *leader == self.crypto.public_key() {
                return None;
            }
            let leader_index = self.supervisor.is_participant(self.view, leader)?;

            // If we already broadcast nullify or set proposal, do nothing
            if round.broadcast_nullify {
                return None;
            }
            if round.proposal.is_some() {
                return None;
            }

            // Check if leader has signed a digest
            let proposal_digest = round.notaries.get(&leader_index)?;
            let notarize = round.notarizes.get(proposal_digest)?.get(&leader_index)?;
            let proposal = notarize.message.proposal.as_ref()?;

            // Check parent validity
            if proposal.view <= proposal.parent {
                debug!(
                    view = proposal.view,
                    parent = proposal.parent,
                    "dropping peer proposal because parent is invalid"
                );
                return None;
            }
            if proposal.parent < self.last_finalized {
                debug!(
                    view = proposal.view,
                    parent = proposal.parent,
                    last_finalized = self.last_finalized,
                    "dropping peer proposal because parent is less than last finalized"
                );
                return None;
            }
            (
                proposal_digest,
                Parsed {
                    message: proposal.clone(),
                    digest: notarize.digest.clone(),
                },
            )
        };

        // Ensure we have required notarizations
        let mut cursor = match self.view {
            0 => {
                return None;
            }
            _ => self.view - 1,
        };
        let parent_payload = loop {
            if cursor == proposal.message.parent {
                // Check if first block
                if proposal.message.parent == GENESIS_VIEW {
                    break self.genesis.as_ref().unwrap().clone();
                }

                // Check notarization exists
                let parent_proposal = match self.is_notarized(cursor) {
                    Some(parent) => parent,
                    None => {
                        debug!(view = cursor, "parent proposal is not notarized");
                        return None;
                    }
                };

                // Peer proposal references a valid parent
                break parent_proposal.clone();
            }

            // Check nullification exists in gap
            if !self.is_nullified(cursor) {
                debug!(
                    view = cursor,
                    "missing nullification during proposal verification"
                );
                return None;
            }
            cursor -= 1;
        };

        // Request verification
        debug!(
            view = proposal.message.view,
            digest = ?proposal_digest,
            payload = ?proposal.digest,
            "requested proposal verification",
        );
        let context = Context {
            view: proposal.message.view,
            parent: (proposal.message.parent, parent_payload),
        };
        let payload = proposal.digest.clone();
        let round_proposal = Some((proposal_digest.clone(), proposal));
        let round = self.views.get_mut(&context.view).unwrap();
        round.proposal = round_proposal;
        Some((
            context.clone(),
            self.automaton.verify(context, payload).await,
        ))
    }

    async fn verified(&mut self, view: View) -> bool {
        // Check if view still relevant
        let round = match self.views.get_mut(&view) {
            Some(view) => view,
            None => {
                debug!(view, reason = "view missing", "dropping verified proposal");
                return false;
            }
        };

        // Ensure we haven't timed out
        if round.broadcast_nullify {
            debug!(
                view,
                reason = "view timed out",
                "dropping verified proposal"
            );
            return false;
        }

        // Mark proposal as verified
        round.leader_deadline = None;
        round.verified_proposal = true;

        // Indicate that verification is done
        debug!(view, "verified proposal");
        true
    }

    fn since_view_start(&self, view: u64) -> Option<(bool, f64)> {
        let round = self.views.get(&view)?;
        let leader = round.leader.as_ref()?;
        let Ok(elapsed) = self.context.current().duration_since(round.start) else {
            return None;
        };
        Some((*leader == self.crypto.public_key(), elapsed.as_secs_f64()))
    }

    fn enter_view(&mut self, view: u64, seed: group::Signature) {
        // Ensure view is valid
        if view <= self.view {
            trace!(
                view = view,
                our_view = self.view,
                "skipping useless view change"
            );
            return;
        }

        // Setup new view
        let round = self
            .views
            .entry(view)
            .or_insert_with(|| Round::new(self.context.current(), self.supervisor.clone(), view));
        round.leader_deadline = Some(self.context.current() + self.leader_timeout);
        round.advance_deadline = Some(self.context.current() + self.notarization_timeout);
        round.set_leader(seed);
        self.view = view;

        // If we are backfilling, exit early
        if self.journal.is_none() {
            return;
        }

        // Check if we should fast exit this view
        let leader = round.leader.as_ref().unwrap().clone();
        if view < self.activity_timeout || leader == self.crypto.public_key() {
            // Don't fast exit the view
            return;
        }
        let mut next = view - 1;
        while next > view - self.activity_timeout {
            let leader_index = match self.supervisor.is_participant(next, &leader) {
                Some(index) => index,
                None => {
                    // Don't punish a participant if they weren't online at any point during
                    // the lookback window.
                    return;
                }
            };
            let round = match self.views.get(&next) {
                Some(round) => round,
                None => {
                    return;
                }
            };
            if round.notaries.contains_key(&leader_index)
                || round.nullifies.contains_key(&leader_index)
            {
                return;
            }
            next -= 1;
        }

        // Reduce leader deadline to now
        debug!(view, ?leader, "skipping leader timeout due to inactivity");
        self.views.get_mut(&view).unwrap().leader_deadline = Some(self.context.current());
    }

    fn interesting(&self, view: View, allow_future: bool) -> bool {
        if view + self.activity_timeout < self.last_finalized {
            return false;
        }
        if !allow_future && view > self.view + 1 {
            return false;
        }
        true
    }

    async fn prune_views(&mut self) {
        // Get last min
        let mut pruned = false;
        let min = loop {
            // Get next key
            let next = match self.views.keys().next() {
                Some(next) => *next,
                None => return,
            };

            // Compare to last finalized
            if !self.interesting(next, false) {
                self.views.remove(&next);
                debug!(
                    view = next,
                    last_finalized = self.last_finalized,
                    "pruned view"
                );
                pruned = true;
            } else {
                break next;
            }
        };

        // Prune journal up to min
        if pruned {
            self.journal
                .as_mut()
                .unwrap()
                .prune(min)
                .await
                .expect("unable to prune journal");
        }
    }

    async fn notarize(&mut self, sender: &C::PublicKey, notarize: wire::Notarize) {
        // Extract proposal
        let Some(proposal) = notarize.proposal.as_ref() else {
            return;
        };

        // Ensure we are in the right view to process this message
        if !self.interesting(proposal.view, false) {
            return;
        }

        // Ensure digest is well-formed
        let Ok(payload) = D::try_from(&proposal.payload) else {
            return;
        };

        // Verify that signer is a validator
        let Some(public_key_index) = self.supervisor.is_participant(proposal.view, sender) else {
            return;
        };
        let Some(identity) = self.supervisor.identity(proposal.view) else {
            return;
        };

        // Verify signature
        let Some(signature) = Eval::deserialize(&notarize.proposal_signature) else {
            return;
        };
        if signature.index != public_key_index {
            return;
        }
        let notarize_message = proposal_message(proposal.view, proposal.parent, &payload);
        if ops::partial_verify_message(
            identity,
            Some(&self.notarize_namespace),
            &notarize_message,
            &signature,
        )
        .is_err()
        {
            return;
        }

        // Verify seed
        let Some(seed) = Eval::deserialize(&notarize.seed_signature) else {
            return;
        };
        if seed.index != public_key_index {
            return;
        }
        let seed_message = seed_message(proposal.view);
        if ops::partial_verify_message(identity, Some(&self.seed_namespace), &seed_message, &seed)
            .is_err()
        {
            return;
        }

        // Handle notarize
        self.handle_notarize(
            public_key_index,
            Parsed {
                message: notarize,
                digest: payload,
            },
        )
        .await;
    }

    async fn handle_notarize(
        &mut self,
        public_key_index: u32,
        notarize: Parsed<wire::Notarize, D>,
    ) {
        // Check to see if notarize is for proposal in view
        let view = notarize.message.proposal.as_ref().unwrap().view;
        let round = self
            .views
            .entry(view)
            .or_insert_with(|| Round::new(self.context.current(), self.supervisor.clone(), view));

        // Handle notarize
        let notarize_bytes = wire::Voter {
            payload: Some(wire::voter::Payload::Notarize(notarize.message.clone())),
        }
        .encode_to_vec()
        .into();
        if round
            .add_verified_notarize(public_key_index, notarize)
            .await
            && self.journal.is_some()
        {
            self.journal
                .as_mut()
                .unwrap()
                .append(view, notarize_bytes)
                .await
                .expect("unable to append to journal");
        }
    }

    async fn notarization(&mut self, notarization: wire::Notarization) {
        // Extract proposal
        let Some(proposal) = &notarization.proposal else {
            return;
        };

        // Check if we are still in a view where this notarization could help
        if !self.interesting(proposal.view, true) {
            return;
        }

        // Ensure digest is well-formed
        let Ok(payload) = D::try_from(&proposal.payload) else {
            return;
        };

        // Determine if we already broadcast notarization for this view (in which
        // case we can ignore this message)
        if let Some(ref round) = self.views.get_mut(&proposal.view) {
            if round.broadcast_notarization {
                return;
            }
        }

        // Verify notarization
        if !verify_notarization::<D, S>(
            &self.supervisor,
            &self.notarize_namespace,
            &self.seed_namespace,
            &notarization,
        ) {
            return;
        }

        // Handle notarization
        self.handle_notarization(Parsed {
            message: notarization,
            digest: payload,
        })
        .await;
    }

    async fn handle_notarization(&mut self, notarization: Parsed<wire::Notarization, D>) {
        // Create round (if it doesn't exist)
        let view = notarization.message.proposal.as_ref().unwrap().view;
        let round = self
            .views
            .entry(view)
            .or_insert_with(|| Round::new(self.context.current(), self.supervisor.clone(), view));

        // Store notarization
        let notarization_bytes = wire::Voter {
            payload: Some(wire::voter::Payload::Notarization(
                notarization.message.clone(),
            )),
        }
        .encode_to_vec()
        .into();
        let seed = group::Signature::deserialize(&notarization.message.seed_signature).unwrap();
        if round.add_verified_notarization(notarization) && self.journal.is_some() {
            self.journal
                .as_mut()
                .unwrap()
                .append(view, notarization_bytes)
                .await
                .expect("unable to append to journal");
        }

        // Enter next view
        self.enter_view(view + 1, seed);
    }

    async fn nullification(&mut self, nullification: wire::Nullification) {
        // Check if we are still in a view where this notarization could help
        if !self.interesting(nullification.view, true) {
            return;
        }

        // Determine if we already broadcast nullification for this view (in which
        // case we can ignore this message)
        if let Some(ref round) = self.views.get_mut(&nullification.view) {
            if round.broadcast_nullification {
                return;
            }
        }

        // Verify nullification
        if !verify_nullification::<S>(
            &self.supervisor,
            &self.nullify_namespace,
            &self.seed_namespace,
            &nullification,
        ) {
            return;
        }

        // Handle notarization
        self.handle_nullification(nullification).await;
    }

    async fn handle_nullification(&mut self, nullification: wire::Nullification) {
        // Create round (if it doesn't exist)
        let view = nullification.view;
        let round = self.views.entry(view).or_insert_with(|| {
            Round::new(
                self.context.current(),
                self.supervisor.clone(),
                nullification.view,
            )
        });

        // Store nullification
        let nullification_bytes = wire::Voter {
            payload: Some(wire::voter::Payload::Nullification(nullification.clone())),
        }
        .encode_to_vec()
        .into();
        let seed = group::Signature::deserialize(&nullification.seed_signature).unwrap();
        if round.add_verified_nullification(nullification) && self.journal.is_some() {
            self.journal
                .as_mut()
                .unwrap()
                .append(view, nullification_bytes)
                .await
                .expect("unable to append to journal");
        }

        // Enter next view
        self.enter_view(view + 1, seed);
    }

    async fn finalize(&mut self, sender: &C::PublicKey, finalize: wire::Finalize) {
        // Extract proposal
        let Some(proposal) = finalize.proposal.as_ref() else {
            return;
        };

        // Ensure we are in the right view to process this message
        if !self.interesting(proposal.view, false) {
            return;
        }

        // Ensure digest is well-formed
        let Ok(payload) = D::try_from(&proposal.payload) else {
            return;
        };

        // Verify that signer is a validator
        let Some(public_key_index) = self.supervisor.is_participant(proposal.view, sender) else {
            return;
        };
        let Some(identity) = self.supervisor.identity(proposal.view) else {
            return;
        };

        // Verify signature
        let Some(signature) = Eval::deserialize(&finalize.proposal_signature) else {
            return;
        };
        if signature.index != public_key_index {
            return;
        }
        let finalize_message = proposal_message(proposal.view, proposal.parent, &payload);
        if ops::partial_verify_message(
            identity,
            Some(&self.finalize_namespace),
            &finalize_message,
            &signature,
        )
        .is_err()
        {
            return;
        }

        // Handle finalize
        self.handle_finalize(
            public_key_index,
            Parsed {
                message: finalize,
                digest: payload,
            },
        )
        .await;
    }

    async fn handle_finalize(
        &mut self,
        public_key_index: u32,
        finalize: Parsed<wire::Finalize, D>,
    ) {
        // Get view for finalize
        let view = finalize.message.proposal.as_ref().unwrap().view;
        let round = self
            .views
            .entry(view)
            .or_insert_with(|| Round::new(self.context.current(), self.supervisor.clone(), view));

        // Handle finalize
        let finalize_bytes = wire::Voter {
            payload: Some(wire::voter::Payload::Finalize(finalize.message.clone())),
        }
        .encode_to_vec()
        .into();
        if round
            .add_verified_finalize(public_key_index, finalize)
            .await
            && self.journal.is_some()
        {
            self.journal
                .as_mut()
                .unwrap()
                .append(view, finalize_bytes)
                .await
                .expect("unable to append to journal");
        }
    }

    async fn finalization(&mut self, finalization: wire::Finalization) {
        // Extract proposal
        let Some(proposal) = &finalization.proposal else {
            return;
        };

        // Check if we are still in a view where this finalization could help
        if !self.interesting(proposal.view, true) {
            return;
        }

        // Ensure digest is well-formed
        let Ok(payload) = D::try_from(&proposal.payload) else {
            return;
        };

        // Determine if we already broadcast finalization for this view (in which
        // case we can ignore this message)
        if let Some(ref round) = self.views.get_mut(&proposal.view) {
            if round.broadcast_finalization {
                return;
            }
        }

        // Verify finalization
        if !verify_finalization::<D, S>(
            &self.supervisor,
            &self.finalize_namespace,
            &self.seed_namespace,
            &finalization,
        ) {
            return;
        }

        // Process finalization
        self.handle_finalization(Parsed {
            message: finalization,
            digest: payload,
        })
        .await;
    }

    async fn handle_finalization(&mut self, finalization: Parsed<wire::Finalization, D>) {
        // Create round (if it doesn't exist)
        let view = finalization.message.proposal.as_ref().unwrap().view;
        let round = self
            .views
            .entry(view)
            .or_insert_with(|| Round::new(self.context.current(), self.supervisor.clone(), view));

        // Store finalization
        let finalization_bytes = wire::Voter {
            payload: Some(wire::voter::Payload::Finalization(
                finalization.message.clone(),
            )),
        }
        .encode_to_vec()
        .into();
        let seed = group::Signature::deserialize(&finalization.message.seed_signature).unwrap();
        if round.add_verified_finalization(finalization) && self.journal.is_some() {
            self.journal
                .as_mut()
                .unwrap()
                .append(view, finalization_bytes)
                .await
                .expect("unable to append to journal");
        }

        // Track view finalized
        if view > self.last_finalized {
            self.last_finalized = view;
        }

        // Enter next view
        self.enter_view(view + 1, seed);
    }

    fn construct_notarize(&mut self, view: u64) -> Option<Parsed<wire::Notarize, D>> {
        let round = match self.views.get_mut(&view) {
            Some(view) => view,
            None => {
                return None;
            }
        };
        if round.broadcast_notarize {
            return None;
        }
        if round.broadcast_nullify {
            return None;
        }
        if !round.verified_proposal {
            return None;
        }
        let share = self.supervisor.share(view).unwrap();
        let proposal = &round.proposal.as_ref().unwrap().1;
        let message = proposal_message(
            proposal.message.view,
            proposal.message.parent,
            &proposal.digest,
        );
        let proposal_signature =
            ops::partial_sign_message(share, Some(&self.notarize_namespace), &message).serialize();
        let message = seed_message(view);
        let seed_signature =
            ops::partial_sign_message(share, Some(&self.seed_namespace), &message).serialize();
        round.broadcast_notarize = true;
        Some(Parsed {
            message: wire::Notarize {
                proposal: Some(proposal.message.clone()),
                proposal_signature,
                seed_signature,
            },
            digest: proposal.digest.clone(),
        })
    }

    fn construct_notarization(
        &mut self,
        view: u64,
        force: bool,
    ) -> Option<Parsed<wire::Notarization, D>> {
        // Get requested view
        let round = match self.views.get_mut(&view) {
            Some(view) => view,
            None => {
                return None;
            }
        };

        // Attempt to construct notarization
        let identity = self.supervisor.identity(view)?;
        let threshold = identity.required();
        round.notarizable(threshold, force)
    }

    fn construct_nullification(&mut self, view: u64, force: bool) -> Option<wire::Nullification> {
        // Get requested view
        let round = match self.views.get_mut(&view) {
            Some(view) => view,
            None => {
                return None;
            }
        };

        // Attempt to construct nullification
        let identity = self.supervisor.identity(view)?;
        let threshold = identity.required();
        round.nullifiable(threshold, force)
    }

    fn construct_finalize(&mut self, view: u64) -> Option<Parsed<wire::Finalize, D>> {
        let round = match self.views.get_mut(&view) {
            Some(view) => view,
            None => {
                return None;
            }
        };
        if round.broadcast_nullify {
            return None;
        }
        if !round.broadcast_notarize {
            // Ensure we notarize before we finalize
            return None;
        }
        if !round.broadcast_notarization {
            // Ensure we broadcast notarization before we finalize
            return None;
        }
        if round.broadcast_finalize {
            return None;
        }
        let share = self.supervisor.share(view).unwrap();
        let proposal = match &round.proposal {
            Some((_, proposal)) => proposal,
            None => {
                return None;
            }
        };
        let message = proposal_message(
            proposal.message.view,
            proposal.message.parent,
            &proposal.digest,
        );
        let proposal_signature =
            ops::partial_sign_message(share, Some(&self.finalize_namespace), &message).serialize();
        round.broadcast_finalize = true;
        Some(Parsed {
            message: wire::Finalize {
                proposal: Some(proposal.message.clone()),
                proposal_signature,
            },
            digest: proposal.digest.clone(),
        })
    }

    fn construct_finalization(
        &mut self,
        view: u64,
        force: bool,
    ) -> Option<Parsed<wire::Finalization, D>> {
        let round = match self.views.get_mut(&view) {
            Some(view) => view,
            None => {
                return None;
            }
        };

        // Attempt to construct finalization
        let identity = self.supervisor.identity(view)?;
        let threshold = identity.required();
        round.finalizable(threshold, force)
    }

    async fn notify(
        &mut self,
        backfiller: &mut resolver::Mailbox,
        sender: &mut impl Sender,
        view: u64,
    ) {
        // Get public key index
        let public_key_index = self.supervisor.share(view).unwrap().index;

        // Attempt to notarize
        if let Some(notarize) = self.construct_notarize(view) {
            // Handle the notarize
            self.handle_notarize(public_key_index, notarize.clone())
                .await;

            // Sync the journal
            self.journal
                .as_mut()
                .unwrap()
                .sync(view)
                .await
                .expect("unable to sync journal");

            // Broadcast the notarize
            let msg = wire::Voter {
                payload: Some(wire::voter::Payload::Notarize(notarize.message)),
            }
            .encode_to_vec()
            .into();
            sender.send(Recipients::All, msg, true).await.unwrap();
            self.broadcast_messages
                .get_or_create(&metrics::NOTARIZE)
                .inc();
        };

        // Attempt to notarization
        if let Some(notarization) = self.construct_notarization(view, false) {
            // Record latency if we are the leader (only way to get unbiased observation)
            if let Some((leader, elapsed)) = self.since_view_start(view) {
                if leader {
                    self.notarization_latency.observe(elapsed);
                }
            }

            // Update backfiller
            backfiller.notarized(notarization.message.clone()).await;

            // Handle the notarization
            self.handle_notarization(notarization.clone()).await;

            // Sync the journal
            self.journal
                .as_mut()
                .unwrap()
                .sync(view)
                .await
                .expect("unable to sync journal");

            // Alert application
            let proposal = notarization.message.proposal.as_ref().unwrap();
            let proof = Prover::<D>::serialize_threshold(
                proposal,
                &notarization.message.proposal_signature,
                &notarization.message.seed_signature,
            );
            self.committer
                .prepared(proof, notarization.digest.clone())
                .await;

            // Broadcast the notarization
            let msg = wire::Voter {
                payload: Some(wire::voter::Payload::Notarization(notarization.message)),
            }
            .encode_to_vec()
            .into();
            sender.send(Recipients::All, msg, true).await.unwrap();
            self.broadcast_messages
                .get_or_create(&metrics::NOTARIZATION)
                .inc();
        };

        // Attempt to nullification
        //
        // We handle broadcast of nullify in `timeout`.
        if let Some(nullification) = self.construct_nullification(view, false) {
            // Update backfiller
            backfiller.nullified(nullification.clone()).await;

            // Handle the nullification
            self.handle_nullification(nullification.clone()).await;

            // Sync the journal
            self.journal
                .as_mut()
                .unwrap()
                .sync(view)
                .await
                .expect("unable to sync journal");

            // Broadcast the nullification
            let msg = wire::Voter {
                payload: Some(wire::voter::Payload::Nullification(nullification)),
            }
            .encode_to_vec()
            .into();
            sender.send(Recipients::All, msg, true).await.unwrap();
            self.broadcast_messages
                .get_or_create(&metrics::NULLIFICATION)
                .inc();

            // If `>= f+1` notarized a given proposal, then we should backfill missing
            // notarizations
            let round = self.views.get(&view).expect("missing round");
            if let Some(parent) = round.at_least_one_honest() {
                if parent >= self.last_finalized {
                    // Compute missing nullifications
                    let mut missing_notarizations = Vec::new();
                    if parent != GENESIS_VIEW && self.is_notarized(parent).is_none() {
                        missing_notarizations.push(parent);
                    }
                    let missing_nullifications = self.missing_nullifications(parent);

                    // Fetch any missing
                    if !missing_notarizations.is_empty() || !missing_nullifications.is_empty() {
                        warn!(
                            proposal_view = view,
                            parent,
                            ?missing_notarizations,
                            ?missing_nullifications,
                            ">= 1 honest notarize for nullified parent"
                        );
                        backfiller
                            .fetch(missing_notarizations, missing_nullifications)
                            .await;
                    }
                } else {
                    // Broadcast last finalized
                    debug!(
                    parent,
                    last_finalized = self.last_finalized,
                    "not backfilling because parent is behind finalized tip, broadcasting finalized"
                );
                    let finalization = self.construct_finalization(self.last_finalized, true);
                    if let Some(finalization) = finalization {
                        let msg = wire::Voter {
                            payload: Some(wire::voter::Payload::Finalization(finalization.message)),
                        }
                        .encode_to_vec()
                        .into();
                        sender
                            .send(Recipients::All, msg, true)
                            .await
                            .expect("unable to broadcast finalization");
                        self.broadcast_messages
                            .get_or_create(&metrics::FINALIZATION)
                            .inc();
                    } else {
                        warn!(
                            last_finalized = self.last_finalized,
                            "unable to construct last finalization"
                        );
                    }
                }
            }
        }

        // Attempt to finalize
        if let Some(finalize) = self.construct_finalize(view) {
            // Handle the finalize
            self.handle_finalize(public_key_index, finalize.clone())
                .await;

            // Sync the journal
            self.journal
                .as_mut()
                .unwrap()
                .sync(view)
                .await
                .expect("unable to sync journal");

            // Broadcast the finalize
            let msg = wire::Voter {
                payload: Some(wire::voter::Payload::Finalize(finalize.message)),
            }
            .encode_to_vec()
            .into();
            sender.send(Recipients::All, msg, true).await.unwrap();
            self.broadcast_messages
                .get_or_create(&metrics::FINALIZE)
                .inc();
        };

        // Attempt to finalization
        if let Some(finalization) = self.construct_finalization(view, false) {
            // Record latency if we are the leader (only way to get unbiased observation)
            if let Some((leader, elapsed)) = self.since_view_start(view) {
                if leader {
                    self.finalization_latency.observe(elapsed);
                }
            }

            // Update backfiller
            backfiller.finalized(view).await;

            // Handle the finalization
            self.handle_finalization(finalization.clone()).await;

            // Sync the journal
            self.journal
                .as_mut()
                .unwrap()
                .sync(view)
                .await
                .expect("unable to sync journal");

            // Alert application
            let proposal = finalization.message.proposal.as_ref().unwrap();
            let proof = Prover::<D>::serialize_threshold(
                proposal,
                &finalization.message.proposal_signature,
                &finalization.message.seed_signature,
            );
            self.committer.finalized(proof, finalization.digest).await;

            // Broadcast the finalization
            let msg = wire::Voter {
                payload: Some(wire::voter::Payload::Finalization(finalization.message)),
            }
            .encode_to_vec()
            .into();
            sender.send(Recipients::All, msg, true).await.unwrap();
            self.broadcast_messages
                .get_or_create(&metrics::FINALIZATION)
                .inc();
        };
    }

    pub fn start(
        self,
        backfiller: resolver::Mailbox,
        sender: impl Sender<PublicKey = C::PublicKey>,
        receiver: impl Receiver<PublicKey = C::PublicKey>,
    ) -> Handle<()> {
        self.context
            .clone()
            .spawn(|_| self.run(backfiller, sender, receiver))
    }

    async fn run(
        mut self,
        mut backfiller: resolver::Mailbox,
        mut sender: impl Sender<PublicKey = C::PublicKey>,
        mut receiver: impl Receiver<PublicKey = C::PublicKey>,
    ) {
        // Compute genesis
        let genesis = self.automaton.genesis().await;
        self.genesis = Some(genesis);

        // Add initial view
        //
        // We start on view 1 because the genesis container occupies view 0/height 0.
        self.enter_view(1, group::Signature::zero());

        // Rebuild from journal
        let mut journal = self.journal.take().expect("missing journal");
        {
            let stream = journal
                .replay(self.replay_concurrency, None)
                .await
                .expect("unable to replay journal");
            pin_mut!(stream);
            while let Some(msg) = stream.next().await {
                let (_, _, _, msg) = msg.expect("unable to decode journal message");
                // We must wrap the message in Voter so we decode the right type of message (otherwise,
                // we can parse a finalize as a notarize)
                let msg = wire::Voter::decode(msg).expect("journal message is unexpected format");
                let msg = msg.payload.expect("missing payload");
                match msg {
                    wire::voter::Payload::Notarize(notarize) => {
                        // Handle notarize
                        let proposal = notarize.proposal.as_ref().unwrap().clone();
                        let payload = D::try_from(&proposal.payload).unwrap();
                        let signature: Eval<group::Signature> =
                            Eval::deserialize(&notarize.proposal_signature).unwrap();
                        let public_key_index = signature.index;
                        let public_key = self
                            .supervisor
                            .participants(proposal.view)
                            .unwrap()
                            .get(public_key_index as usize)
                            .unwrap()
                            .clone();
                        self.handle_notarize(
                            public_key_index,
                            Parsed {
                                message: notarize,
                                digest: payload.clone(),
                            },
                        )
                        .await;

                        // Update round info
                        if public_key == self.crypto.public_key() {
                            let round = self.views.get_mut(&proposal.view).expect("missing round");
                            let proposal_message =
                                proposal_message(proposal.view, proposal.parent, &payload);
                            let proposal_digest = hash(&proposal_message);
                            round.proposal = Some((
                                proposal_digest,
                                Parsed {
                                    message: proposal,
                                    digest: payload,
                                },
                            ));
                            round.verified_proposal = true;
                            round.broadcast_notarize = true;
                        }
                    }
                    wire::voter::Payload::Notarization(notarization) => {
                        // Handle notarization
                        let proposal = notarization.proposal.as_ref().unwrap().clone();
                        let payload = D::try_from(&proposal.payload).unwrap();
                        self.handle_notarization(Parsed {
                            message: notarization,
                            digest: payload,
                        })
                        .await;

                        // Update round info
                        let round = self.views.get_mut(&proposal.view).expect("missing round");
                        round.broadcast_notarization = true;
                    }
                    wire::voter::Payload::Nullify(nullify) => {
                        // Handle nullify
                        let view = nullify.view;
                        let signature: Eval<group::Signature> =
                            Eval::deserialize(&nullify.view_signature).unwrap();
                        let public_key_index = signature.index;
                        let public_key = self
                            .supervisor
                            .participants(view)
                            .unwrap()
                            .get(public_key_index as usize)
                            .unwrap()
                            .clone();
                        self.handle_nullify(public_key_index, nullify).await;

                        // Update round info
                        if public_key == self.crypto.public_key() {
                            let round = self.views.get_mut(&view).expect("missing round");
                            round.broadcast_nullify = true;
                        }
                    }
                    wire::voter::Payload::Nullification(nullification) => {
                        // Handle nullification
                        let view = nullification.view;
                        self.handle_nullification(nullification).await;

                        // Update round info
                        let round = self.views.get_mut(&view).expect("missing round");
                        round.broadcast_nullification = true;
                    }
                    wire::voter::Payload::Finalize(finalize) => {
                        // Handle finalize
                        let proposal = finalize.proposal.as_ref().unwrap();
                        let view = proposal.view;
                        let payload = D::try_from(&proposal.payload).unwrap();
                        let signature: Eval<group::Signature> =
                            Eval::deserialize(&finalize.proposal_signature).unwrap();
                        let public_key_index = signature.index;
                        let public_key = self
                            .supervisor
                            .participants(proposal.view)
                            .unwrap()
                            .get(public_key_index as usize)
                            .unwrap()
                            .clone();
                        self.handle_finalize(
                            public_key_index,
                            Parsed {
                                message: finalize,
                                digest: payload,
                            },
                        )
                        .await;

                        // Update round info
                        //
                        // If we are sending a finalize message, we must be in the next view
                        if public_key == self.crypto.public_key() {
                            let round = self.views.get_mut(&view).expect("missing round");
                            round.broadcast_finalize = true;
                        }
                    }
                    wire::voter::Payload::Finalization(finalization) => {
                        // Handle finalization
                        let proposal = finalization.proposal.as_ref().unwrap();
                        let view = proposal.view;
                        let payload = D::try_from(&proposal.payload).unwrap();
                        self.handle_finalization(Parsed {
                            message: finalization,
                            digest: payload,
                        })
                        .await;

                        // Update round info
                        let round = self.views.get_mut(&view).expect("missing round");
                        round.broadcast_finalization = true;
                    }
                }
            }
        }
        self.journal = Some(journal);

        // Update current view and immediately move to timeout (very unlikely we restarted and still within timeout)
        let observed_view = self.view;
        debug!(current_view = observed_view, "replayed journal");
        {
            let round = self.views.get_mut(&observed_view).expect("missing round");
            round.leader_deadline = Some(self.context.current());
            round.advance_deadline = Some(self.context.current());
        }
        self.current_view.set(observed_view as i64);
        self.tracked_views.set(self.views.len() as i64);

        // Create shutdown tracker
        let mut shutdown = self.context.stopped();

        // Process messages
        let mut pending_set = None;
        let mut pending_propose_context = None;
        let mut pending_propose = None;
        let mut pending_verify_context = None;
        let mut pending_verify = None;
        loop {
            // Reset pending set if we have moved to a new view
            if let Some(view) = pending_set {
                if view != self.view {
                    pending_set = None;
                    pending_propose_context = None;
                    pending_propose = None;
                    pending_verify_context = None;
                    pending_verify = None;
                }
            }

            // Attempt to propose a container
            if let Some((context, new_propose)) = self.propose(&mut backfiller).await {
                pending_set = Some(self.view);
                pending_propose_context = Some(context);
                pending_propose = Some(new_propose);
            }
            let propose_wait = match &mut pending_propose {
                Some(propose) => Either::Left(propose),
                None => Either::Right(futures::future::pending()),
            };

            // Attempt to verify current view
            if let Some((context, new_verify)) = self.peer_proposal().await {
                pending_set = Some(self.view);
                pending_verify_context = Some(context);
                pending_verify = Some(new_verify);
            }
            let verify_wait = match &mut pending_verify {
                Some(verify) => Either::Left(verify),
                None => Either::Right(futures::future::pending()),
            };

            // Wait for a timeout to fire or for a message to arrive
            let timeout = self.timeout_deadline();
            let view;
            select! {
                _ = &mut shutdown => {
                    // Close journal
                    self.journal
                        .take()
                        .unwrap()
                        .close()
                        .await
                        .expect("unable to close journal");
                    return;
                },
                _ = self.context.sleep_until(timeout) => {
                    // Trigger the timeout
                    self.timeout(&mut sender).await;
                    view = self.view;
                },
                proposed = propose_wait => {
                    // Clear propose waiter
                    let context = pending_propose_context.take().unwrap();
                    pending_propose = None;

                    // Try to use result
                    let proposed = match proposed {
                        Ok(proposed) => proposed,
                        Err(err) => {
                            debug!(?err, view = context.view, "failed to propose container");
                            continue;
                        }
                    };

                    // If we have already moved to another view, drop the response as we will
                    // not broadcast it
                    if self.view != context.view {
                        debug!(view = context.view, our_view = self.view, reason = "no longer in required view", "dropping requested proposal");
                        continue;
                    }

                    // Construct proposal
                    let message = proposal_message(context.view, context.parent.0, &proposed);
                    let proposal_digest = hash(&message);
                    let proposal = wire::Proposal {
                        view: context.view,
                        parent: context.parent.0,
                        payload: proposed.to_vec(),
                    };
                    if !self.our_proposal(
                        proposal_digest,
                        Parsed{
                            message: proposal.clone(),
                            digest: proposed.clone(),
                        },
                    ).await {
                        warn!(view = context.view, "failed to record our container");
                        continue;
                    }
                    view = self.view;

                    // Notify application of proposal
                    self.relay.broadcast(proposed).await;
                },
                verified = verify_wait => {
                    // Clear verify waiter
                    let context = pending_verify_context.take().unwrap();
                    pending_verify = None;

                    // Try to use result
                    match verified {
                        Ok(verified) => {
                            if !verified {
                                debug!(view = context.view, "proposal failed verification");
                                continue;
                            }
                        },
                        Err(err) => {
                            debug!(?err, view = context.view, "failed to verify proposal");
                            continue;
                        }
                    };

                    // Handle verified proposal
                    view = context.view;
                    if !self.verified(view).await {
                        continue;
                    }
                },
                mailbox = self.mailbox_receiver.next() => {
                    let msg = mailbox.unwrap();
                    match msg {
                        Message::Notarization{ notarization }  => {
                            view = notarization.message.proposal.as_ref().unwrap().view;
                            debug!(view, "received notarization from backfiller");
                            self.handle_notarization(notarization).await;
                        },
                        Message::Nullification { nullification } => {
                            view = nullification.view;
                            debug!(view, "received nullification from backfiller");
                            self.handle_nullification(nullification).await;
                        },
                    }
                },
                msg = receiver.recv() => {
                    // Parse message
                    let Ok((s, msg)) = msg else {
                        break;
                    };
                    let Ok(msg) = wire::Voter::decode(msg) else {
                        continue;
                    };
                    let Some(payload) = msg.payload else {
                        continue;
                    };

                    // Process message
                    match payload {
                        wire::voter::Payload::Notarize(notarize) => {
                            self.received_messages.get_or_create(&metrics::PeerMessage::notarize(&s)).inc();
                            view = match &notarize.proposal {
                                Some(proposal) => proposal.view,
                                None => {
                                    continue;
                                }
                            };
                            self.notarize(&s, notarize).await;
                        }
                        wire::voter::Payload::Notarization(notarization) => {
                            self.received_messages.get_or_create(&metrics::PeerMessage::notarization(&s)).inc();
                            view = match &notarization.proposal {
                                Some(proposal) => proposal.view,
                                None => {
                                    continue;
                                }
                            };
                            self.notarization(notarization).await;
                        }
                        wire::voter::Payload::Nullify(nullify) => {
                            self.received_messages.get_or_create(&metrics::PeerMessage::nullify(&s)).inc();
                            view = nullify.view;
                            self.nullify(&s, nullify).await;
                        }
                        wire::voter::Payload::Nullification(nullification) => {
                            self.received_messages.get_or_create(&metrics::PeerMessage::nullification(&s)).inc();
                            view = nullification.view;
                            self.nullification(nullification).await;
                        }
                        wire::voter::Payload::Finalize(finalize) => {
                            self.received_messages.get_or_create(&metrics::PeerMessage::finalize(&s)).inc();
                            view = match &finalize.proposal {
                                Some(proposal) => proposal.view,
                                None => {
                                    continue;
                                }
                            };
                            self.finalize(&s, finalize).await;
                        }
                        wire::voter::Payload::Finalization(finalization) => {
                            self.received_messages.get_or_create(&metrics::PeerMessage::finalization(&s)).inc();
                            view = match &finalization.proposal {
                                Some(proposal) => proposal.view,
                                None => {
                                    continue;
                                }
                            };
                            self.finalization(finalization).await;
                        }
                    };
                },
            };

            // Attempt to send any new view messages
            self.notify(&mut backfiller, &mut sender, view).await;

            // After sending all required messages, prune any views
            // we no longer need
            self.prune_views().await;

            // Update metrics
            self.current_view.set(view as i64);
            self.tracked_views.set(self.views.len() as i64);
        }
    }
}
