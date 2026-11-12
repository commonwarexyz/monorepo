//! The correct reshare engines of a run, one per identity, kept across their
//! restarts.
//!
//! A [`Session`] is what every engine of a run starts from: the identities,
//! the committee schedule, and the first output, which a trusted dealer deals
//! to the first committee.
//!
//! A [`Cluster`] runs one real reshare engine per identity and holds what a
//! restart of each must find again: its storage partitions, which are named
//! after the identity, its secret store, and the records the oracle reads.
//! It implements [`Stack`], so [`environment::play`]
//! can crash its engines and start them again. Every start, the first one
//! included, registers the identity's channels and builds the engine anew on
//! what the identity retained. Nothing is carried from one instance to the
//! next in memory, and no state is ever taken away: the secret store and the
//! records are shared by all the instances of an identity, so a share an
//! instance stored and a scheme it registered stay on record whatever
//! happens to the instance. A driver that plays the cluster under a program
//! has the program pace the durable writes of every engine (see
//! [`pacing`](super::pacing)).
//!
//! An identity has reached the end of what the cluster observes once the
//! latest instance of its engine has registered the scheme of the epoch after
//! the last one the run was asked to complete. The reshare actor registers
//! the scheme of the epoch it is in at every start, so an instance that
//! starts past that epoch reaches the end as soon as it has set itself up.
//! The cluster therefore has the environment follow the engines a restart
//! brought back ([`Stack::follows`]): a run of the cluster goes on until each
//! of them has applied a block since its restart, or the environment's bound
//! on that wait has passed. A stack that wraps the cluster decides for itself
//! whether its runs do.
//!
//! A [`View`] reads the records and the secret stores once the run is over.
//! It also counts, for the run's report only, where each crash found its
//! engine and where each restart found its peers. A crash is placed by the
//! height the engine's marshal has processed, which is where the restarted
//! engine resumes. An engine crashed after it stored its share of the next
//! output and registered the next epoch's scheme, and before its marshal
//! recorded the epoch's final block, is at the boundary: the engine that
//! comes back applies that block again, and its restart is counted as one
//! that repeats a boundary. Only a restart after a crash in a ceremony is
//! counted as re-entering that ceremony or as following an outage across an
//! epoch boundary.
//!
//! The cluster holds no adversary and draws no schedule, so every driver
//! that runs correct reshare engines under restarts can use it.

use super::{
    Info, MockGroup, PublicKey,
    app::App,
    environment::{self, Landing, Program, Stack, position, processed_height},
    invariants::{Records, Reshare, Resharer},
    joiner::Entry,
    public_keys,
    reshare_restarts_input::SessionControls,
    reshare_stack::{self, Config},
    schedule::Schedule,
    store::Secrets,
};
use commonware_consensus::{simplex::elector::RoundRobin, types::Epoch};
use commonware_cryptography::{
    Sha256,
    bls12381::{
        dkg::feldman_desmedt::deal,
        primitives::{group::Share, sharing::Mode},
    },
    ed25519,
};
use commonware_glue::dkg::types::EpochOutcome;
use commonware_p2p::simulated::Oracle;
use commonware_runtime::{Handle, deterministic};
use commonware_utils::{N3f1, channel::mpsc, ordered::Map, sequence::Unit, sync::Mutex};
use futures::future::select_all;
use rand_core::CryptoRng;
use std::sync::Arc;

/// Leader election of every epoch's Simplex engine: the committee in turn.
pub(super) type Elector = RoundRobin<Sha256>;

/// What every engine of a reshare run starts from.
#[derive(Clone)]
pub(super) struct Session {
    /// The identity keys, in identity order.
    pub(super) signers: Arc<[ed25519::PrivateKey]>,
    /// The identities, in identity order.
    pub(super) participants: Arc<[PublicKey]>,
    /// The description of epoch zero: the first output and the players of
    /// the first two ceremonies.
    pub(super) genesis: Info,
    /// The player set of every epoch's ceremony.
    pub(super) schedule: Schedule,
    /// How the ceremonies assign evaluation points.
    pub(super) sharing_mode: Mode,
    /// The epoch after the last one the run is asked to complete.
    pub(super) last: Epoch,
    /// Each first-committee member's share of the first output.
    shares: Map<PublicKey, Share>,
}

impl Session {
    /// The session `controls` describe among the identities of `signers`,
    /// with the first output dealt from the randomness of `rng`.
    pub(super) fn deal(
        rng: impl CryptoRng,
        signers: Vec<ed25519::PrivateKey>,
        controls: &SessionControls,
    ) -> Self {
        let participants: Arc<[PublicKey]> = public_keys(&signers);
        let schedule = Schedule::new(
            &participants,
            usize::from(controls.outsider),
            &controls.rotations,
        );
        let (output, shares) =
            deal::<MockGroup, _, N3f1>(rng, controls.sharing_mode, schedule.committee())
                .expect("a trusted deal among the first committee must succeed");
        let genesis = Info {
            outcome: EpochOutcome::Success,
            epoch: Epoch::zero(),
            output,
            players: schedule.players(Epoch::zero()),
            next_players: schedule.players(Epoch::new(1)),
            directory: Unit,
        };
        Self {
            signers: signers.into(),
            participants,
            genesis,
            schedule,
            sharing_mode: controls.sharing_mode,
            last: Epoch::new(u64::from(controls.epochs)),
            shares,
        }
    }

    /// The share of the first output the identity at `index` was dealt, if
    /// it is in the first committee.
    pub(super) fn share(&self, index: usize) -> Option<Share> {
        self.shares.get_value(&self.participants[index]).cloned()
    }
}

/// How much of its restart schedule a reshare run performed, where each
/// crash found its engine, and where each restart found the engine's peers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReshareRestartCounts {
    /// Engines the schedule crashed.
    pub crashes: usize,
    /// Crashed engines the schedule brought back before the run ended.
    pub restarts: usize,
    /// Crashes that found the engine in the dealing window of an epoch the
    /// run was asked to complete.
    pub dealing: usize,
    /// Crashes that found the engine in the inclusion window of such an
    /// epoch.
    pub inclusion: usize,
    /// Crashes that found the engine at the boundary of such an epoch: it
    /// had stored its share of the next output and registered the next
    /// epoch's scheme, and its marshal had not recorded the epoch's final
    /// block.
    pub boundary: usize,
    /// Crashes that found the engine past the last epoch the run was asked
    /// to complete.
    pub finished: usize,
    /// Restarts after a crash in the dealing or the inclusion window of a
    /// ceremony that found no peer past that ceremony: the engine re-enters
    /// the ceremony it left.
    pub resumed: usize,
    /// Restarts after a crash in the dealing or the inclusion window of a
    /// ceremony that found a peer in a later epoch: the engine was down
    /// across an epoch boundary, and learns how the ceremony ended from the
    /// chain.
    pub across: usize,
    /// Restarts after a crash at a boundary: the engine had ended the
    /// ceremony itself, so it was not down across the boundary, and it
    /// applies the epoch's final block a second time.
    pub repeated: usize,
}

/// One identity's engine across its restarts.
pub(super) struct Node {
    /// The identity's secret store, which every instance of its engine is
    /// given and the oracle reads.
    pub(super) secrets: Secrets,
    /// What the instances of the identity's engine report.
    pub(super) records: Records,
    /// The epochs the identity's engine registers a scheme for, as it does.
    registered: mpsc::UnboundedReceiver<Epoch>,
    /// The latest epoch any instance of the engine registered the scheme
    /// of.
    entered: Epoch,
    /// Whether the latest instance of the engine has registered the scheme
    /// of the run's last epoch, or of a later one.
    reached: bool,
    /// The epoch the schedule's latest crash of the engine leaves it to
    /// resume in, and where that crash found it.
    pub(super) crashed: Option<(Epoch, Landing)>,
    /// Whether the schedule crashed the engine and has not brought it back.
    down: bool,
}

impl Node {
    fn new(secrets: Secrets) -> Self {
        let records = Records::default();
        let registered = records.watch();
        Self {
            secrets,
            records,
            registered,
            entered: Epoch::zero(),
            reached: false,
            crashed: None,
            down: false,
        }
    }

    /// Note that the engine registered the scheme of `epoch`, in a run that
    /// is over once its engines have entered the epoch `last`.
    fn note(&mut self, epoch: Epoch, last: Epoch) {
        self.entered = self.entered.max(epoch);
        self.reached |= epoch >= last;
    }

    /// Note every registration the engine has made and that is not noted
    /// yet.
    fn catch_up(&mut self, last: Epoch) {
        while let Ok(epoch) = self.registered.try_recv() {
            self.note(epoch, last);
        }
    }
}

/// The cluster of real reshare engines: what each identity runs with, kept
/// across its restarts.
pub(super) struct Cluster {
    /// The context every engine's context derives from. A crash reads the
    /// height its engine has processed from the metrics registered below it.
    pub(super) context: deterministic::Context,
    pub(super) oracle: Oracle<PublicKey, deterministic::Context>,
    pub(super) session: Session,
    /// One entry per identity, in identity order.
    pub(super) nodes: Vec<Node>,
    /// What the schedule did, shared so that it can be read after the run.
    counts: Arc<Mutex<ReshareRestartCounts>>,
}

impl Cluster {
    /// A cluster of the identities of `session` over the network of
    /// `oracle`, with no engine started. Every engine runs on a context
    /// derived from `context`.
    pub(super) fn new(
        context: &deterministic::Context,
        oracle: Oracle<PublicKey, deterministic::Context>,
        session: Session,
    ) -> Self {
        let nodes = (0..session.participants.len())
            .map(|index| Node::new(Secrets::dealt(session.share(index))))
            .collect();
        Self {
            context: environment::cluster(context),
            oracle,
            session,
            nodes,
            counts: Arc::default(),
        }
    }

    /// This cluster with the durable writes of every engine paced by
    /// `program`: the writes of its secret store, and those of the storage
    /// every start of the engine opens.
    pub(super) fn paced(mut self, program: &Program) -> Self {
        for (index, node) in self.nodes.iter_mut().enumerate() {
            node.secrets = std::mem::take(&mut node.secrets).paced(program.pacing(index));
        }
        self
    }

    /// A reader of what the cluster's engines report and hold.
    pub(super) fn view(&self) -> View {
        View {
            session: self.session.clone(),
            records: self.nodes.iter().map(|node| node.records.clone()).collect(),
            secrets: self.nodes.iter().map(|node| node.secrets.clone()).collect(),
            counts: self.counts.clone(),
        }
    }

    /// What an engine of the identity at `index` runs with, at its first
    /// start and at every later one.
    pub(super) fn config(&self, index: usize) -> Config<App, Elector> {
        let node = &self.nodes[index];
        Config {
            signer: self.session.signers[index].clone(),
            partition: format!("engine-{index}"),
            secrets: node.secrets.clone(),
            sharing_mode: self.session.sharing_mode,
            genesis: self.session.genesis.clone(),
            schedule: self.session.schedule.clone(),
            records: node.records.clone(),
            application: App,
            elector: Elector::default(),
            entry: Entry::Genesis,
        }
    }

    /// Start an engine of the identity at `index` that runs with `config`,
    /// over the identity's channels, registered again.
    pub(super) async fn launch(
        &mut self,
        index: usize,
        config: Config<App, Elector>,
    ) -> Handle<()> {
        self.starting(index);

        // Registering a channel again replaces the registration the crashed
        // instance held.
        let channels =
            reshare_stack::register(&self.oracle, &self.session.participants[index]).await;
        let (_, context) = environment::contexts(&self.context, index);
        reshare_stack::spawn(
            context,
            &self.oracle,
            config,
            channels.chain.votes,
            channels.chain.certificates,
            channels.chain.resolver,
            channels.chain.backfill,
            channels.chain.broadcast,
            channels.chain.dkg,
            channels.probe,
        )
    }

    /// The epoch the running engine of the identity at `index` would resume
    /// in, read from the height its marshal reports as processed, and the
    /// window a crash would find it in. An engine that has not started its
    /// marshal reports nothing.
    fn position(&self, index: usize) -> Option<(Epoch, Landing)> {
        processed_height(&self.context, index)
            .map(|processed| position(processed, self.session.last))
    }

    /// Note that a new instance of the engine of the identity at `index` is
    /// about to start.
    fn starting(&mut self, index: usize) {
        // What the instance before this one registered is not this one's.
        let last = self.session.last;
        for node in &mut self.nodes {
            node.catch_up(last);
        }
        let node = &mut self.nodes[index];
        node.reached = false;
        if !std::mem::take(&mut node.down) {
            return;
        }
        let (epoch, landing) = node.crashed.expect("an engine that is down was crashed");

        // A restart after a crash in a ceremony either re-enters that
        // ceremony or finds that a peer has left it behind. A peer leaves a
        // ceremony when it registers the scheme of the next epoch. An engine
        // crashed at a boundary had left the ceremony itself.
        let ahead = self
            .nodes
            .iter()
            .enumerate()
            .any(|(peer, node)| peer != index && node.entered > epoch);
        let mut counts = self.counts.lock();
        counts.restarts += 1;
        match landing {
            Landing::Finished => {}
            Landing::Boundary => counts.repeated += 1,
            Landing::Dealing | Landing::Inclusion if ahead => counts.across += 1,
            Landing::Dealing | Landing::Inclusion => counts.resumed += 1,
        }
    }
}

impl Stack for Cluster {
    async fn start(&mut self, index: usize) -> Handle<()> {
        let config = self.config(index);
        self.launch(index, config).await
    }

    fn crashing(&mut self, index: usize) {
        // An engine crashed before its marshal has reported a height
        // resumes where its last crash left it, or at the start of the
        // chain.
        let last = self.session.last;
        let reported = self.position(index);
        let node = &mut self.nodes[index];
        let (epoch, landing) = reported
            .or(node.crashed)
            .unwrap_or_else(|| position(0, last));

        // An engine that has registered a later epoch than the one its
        // marshal leaves it in has ended the ceremony, and its marshal is
        // one block behind.
        node.catch_up(last);
        let landing = match landing {
            Landing::Dealing | Landing::Inclusion if node.entered > epoch => Landing::Boundary,
            landing => landing,
        };
        node.crashed = Some((epoch, landing));
        node.down = true;
        let mut counts = self.counts.lock();
        counts.crashes += 1;
        match landing {
            Landing::Dealing => counts.dealing += 1,
            Landing::Inclusion => counts.inclusion += 1,
            Landing::Boundary => counts.boundary += 1,
            Landing::Finished => counts.finished += 1,
        }
    }

    async fn settled(&mut self, absent: &[bool]) {
        let last = self.session.last;
        loop {
            for node in &mut self.nodes {
                node.catch_up(last);
            }
            let settled = self
                .nodes
                .iter()
                .zip(absent)
                .all(|(node, absent)| *absent || node.reached);
            if settled {
                return;
            }

            // Wait for the next registration of any engine.
            let registrations = self
                .nodes
                .iter_mut()
                .map(|node| Box::pin(node.registered.recv()));
            let (registered, index, _) = select_all(registrations).await;
            match registered {
                Some(epoch) => self.nodes[index].note(epoch, last),
                None => return std::future::pending().await,
            }
        }
    }

    fn follows(&self) -> bool {
        true
    }
}

/// A reader of what the engines of a [`Cluster`] reported and of what their
/// secret stores held, for the oracle.
#[derive(Clone)]
pub(super) struct View {
    session: Session,
    records: Vec<Records>,
    secrets: Vec<Secrets>,
    counts: Arc<Mutex<ReshareRestartCounts>>,
}

impl View {
    /// The run as the engines observed it up to now: what every instance of
    /// each engine reported, and every share each engine's store ever held.
    pub(super) fn reshare(&self) -> Reshare {
        let nodes = self
            .records
            .iter()
            .zip(&self.secrets)
            .enumerate()
            .map(|(engine, (records, secrets))| {
                Resharer::observed(
                    engine,
                    self.session.participants[engine].clone(),
                    records,
                    secrets.held(),
                )
            })
            .collect();
        Reshare {
            genesis: self.session.genesis.clone(),
            schedule: self.session.schedule.clone(),
            nodes,
        }
    }

    /// What the restart schedule did up to now.
    pub(super) fn counts(&self) -> ReshareRestartCounts {
        *self.counts.lock()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::{COMMITTEE, RESHARE_IDENTITIES, Rotation, reshare_input::ROTATIONS, signers};
    use commonware_utils::TestRng;

    fn controls(epochs: u8, outsider: u8) -> SessionControls {
        SessionControls {
            epochs,
            sharing_mode: Mode::NonZeroCounter,
            outsider,
            rotations: [Rotation::Replace(1); ROTATIONS],
        }
    }

    #[test]
    fn session_deals_the_first_output_to_the_first_committee() {
        let session = Session::deal(
            TestRng::new(1),
            signers(RESHARE_IDENTITIES),
            &controls(2, 3),
        );
        assert_eq!(session.participants.len(), RESHARE_IDENTITIES as usize);
        assert_eq!(session.last, Epoch::new(2));
        assert_eq!(session.genesis.epoch, Epoch::zero());
        assert_eq!(session.genesis.outcome, EpochOutcome::Success);

        // The first committee is every identity but the outsider, and the
        // schedule names the players of the first two ceremonies.
        let committee = session.schedule.committee();
        assert_eq!(committee.len(), COMMITTEE.get() as usize);
        assert!(committee.position(&session.participants[3]).is_none());
        assert_eq!(session.genesis.output.players(), &committee);
        assert_eq!(
            session.genesis.players,
            session.schedule.players(Epoch::zero())
        );
        assert_eq!(
            session.genesis.next_players,
            session.schedule.players(Epoch::new(1))
        );

        // Every member starts with its share and the outsider with none.
        for index in 0..session.participants.len() {
            let share = Secrets::dealt(session.share(index)).share(Epoch::zero());
            let dealt = session.shares.get_value(&session.participants[index]);
            assert_eq!(share.as_ref(), dealt);
            assert_eq!(share.is_some(), index != 3);
        }
    }

    #[test]
    fn session_depends_only_on_its_controls_and_randomness() {
        let deal = |seed, outsider| {
            Session::deal(
                TestRng::new(seed),
                signers(RESHARE_IDENTITIES),
                &controls(1, outsider),
            )
        };
        assert_eq!(deal(1, 0).genesis, deal(1, 0).genesis);
        assert_ne!(deal(1, 0).genesis, deal(2, 0).genesis);
        assert_ne!(deal(1, 0).genesis, deal(1, 4).genesis);
    }
}
