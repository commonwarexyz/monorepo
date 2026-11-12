//! The caller's side of DKG state sync: what a node that enters the chain
//! through the probe must do around the DKG module, as
//! [`commonware_glue::dkg`] documents it.
//!
//! The DKG module leaves three things to its caller. The caller keeps the
//! floor a state sync starts from durable, so that a restart finds it. It
//! hands a floor it finds to the probe, so that discovery cannot return the
//! description of an older epoch. And it starts marshal and the DKG actors
//! from the later, by round, of the floor it kept and the floor the probe
//! sampled, paired with the description the probe returned. A node that runs
//! the stateful layer leaves the record to that layer's startup plan. The
//! reshare stack of this crate has no stateful layer, so the [`Ledger`] here
//! is that record: one durable value under the engine's partition, which is
//! either the floor of a sync in progress or the height of the floor of the
//! sync that completed.
//!
//! A sync is complete once its completion is on the ledger, and not before,
//! as a sync of the stateful layer is complete once that layer has recorded
//! it. The caller records the completion when marshal has delivered the
//! floor's block to the engine, which marshal does only once it holds the
//! floor durably. An engine crashed after marshal stored the floor and
//! before the completion is on the ledger has an interrupted sync: its next
//! start syncs again, through the probe, and may enter from a later floor. A
//! caller cannot do better through the public interfaces. What marshal holds
//! is told only by the value its initialisation returns, and the
//! initialisation takes the floor to start from.
//!
//! A [`Joiner`] plays the caller's role at one start of an engine, in three
//! steps that [`reshare_stack`](super::reshare_stack) calls in order:
//!
//! 1. [`Joiner::open`] reads the ledger and decides whether the start state
//!    syncs: it does unless a sync has completed, because the driver requests
//!    state sync at every start of a joining engine. An engine that enters
//!    from the height-zero block has no caller-side record and no joiner.
//! 2. [`Joiner::discover`] waits for the probe's artifact, selects the floor,
//!    records it durably, and returns the material marshal and the DKG
//!    actors start from. A start that does not sync returns none, and
//!    marshal resumes from what it stored.
//! 3. [`Joiner::settle`] waits until marshal has delivered the floor's block
//!    to the engine and then records the completion, after which no start
//!    syncs again.
//!
//! Every step is reported to the engine's [`Records`], which is what I15 to
//! I17 are judged on.
//!
//! All of this is the harness's code, and the tasks of the engine run it. It
//! runs as belonging to no engine (see [`unattributed_future`]), so that a
//! panic in it is reported as the harness's.

use super::{
    Digest, MockGroup,
    app::Block,
    invariants::{Material, ProbeArtifact, Records, Startup, Step},
    scheme::Scheme,
};
use crate::stateful::runner::{unattributed, unattributed_future};
use commonware_codec::{
    Buf, EncodeSize, Error as CodecError, FixedSize as _, Read, ReadExt as _, Write,
};
use commonware_consensus::{
    marshal::standard::Standard, simplex::types::Finalization, types::Height,
};
#[cfg(test)]
use commonware_cryptography::Digest as _;
#[cfg(test)]
use commonware_glue::dkg::types::EpochOutcome;
use commonware_glue::dkg::{probe, state_sync::StateSync};
use commonware_runtime::{BufMut, Spawner};
use commonware_storage::{
    Context,
    metadata::{self, Metadata},
};
use commonware_utils::{channel::oneshot::error::RecvError, fixed_bytes, sequence::FixedBytes};

/// The finalization a state sync starts from.
pub(super) type Floor = Finalization<Scheme, Digest>;

/// What marshal and the DKG actors of a state-synced engine start from.
pub(super) type Sync = StateSync<Scheme, Digest, MockGroup>;

/// The probe of a reshare engine, as its caller reaches it.
pub(super) type Probe = probe::Mailbox<Scheme, Standard<Block>>;

/// Suffix of the partition that holds an engine's ledger.
const LEDGER_SUFFIX: &str = "-joiner";

/// Key of the ledger's one value.
const PROGRESS_KEY: FixedBytes<1> = fixed_bytes!("00");

/// How an engine enters the chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Entry {
    /// From the height-zero block, as a node that is there from the start
    /// does. Its caller keeps no record and never state syncs.
    Genesis,
    /// Through the probe and state sync, as a node that joins late does. Its
    /// caller requests state sync at every start.
    StateSync,
    /// As [`Entry::StateSync`], by a caller that lapses.
    #[cfg(test)]
    Lapsed(Lapse),
}

/// What a control has the caller of a joining engine do: a fault it plants,
/// or a delay it brings about at a chosen time.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Lapse {
    /// Leave a completed sync off the ledger, so that a later start syncs
    /// again.
    Forget,
    /// Report a floor over another block than the one marshal started from.
    Refloor,
    /// Report another description than the one paired with the floor.
    Redescribe,
    /// Leave the sync of a start that found no floor on the ledger without
    /// a completion, recorded or reported, as a caller does whose write of
    /// the completion is held until its engine is crashed. The engine runs
    /// on meanwhile, and its next start resumes the sync. This is no fault.
    Stall,
}

#[cfg(test)]
impl Lapse {
    /// What a caller that lapses like this reports of `material`.
    fn report(self, mut material: Material) -> Material {
        match self {
            Self::Forget | Self::Stall => {}
            Self::Refloor => material.digest = Digest::EMPTY,
            Self::Redescribe => {
                material.info.outcome = match material.info.outcome {
                    EpochOutcome::Success => EpochOutcome::Failure,
                    EpochOutcome::Failure => EpochOutcome::Success,
                };
            }
        }
        material
    }
}

/// How far an engine's state sync has come.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Progress {
    /// A floor is selected and the sync has not completed.
    Syncing(Floor),
    /// The sync completed from a floor at this height.
    Synced(Height),
}

impl Write for Progress {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Syncing(floor) => {
                0u8.write(buf);
                floor.write(buf);
            }
            Self::Synced(height) => {
                1u8.write(buf);
                height.write(buf);
            }
        }
    }
}

impl EncodeSize for Progress {
    fn encode_size(&self) -> usize {
        u8::SIZE
            + match self {
                Self::Syncing(floor) => floor.encode_size(),
                Self::Synced(height) => height.encode_size(),
            }
    }
}

impl Read for Progress {
    type Cfg = <Floor as Read>::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Syncing(Floor::read_cfg(buf, cfg)?)),
            1 => Ok(Self::Synced(Height::read(buf)?)),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

/// The durable record a caller keeps of its engine's state sync.
///
/// A write is durable when its future resolves. A storage failure panics: a
/// caller that cannot tell whether its sync completed cannot choose how to
/// start.
struct Ledger<E: Context> {
    metadata: Metadata<E, FixedBytes<1>, Progress>,
}

impl<E: Context> Ledger<E> {
    /// Open the ledger of the engine whose storage is under `partition`.
    async fn open(context: E, partition: &str) -> Self {
        let metadata = Metadata::init(
            context,
            metadata::Config {
                partition: format!("{partition}{LEDGER_SUFFIX}"),
                codec_config: (),
            },
        )
        .await
        .expect("the ledger must open");
        Self { metadata }
    }

    /// The floor of the sync in progress, if one is.
    fn floor(&self) -> Option<&Floor> {
        match self.metadata.get(&PROGRESS_KEY) {
            Some(Progress::Syncing(floor)) => Some(floor),
            _ => None,
        }
    }

    /// The height of the floor of the completed sync, if one completed.
    fn synced(&self) -> Option<Height> {
        match self.metadata.get(&PROGRESS_KEY) {
            Some(Progress::Synced(height)) => Some(*height),
            _ => None,
        }
    }

    /// Record `progress`.
    async fn record(self, progress: Progress) -> Self {
        let metadata = self
            .metadata
            .put_sync(PROGRESS_KEY, progress)
            .await
            .expect("the ledger must persist");
        Self { metadata }
    }
}

/// The later of the floor `kept` on record and the floor `sampled` by the
/// probe, by round. The floor on record stays when the probe's is not later.
fn later(kept: Option<&Floor>, sampled: Floor) -> Floor {
    match kept {
        Some(kept) if kept.round() >= sampled.round() => kept.clone(),
        _ => sampled,
    }
}

/// The caller of one engine that enters through state sync, at one start of
/// the engine.
pub(super) struct Joiner<E: Context> {
    /// Present until the sync this start runs has been settled.
    ledger: Option<Ledger<E>>,
    records: Records,
    /// Whether this start state syncs.
    syncs: bool,
    /// The floor this start entered from, once it has.
    entered: Option<Floor>,
    /// How the caller lapses, in a negative control.
    #[cfg(test)]
    lapse: Option<Lapse>,
}

impl<E: Context> Joiner<E> {
    /// The caller of an engine that enters as `entry` says, at one start of
    /// it: none for an engine that enters from the height-zero block.
    ///
    /// Reads the ledger under `partition` and decides how this start enters.
    pub(super) async fn open(
        context: &E,
        entry: Entry,
        partition: &str,
        records: &Records,
    ) -> Option<Self> {
        if entry == Entry::Genesis {
            return None;
        }
        let joiner =
            unattributed_future(Self::read(context.child("ledger"), partition, records)).await;
        #[cfg(test)]
        let joiner = Self {
            lapse: match entry {
                // A start that resumes a sync completes it.
                Entry::Lapsed(Lapse::Stall) if joiner.floor().is_some() => None,
                Entry::Lapsed(lapse) => Some(lapse),
                _ => None,
            },
            ..joiner
        };
        Some(joiner)
    }

    /// Read the ledger under `partition` and decide how this start enters.
    async fn read(context: E, partition: &str, records: &Records) -> Self {
        let ledger = Ledger::open(context, partition).await;

        // The driver requests state sync at every start of a joining engine,
        // so a start syncs until a sync has completed.
        let resumed = ledger.floor().map(|floor| floor.round());
        let synced = ledger.synced();
        let syncs = synced.is_none();
        records.stepped(Step::Started(Startup {
            resumed,
            synced,
            syncs,
        }));
        Self {
            ledger: Some(ledger),
            records: records.clone(),
            syncs,
            entered: None,
            #[cfg(test)]
            lapse: None,
        }
    }

    /// What the caller reports of the `material` it enters from.
    fn reported(&self, material: Material) -> Material {
        #[cfg(test)]
        if let Some(lapse) = self.lapse {
            return lapse.report(material);
        }
        material
    }

    /// Whether the caller records the completion of its sync.
    fn remembers(&self) -> bool {
        #[cfg(test)]
        if self.lapse == Some(Lapse::Forget) {
            return false;
        }
        true
    }

    /// Whether the caller completes the sync this start runs at all.
    fn completes(&self) -> bool {
        #[cfg(test)]
        if self.lapse == Some(Lapse::Stall) {
            return false;
        }
        true
    }

    /// The floor an interrupted sync left on record, for the probe.
    pub(super) fn floor(&self) -> Option<Floor> {
        self.ledger.as_ref().and_then(Ledger::floor).cloned()
    }

    /// The material this start enters from, if it state syncs.
    ///
    /// Waits for the artifact of `probe` and enters from it (see
    /// [`Joiner::enter`]). Fails if the probe stops before it returns an
    /// artifact.
    pub(super) async fn discover(&mut self, probe: &Probe) -> Result<Option<Sync>, RecvError> {
        if !self.syncs {
            return Ok(None);
        }
        let artifact = probe.subscribe().await?;
        Ok(Some(unattributed_future(self.enter(artifact)).await))
    }

    /// The material a start that state syncs enters from, given the
    /// `artifact` its probe discovered.
    ///
    /// Pairs the artifact's description with the later, by round, of the
    /// floor on record and the floor the probe sampled, and records that
    /// floor before returning, so that it is durable before marshal or the
    /// DKG actors start from it.
    pub(super) async fn enter(&mut self, artifact: ProbeArtifact) -> Sync {
        let ledger = self
            .ledger
            .take()
            .expect("the ledger is present until the sync is settled");
        let kept = ledger.floor().map(|floor| floor.round());
        let floor = later(ledger.floor(), artifact.floor);
        let ledger = if kept == Some(floor.round()) {
            ledger
        } else {
            ledger.record(Progress::Syncing(floor.clone())).await
        };
        self.ledger = Some(ledger);
        let material = self.reported(Material {
            round: floor.round(),
            digest: floor.proposal.payload,
            info: artifact.info.clone(),
            boundary: artifact.finalization.is_some(),
        });
        self.records.stepped(Step::Entered(material));
        self.entered = Some(floor.clone());
        StateSync {
            info: artifact.info,
            floor,
        }
    }

    /// Record the completion of the sync this start entered from, once
    /// marshal has delivered the floor's block to the engine. A start that
    /// did not state sync has nothing to complete.
    ///
    /// Marshal delivers a block only once the block is durable, and it
    /// delivers the floor's block once it has stored the floor and recorded
    /// the height below it as processed. The delivery is read from what the
    /// engine reports, which holds the block also when an earlier start of
    /// the engine was delivered it. The wait runs as a task of `context`, so
    /// it ends with the engine.
    pub(super) fn settle(self, context: impl Spawner) {
        let entered = unattributed(|| {
            let floor = self.entered.clone().filter(|_| self.completes())?;
            let remembers = self.remembers();
            let ledger = self
                .ledger
                .expect("the ledger is present until the sync is settled");
            Some((floor, remembers, ledger, self.records))
        });
        let Some((floor, remembers, ledger, records)) = entered else {
            return;
        };
        drop(context.spawn(move |_| {
            unattributed_future(async move {
                let mut commits = records.watch_commits();
                let height = loop {
                    let delivered = records
                        .commits()
                        .into_iter()
                        .find(|(_, digest)| *digest == floor.proposal.payload);
                    if let Some((height, _)) = delivered {
                        break height;
                    }
                    if commits.recv().await.is_none() {
                        return;
                    }
                };
                if remembers {
                    ledger.record(Progress::Synced(height)).await;
                }
                records.stepped(Step::Synced(height));
            })
        }));
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::{
        dkg::{
            RESHARE_NAMESPACE,
            context::EngineContext,
            fixtures::{described, raised},
        },
        stateful::runner::tolerating,
    };
    use bytes::Bytes;
    use commonware_codec::Encode as _;
    use commonware_consensus::{
        Epochable as _,
        simplex::types::{Finalize, Proposal},
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{Hasher as _, Sha256};
    use commonware_parallel::Sequential;
    use commonware_runtime::{Clock as _, Runner as _, Supervisor as _, deterministic};
    use commonware_utils::non_empty;
    use std::time::Duration;

    /// A finalization of `block` at view `view` of `epoch`, signed by a
    /// committee a trusted dealer dealt to.
    pub(in crate::dkg) fn finalization(epoch: u64, view: u64, block: &[u8]) -> Floor {
        let (info, shares) = described(5, Epoch::zero());
        let schemes: Vec<Scheme> = shares
            .into_iter()
            .map(|share| {
                Scheme::signer(
                    RESHARE_NAMESPACE,
                    info.players.clone(),
                    info.output.public().clone(),
                    share,
                )
                .expect("a dealt share builds a signer")
            })
            .collect();
        let proposal = Proposal::new(
            Round::new(Epoch::new(epoch), View::new(view)),
            View::new(view.saturating_sub(1)),
            Sha256::hash(&[block]),
        );
        let finalizes: Vec<_> = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).expect("a signer signs"))
            .collect();
        Finalization::from_finalizes(&schemes[0], non_empty![@finalizes.iter()], &Sequential)
            .expect("a quorum of votes makes a finalization")
    }

    #[test]
    fn progress_roundtrips() {
        for progress in [
            Progress::Syncing(finalization(2, 7, b"floor")),
            Progress::Synced(Height::new(70)),
        ] {
            let decoded =
                Progress::read_cfg(&mut progress.encode(), &()).expect("progress must decode");
            assert_eq!(decoded, progress);
        }
        assert!(matches!(
            Progress::read_cfg(&mut Bytes::from_static(&[2]), &()),
            Err(CodecError::InvalidEnum(2))
        ));
    }

    #[test]
    fn later_floor_is_chosen_by_round() {
        let (early, late) = (finalization(1, 3, b"early"), finalization(1, 9, b"late"));
        let next = finalization(2, 1, b"next");
        assert_eq!(later(None, early.clone()), early);
        assert_eq!(later(Some(&early), late.clone()), late);
        assert_eq!(later(Some(&late), early.clone()), late);

        // An epoch orders before a view.
        assert_eq!(later(Some(&late), next.clone()), next);
        assert_eq!(later(Some(&next), late), next);

        // The floor on record stays when the probe samples its round again.
        let again = finalization(1, 3, b"other");
        assert_eq!(later(Some(&early), again), early);
    }

    /// What one start of a joiner found on its ledger and decided.
    fn started(records: &Records) -> Startup {
        match records.steps().last() {
            Some(Step::Started(startup)) => *startup,
            step => panic!("the last step is not a start: {step:?}"),
        }
    }

    #[test]
    fn ledger_survives_reopening() {
        deterministic::Runner::default().start(|context| async move {
            let (first, second) = (finalization(1, 4, b"first"), finalization(1, 8, b"second"));

            // A fresh ledger holds nothing.
            let ledger = Ledger::open(context.child("fresh"), "engine").await;
            assert!(ledger.floor().is_none());
            assert!(ledger.synced().is_none());

            // A selected floor is found again, and a later one replaces it.
            drop(ledger.record(Progress::Syncing(first.clone())).await);
            let ledger = Ledger::open(context.child("selected"), "engine").await;
            assert_eq!(ledger.floor(), Some(&first));
            assert!(ledger.synced().is_none());
            drop(ledger.record(Progress::Syncing(second.clone())).await);
            let ledger = Ledger::open(context.child("replaced"), "engine").await;
            assert_eq!(ledger.floor(), Some(&second));

            // A completion replaces the floor for good.
            drop(ledger.record(Progress::Synced(Height::new(40))).await);
            let ledger = Ledger::open(context.child("completed"), "engine").await;
            assert!(ledger.floor().is_none());
            assert_eq!(ledger.synced(), Some(Height::new(40)));

            // Another engine's ledger is its own.
            let other = Ledger::open(context.child("other"), "other").await;
            assert!(other.floor().is_none());
            assert!(other.synced().is_none());
        });
    }

    #[test]
    fn start_syncs_until_a_sync_completed() {
        deterministic::Runner::default().start(|context| async move {
            let records = Records::default();
            let floor = finalization(1, 4, b"floor");

            // A first start is asked to sync and has nothing to resume.
            let open = |label| {
                let (context, records) = (context.child(label), records.clone());
                async move {
                    Joiner::open(&context, Entry::StateSync, "engine", &records)
                        .await
                        .expect("an engine that state syncs has a joiner")
                }
            };
            let joiner = open("first").await;
            assert!(joiner.floor().is_none());
            assert_eq!(
                started(&records),
                Startup {
                    resumed: None,
                    synced: None,
                    syncs: true,
                }
            );

            // A start after a floor was selected resumes from it, and hands
            // it to the probe.
            let ledger = joiner.ledger.expect("the ledger is present");
            drop(ledger.record(Progress::Syncing(floor.clone())).await);
            let joiner = open("second").await;
            assert_eq!(joiner.floor(), Some(floor.clone()));
            assert_eq!(
                started(&records),
                Startup {
                    resumed: Some(floor.round()),
                    synced: None,
                    syncs: true,
                }
            );

            // A start after the sync completed does not sync, although it is
            // asked to, and has no floor for the probe.
            let ledger = joiner.ledger.expect("the ledger is present");
            drop(ledger.record(Progress::Synced(Height::new(40))).await);
            let joiner = open("third").await;
            assert!(joiner.floor().is_none());
            assert_eq!(
                started(&records),
                Startup {
                    resumed: None,
                    synced: Some(Height::new(40)),
                    syncs: false,
                }
            );
            assert_eq!(records.steps().len(), 3);

            // An engine that enters from the height-zero block has no joiner
            // and takes no step.
            let genesis = Joiner::open(&context, Entry::Genesis, "engine", &records).await;
            assert!(genesis.is_none());
            assert_eq!(records.steps().len(), 3);
        });
    }

    /// An artifact whose probe sampled `floor`, with the description of the
    /// floor's epoch.
    pub(in crate::dkg) fn artifact(floor: &Floor) -> ProbeArtifact {
        ProbeArtifact {
            finalization: None,
            info: described(floor.epoch().get(), floor.epoch()).0,
            floor: floor.clone(),
        }
    }

    /// The joiner of the engine whose storage is under `engine`, at one start
    /// of it.
    async fn opened(
        context: &deterministic::Context,
        label: &'static str,
        records: &Records,
    ) -> Joiner<deterministic::Context> {
        let context = context.child(label);
        Joiner::open(&context, Entry::StateSync, "engine", records)
            .await
            .expect("an engine that state syncs has a joiner")
    }

    /// The material the caller reported at its latest entry.
    fn entered(records: &Records) -> Material {
        match records.steps().last() {
            Some(Step::Entered(material)) => material.clone(),
            step => panic!("the last step is not an entry: {step:?}"),
        }
    }

    /// R24: the description the probe returned is paired with the later, by
    /// round, of the floor on record and the floor the probe sampled, and
    /// that floor is what the ledger holds afterwards. These floors differ in
    /// round, which a run of the target cannot arrange at will.
    #[test]
    fn entry_starts_from_the_later_of_the_kept_and_the_sampled_floor() {
        deterministic::Runner::default().start(|context| async move {
            let records = Records::default();
            let (early, kept, late) = (
                finalization(1, 3, b"early"),
                finalization(1, 9, b"kept"),
                finalization(1, 12, b"late"),
            );

            // With nothing on record, the start enters from the sampled
            // floor and records it.
            let mut joiner = opened(&context, "first", &records).await;
            let material = joiner.enter(artifact(&kept)).await;
            assert_eq!(material.floor, kept);
            assert_eq!(material.info, artifact(&kept).info);
            assert_eq!(entered(&records).round, kept.round());
            assert_eq!(entered(&records).digest, kept.proposal.payload);
            drop(joiner);

            // A probe that samples an earlier round does not move the floor
            // back: the start enters from the floor on record, paired with
            // the description the probe returned.
            let mut joiner = opened(&context, "second", &records).await;
            assert_eq!(joiner.floor(), Some(kept.clone()));
            let material = joiner.enter(artifact(&early)).await;
            assert_eq!(material.floor, kept);
            assert_eq!(material.info, artifact(&early).info);
            assert_eq!(entered(&records).round, kept.round());
            assert_eq!(entered(&records).digest, kept.proposal.payload);
            drop(joiner);
            let joiner = opened(&context, "third", &records).await;
            assert_eq!(joiner.floor(), Some(kept.clone()));
            drop(joiner);

            // A probe that samples a later round moves it forward.
            let mut joiner = opened(&context, "fourth", &records).await;
            let material = joiner.enter(artifact(&late)).await;
            assert_eq!(material.floor, late);
            assert_eq!(entered(&records).round, late.round());
            drop(joiner);
            let joiner = opened(&context, "fifth", &records).await;
            assert_eq!(joiner.floor(), Some(late.clone()));
            drop(joiner);

            // An epoch orders before a view.
            let next = finalization(2, 1, b"next");
            let mut joiner = opened(&context, "sixth", &records).await;
            assert_eq!(joiner.enter(artifact(&next)).await.floor, next);
            drop(joiner);
            let mut joiner = opened(&context, "seventh", &records).await;
            let material = joiner.enter(artifact(&late)).await;
            assert_eq!(material.floor, next);
            assert_eq!(material.info, artifact(&late).info);
        });
    }

    /// The completion is recorded once the engine reports that marshal
    /// delivered the floor's block, at the height of that block, and not
    /// before: a start that is dropped while it waits leaves the sync in
    /// progress.
    #[test]
    fn sync_completes_once_the_floor_is_delivered() {
        deterministic::Runner::default().start(|context| async move {
            let records = Records::default();
            let floor = finalization(1, 4, b"floor");
            let other = finalization(1, 5, b"other").proposal.payload;

            // An engine whose caller waits for the floor's block. The wait
            // is a task of the engine and ends with it.
            let engine = |label, joiner: Joiner<deterministic::Context>| {
                context.child(label).spawn(|context| async move {
                    joiner.settle(context.child("joined"));
                    std::future::pending::<()>().await
                })
            };

            // The block of another floor is delivered, and the engine is
            // crashed.
            let mut joiner = opened(&context, "first", &records).await;
            joiner.enter(artifact(&floor)).await;
            let running = engine("first_engine", joiner);
            context.sleep(Duration::from_millis(10)).await;
            records.committed(Height::new(41), other);
            context.sleep(Duration::from_millis(10)).await;
            assert!(matches!(records.steps().last(), Some(Step::Entered(_))));
            running.abort();
            let _ = running.await;
            context.sleep(Duration::from_millis(10)).await;

            // The next start finds the sync in progress. The floor's block is
            // delivered, and the completion is recorded at its height.
            let mut joiner = opened(&context, "second", &records).await;
            assert_eq!(started(&records).resumed, Some(floor.round()));
            assert!(started(&records).syncs);
            joiner.enter(artifact(&floor)).await;
            let running = engine("second_engine", joiner);
            context.sleep(Duration::from_millis(10)).await;
            assert!(matches!(records.steps().last(), Some(Step::Entered(_))));
            records.committed(Height::new(40), floor.proposal.payload);
            context.sleep(Duration::from_millis(10)).await;
            assert_eq!(records.steps().last(), Some(&Step::Synced(Height::new(40))));
            running.abort();
            let _ = running.await;
            context.sleep(Duration::from_millis(10)).await;

            // A later start finds the completion and does not sync.
            let joiner = opened(&context, "third", &records).await;
            assert_eq!(started(&records).synced, Some(Height::new(40)));
            assert!(!started(&records).syncs);
            assert!(joiner.floor().is_none());
        });
    }

    /// The harness's code that a task of an engine runs is attributed to no
    /// engine, at every poll and when it is dropped.
    #[test]
    fn harness_code_in_an_engine_task_is_attributed_to_no_engine() {
        struct Bomb;

        impl Drop for Bomb {
            fn drop(&mut self) {
                panic!("dropping");
            }
        }

        let config = deterministic::Config::new().with_catch_panics(true);
        let (_, panics) = tolerating(|| {
            deterministic::Runner::new(config).start(|context| async move {
                let engine = |label| EngineContext::new(context.child(label), 3);
                drop(engine("first").spawn(|context| {
                    unattributed_future(async move {
                        context.sleep(Duration::from_millis(1)).await;
                        panic!("polling");
                    })
                }));
                let handle = engine("second").spawn(|_| {
                    unattributed_future(async {
                        let _bomb = Bomb;
                        std::future::pending::<()>().await;
                    })
                });
                drop(engine("third").spawn(|_| async { panic!("engine") }));
                context.sleep(Duration::from_millis(10)).await;
                handle.abort();
                context.sleep(Duration::from_millis(10)).await;
            })
        });
        let mut raised = raised(panics);
        raised.sort();
        assert_eq!(
            raised,
            vec![
                (None, "dropping".to_string()),
                (None, "polling".to_string()),
                (Some(3), "engine".to_string()),
            ]
        );
    }
}
