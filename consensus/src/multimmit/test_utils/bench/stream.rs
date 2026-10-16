//! A deployment-scale vote stream: validator zero of `n = 50` with window cap `N = 12` reads
//! every peer's vote update as it arrives, alongside the producer headers the updates endorse and
//! the V-QCs that end each view. Every other validator produces one chain (`K = 49`), so the
//! measured validator runs every validator duty but production.
//!
//! The stream follows the paced regime: every producer builds one block per `theta`, with
//! `theta = eta = 25 ms`, so a view of [`STREAM_TICKS`] vote ticks lasts `N theta`. At every tick
//! each chain gains one header, [`STREAM_LEAD`] blocks above the tips votes endorse (the blocks
//! still crossing the network, about `(delta + eta) / theta` at `delta = 100 ms`), and every peer
//! sends one update moving its tip on every chain by one block, with the payload hashes a
//! production sender attaches. Production runs ahead of views, so tips enter a view already
//! [`STREAM_TICKS`] `-` [`STREAM_CAPPED_TICK`] blocks into its window and reach the window end,
//! where they bind their senders, at tick [`STREAM_CAPPED_TICK`]; peers then send nothing until
//! their final vote at the last tick. The view ends on [`STREAM_VQCS`] distinct V-QCs of the final
//! votes, as forwarding delivers several, and an L-QC finalizes its leader block. Every update is
//! observed alone, as ingress hands it over, so the machine's per-read work is measured rather
//! than amortised over a batch.
//!
//! Artifacts are signed once when a [`Stream`] is built and replayed against a fresh machine on
//! every run, through the symbolic driver: verification and persistence are free, so the figures
//! are pure state-machine work. Each artifact is replayed as ingress hands it over: decoded from
//! its wire encoding, so signatures keep their received bytes, and identified off the voter loop.

use crate::{
    multimmit::{
        config::{Role, Tuning},
        machine::{
            BlockValidity, IdentifiedArtifact,
            testing::{
                HeldVqc,
                fixtures::{
                    Block, TestDriver, built_body, elapse, enter_next_view_identified,
                    observe_identified, persist_all, quiesce, reference, resolution_paths,
                    started_with, tuned, validate,
                },
            },
        },
        mocks::Committee,
        types::{
            Artifact, BlockRef, ChainChange, ChainSet, CodecConfig, LeaderBlock, Lqc, VoteContent,
            VoteUpdate, Vqc, Window,
        },
    },
    types::Participant,
};
use commonware_codec::{Decode as _, DecodeExt as _, Encode as _, EncodeSize as _};
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk, sha256::Digest};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

/// Validators; every one but the measured validator zero produces one chain.
pub const STREAM_PARTICIPANTS: u32 = 50;

/// The window cap `N`.
pub const STREAM_CAP: u32 = 12;

/// Views a stream runs; the first warms the machine up and is not measured.
pub const STREAM_VIEWS: u64 = 4;

/// Vote ticks per view, the last carrying every validator's final vote: one per block, so a view
/// lasts `N theta`.
pub const STREAM_TICKS: u32 = STREAM_CAP;

/// The tick at which every tip reaches the window end.
pub const STREAM_CAPPED_TICK: u32 = 8;

/// Blocks each chain's newest header leads the tips votes endorse.
pub const STREAM_LEAD: u64 = 5;

/// The vote tick, `eta`, and the production pace, `theta`, in milliseconds.
pub const STREAM_ETA: u64 = 25;

/// Distinct V-QCs delivered at the end of each view.
pub const STREAM_VQCS: usize = 4;

const SEED: u64 = 0x5713_ea11;

/// An artifact as ingress hands it to the voter.
type Received = IdentifiedArtifact<MinPk, Digest>;

/// Returns `artifact` decoded from its wire encoding and identified.
fn received(artifact: Artifact<MinPk, Digest>, codec: &CodecConfig) -> Received {
    let decoded = match artifact {
        Artifact::TransactionBlock(block) => {
            Artifact::TransactionBlock(Block::decode(block.encode()).expect("the block decodes"))
        }
        Artifact::Update(update) => Artifact::Update(
            VoteUpdate::decode_cfg(update.encode(), codec).expect("the update decodes"),
        ),
        Artifact::Vqc(vqc) => {
            Artifact::Vqc(Vqc::decode_cfg(vqc.encode(), codec).expect("the V-QC decodes"))
        }
        Artifact::Lqc(lqc) => {
            Artifact::Lqc(Lqc::decode_cfg(lqc.encode(), codec).expect("the L-QC decodes"))
        }
        other => other,
    };
    decoded.identify::<Sha256>(&mut Vec::new())
}

/// Returns the vote update `artifact` carries.
fn update_of(artifact: &Received) -> &VoteUpdate<MinPk, Digest> {
    match &artifact.artifact {
        Artifact::Update(update) => update,
        _ => unreachable!("the stream sends updates only as updates"),
    }
}

/// One vote tick: the headers that arrive before it, then every validator's update.
struct Tick {
    blocks: Vec<Received>,
    updates: Vec<Received>,
}

/// One scripted view.
struct StreamView {
    ticks: Vec<Tick>,
    vqcs: Vec<Received>,
    lqc: Received,
}

/// A committee and the artifacts of [`STREAM_VIEWS`] consecutive views from genesis.
pub struct Stream {
    committee: Committee<MinPk>,
    /// Headers every chain holds before the first view: one window, the lead of the producers.
    preroll: Vec<Received>,
    views: Vec<StreamView>,
}

/// What one run of a [`Stream`] measured, over every view but the first.
#[derive(Clone, Copy, Debug, Default)]
pub struct StreamReport {
    /// Views measured.
    pub views: usize,
    /// Vote updates read.
    pub updates: usize,
    /// Host time spent observing and reading the updates.
    pub update_time: Duration,
    /// Producer headers received and validated.
    pub headers: usize,
    /// Host time spent receiving and validating the headers.
    pub header_time: Duration,
    /// V-QCs and L-QCs delivered.
    pub certificates: usize,
    /// Host time spent on the certificates and the view changes they cause.
    pub certificate_time: Duration,
    /// Total encoded bytes of the updates read.
    pub update_bytes: usize,
}

impl StreamReport {
    /// Returns the measured host time.
    pub fn total(&self) -> Duration {
        self.update_time + self.header_time + self.certificate_time
    }

    /// Returns the measured host time per update read: everything a validator does per vote it
    /// reads, including its share of headers and certificates.
    pub fn per_update(&self) -> Duration {
        self.total() / u32::try_from(self.updates.max(1)).unwrap_or(u32::MAX)
    }

    /// Returns the share of one core the measured work takes when every view lasts
    /// [`STREAM_TICKS`] ticks of [`STREAM_ETA`].
    pub fn utilisation(&self) -> f64 {
        let wall = Duration::from_millis(STREAM_ETA * u64::from(STREAM_TICKS)) * self.views as u32;
        self.total().as_secs_f64() / wall.as_secs_f64().max(f64::MIN_POSITIVE)
    }
}

/// Builds the producer headers of every chain from `tips` up to `height`, advancing `tips` and
/// remembering every header in `held`, and returns them as received.
fn extend_chains(
    committee: &Committee<MinPk>,
    tips: &mut [BlockRef<Digest>],
    height: u64,
    held: &mut BTreeMap<BlockRef<Digest>, Block>,
) -> Vec<Received> {
    let mut blocks = Vec::new();
    for tip in tips.iter_mut() {
        while tip.height().get() < height {
            let block = committee.sign_header(committee.header(tip, built_body(tip.digest())));
            *tip = reference(&block);
            held.insert(*tip, block.clone());
            blocks.push(received(
                Artifact::TransactionBlock(block),
                &committee.codec(),
            ));
        }
    }
    blocks
}

/// Returns the ancestor of `tip` at `height` among `held`.
fn ancestor(
    held: &BTreeMap<BlockRef<Digest>, Block>,
    mut tip: BlockRef<Digest>,
    height: u64,
) -> BlockRef<Digest> {
    while tip.height().get() > height {
        tip = held[&tip].header().parent_ref();
    }
    tip
}

impl Stream {
    /// Signs the artifacts of [`STREAM_VIEWS`] views.
    ///
    /// Building runs the views once on a reference machine, which names each V-QC's parent.
    pub fn new() -> Self {
        let committee = Committee::<MinPk>::builder(SEED, STREAM_PARTICIPANTS)
            .producers((1..STREAM_PARTICIPANTS).map(Participant::new).collect())
            .window(Window::new(STREAM_CAP).expect("the window is valid"))
            .build();
        let codec = committee.codec();
        let cap = u64::from(STREAM_CAP);
        let entered = u64::from(STREAM_TICKS - STREAM_CAPPED_TICK);
        let mut held = BTreeMap::new();
        let mut produced = committee.genesis().tips().to_vec();
        let preroll = extend_chains(&committee, &mut produced, entered + STREAM_LEAD, &mut held);
        let mut driver = validator(&committee);
        receive_all(&mut driver, &preroll);
        let mut parent = HeldVqc::genesis(committee.genesis());
        let mut views = Vec::new();
        for _ in 0..STREAM_VIEWS {
            let view = parent.view.next();
            let base = parent.view.get() * cap;
            let leader = LeaderBlock::new(committee.round(view), parent.id, parent.history)
                .expect("the view is above genesis");
            let leader_digest = leader.digest::<Sha256>();
            // The tips of the last two updates sent; update zero is the previous final vote.
            let mut previous = parent.tips.to_vec();
            let mut before = previous.clone();
            let mut ticks = Vec::new();
            for tick in 1..=STREAM_TICKS {
                let blocks = extend_chains(
                    &committee,
                    &mut produced,
                    base + entered + STREAM_LEAD + u64::from(tick),
                    &mut held,
                );
                let advance = (entered + u64::from(tick)).min(cap);
                let tips = produced
                    .iter()
                    .map(|tip| ancestor(&held, *tip, base + advance))
                    .collect::<Vec<_>>();
                let final_ = tick == STREAM_TICKS;
                if !final_ && tips == previous {
                    ticks.push(Tick {
                        blocks,
                        updates: Vec::new(),
                    });
                    continue;
                }
                let seq = ticks.iter().filter(|tick| !tick.updates.is_empty()).count() as u32 + 1;
                let content = committee.content(
                    view,
                    Some(leader_digest),
                    final_,
                    committee.endorsement(ChainSet::empty(codec.chains()), tips.clone()),
                );
                // As a production sender: every chain changed since either of the last two
                // updates, with the payload hashes above the older one's tip.
                let changes = tips
                    .iter()
                    .zip(previous.iter().zip(&before))
                    .filter(|(tip, (previous, before))| final_ || tip != previous || tip != before)
                    .map(|(tip, (_, before))| {
                        let count = (tip.height().get() - before.height().get())
                            .min(u64::from(codec.window().delta_max()))
                            .min(tip.height().get());
                        let mut payloads = Vec::new();
                        let mut block = *tip;
                        while (payloads.len() as u64) < count {
                            let header = held[&block].header();
                            payloads.push(header.body_digest());
                            block = header.parent_ref();
                        }
                        payloads.reverse();
                        ChainChange::new(*tip, payloads, codec).expect("the change is valid")
                    })
                    .collect::<Vec<_>>();
                let updates = (1..codec.participants())
                    .map(|signer| {
                        let update = committee.update_with(
                            Participant::from_usize(signer),
                            &content,
                            changes.clone(),
                            seq,
                        );
                        received(Artifact::Update(update), &codec)
                    })
                    .collect::<Vec<_>>();
                before = core::mem::replace(&mut previous, tips);
                ticks.push(Tick { blocks, updates });
            }
            let finals = update_of(&ticks.last().expect("a view has ticks").updates[0])
                .content(&previous, codec)
                .expect("the final vote rebuilds");
            // The measured validator's V-QCs and L-QC record peers' votes only.
            let vqcs = (0..STREAM_VQCS)
                .map(|offset| {
                    let vqc = vqc_of_finals(&committee, &parent, &finals, offset, &held);
                    received(Artifact::Vqc(vqc), &codec)
                })
                .collect::<Vec<_>>();
            let contents = (1..=codec.view_quorum())
                .map(|signer| (Participant::from_usize(signer), finals.clone()))
                .collect();
            let lqc = received(Artifact::Lqc(committee.lqc_from(leader, contents)), &codec);
            let script = StreamView { ticks, vqcs, lqc };
            parent = script.run(&mut driver, &mut StreamReport::default());
            views.push(script);
        }
        Self {
            committee,
            preroll,
            views,
        }
    }

    /// Returns the size of every update the stream sends, in bytes, for the final and the other
    /// updates.
    pub fn update_sizes(&self) -> (Vec<usize>, Vec<usize>) {
        let (finals, others): (Vec<_>, Vec<_>) = self
            .views
            .iter()
            .flat_map(|view| &view.ticks)
            .flat_map(|tick| &tick.updates)
            .map(update_of)
            .partition(|update| update.is_final());
        let sizes = |updates: Vec<&VoteUpdate<MinPk, Digest>>| {
            updates
                .into_iter()
                .map(|update| update.encode_size())
                .collect()
        };
        (sizes(finals), sizes(others))
    }
}

impl Default for Stream {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns a V-QC above `parent` recording `content` as the final vote of the `n - f`
/// participants starting at `offset`.
fn vqc_of_finals(
    committee: &Committee<MinPk>,
    parent: &HeldVqc<Digest>,
    content: &VoteContent<Digest>,
    offset: usize,
    held: &BTreeMap<BlockRef<Digest>, Block>,
) -> Vqc<MinPk, Digest> {
    let codec = committee.codec();
    let peers = codec.participants() - 1;
    let mut signers = (0..codec.view_quorum())
        .map(|index| Participant::from_usize(1 + (offset + index) % peers))
        .collect::<Vec<_>>();
    signers.sort();
    let contents = signers
        .into_iter()
        .map(|signer| (signer, content.clone()))
        .collect::<Vec<_>>();
    let blocks = held.values().cloned().collect::<Vec<_>>();
    let paths = resolution_paths(committee, &parent.tips, &contents, &blocks);
    committee.vqc_from(parent.id, contents, paths)
}

impl StreamView {
    /// Runs the view on `driver`, recording its costs in `report`, and returns the V-QC the node
    /// entered the next view on.
    fn run(&self, driver: &mut TestDriver, report: &mut StreamReport) -> HeldVqc<Digest> {
        for tick in &self.ticks {
            let started = Instant::now();
            elapse(driver, STREAM_ETA);
            receive_all(driver, &tick.blocks);
            report.header_time += started.elapsed();
            report.headers += tick.blocks.len();
            let started = Instant::now();
            for update in &tick.updates {
                deliver(driver, update);
            }
            report.update_time += started.elapsed();
            report.updates += tick.updates.len();
            report.update_bytes += tick
                .updates
                .iter()
                .map(|update| update_of(update).encode_size())
                .sum::<usize>();
        }
        let started = Instant::now();
        let (first, rest) = self.vqcs.split_first().expect("a view ends on a V-QC");
        let held = enter_next_view_identified(driver, first.clone());
        for vqc in rest {
            deliver(driver, vqc);
        }
        deliver(driver, &self.lqc);
        report.certificate_time += started.elapsed();
        report.certificates += self.vqcs.len() + 1;
        report.views += 1;
        held
    }
}

/// Observes `artifact`, verifies it, and runs everything its admission leads to durably.
fn deliver(driver: &mut TestDriver, artifact: &Received) {
    let step = observe_identified(driver, vec![artifact.clone()]);
    persist_all(driver, step);
    quiesce(driver);
}

/// Receives each of `blocks` alone and validates it.
fn receive_all(driver: &mut TestDriver, blocks: &[Received]) {
    for block in blocks {
        observe_identified(driver, vec![block.clone()]);
        let Artifact::TransactionBlock(header) = &block.artifact else {
            unreachable!("the stream sends headers only as blocks");
        };
        validate(driver, header, BlockValidity::Valid);
    }
}

/// Returns a started driver for validator zero.
fn validator(committee: &Committee<MinPk>) -> TestDriver {
    started_with(tuned(
        committee,
        Role::Validator(Participant::new(0)),
        Tuning::default(),
    ))
}

/// Runs `stream` once on a fresh validator and returns what its views after the first cost.
///
/// # Panics
///
/// Panics if the machine leaves the script.
pub fn run_stream(stream: &Stream) -> StreamReport {
    let mut driver = validator(&stream.committee);
    receive_all(&mut driver, &stream.preroll);
    let (warmup, measured) = stream.views.split_first().expect("a stream has views");
    warmup.run(&mut driver, &mut StreamReport::default());
    let mut report = StreamReport::default();
    for view in measured {
        view.run(&mut driver, &mut report);
    }
    assert_eq!(driver.inspect().view().get(), STREAM_VIEWS + 1);
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Prints what one run of the stream costs; run with `--ignored --nocapture`.
    #[test]
    #[ignore = "deployment-scale measurement"]
    fn stream_report() {
        let started = Instant::now();
        let stream = Stream::new();
        println!("built in {:?}", started.elapsed());
        let (finals, others) = stream.update_sizes();
        let mean = |sizes: &[usize]| sizes.iter().sum::<usize>() / sizes.len().max(1);
        println!(
            "update bytes: final mean {} other mean {} (max {})",
            mean(&finals),
            mean(&others),
            others.iter().max().unwrap_or(&0)
        );
        for _ in 0..3 {
            let report = run_stream(&stream);
            println!(
                "{report:?} per update {:?}, per header {:?}, per certificate {:?}, \
                 utilisation {:.1}%",
                report.per_update(),
                report.header_time / report.headers.max(1) as u32,
                report.certificate_time / report.certificates.max(1) as u32,
                100.0 * report.utilisation(),
            );
        }
    }
}
