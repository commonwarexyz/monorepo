//! The vote pool: rebuilding updates from their predecessors, parking and requesting what is
//! missing, resolving tips through payload hashes and fetched headers, reading each vote once, and
//! the view-level counts over what was read.

use crate::{
    Epochable as _, Viewable as _,
    multimmit::{
        algebra::reference,
        config::{Profile, ResourceLimits, Tuning},
        machine::{
            capability::{Capabilities, Capability, ResolverCommand},
            input::{BlockValidity, Input, ObservationStatus, Rejection, StepStatus},
            resolution::{ResolutionCompletion, ResolutionJob, RetrievalKey},
            testing::{
                CapabilitiesExt as _, Drive as _, SymbolicVerifier, Until, cohort,
                fixtures::{
                    Block, TestDriver, block, committee, digest, enter_next_view, path, profile,
                    quiesce, receive, reference as block_ref, stage_view_entries, started,
                    started_with, validate, validator, vqc_above,
                },
            },
            view::proposal::HeldVqc,
        },
        mocks::Committee,
        types::{
            Artifact, BlockRef, ChainChange, ChainId, ChainSet, TransactionBlockHeader,
            VoteContent, VoteUpdate,
        },
    },
    types::{Height, Participant, View},
};
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk, sha256::Digest};
use commonware_utils::test_rng;
use rand::RngExt as _;
use std::{collections::BTreeMap, num::NonZeroUsize, sync::Arc};

type Update = VoteUpdate<MinPk, Digest>;

const VIEW: View = View::new(1);
const SENDER: Participant = Participant::new(1);
const CHAIN: ChainId = ChainId::new(1);

/// The verification items and the other capabilities one delivery led to.
struct Delivered {
    statuses: Vec<ObservationStatus>,
    /// The rebuilt content of every vote update verified, in verification order.
    verified: Vec<VoteContent<Digest>>,
    capabilities: Capabilities<MinPk, Digest>,
}

impl Delivered {
    /// Returns the keys of the retrievals requested.
    fn requested(&self) -> Vec<RetrievalKey<Digest>> {
        self.jobs().into_iter().map(ResolutionJob::key).collect()
    }

    /// Returns the retrievals requested.
    fn jobs(&self) -> Vec<ResolutionJob<Digest>> {
        self.capabilities
            .iter()
            .filter_map(|capability| match capability {
                Capability::Resolver(ResolverCommand::Resolve(job)) => Some(*job),
                _ => None,
            })
            .collect()
    }
}

/// Observes `artifacts` and completes every verification the machine issues with `verifier`'s
/// verdicts, until it issues none.
fn deliver_with(
    driver: &mut TestDriver,
    artifacts: Vec<Artifact<MinPk, Digest>>,
    verifier: &SymbolicVerifier<Digest>,
) -> Delivered {
    let step = driver.submit(cohort::<Sha256, _>(artifacts)).unwrap();
    let StepStatus::Observed(results) = step.status() else {
        panic!("an observation reports its results");
    };
    let statuses = results.iter().map(|result| result.status()).collect();
    complete_verifications(driver, statuses, step.into_capabilities(), verifier)
}

/// Completes every verification `pending` and its successors issue with `verifier`'s verdicts,
/// until the machine issues none.
fn complete_verifications(
    driver: &mut TestDriver,
    statuses: Vec<ObservationStatus>,
    mut pending: Capabilities<MinPk, Digest>,
    verifier: &SymbolicVerifier<Digest>,
) -> Delivered {
    let mut delivered = Delivered {
        statuses,
        verified: Vec::new(),
        capabilities: Capabilities::new(),
    };
    while !pending.is_empty() {
        let mut next = Capabilities::new();
        for capability in pending {
            let Capability::Verify(job) = capability else {
                delivered.capabilities.push(capability);
                continue;
            };
            delivered.verified.extend(
                job.items()
                    .iter()
                    .filter_map(|item| item.content().cloned()),
            );
            let step = driver
                .submit(Input::Verified(verifier.complete(&job)))
                .unwrap();
            next.extend(driver.settle(step, Until::Quiesce).into_capabilities());
        }
        pending = next;
    }
    delivered
}

/// Observes `updates` and accepts every signature.
fn deliver(driver: &mut TestDriver, updates: &[Update]) -> Delivered {
    deliver_with(
        driver,
        updates.iter().cloned().map(Artifact::Update).collect(),
        &SymbolicVerifier::new(true),
    )
}

/// Returns the content of a vote in `view` with `tips`, declaring `declared`.
fn content(
    committee: &Committee<MinPk>,
    view: View,
    final_: bool,
    declared: &[u32],
    tips: Vec<BlockRef<Digest>>,
) -> VoteContent<Digest> {
    let mut set = ChainSet::empty(committee.codec().chains());
    for chain in declared {
        set.insert(ChainId::new(*chain));
    }
    committee.content(view, None, final_, committee.endorsement(set, tips))
}

/// Returns the genesis tips with `tip` replacing its chain's.
fn tips_with(committee: &Committee<MinPk>, changed: &[BlockRef<Digest>]) -> Vec<BlockRef<Digest>> {
    let mut tips = committee.genesis().tips().to_vec();
    for tip in changed {
        tips[tip.chain().index()] = *tip;
    }
    tips
}

/// Returns `signer`'s update `seq` for `content` naming `changes`.
fn update(
    committee: &Committee<MinPk>,
    signer: Participant,
    content: &VoteContent<Digest>,
    seq: u32,
    changes: Vec<ChainChange<Digest>>,
) -> Update {
    VoteUpdate::new(
        content.round(),
        content.leader(),
        content.is_final(),
        content.declared().clone(),
        seq,
        changes,
        committee.sign_vote(signer, content),
        committee.codec(),
    )
    .unwrap()
}

/// Returns a change to `tip` carrying `payloads`.
fn change(
    committee: &Committee<MinPk>,
    tip: BlockRef<Digest>,
    payloads: Vec<Digest>,
) -> ChainChange<Digest> {
    ChainChange::new(tip, payloads, committee.codec()).unwrap()
}

/// Returns a change to every chain's tip of `content`, without payload hashes.
fn every_chain(
    committee: &Committee<MinPk>,
    content: &VoteContent<Digest>,
) -> Vec<ChainChange<Digest>> {
    content
        .tips()
        .iter()
        .map(|tip| change(committee, *tip, Vec::new()))
        .collect()
}

/// Returns `count` headers extending `from` with bodies labelled by `label`, lowest first.
fn headers(
    committee: &Committee<MinPk>,
    from: BlockRef<Digest>,
    count: usize,
    label: &[u8],
) -> Vec<TransactionBlockHeader<Digest>> {
    let mut parent = from;
    (0..count)
        .map(|index| {
            let header = committee.header(
                &parent,
                digest(&[label, index.to_be_bytes().as_slice()].concat()),
            );
            parent = header.block_ref::<Sha256>();
            header
        })
        .collect()
}

/// Returns the reference of `header`.
fn top(header: &TransactionBlockHeader<Digest>) -> BlockRef<Digest> {
    header.block_ref::<Sha256>()
}

/// Returns the body digests of `headers`, lowest first.
fn payloads(headers: &[TransactionBlockHeader<Digest>]) -> Vec<Digest> {
    headers
        .iter()
        .map(TransactionBlockHeader::body_digest)
        .collect()
}

/// Returns the latest vote read from `signer` tagged `view`.
fn latest(driver: &TestDriver, signer: Participant, view: View) -> Option<VoteContent<Digest>> {
    driver
        .machine()
        .latest_vote(signer, view)
        .map(|content| content.as_ref().clone())
}

/// Returns whether `signer` endorses the held header `block`.
fn endorses(driver: &TestDriver, signer: Participant, block: &BlockRef<Digest>) -> bool {
    driver
        .machine()
        .chain_layer()
        .headers
        .get(block)
        .is_some_and(|entry| entry.endorsers.get(u64::from(signer.get())))
}

#[test]
fn updates_rebuild_omitted_chains_and_resolve_tips_from_payload_hashes() {
    let committee = committee(70);
    let mut driver = started(&committee, validator(0));
    let genesis = committee.genesis().tips()[CHAIN.index()];

    // Update one omits every chain: each takes its genesis object in view one.
    let first = content(&committee, VIEW, false, &[], tips_with(&committee, &[]));
    let delivered = deliver(
        &mut driver,
        &[update(&committee, SENDER, &first, 1, Vec::new())],
    );
    assert_eq!(delivered.verified, vec![first.clone()]);
    assert_eq!(latest(&driver, SENDER, VIEW), Some(first));

    // Update two names chain one's tip three blocks up; its payload hashes rebuild the headers.
    let path = headers(&committee, genesis, 6, b"path");
    let second = content(
        &committee,
        VIEW,
        false,
        &[],
        tips_with(&committee, &[top(&path[2])]),
    );
    let changes = vec![change(&committee, top(&path[2]), payloads(&path[..3]))];
    let delivered = deliver(
        &mut driver,
        &[update(&committee, SENDER, &second, 2, changes)],
    );
    assert_eq!(delivered.verified, vec![second.clone()]);
    assert!(delivered.requested().is_empty());
    assert_eq!(latest(&driver, SENDER, VIEW), Some(second));
    for header in &path[..3] {
        assert!(endorses(&driver, SENDER, &top(header)));
    }

    // Update three carries the last three payload hashes; they rebuild above the previous tip.
    let third = content(
        &committee,
        VIEW,
        false,
        &[],
        tips_with(&committee, &[top(&path[5])]),
    );
    let changes = vec![change(&committee, top(&path[5]), payloads(&path[3..]))];
    deliver(
        &mut driver,
        &[update(&committee, SENDER, &third, 3, changes)],
    );
    assert_eq!(latest(&driver, SENDER, VIEW), Some(third));
    for header in &path {
        assert!(endorses(&driver, SENDER, &top(header)));
    }
}

#[test]
fn an_update_is_rebuilt_from_update_k_minus_two_or_from_every_chain() {
    let committee = committee(71);
    let mut driver = started(&committee, validator(0));
    let genesis = committee.genesis().tips();
    let first = content(&committee, VIEW, false, &[], genesis.to_vec());
    deliver(
        &mut driver,
        &[update(&committee, SENDER, &first, 1, Vec::new())],
    );

    // Update two is lost; update three names what changed since either and rebuilds from one.
    let header = &headers(&committee, genesis[2], 1, b"two")[0];
    let third = content(
        &committee,
        VIEW,
        false,
        &[],
        tips_with(&committee, &[top(header)]),
    );
    let changes = vec![change(
        &committee,
        top(header),
        payloads(std::slice::from_ref(header)),
    )];
    let delivered = deliver(
        &mut driver,
        &[update(&committee, SENDER, &third, 3, changes)],
    );
    assert_eq!(delivered.verified, vec![third.clone()]);
    assert_eq!(latest(&driver, SENDER, VIEW), Some(third));

    // A sender resuming after a restart names every chain, which needs no predecessor.
    let other = Participant::new(2);
    let resumed = content(&committee, VIEW, false, &[], genesis.to_vec());
    let delivered = deliver(
        &mut driver,
        &[update(
            &committee,
            other,
            &resumed,
            7,
            every_chain(&committee, &resumed),
        )],
    );
    assert_eq!(delivered.verified, vec![resumed.clone()]);
    assert_eq!(latest(&driver, other, VIEW), Some(resumed));
}

#[test]
fn an_update_without_its_predecessor_parks_until_it_is_read() {
    let committee = committee(72);
    let mut driver = started(&committee, validator(0));
    let genesis = committee.genesis().tips();
    let header = &headers(&committee, genesis[CHAIN.index()], 1, b"park")[0];
    let third = content(
        &committee,
        VIEW,
        false,
        &[],
        tips_with(&committee, &[top(header)]),
    );
    let changes = vec![change(
        &committee,
        top(header),
        payloads(std::slice::from_ref(header)),
    )];

    // Neither update one nor two was read: update three parks unverified and update two is
    // requested.
    let delivered = deliver(
        &mut driver,
        &[update(&committee, SENDER, &third, 3, changes)],
    );
    assert_eq!(delivered.statuses, vec![ObservationStatus::Scheduled]);
    assert!(delivered.verified.is_empty());
    assert_eq!(
        delivered.requested(),
        vec![RetrievalKey::Update {
            signer: SENDER,
            view: VIEW,
        }]
    );
    assert_eq!(driver.inspect().pending_artifacts(), 1);
    assert_eq!(driver.inspect().parked_updates(), 1);
    assert_eq!(latest(&driver, SENDER, VIEW), None);

    // Update two rebuilds from update zero; reading it wakes update three, verified and read.
    let second = content(&committee, VIEW, false, &[], genesis.to_vec());
    let delivered = deliver(
        &mut driver,
        &[update(&committee, SENDER, &second, 2, Vec::new())],
    );
    assert_eq!(delivered.verified, vec![second, third.clone()]);
    assert_eq!(latest(&driver, SENDER, VIEW), Some(third));
    assert_eq!(driver.inspect().cached_artifacts(), 0);
    assert_eq!(driver.inspect().parked_updates(), 0);
}

#[test]
fn a_parked_update_passed_by_a_later_read_is_dropped_and_its_predecessor_not_refetched() {
    let committee = committee(80);
    let mut driver = started(&committee, validator(0));
    let genesis = committee.genesis().tips();
    let header = &headers(&committee, genesis[CHAIN.index()], 1, b"passed")[0];
    let tips = tips_with(&committee, &[top(header)]);
    let third = content(&committee, VIEW, false, &[], tips.clone());
    let changes = vec![change(
        &committee,
        top(header),
        payloads(std::slice::from_ref(header)),
    )];
    let delivered = deliver(
        &mut driver,
        &[update(&committee, SENDER, &third, 3, changes)],
    );
    let [Capability::Resolver(ResolverCommand::Resolve(job))] = delivered.capabilities.as_slice()
    else {
        panic!(
            "the sender's vote of the tag is requested: {:?}",
            delivered.capabilities
        );
    };
    let job = *job;
    assert_eq!(driver.inspect().parked_updates(), 1);

    // A restarted sender's update four names every chain and is read at once, so update three
    // can never be read.
    let fourth = content(&committee, VIEW, false, &[CHAIN.get()], tips);
    let mut all = every_chain(&committee, &fourth);
    all[CHAIN.index()] = change(
        &committee,
        top(header),
        payloads(std::slice::from_ref(header)),
    );
    deliver(&mut driver, &[update(&committee, SENDER, &fourth, 4, all)]);
    assert_eq!(latest(&driver, SENDER, VIEW), Some(fourth));
    quiesce(&mut driver);
    assert_eq!(
        driver.inspect().parked_updates(),
        0,
        "update three is dropped"
    );

    // Update two arrives for the outstanding retrieval and is refused; nothing waits on the
    // sender's vote any more, so it is not requested again.
    let second = content(&committee, VIEW, false, &[], genesis.to_vec());
    let retrieved = Artifact::Update(update(&committee, SENDER, &second, 2, Vec::new()))
        .identify::<Sha256>(&mut Vec::new());
    let step = driver
        .submit(Input::ResolutionCompleted(ResolutionCompletion::new(
            job, retrieved,
        )))
        .unwrap();
    let step = driver.settle(step, Until::Quiesce);
    assert!(
        !step.capabilities().iter().any(|capability| matches!(
            capability,
            Capability::Resolver(ResolverCommand::Resolve(_))
        )),
        "a refused predecessor nobody waits on is not fetched again: {:?}",
        step.capabilities()
    );
}

#[test]
fn a_first_update_waits_for_the_senders_final_vote_of_the_previous_view() {
    let committee = committee(73);
    let mut driver = started(&committee, validator(0));
    let genesis = committee.genesis().tips();
    let header = &headers(&committee, genesis[CHAIN.index()], 1, b"final")[0];
    let tips = tips_with(&committee, &[top(header)]);
    let second_view = View::new(2);
    let opening = content(&committee, second_view, false, &[], tips.clone());
    let delivered = deliver(
        &mut driver,
        &[update(&committee, SENDER, &opening, 1, Vec::new())],
    );
    assert_eq!(
        delivered.requested(),
        vec![RetrievalKey::Update {
            signer: SENDER,
            view: VIEW,
        }]
    );

    // The final vote of view one sets the tips update one of view two omits.
    let last = content(&committee, VIEW, true, &[], tips);
    let changes = vec![change(
        &committee,
        top(header),
        payloads(std::slice::from_ref(header)),
    )];
    let delivered = deliver(
        &mut driver,
        &[update(&committee, SENDER, &last, 1, changes)],
    );
    assert_eq!(delivered.verified, vec![last, opening.clone()]);
    assert_eq!(latest(&driver, SENDER, second_view), Some(opening));
}

#[test]
fn pending_updates_are_bounded_per_sender() {
    let committee = committee(74);
    let mut driver = started(&committee, validator(0));
    let bound = driver
        .machine()
        .profile
        .tuning()
        .pending_updates_per_sender
        .get() as u32;
    let genesis = committee.genesis().tips();
    let header = &headers(&committee, genesis[CHAIN.index()], 1, b"bound")[0];
    let parked = content(
        &committee,
        VIEW,
        false,
        &[],
        tips_with(&committee, &[top(header)]),
    );
    let updates = (3..3 + bound + 1)
        .map(|seq| {
            update(
                &committee,
                SENDER,
                &parked,
                seq,
                vec![change(&committee, top(header), Vec::new())],
            )
        })
        .collect::<Vec<_>>();
    let delivered = deliver(&mut driver, &updates);
    let mut expected = vec![ObservationStatus::Scheduled; bound as usize];
    expected.push(ObservationStatus::Rejected(Rejection::PendingUpdatesFull));
    assert_eq!(delivered.statuses, expected);

    // Another sender's queue is its own.
    let other = Participant::new(2);
    let first = content(&committee, VIEW, false, &[], genesis.to_vec());
    deliver(
        &mut driver,
        &[update(&committee, other, &first, 1, Vec::new())],
    );
    assert_eq!(latest(&driver, other, VIEW), Some(first));
}

#[test]
fn a_flooding_sender_cannot_crowd_out_another_senders_header_dependent_update() {
    let committee = committee(80);
    let mut driver = started(&committee, validator(0));
    let resources = driver.machine().profile.resources();
    let waiters = resources.max_dependency_waiters() as u32;
    let bound = driver
        .machine()
        .profile
        .tuning()
        .pending_updates_per_sender
        .get();
    let genesis = committee.genesis().tips()[CHAIN.index()];

    // The sender's updates name every chain, so they need no predecessor, and each names a tip
    // nobody serves. Only the per-sender bound of them is admitted.
    let flood = (1..=waiters + 1)
        .map(|seq| {
            let tip = top(&headers(&committee, genesis, 1, &seq.to_be_bytes())[0]);
            let vote = content(&committee, VIEW, false, &[], tips_with(&committee, &[tip]));
            update(
                &committee,
                SENDER,
                &vote,
                seq,
                every_chain(&committee, &vote),
            )
        })
        .collect::<Vec<_>>();
    let delivered = deliver(&mut driver, &flood);
    let mut expected = vec![ObservationStatus::Scheduled; bound];
    expected.resize(
        flood.len(),
        ObservationStatus::Rejected(Rejection::PendingUpdatesFull),
    );
    assert_eq!(delivered.statuses, expected);

    // Another sender's update still waits for its header, which is fetched, and is then read.
    let other = Participant::new(2);
    let blocks = path(&committee, CHAIN, 1);
    let tip = block_ref(&blocks[0]);
    let vote = content(&committee, VIEW, false, &[], tips_with(&committee, &[tip]));
    let delivered = deliver(
        &mut driver,
        &[update(
            &committee,
            other,
            &vote,
            1,
            vec![change(&committee, tip, Vec::new())],
        )],
    );
    assert!(delivered.requested().contains(&RetrievalKey::Header {
        chain: CHAIN,
        digest: tip.digest(),
    }));
    receive(&mut driver, &blocks);
    assert_eq!(latest(&driver, other, VIEW), Some(vote));
}

#[test]
fn a_senders_latest_vote_naming_every_chain_supersedes_its_parked_updates() {
    let committee = committee(76);
    let mut driver = started(&committee, validator(0));
    let bound = driver
        .machine()
        .profile
        .tuning()
        .pending_updates_per_sender
        .get() as u32;
    let genesis = committee.genesis().tips();
    let header = &headers(&committee, genesis[CHAIN.index()], 1, b"latest")[0];
    let vote = content(
        &committee,
        VIEW,
        false,
        &[],
        tips_with(&committee, &[top(header)]),
    );
    let partial = |seq| {
        update(
            &committee,
            SENDER,
            &vote,
            seq,
            vec![change(&committee, top(header), Vec::new())],
        )
    };

    // Updates one and two were lost and the sender no longer holds them. Every later update parks
    // on the sender's vote of the tag, requested once, until the bound refuses the next.
    let parked = (3..3 + bound).map(partial).collect::<Vec<_>>();
    let delivered = deliver(&mut driver, &parked);
    assert_eq!(
        delivered.statuses,
        vec![ObservationStatus::Scheduled; bound as usize]
    );
    let key = RetrievalKey::Update {
        signer: SENDER,
        view: VIEW,
    };
    let [job] = delivered.jobs()[..] else {
        panic!("the parked updates request their sender's vote once");
    };
    assert_eq!(job.key(), key);
    assert_eq!(driver.inspect().parked_updates(), bound as usize);
    let delivered = deliver(&mut driver, &[partial(3 + bound)]);
    assert_eq!(
        delivered.statuses,
        vec![ObservationStatus::Rejected(Rejection::PendingUpdatesFull)]
    );

    // The sender answers with its latest update naming every chain. It is admitted past the
    // bound and read, and the parked updates it supersedes are dropped without being read.
    let mut changes = every_chain(&committee, &vote);
    changes[CHAIN.index()] = change(
        &committee,
        top(header),
        payloads(std::slice::from_ref(header)),
    );
    let latest_update = update(&committee, SENDER, &vote, 3 + bound, changes);
    let step = driver
        .submit(Input::ResolutionCompleted(ResolutionCompletion::new(
            job,
            Artifact::Update(latest_update).identify::<Sha256>(&mut Vec::new()),
        )))
        .unwrap();
    let StepStatus::ResolutionCompleted { admission } = *step.status() else {
        panic!("a retrieval reports its admission");
    };
    let delivered = complete_verifications(
        &mut driver,
        vec![admission],
        step.into_capabilities(),
        &SymbolicVerifier::new(true),
    );
    assert_eq!(delivered.statuses, vec![ObservationStatus::Scheduled]);
    assert_eq!(delivered.verified, vec![vote.clone()]);
    assert!(delivered.requested().is_empty());
    assert_eq!(latest(&driver, SENDER, VIEW), Some(vote.clone()));
    assert!(endorses(&driver, SENDER, &top(header)));
    assert_eq!(driver.inspect().parked_updates(), 0);
    assert_eq!(driver.inspect().pending_artifacts(), 0);

    // The sender's next update, naming no chain, rebuilds from the one read.
    let next = content(
        &committee,
        VIEW,
        false,
        &[CHAIN.get()],
        tips_with(&committee, &[top(header)]),
    );
    let delivered = deliver(
        &mut driver,
        &[update(&committee, SENDER, &next, 4 + bound, Vec::new())],
    );
    assert_eq!(delivered.verified, vec![next.clone()]);
    assert_eq!(latest(&driver, SENDER, VIEW), Some(next));
}

#[test]
fn superseded_updates_and_updates_after_a_final_are_refused() {
    let committee = committee(75);
    let mut driver = started(&committee, validator(0));
    let genesis = committee.genesis().tips().to_vec();
    let vote = content(&committee, VIEW, false, &[], genesis.clone());
    let last = content(&committee, VIEW, true, &[], genesis);
    deliver(
        &mut driver,
        &[update(&committee, SENDER, &vote, 2, Vec::new())],
    );

    let refused = Rejection::Superseded;
    let delivered = deliver(
        &mut driver,
        &[update(&committee, SENDER, &vote, 1, Vec::new())],
    );
    assert_eq!(
        delivered.statuses,
        vec![ObservationStatus::Rejected(refused)]
    );

    deliver(
        &mut driver,
        &[update(&committee, SENDER, &last, 3, Vec::new())],
    );
    assert_eq!(latest(&driver, SENDER, VIEW), Some(last));
    let delivered = deliver(
        &mut driver,
        &[update(&committee, SENDER, &vote, 4, Vec::new())],
    );
    assert_eq!(
        delivered.statuses,
        vec![ObservationStatus::Rejected(refused)]
    );
}

/// Returns a validator that entered view five; its pool reads tags 3 ..= 7 with the default
/// window of two.
fn in_view_five(committee: &Committee<MinPk>) -> TestDriver {
    let mut driver = started(committee, validator(0));
    stage_view_entries(&mut driver, committee, View::new(5));
    driver
}

#[test]
fn updates_are_read_only_within_the_tag_window() {
    let committee = committee(76);
    let mut driver = in_view_five(&committee);

    let genesis = committee.genesis().tips().to_vec();
    let statuses = [2, 3, 7, 8]
        .into_iter()
        .map(|view| {
            let vote = content(&committee, View::new(view), false, &[], genesis.clone());
            let changes = every_chain(&committee, &vote);
            deliver(
                &mut driver,
                &[update(&committee, SENDER, &vote, 1, changes)],
            )
            .statuses[0]
        })
        .collect::<Vec<_>>();
    assert_eq!(
        statuses,
        vec![
            ObservationStatus::Rejected(Rejection::TagWindow),
            ObservationStatus::Scheduled,
            ObservationStatus::Scheduled,
            ObservationStatus::Rejected(Rejection::TagWindow),
        ]
    );
    assert!(latest(&driver, SENDER, View::new(3)).is_some());
    assert!(latest(&driver, SENDER, View::new(7)).is_some());
}

#[test]
fn an_update_rebuilt_from_a_tag_below_the_window_is_refused() {
    let committee = committee(84);
    let mut driver = in_view_five(&committee);
    // Update one of tag three rebuilds the chains it omits from the sender's final vote of tag
    // two, which the pool no longer reads: it is refused rather than parked on a request that
    // can never be read.
    let genesis = committee.genesis().tips();
    let header = &headers(&committee, genesis[CHAIN.index()], 1, b"below")[0];
    let vote = content(
        &committee,
        View::new(3),
        false,
        &[],
        tips_with(&committee, &[top(header)]),
    );
    let changes = vec![change(
        &committee,
        top(header),
        payloads(std::slice::from_ref(header)),
    )];
    let delivered = deliver(
        &mut driver,
        &[update(&committee, SENDER, &vote, 1, changes)],
    );
    assert_eq!(
        delivered.statuses,
        vec![ObservationStatus::Rejected(Rejection::TagWindow)]
    );
    assert!(delivered.requested().is_empty());
    assert_eq!(driver.inspect().parked_updates(), 0);
}

#[test]
fn an_update_whose_signature_fails_is_discarded_without_blame() {
    let committee = committee(77);
    let mut driver = started(&committee, validator(0));
    let vote = content(
        &committee,
        VIEW,
        false,
        &[],
        committee.genesis().tips().to_vec(),
    );
    let forged = update(&committee, SENDER, &vote, 1, Vec::new());
    let delivered = deliver_with(
        &mut driver,
        vec![Artifact::Update(forged)],
        &SymbolicVerifier::new(false),
    );
    assert_eq!(delivered.verified, vec![vote]);
    assert!(
        !delivered
            .capabilities
            .iter()
            .any(|capability| matches!(capability, Capability::Quarantine(_)))
    );
    assert_eq!(latest(&driver, SENDER, VIEW), None);
    assert_eq!(driver.inspect().cached_artifacts(), 0);
}

#[test]
fn an_unknown_tip_waits_for_its_header() {
    let committee = committee(78);
    let mut driver = started(&committee, validator(0));
    let blocks = path(&committee, CHAIN, 1);
    let tip = block_ref(&blocks[0]);
    let vote = content(&committee, VIEW, false, &[], tips_with(&committee, &[tip]));
    let changes = vec![change(&committee, tip, Vec::new())];
    let delivered = deliver(
        &mut driver,
        &[update(&committee, SENDER, &vote, 1, changes)],
    );
    assert_eq!(
        delivered.requested(),
        vec![RetrievalKey::Header {
            chain: CHAIN,
            digest: tip.digest()
        }]
    );
    assert_eq!(latest(&driver, SENDER, VIEW), None);

    // The fetched header is buffered, and the update is read.
    receive(&mut driver, &blocks);
    assert_eq!(latest(&driver, SENDER, VIEW), Some(vote));
    assert!(endorses(&driver, SENDER, &tip));
}

/// Completes `job` with `block` and every verification that follows, returning what the machine
/// did.
fn answer(driver: &mut TestDriver, job: ResolutionJob<Digest>, block: &Block) -> Delivered {
    let retrieved = Artifact::TransactionBlock(block.clone()).identify::<Sha256>(&mut Vec::new());
    let step = driver
        .submit(Input::ResolutionCompleted(ResolutionCompletion::new(
            job, retrieved,
        )))
        .unwrap();
    let StepStatus::ResolutionCompleted { admission } = *step.status() else {
        panic!("a retrieval reports its admission");
    };
    complete_verifications(
        driver,
        vec![admission],
        step.into_capabilities(),
        &SymbolicVerifier::new(true),
    )
}

#[test]
fn a_tip_retention_passed_while_its_header_was_fetched_is_read() {
    let committee = committee(82);
    let mut driver = started(&committee, validator(0));
    let blocks = path(&committee, CHAIN, 1);
    let tip = block_ref(&blocks[0]);
    let vote = content(&committee, VIEW, false, &[], tips_with(&committee, &[tip]));
    let changes = vec![change(&committee, tip, Vec::new())];
    let delivered = deliver(
        &mut driver,
        &[update(&committee, SENDER, &vote, 1, changes)],
    );
    let [job] = delivered.jobs()[..] else {
        panic!(
            "the tip's header is requested once: {:?}",
            delivered.capabilities
        );
    };
    assert_eq!(latest(&driver, SENDER, VIEW), None);

    // Retention raises the chain's floor to the tip's height, so its header can no longer be
    // held: it is refused, the update stops waiting for it and is read (the tip lies at or below
    // the floor), and the header is not fetched again.
    driver
        .machine_mut()
        .components
        .chain
        .headers
        .retain_above(CHAIN, tip.height());
    let delivered = answer(&mut driver, job, &blocks[0]);
    assert_eq!(
        delivered.statuses,
        vec![ObservationStatus::Rejected(Rejection::TipLead)]
    );
    assert!(
        delivered.requested().is_empty(),
        "a header nothing can wait on is not fetched again"
    );
    assert_eq!(latest(&driver, SENDER, VIEW), Some(vote));
}

#[test]
fn a_tip_on_another_branch_below_the_accepted_tip_is_fetched_and_read_off_base() {
    let committee = committee(85);
    let mut driver = started(&committee, validator(0));
    let accepted = path(&committee, CHAIN, 2);
    for block in &accepted {
        receive(&mut driver, std::slice::from_ref(block));
        validate(&mut driver, block, BlockValidity::Valid);
    }
    let genesis = committee.genesis().tips()[CHAIN.index()];
    let fork = block(&committee, &genesis, b"fork one");
    let tip = block(&committee, &block_ref(&fork), b"fork two");
    let vote = content(
        &committee,
        VIEW,
        false,
        &[],
        tips_with(&committee, &[block_ref(&tip)]),
    );
    let changes = vec![change(&committee, block_ref(&tip), Vec::new())];

    // The tip lies on another branch at the accepted tip's height: the update waits for it.
    let delivered = deliver(
        &mut driver,
        &[update(&committee, SENDER, &vote, 1, changes)],
    );
    let [job] = delivered.jobs()[..] else {
        panic!(
            "the tip's header is requested once: {:?}",
            delivered.capabilities
        );
    };
    assert_eq!(
        job.key(),
        RetrievalKey::Header {
            chain: CHAIN,
            digest: block_ref(&tip).digest()
        }
    );

    // The tip is held without its parent, so it is not yet linked and the update waits for the
    // parent instead.
    let delivered = answer(&mut driver, job, &tip);
    assert_eq!(delivered.statuses, vec![ObservationStatus::Scheduled]);
    let [job] = delivered.jobs()[..] else {
        panic!(
            "the tip's parent is requested once: {:?}",
            delivered.capabilities
        );
    };
    assert_eq!(
        job.key(),
        RetrievalKey::Header {
            chain: CHAIN,
            digest: block_ref(&fork).digest()
        }
    );
    let headers = &driver.machine().chain_layer().headers;
    assert!(
        headers
            .get(&block_ref(&tip))
            .is_some_and(|entry| !entry.linked)
    );
    assert_eq!(latest(&driver, SENDER, VIEW), None);

    // The parent links the branch to genesis: the vote is read and endorses the branch, which
    // lies off the accepted path.
    let delivered = answer(&mut driver, job, &fork);
    assert_eq!(delivered.statuses, vec![ObservationStatus::Scheduled]);
    assert!(delivered.requested().is_empty());
    assert_eq!(latest(&driver, SENDER, VIEW), Some(vote));
    assert!(endorses(&driver, SENDER, &block_ref(&tip)));
    assert!(endorses(&driver, SENDER, &block_ref(&fork)));
    assert_eq!(
        driver.machine().chain_layer().tip(CHAIN),
        block_ref(&accepted[1])
    );
}

#[test]
fn tips_the_chain_layer_can_never_hold_are_read_unresolved() {
    let committee = committee(79);
    let mut driver = started(&committee, validator(0));
    let genesis = committee.genesis().tips();
    let lead = driver.machine().profile.height_window();
    // Beyond the held window on chain one, and a copy of the local producer's chain zero.
    let far = BlockRef::new(CHAIN, Height::new(lead + 1), digest(b"far"));
    let own = block_ref(&block(&committee, &genesis[0], b"forged"));
    let vote = content(
        &committee,
        VIEW,
        false,
        &[],
        tips_with(&committee, &[far, own]),
    );
    let changes = vec![
        change(&committee, own, Vec::new()),
        change(&committee, far, Vec::new()),
    ];
    let delivered = deliver(
        &mut driver,
        &[update(&committee, SENDER, &vote, 1, changes)],
    );
    assert!(delivered.requested().is_empty());
    assert_eq!(latest(&driver, SENDER, VIEW), Some(vote));
    assert!(driver.machine().chain_layer().headers.get(&far).is_none());
}

#[test]
fn a_capped_vote_read_before_the_base_resolves_binds_only_once_final() {
    let committee = committee(86);
    let mut driver = started(&committee, validator(0));
    let cap = u64::from(committee.codec().window().cap());
    let next = View::new(2);
    assert!(driver.machine().base_of(next).is_none());

    // A vote of tag two whose tip lies a whole window above genesis: capped against genesis, but
    // the base of view two is not resolved, so it binds nothing.
    let capped = BlockRef::new(CHAIN, Height::new(cap), digest(b"capped"));
    let vote = content(
        &committee,
        next,
        false,
        &[],
        tips_with(&committee, &[capped]),
    );
    let now = driver.now();
    driver
        .machine_mut()
        .read_vote(SENDER, 1, Arc::new(vote), now, now);
    assert!(driver.machine().first_binding(next, CHAIN).is_empty());

    // The sender's final vote binds it at its tip.
    let last = content(
        &committee,
        next,
        true,
        &[],
        tips_with(&committee, &[capped]),
    );
    driver
        .machine_mut()
        .read_vote(SENDER, 2, Arc::new(last), now, now);
    assert_eq!(
        driver.machine().first_binding(next, CHAIN).to_vec(),
        vec![(SENDER, capped)]
    );
}

#[test]
fn a_lagging_readers_capped_votes_do_not_settle_a_chain_early() {
    let committee = committee(87);
    let cap = committee.codec().window().cap() as usize;
    let blocks = path(&committee, CHAIN, cap + 1);
    let mut driver = started(&committee, validator(0));
    for block in &blocks {
        assert!(driver.machine_mut().hold_header(block.header().clone()));
    }
    let next = View::new(2);
    let top = block_ref(&blocks[cap]);

    // While this node is still in view one, five senders vote in view two at the window's top
    // above genesis, the base this node would have measured caps against: four of them only
    // reach it, the fifth also declares the chain.
    let now = driver.now();
    for signer in 1..=5u32 {
        let declared: &[u32] = if signer == 5 { &[CHAIN.get()] } else { &[] };
        let vote = content(
            &committee,
            next,
            false,
            declared,
            tips_with(&committee, &[top]),
        );
        driver
            .machine_mut()
            .read_vote(Participant::new(signer), 1, Arc::new(vote), now, now);
    }

    // View one ends one block up the chain: the window of view two reaches a block further than
    // the senders' tips, which they remain free to endorse.
    let genesis = HeldVqc::genesis(committee.genesis());
    let base = tips_with(&committee, &[block_ref(&blocks[0])]);
    let one = enter_next_view(
        &mut driver,
        vqc_above(&committee, &genesis, false, base, &blocks[..1]),
    );
    let beta = driver
        .machine()
        .base_of(next)
        .expect("view two's base resolves on entry")[CHAIN.index()];
    assert_eq!(beta, one.tips[CHAIN.index()]);
    let final_tip = driver.machine().final_tip(next, &beta, beta);
    assert_eq!(final_tip, top);
    let settledness = driver.machine().settledness(next, &beta, &final_tip);
    assert_eq!(settledness.bound, 1, "only the declaring sender is bound");
    assert!(!settledness.settled);
}

#[test]
fn the_first_binding_vote_per_chain_is_kept() {
    let committee = committee(80);
    let mut driver = started(&committee, validator(0));
    let genesis = committee.genesis().tips();
    let cap = committee.codec().window().cap() as usize;
    let one = headers(&committee, genesis[1], cap + 1, b"one");
    let two = headers(&committee, genesis[2], 1, b"two");
    let first_binding = |driver: &TestDriver, chain: u32| {
        driver
            .machine()
            .first_binding(VIEW, ChainId::new(chain))
            .to_vec()
    };

    // A pre-vote below the cap binds nothing.
    let vote = content(
        &committee,
        VIEW,
        false,
        &[],
        tips_with(&committee, &[top(&one[0])]),
    );
    let changes = vec![change(&committee, top(&one[0]), payloads(&one[..1]))];
    deliver(
        &mut driver,
        &[update(&committee, SENDER, &vote, 1, changes)],
    );
    assert!(first_binding(&driver, 1).is_empty());

    // Declaring chain two binds it at its tip.
    let declared = content(
        &committee,
        VIEW,
        false,
        &[2],
        tips_with(&committee, &[top(&one[0]), top(&two[0])]),
    );
    let changes = vec![change(&committee, top(&two[0]), payloads(&two))];
    deliver(
        &mut driver,
        &[update(&committee, SENDER, &declared, 2, changes)],
    );
    assert_eq!(first_binding(&driver, 2), vec![(SENDER, top(&two[0]))]);

    // A tip at the cap binds chain one.
    let capped_tip = top(&one[cap - 1]);
    let capped = content(
        &committee,
        VIEW,
        false,
        &[2],
        tips_with(&committee, &[capped_tip, top(&two[0])]),
    );
    let changes = vec![change(&committee, capped_tip, payloads(&one[1..cap]))];
    deliver(
        &mut driver,
        &[update(&committee, SENDER, &capped, 3, changes)],
    );
    assert_eq!(first_binding(&driver, 1), vec![(SENDER, capped_tip)]);

    // The final vote binds every chain, but chains already bound keep their first binding tip.
    let last_tip = top(&one[cap]);
    let last = content(
        &committee,
        VIEW,
        true,
        &[2],
        tips_with(&committee, &[last_tip, top(&two[0])]),
    );
    let changes = vec![change(&committee, last_tip, payloads(&one[cap..]))];
    deliver(
        &mut driver,
        &[update(&committee, SENDER, &last, 4, changes)],
    );
    assert_eq!(first_binding(&driver, 1), vec![(SENDER, capped_tip)]);
    assert_eq!(first_binding(&driver, 2), vec![(SENDER, top(&two[0]))]);
    assert_eq!(first_binding(&driver, 3), vec![(SENDER, genesis[3])]);
    assert_eq!(
        driver
            .machine()
            .finals(VIEW)
            .map(|(signer, _)| signer)
            .collect::<Vec<_>>(),
        vec![SENDER]
    );
}

/// One vote of a random pool.
struct Vote {
    signer: Participant,
    content: VoteContent<Digest>,
}

#[test]
fn pool_counts_match_the_reference_on_random_pools() {
    let mut rng = test_rng();
    let committee = committee(81);
    let codec = committee.codec();
    let cap = codec.window().cap();
    let participants = codec.participants();
    let chains = codec.chains();
    let genesis = committee.genesis().tips().to_vec();
    let leaders = [digest(b"left"), digest(b"right")];
    // Every signer but this one endorses one path per chain; this one endorses anything.
    let faulty = Participant::new(participants as u32 - 1);
    let (mut advanced, mut settled_chains, mut unsettled_chains) = (0, 0, 0);
    for _ in 0..24 {
        let mut driver = started(&committee, validator(0));
        let mut tree = reference::Tree::new(committee.config.epoch());
        // A few branching chains at most two windows high; every header is held.
        let mut blocks = genesis.iter().map(|tip| vec![*tip]).collect::<Vec<_>>();
        for _ in 0..40 {
            let chain = rng.random_range(1..chains);
            let parent = blocks[chain][rng.random_range(0..blocks[chain].len())];
            let next = parent.height().next();
            if parent.height().get() >= u64::from(2 * cap)
                || driver
                    .machine()
                    .chain_layer()
                    .headers
                    .at(parent.chain(), next)
                    .len()
                    >= participants
            {
                continue;
            }
            let body = digest(&rng.random::<[u8; 8]>());
            let header = committee.header(&parent, body);
            assert_eq!(tree.extend::<Sha256>(&parent, body), top(&header));
            assert!(driver.machine_mut().hold_header(header.clone()));
            blocks[chain].push(top(&header));
        }

        // Random votes over three tags, each signer's sequence numbers increasing per tag. A
        // correct signer's tips lie on one path per chain, below a leaf drawn per signer, mostly
        // the chain's shared trunk.
        let trunks = blocks
            .iter()
            .map(|chain| chain[rng.random_range(0..chain.len())])
            .collect::<Vec<_>>();
        let leaves = (0..participants)
            .map(|_| {
                blocks
                    .iter()
                    .zip(&trunks)
                    .map(|(chain, trunk)| {
                        if rng.random_bool(0.8) {
                            *trunk
                        } else {
                            chain[rng.random_range(0..chain.len())]
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let mut votes = Vec::new();
        let mut seqs = BTreeMap::new();
        let mut leader_of = BTreeMap::new();
        for _ in 0..60 {
            let signer = Participant::new(rng.random_range(0..participants as u32));
            let view = View::new(rng.random_range(1..=3));
            let tips = blocks
                .iter()
                .zip(&leaves[signer.get() as usize])
                .map(|(chain, leaf)| {
                    if signer == faulty {
                        return chain[rng.random_range(0..chain.len())];
                    }
                    let lineage = tree.lineage(leaf);
                    if rng.random_bool(0.5) {
                        lineage[0]
                    } else {
                        lineage[rng.random_range(0..lineage.len())]
                    }
                })
                .collect::<Vec<_>>();
            let declared = (0..chains as u32)
                .filter(|_| rng.random_bool(0.2))
                .collect::<Vec<_>>();
            let leader = *leader_of
                .entry((signer, view))
                .or_insert_with(|| leaders.get(rng.random_range(0..3)).copied());
            let seq = seqs.entry((signer, view)).or_insert(0u32);
            *seq += 1;
            let mut set = ChainSet::empty(chains);
            for chain in declared {
                set.insert(ChainId::new(chain));
            }
            let vote = committee.content(
                view,
                leader,
                rng.random_bool(0.1),
                committee.endorsement(set, tips),
            );
            let now = driver.now();
            driver
                .machine_mut()
                .read_vote(signer, *seq, Arc::new(vote.clone()), now, now);
            votes.push(Vote {
                signer,
                content: vote,
            });
        }

        let machine = driver.machine();
        for view in (1..=3).map(View::new) {
            let pooled = votes
                .iter()
                .filter(|vote| vote.content.view() <= view)
                .collect::<Vec<_>>();
            for chain in 0..chains {
                let tips = pooled
                    .iter()
                    .map(|vote| (vote.signer, vote.content.tips()[chain]))
                    .collect::<Vec<_>>();
                // Every held block as a base, genesis included.
                for base in &blocks[chain] {
                    let expected = reference::tip(&tree, base, cap, codec.view_quorum(), &tips);
                    assert_eq!(machine.final_tip(view, base, *base), expected);
                    advanced += usize::from(expected != *base);
                }

                // Settledness reads each signer's first vote tagged `view` binding it on the chain.
                // A capped tip binds only against a resolved base: genesis in view one, while views
                // two and three have none.
                let base = genesis[chain];
                let final_tip = machine.final_tip(view, &base, base);
                let first_binding = votes
                    .iter()
                    .filter(|vote| {
                        vote.content.view() == view
                            && (vote.content.is_final()
                                || vote.content.declared().contains(ChainId::new(chain as u32))
                                || (view == View::new(1)
                                    && vote.content.tips()[chain].height().get() >= u64::from(cap)))
                    })
                    .map(|vote| (vote.signer, vote.content.tips()[chain]))
                    .collect::<Vec<_>>();
                let expected = reference::settled(
                    &tree,
                    &base,
                    &final_tip,
                    cap,
                    participants,
                    codec.settled_bound(),
                    &first_binding,
                );
                assert_eq!(
                    machine.settledness(view, &base, &final_tip).settled,
                    expected
                );
                if expected {
                    settled_chains += 1;
                } else {
                    unsettled_chains += 1;
                }
            }
            for leader in leaders {
                let expected = leader_of
                    .iter()
                    .filter(|((_, tag), voted)| *tag == view && **voted == Some(leader))
                    .count();
                assert_eq!(machine.leader_votes(view, &leader), expected);
            }
        }
    }
    assert!(advanced > 0 && settled_chains > 0 && unsettled_chains > 0);
}

/// Returns validator 0's profile in `committee` with at most `jobs` verification jobs in flight.
fn limited_jobs(committee: &Committee<MinPk>, jobs: usize) -> Profile<Digest> {
    let profile = profile(committee, validator(0));
    let resources = profile.resources();
    let nonzero = |value| NonZeroUsize::new(value).unwrap();
    let resources = ResourceLimits::new(
        nonzero(resources.max_artifact_bytes()),
        nonzero(resources.max_cached_artifacts()),
        nonzero(resources.max_verification_batch()),
        nonzero(jobs),
        resources.max_future_view_distance(),
        nonzero(resources.max_future_artifacts()),
        nonzero(resources.max_dependency_waiters()),
        nonzero(resources.max_outbox_effects()),
        nonzero(resources.max_forwarded_certificates()),
    );
    Profile::with_limits(
        profile.protocol().clone(),
        profile.role(),
        Tuning::default(),
        resources,
    )
    .unwrap()
}

#[test]
fn updates_woken_by_one_verification_stay_within_the_verification_job_bound() {
    let committee = committee(93);
    let mut driver = started_with(limited_jobs(&committee, 2));
    let genesis = committee.genesis().tips();
    let header = &headers(&committee, genesis[CHAIN.index()], 1, b"woken")[0];
    let third = content(
        &committee,
        VIEW,
        false,
        &[],
        tips_with(&committee, &[top(header)]),
    );
    let changes = vec![change(
        &committee,
        top(header),
        payloads(std::slice::from_ref(header)),
    )];
    let senders = [Participant::new(1), Participant::new(2)];

    // Each sender's third update parks until its second is read.
    for sender in senders {
        let parked = deliver(
            &mut driver,
            &[update(&committee, sender, &third, 3, changes.clone())],
        );
        assert!(parked.verified.is_empty());
    }

    // Both second updates verify in one job while another sender's update occupies the other
    // slot.
    let second = content(&committee, VIEW, false, &[], genesis.to_vec());
    let seconds = driver
        .submit(cohort::<Sha256, _>(
            senders
                .iter()
                .map(|sender| Artifact::Update(update(&committee, *sender, &second, 2, Vec::new())))
                .collect(),
        ))
        .unwrap();
    let other = Participant::new(3);
    let occupying = driver
        .submit(cohort::<Sha256, _>(vec![Artifact::Update(update(
            &committee,
            other,
            &second,
            7,
            every_chain(&committee, &second),
        ))]))
        .unwrap();
    assert_eq!(driver.inspect().verification_jobs_len(), 2);

    // Reading both seconds wakes both thirds, but at most one more job fits.
    let verifier = SymbolicVerifier::new(true);
    let woken = driver
        .submit(Input::Verified(verifier.complete(&seconds.verify_job())))
        .unwrap();
    let woken = driver.settle(woken, Until::Quiesce);
    assert!(
        driver.inspect().verification_jobs_len() <= 2,
        "{} verification jobs in flight",
        driver.inspect().verification_jobs_len()
    );

    // Once the other job completes, the deferred update is verified too and both thirds are read.
    let mut pending = woken.into_capabilities();
    pending.extend(occupying.into_capabilities());
    complete_verifications(&mut driver, Vec::new(), pending, &verifier);
    for sender in senders {
        assert_eq!(latest(&driver, sender, VIEW), Some(third.clone()));
    }
    assert_eq!(latest(&driver, other, VIEW), Some(second));
    assert_eq!(driver.inspect().parked_updates(), 0);
}
