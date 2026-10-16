//! Round-trip and adversarial-bound tests for the durable codecs.

use super::*;
use crate::{
    Epochable as _,
    multimmit::{
        machine::durability::{EffectId, OutboxEntry},
        mocks::Committee,
        types::{ChainId, EpochGenesis, LeaderBlock},
    },
    types::Round,
};
use commonware_codec::{Decode as _, DecodeExt as _, Encode as _, Input};
use commonware_cryptography::{
    Hasher as _, Sha256,
    bls12381::primitives::variant::{MinPk, MinSig},
    sha256::Digest as Sha256Digest,
};
use commonware_utils::Participant as P;

type D = Sha256Digest;

const MAX_ARTIFACT_BYTES: usize = 1 << 20;
const MAX_RETIRED: usize = 4;
const MAX_ACCEPTED: usize = 3;
const MAX_ANCESTORS: usize = 2;

/// Real signed artifacts of one committee, one of each kind, and the codec bounds around them.
struct Fixture<V: Variant> {
    committee: Committee<V>,
    header: Arc<Artifact<V, D>>,
    leader: Arc<Artifact<V, D>>,
    update: Arc<Artifact<V, D>>,
    vqc: Arc<Vqc<V, D>>,
    lqc: Arc<Artifact<V, D>>,
}

impl<V: Variant> Fixture<V> {
    fn new(seed: u64) -> Self {
        let committee = Committee::<V>::builder(seed, 4).build();
        let genesis = committee.genesis().tips().to_vec();
        let header = committee.sign_header(committee.header(&genesis[0], Sha256::hash(&[b"body"])));
        let mut tips = genesis.clone();
        tips[0] = header.header().block_ref::<Sha256>();
        let leader = committee.leader_block(View::new(2));
        let declared = ChainSet::from_chains(4, [ChainId::new(0)]).unwrap();
        let content = committee.content(
            View::new(2),
            Some(leader.block().digest::<Sha256>()),
            false,
            committee.endorsement(declared, tips),
        );
        let update = committee.update(P::new(1), &content, &genesis, 1);
        Self {
            header: Arc::new(Artifact::TransactionBlock(header)),
            leader: Arc::new(Artifact::LeaderBlock(leader)),
            update: Arc::new(Artifact::Update(update)),
            vqc: Arc::new(committee.vqc(View::new(2))),
            lqc: Arc::new(Artifact::Lqc(committee.lqc(View::new(2)))),
            committee,
        }
    }

    /// Returns the history record extending the genesis history with the genesis tips.
    fn genesis_record(&self) -> HistoryRecord<D> {
        HistoryRecord::new(self.genesis().history(), self.genesis().tips().to_vec()).unwrap()
    }

    fn genesis(&self) -> &EpochGenesis<D> {
        self.committee.genesis()
    }

    fn event_config(&self) -> DomainEventCodecConfig {
        DomainEventCodecConfig::new(
            self.committee.codec(),
            MAX_ARTIFACT_BYTES,
            MAX_RETIRED,
            MAX_ACCEPTED,
            MAX_ANCESTORS,
        )
    }

    fn snapshot_config(&self) -> SnapshotCodecConfig {
        SnapshotCodecConfig::new(self.event_config(), 16, 8, 3)
    }

    fn signed_header(&self) -> Arc<SignedTransactionBlock<V, D>> {
        match self.header.as_ref() {
            Artifact::TransactionBlock(header) => Arc::new(header.clone()),
            _ => unreachable!("the fixture header is a transaction block"),
        }
    }

    fn vqc_artifact(&self) -> Arc<Artifact<V, D>> {
        Arc::new(Artifact::Vqc(self.vqc.as_ref().clone()))
    }

    fn update_request(&self) -> UpdateRequest<D> {
        let Artifact::Update(update) = self.update.as_ref() else {
            unreachable!("the fixture update is an update");
        };
        let content = update
            .content(self.genesis().tips(), self.committee.codec())
            .unwrap();
        UpdateRequest::new(content, update.seq(), update.changes().to_vec())
    }

    fn proposal(&self) -> Publication<V, D> {
        let Artifact::LeaderBlock(block) = self.leader.as_ref() else {
            unreachable!("the fixture leader block is a leader block");
        };
        Publication::Propose(Proposal::new(
            Arc::new(block.clone()),
            ProposalParent::Exact(Arc::clone(&self.vqc)),
            true,
        ))
    }

    fn watermark(&self) -> VoteWatermark<D> {
        let request = self.update_request();
        VoteWatermark {
            seq: request.seq(),
            tips: request.content().tips().to_vec(),
            declared: request.content().declared().clone(),
            declared_at: vec![Height::new(1)],
            final_content: Some(request.content().clone()),
        }
    }

    /// Returns every change kind, each holding the fixture's real artifacts.
    fn changes(&self) -> Vec<Change<V, D>> {
        let leader = LeaderBlock::new(
            Round::new(self.committee.config.epoch(), View::new(3)),
            self.vqc.id::<Sha256>(),
            Sha256::hash(&[b"history"]),
        )
        .unwrap();
        vec![
            Change::GenerationAdvanced(Generation::new(3)),
            Change::OutboxQueued {
                id: EffectId::new(4),
                effect: Box::new(DurableEffect::sign(SignRequest::TransactionBlock(
                    self.signed_header().header().clone(),
                ))),
            },
            Change::OutboxQueued {
                id: EffectId::new(5),
                effect: Box::new(DurableEffect::sign(SignRequest::LeaderBlock(
                    Proposal::new(leader, ProposalParent::Exact(Arc::clone(&self.vqc)), false),
                ))),
            },
            Change::OutboxQueued {
                id: EffectId::new(6),
                effect: Box::new(DurableEffect::sign(SignRequest::Update(
                    self.update_request(),
                ))),
            },
            Change::OutboxQueued {
                id: EffectId::new(7),
                effect: Box::new(DurableEffect::Publish(self.proposal())),
            },
            Change::SignedArtifacts {
                sign: EffectId::new(6),
                publication: EffectId::new(8),
                artifacts: Arc::from([Arc::clone(&self.update), Arc::clone(&self.header)]),
            },
            Change::Accepted {
                blocks: vec![
                    Acceptance::Full(self.signed_header()),
                    Acceptance::Adopted(self.signed_header().header().clone()),
                ],
            },
            Change::EmissionResolved {
                view: View::new(2),
                record: self.genesis_record(),
                by: Resolution::Determined,
            },
            Change::EmissionResolved {
                view: View::new(3),
                record: self.genesis_record(),
                by: Resolution::Pinned {
                    view: View::new(5),
                    lqc: CertificateId::new(Sha256::hash(&[b"lqc"])),
                },
            },
            Change::ArtifactForwarded {
                publication: EffectId::new(9),
                artifact: self.vqc_artifact(),
            },
            Change::ViewEntered {
                proof: self.lqc.id::<Sha256>(),
                ancestors: vec![self.vqc_artifact()],
                retired_publications: vec![EffectId::new(3)],
            },
            Change::CertificateCreated {
                artifact: Arc::clone(&self.lqc),
            },
            Change::RetentionAdvanced {
                floor: View::new(1),
                root: self.root(),
                retired_signing: vec![EffectId::new(5)],
                retired_publications: Vec::new(),
            },
            Change::Anchored {
                floor: self.floor(),
                retired_signing: vec![EffectId::new(5)],
                retired_publications: vec![EffectId::new(7)],
            },
        ]
    }

    /// Returns a floor of view two whose opening is the genesis record.
    fn floor(&self) -> Arc<Artifact<V, D>> {
        let Artifact::Lqc(lqc) = self.lqc.as_ref() else {
            unreachable!("the fixture L-QC is an L-QC");
        };
        Arc::new(Artifact::Floor(Floor::new(
            Arc::new(lqc.clone()),
            Arc::new(self.genesis_record()),
        )))
    }

    /// Returns the retention root of view one.
    fn root(&self) -> RetentionRoot<D> {
        RetentionRoot {
            vqc: CertificateId::new(Sha256::hash(&[b"root"])),
            record: self.genesis_record(),
        }
    }

    /// Returns a snapshot whose every durable field is populated.
    fn snapshot(&self) -> Snapshot<V, D> {
        let mut state = DurableState::new(self.genesis().tips().to_vec(), Height::zero());
        state.view = View::new(4);
        state.generation = Generation::new(2);
        state.cursor = Cursor::new(11);
        state.retired_view = View::new(1);
        state.root = Some(self.root());
        state.accepted[0].insert(
            Height::new(1),
            Acceptance::Adopted(self.signed_header().header().clone()),
        );
        state.produced = Height::new(1);
        state.leader_blocks.insert(
            View::new(2),
            (self.vqc.id::<Sha256>(), Sha256::hash(&[b"history"])),
        );
        state
            .notarised
            .insert(View::new(2), Sha256::hash(&[b"leader"]));
        state.watermark.insert(View::new(2), self.watermark());
        state.last_final = (View::new(2), self.watermark().tips);
        state.anchored_tag = Some(View::new(3));
        state.emission.insert(
            View::new(2),
            Emission {
                record: self.genesis_record(),
                by: Resolution::Determined,
            },
        );
        state
            .local
            .insert(self.update.id::<Sha256>(), Arc::clone(&self.update));
        state.signing_reservations.insert(
            EffectId::new(10),
            SignEffect::one(SignRequest::Update(self.update_request())),
        );
        state.outbox.insert(
            EffectId::new(9),
            OutboxEntry::new(
                Publication::Broadcast(Arc::from([
                    Arc::clone(&self.header),
                    Arc::clone(&self.update),
                ])),
                vec![
                    Discharge::new(
                        0,
                        DischargeKind::HeaderBelowHstar {
                            chain: ChainId::new(0),
                            height: Height::new(1),
                        },
                    ),
                    Discharge::new(
                        1,
                        DischargeKind::UpdateSuperseded {
                            view: View::new(2),
                            seq: 1,
                        },
                    ),
                ],
            ),
        );
        state.outbox.insert(
            EffectId::new(7),
            OutboxEntry::new(
                self.proposal(),
                vec![Discharge::new(
                    0,
                    DischargeKind::ViewUnread { view: View::new(2) },
                )],
            ),
        );
        state.forwarded_vqcs.insert(
            View::new(2),
            BTreeSet::from([
                self.vqc.id::<Sha256>(),
                CertificateId::new(Sha256::hash(&[b"x"])),
            ]),
        );
        state.exits.insert(View::new(2), self.vqc_artifact());
        state.exits.insert(View::new(3), Arc::clone(&self.lqc));
        state
            .ancestors
            .insert(self.vqc.id::<Sha256>(), self.vqc_artifact());
        Snapshot::new(
            self.committee.config.epoch(),
            Role::Validator(P::new(1)),
            state,
        )
    }

    fn event(&self, change: Change<V, D>) -> DomainEvent<V, D> {
        DomainEvent::new(self.committee.config.epoch(), Cursor::new(12), change)
    }

    fn decode_event(&self, bytes: impl Input) -> Result<DomainEvent<V, D>, Error> {
        DomainEvent::decode_cfg(bytes, &self.event_config())
    }

    fn decode_snapshot(&self, bytes: impl Input) -> Result<Snapshot<V, D>, Error> {
        Snapshot::decode_cfg(bytes, &self.snapshot_config())
    }
}

fn round_trips_every_change<V: Variant>() {
    let fixture = Fixture::<V>::new(1);
    for change in fixture.changes() {
        let event = fixture.event(change);
        let bytes = event.encode();
        assert_eq!(bytes.len(), event.encode_size());
        assert!(bytes.len() <= fixture.event_config().max_encoded_size::<D>());
        assert_eq!(fixture.decode_event(bytes.clone()).unwrap(), event);
    }
}

#[test]
fn every_change_round_trips_min_pk() {
    round_trips_every_change::<MinPk>();
}

#[test]
fn every_change_round_trips_min_sig() {
    round_trips_every_change::<MinSig>();
}

#[test]
fn snapshot_round_trips_every_state_field() {
    let fixture = Fixture::<MinSig>::new(2);
    let snapshot = fixture.snapshot();
    let bytes = snapshot.encode();
    assert_eq!(bytes.len(), snapshot.encode_size());
    assert_eq!(fixture.decode_snapshot(bytes).unwrap(), snapshot);

    let observer = Snapshot::new(
        snapshot.epoch(),
        Role::Observer,
        DurableState::new(fixture.genesis().tips().to_vec(), Height::zero()),
    );
    assert_eq!(
        fixture.decode_snapshot(observer.encode()).unwrap(),
        observer
    );

    // The field variants the full snapshot does not hold: a header accepted in full, a watermark
    // without declarations or a final vote, a pinned emission, and one reservation signing a
    // header and a leader block on the genesis V-QC.
    let mut variants = snapshot;
    let state = &mut variants.state;
    state.accepted[0].insert(Height::new(1), Acceptance::Full(fixture.signed_header()));
    state.watermark.insert(
        View::new(3),
        VoteWatermark {
            seq: 2,
            tips: fixture.genesis().tips().to_vec(),
            declared: ChainSet::empty(4),
            declared_at: Vec::new(),
            final_content: None,
        },
    );
    state.emission.insert(
        View::new(3),
        Emission {
            record: fixture.genesis_record(),
            by: Resolution::Pinned {
                view: View::new(4),
                lqc: CertificateId::new(Sha256::hash(&[b"lqc"])),
            },
        },
    );
    let leader = LeaderBlock::new(
        Round::new(fixture.committee.config.epoch(), View::new(4)),
        fixture.genesis().vqc(),
        fixture.genesis().history(),
    )
    .unwrap();
    state.signing_reservations.insert(
        EffectId::new(11),
        SignEffect::new(Arc::from([
            SignRequest::TransactionBlock(fixture.signed_header().header().clone()),
            SignRequest::LeaderBlock(Proposal::new(leader, ProposalParent::Genesis, true)),
        ])),
    );
    assert_eq!(
        fixture.decode_snapshot(variants.encode()).unwrap(),
        variants
    );
}

#[test]
fn change_tags_are_dense_and_unknown_tags_are_rejected() {
    let fixture = Fixture::<MinSig>::new(3);
    let mut tags = fixture
        .changes()
        .iter()
        .map(|change| change.encode()[0])
        .collect::<Vec<_>>();
    tags.dedup();
    assert_eq!(tags, (0..=9).collect::<Vec<u8>>());

    let event = fixture.event(Change::GenerationAdvanced(Generation::new(1)));
    let mut bytes = event.encode().to_vec();
    let tag = bytes.len() - event.change().encode_size();
    assert_eq!(bytes[tag], 0);
    bytes[tag] = 10;
    let decoded = fixture.decode_event(bytes.clone());
    assert!(
        matches!(decoded, Err(Error::InvalidEnum(10))),
        "{decoded:?}"
    );

    for (bytes, tag) in [(vec![4u8, 0], 4u8), (vec![2u8], 2)] {
        let decoded = if tag == 4 {
            DischargeKind::decode(bytes.clone()).map(|_| ())
        } else {
            Resolution::<D>::decode(bytes.clone()).map(|_| ())
        };
        assert!(matches!(decoded, Err(Error::InvalidEnum(found)) if found == tag));
    }
    assert!(matches!(
        Role::decode(vec![2u8]),
        Err(Error::InvalidEnum(2))
    ));
    assert!(matches!(
        SignRequest::<MinSig, D>::decode_cfg(vec![3u8], &fixture.event_config()),
        Err(Error::InvalidEnum(3))
    ));
    assert!(matches!(
        Publication::<MinSig, D>::decode_cfg(vec![2u8], &fixture.event_config()),
        Err(Error::InvalidEnum(2))
    ));
    assert!(matches!(
        DurableEffect::<MinSig, D>::decode_cfg(vec![2u8], &fixture.event_config()),
        Err(Error::InvalidEnum(2))
    ));
}

#[test]
fn rejects_other_schema_versions_and_trailing_bytes() {
    let fixture = Fixture::<MinSig>::new(4);
    let event = fixture.event(Change::GenerationAdvanced(Generation::new(1)));
    let mut bytes = event.encode().to_vec();
    bytes[0] = DURABILITY_SCHEMA_VERSION + 1;
    assert!(fixture.decode_event(bytes.clone()).is_err());
    bytes[0] = DURABILITY_SCHEMA_VERSION;
    bytes.push(0);
    assert!(fixture.decode_event(bytes.clone()).is_err());

    let mut snapshot = fixture.snapshot().encode().to_vec();
    snapshot[0] = DURABILITY_SCHEMA_VERSION + 1;
    assert!(fixture.decode_snapshot(snapshot.clone()).is_err());
    snapshot[0] = DURABILITY_SCHEMA_VERSION;
    snapshot.push(0);
    assert!(fixture.decode_snapshot(snapshot.clone()).is_err());
}

#[test]
fn event_bounds_reject_oversized_lists() {
    let fixture = Fixture::<MinSig>::new(5);
    let header = fixture.signed_header();
    let rejected = [
        Change::Accepted { blocks: Vec::new() },
        Change::Accepted {
            blocks: vec![Acceptance::Full(header); MAX_ACCEPTED + 1],
        },
        Change::ViewEntered {
            proof: fixture.vqc_artifact().id::<Sha256>(),
            ancestors: Vec::new(),
            retired_publications: (0..=MAX_RETIRED as u64).map(EffectId::new).collect(),
        },
        Change::ViewEntered {
            proof: fixture.lqc.id::<Sha256>(),
            ancestors: vec![fixture.vqc_artifact(); MAX_ANCESTORS + 1],
            retired_publications: Vec::new(),
        },
        Change::Anchored {
            floor: fixture.floor(),
            retired_signing: (0..=MAX_RETIRED as u64).map(EffectId::new).collect(),
            retired_publications: Vec::new(),
        },
        Change::SignedArtifacts {
            sign: EffectId::new(1),
            publication: EffectId::new(2),
            artifacts: Arc::from(vec![Arc::clone(&fixture.update); MAX_BATCH_ARTIFACTS + 1]),
        },
        Change::SignedArtifacts {
            sign: EffectId::new(1),
            publication: EffectId::new(2),
            artifacts: Arc::from(Vec::new()),
        },
        Change::EmissionResolved {
            view: View::new(2),
            record: HistoryRecord::new(
                fixture.genesis().history(),
                fixture.genesis().tips()[..1].to_vec(),
            )
            .unwrap(),
            by: Resolution::Determined,
        },
    ];
    for change in rejected {
        let bytes = fixture.event(change).encode();
        assert!(fixture.decode_event(bytes.clone()).is_err());
    }

    // An artifact above the byte ceiling is rejected after decoding.
    let tight = DomainEventCodecConfig::new(
        fixture.committee.codec(),
        fixture.lqc.encoded_len() - 1,
        MAX_RETIRED,
        MAX_ACCEPTED,
        MAX_ANCESTORS,
    );
    let bytes = fixture
        .event(Change::CertificateCreated {
            artifact: Arc::clone(&fixture.lqc),
        })
        .encode();
    assert!(DomainEvent::<MinSig, D>::decode_cfg(bytes, &tight).is_err());
}

#[test]
fn outbox_discharges_are_bounded_by_publication_items() {
    let fixture = Fixture::<MinSig>::new(6);
    let discharge = Discharge::new(0, DischargeKind::ViewUnread { view: View::new(2) });
    let entry = OutboxEntry::new(fixture.proposal(), vec![discharge, discharge]);
    assert!(OutboxEntry::<MinSig, D>::decode_cfg(entry.encode(), &fixture.event_config()).is_err());
    let entry = OutboxEntry::new(fixture.proposal(), Vec::new());
    assert!(OutboxEntry::<MinSig, D>::decode_cfg(entry.encode(), &fixture.event_config()).is_err());
}

#[test]
fn watermark_declaration_heights_match_declared_chains() {
    let fixture = Fixture::<MinSig>::new(7);
    let config = fixture.event_config();
    let watermark = fixture.watermark();
    assert_eq!(
        VoteWatermark::<D>::decode_cfg(watermark.encode(), &config).unwrap(),
        watermark
    );
    for declared_at in [Vec::new(), vec![Height::new(1); 2]] {
        let malformed = VoteWatermark {
            declared_at,
            ..watermark.clone()
        };
        assert!(VoteWatermark::<D>::decode_cfg(malformed.encode(), &config).is_err());
    }
    let short = VoteWatermark {
        tips: watermark.tips[1..].to_vec(),
        ..watermark
    };
    assert!(VoteWatermark::<D>::decode_cfg(short.encode(), &config).is_err());
}

#[test]
fn snapshot_bounds_reject_oversized_state() {
    let fixture = Fixture::<MinSig>::new(8);
    let config = fixture.snapshot_config();
    let snapshot = fixture.snapshot();

    // Forwarded certificates are bounded in total, not only per view.
    let mut forwarded = snapshot.clone();
    forwarded.state.forwarded_vqcs.insert(
        View::new(3),
        BTreeSet::from([
            CertificateId::new(Sha256::hash(&[b"y"])),
            CertificateId::new(Sha256::hash(&[b"z"])),
        ]),
    );
    assert!(fixture.decode_snapshot(forwarded.encode()).is_err());

    // An empty forwarded set is not canonical.
    let mut empty = snapshot.clone();
    empty
        .state
        .forwarded_vqcs
        .insert(View::new(3), BTreeSet::new());
    assert!(fixture.decode_snapshot(empty.encode()).is_err());

    // Signing reservations and publications share one outbox bound.
    let mut outbox = snapshot.clone();
    for id in 20..27 {
        outbox.state.signing_reservations.insert(
            EffectId::new(id),
            SignEffect::one(SignRequest::Update(fixture.update_request())),
        );
    }
    assert!(fixture.decode_snapshot(outbox.encode()).is_err());

    // Every chain holds one accepted map.
    let mut chains = snapshot.clone();
    chains.state.accepted.pop();
    assert!(fixture.decode_snapshot(chains.encode()).is_err());

    // Each per-view map is bounded by the artifact cache.
    let mut views = snapshot;
    for view in 10..=(10 + 16) {
        views
            .state
            .notarised
            .insert(View::new(view), Sha256::hash(&[b"leader"]));
    }
    assert!(Snapshot::<MinSig, D>::decode_cfg(views.encode(), &config).is_err());
}

#[cfg(feature = "arbitrary")]
mod conformance {
    use super::*;
    use commonware_conformance::Conformance;

    /// Encodes one event of every change kind, each holding the seed committee's real artifacts.
    fn event_bytes<V: Variant>(seed: u64) -> Vec<u8> {
        let fixture = Fixture::<V>::new(seed);
        let mut bytes = Vec::new();
        for change in fixture.changes() {
            let event = fixture.event(change);
            let encoded = event.encode();
            assert_eq!(fixture.decode_event(encoded.clone()).unwrap(), event);
            bytes.extend_from_slice(&encoded);
        }
        bytes
    }

    /// Encodes a snapshot of the seed committee whose every durable field is populated.
    fn snapshot_bytes<V: Variant>(seed: u64) -> Vec<u8> {
        let fixture = Fixture::<V>::new(seed);
        let snapshot = fixture.snapshot();
        let encoded = snapshot.encode();
        assert_eq!(fixture.decode_snapshot(encoded.clone()).unwrap(), snapshot);
        encoded.to_vec()
    }

    struct EventMinPkConformance;
    struct EventMinSigConformance;
    struct SnapshotMinPkConformance;
    struct SnapshotMinSigConformance;

    impl Conformance for EventMinPkConformance {
        async fn commit(seed: u64) -> Vec<u8> {
            event_bytes::<MinPk>(seed)
        }
    }

    impl Conformance for EventMinSigConformance {
        async fn commit(seed: u64) -> Vec<u8> {
            event_bytes::<MinSig>(seed)
        }
    }

    impl Conformance for SnapshotMinPkConformance {
        async fn commit(seed: u64) -> Vec<u8> {
            snapshot_bytes::<MinPk>(seed)
        }
    }

    impl Conformance for SnapshotMinSigConformance {
        async fn commit(seed: u64) -> Vec<u8> {
            snapshot_bytes::<MinSig>(seed)
        }
    }

    commonware_conformance::conformance_tests! {
        EventMinPkConformance => 8,
        EventMinSigConformance => 8,
        SnapshotMinPkConformance => 8,
        SnapshotMinSigConformance => 8,
    }
}
