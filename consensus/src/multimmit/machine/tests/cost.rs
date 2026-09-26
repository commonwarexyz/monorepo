//! Hashing and completion cost regression tests.

use super::fixtures::{
    CountingHasher, Harness, TEST_RESOURCES, TestConfig, attestation, digest, leader, lqc,
    retention_for, threshold_share, view_one_vqc, view_vote, vqc,
};
use crate::{
    Epochable as _,
    multimmit::{
        algebra::{CertificateDerivations, DerivedVqc, validate_vqc},
        config::{Profile, ResourceLimits, Role, Tuning},
        machine::{
            capability::{Capability, CryptoJob},
            durability::{
                DomainEventCodecConfig, DurableEffect, EffectCompletion, PersistDirective,
                SignEffect, SignRequest,
            },
            finality::FinalityState,
            input::{CryptoCompletion, Input},
            reducer::machine::Machine,
            scheduler,
            testing::{
                CapabilitiesExt as _, CapabilityExt as _, Drive as _, Driver, EffectExt,
                MachineExt as _, SymbolicPersistence, SymbolicVerifier, Until, cohort,
            },
            verification::Observation,
            view::{ViewState, VqcAggregateCompletion},
        },
        types::{
            Artifact, ChainId, ChainProposal, DaVote, DigestedLeader, Extension, LeaderBlock,
            Position, SignedLeaderBlock, SignedTransactionBlock, TransactionBlockHeader,
            ViewMessage, Vote, VoteBody,
        },
    },
    types::{Height, Participant, View},
};
use commonware_codec::{Decode, Encode};
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk, sha256::Digest};
use core::{num::NonZeroUsize, time::Duration};
use std::sync::Arc;

#[test]
fn vqc_parent_hashes_each_large_value_once() {
    let machine = Machine::new(Harness::observer().participants(6).depth(4).profile());
    let parent = Arc::new(Artifact::Vqc(view_one_vqc(&machine)));
    let resources = TEST_RESOURCES;
    let profile = Harness::observer()
        .participants(6)
        .depth(4)
        .resources(resources)
        .profile_with_hasher::<CountingHasher>();
    let mut views = ViewState::new::<Sha256>(&profile);

    CountingHasher::reset();
    let id = views.retain_vqc_parent::<CountingHasher>(&parent).unwrap();
    // The third hash is the history commitment a child proposal names, which validation derives
    // once so proposal checks never recompute it.
    assert_eq!(
        CountingHasher::count(),
        3,
        "parent retention should hash the certificate, leader, and child history once each"
    );

    CountingHasher::reset();
    assert_eq!(
        views
            .retain_vqc_parent::<CountingHasher>(&Arc::clone(&parent))
            .unwrap(),
        id
    );
    assert_eq!(CountingHasher::count(), 0);

    let decoded = Arc::new(
        Artifact::decode_cfg(
            parent.encode(),
            &DomainEventCodecConfig::from_profile(&profile),
        )
        .unwrap(),
    );
    assert_eq!(decoded, parent);
    assert!(!Arc::ptr_eq(&decoded, &parent));
    CountingHasher::reset();
    assert_eq!(
        views.retain_vqc_parent::<CountingHasher>(&decoded).unwrap(),
        id
    );
    assert_eq!(CountingHasher::count(), 3);

    assert_eq!(views.retire_parents_through(View::new(2), None), [id]);
    CountingHasher::reset();
    assert_eq!(
        views.retain_vqc_parent::<CountingHasher>(&parent).unwrap(),
        id
    );
    assert_eq!(CountingHasher::count(), 3);

    let proposed = leader(&machine, 1);
    let messages = (0..5)
        .map(|signer| ViewMessage::Vote(view_vote(&machine, &proposed, signer)))
        .collect::<Vec<_>>();
    let other = Arc::new(Artifact::Vqc(vqc(&machine, proposed, &messages)));
    CountingHasher::reset();
    let other_id = views.retain_vqc_parent::<CountingHasher>(&other).unwrap();
    assert_ne!(other_id, id);
    assert_eq!(CountingHasher::count(), 3);
    assert_eq!(views.retained_parents(), 3);
}

#[test]
fn verified_lqc_reuses_its_exact_parent_projection() {
    let source = Machine::new(Harness::observer().participants(6).depth(4).profile());
    let block = leader(&source, 1);
    let votes = (0..5)
        .map(|signer| view_vote(&source, &block, signer))
        .collect::<Vec<_>>();
    let certificate = lqc(&source, block, &votes);
    let projection =
        DerivedVqc::from_lqc::<CountingHasher>(&certificate, source.profile.codec()).unwrap();
    let expected = Arc::clone(projection.artifact.arc());
    let proof = Arc::new(Artifact::Lqc(certificate));
    let profile = Profile::new::<MinPk>(
        TestConfig::new(6).depth(4).build(),
        Role::Observer,
        Tuning::default(),
    )
    .unwrap();
    let mut machine = Machine::<CountingHasher, MinPk>::new(profile);

    CountingHasher::reset();
    machine
        .apply_finality(Observation::new(1, 0), Arc::clone(&proof), Some(projection))
        .unwrap();
    assert_eq!(CountingHasher::count(), 0);
    let projection = machine.finality.finality_anchor(&proof).unwrap();
    assert!(Arc::ptr_eq(projection.artifact.arc(), &expected));
    assert!(
        machine
            .finality
            .finality_anchor(&Arc::new(proof.as_ref().clone()))
            .is_none()
    );
    let forwarded = machine.views.next_forward().unwrap();
    assert!(Arc::ptr_eq(&forwarded, &expected));
}

#[test]
fn verified_vqc_reuses_validation_derivations() {
    let machine = Machine::new(Harness::observer().participants(6).depth(4).profile());
    let parent = Arc::new(Artifact::Vqc(view_one_vqc(&machine)));
    let resources = TEST_RESOURCES;
    let profile = Harness::observer()
        .participants(6)
        .depth(4)
        .resources(resources)
        .profile_with_hasher::<CountingHasher>();
    let mut views = ViewState::new::<Sha256>(&profile);
    let Artifact::Vqc(certificate) = parent.as_ref() else {
        unreachable!();
    };
    let validated =
        validate_vqc::<CountingHasher, MinPk, Digest>(certificate, profile.codec()).unwrap();
    let artifact_id = parent.id::<CountingHasher>();

    CountingHasher::reset();
    views
        .observe::<CountingHasher>(
            artifact_id,
            Observation::new(1, 0),
            &parent,
            Some(validated),
        )
        .unwrap();
    assert_eq!(
        CountingHasher::count(),
        0,
        "ready V-QC observation should reuse off-thread validation derivations"
    );
    views.retain_vqc_parent::<CountingHasher>(&parent).unwrap();
    assert_eq!(
        CountingHasher::count(),
        0,
        "anchor installation should reuse the observed certificate's validated parent"
    );
}

/// Counts the hashes one signed data-availability batch transition performs.
fn signed_batch_hash_calls(batch_items: usize) -> usize {
    let profile: Profile<Digest> = Profile::new::<MinPk>(
        TestConfig::new(scheduler::CORE_BUDGET as usize)
            .depth(1)
            .build(),
        Role::Validator(Participant::new(0)),
        Tuning {
            max_artifact_bytes: NonZeroUsize::new(4 * 1024 * 1024),
            ..Tuning::default()
        },
    )
    .unwrap();
    let mut machine = Machine::<CountingHasher, MinPk>::new(profile);
    let mut step = machine.step(Input::Start).unwrap();
    loop {
        let jobs = step
            .capabilities()
            .iter()
            .filter_map(|effect| match effect {
                Capability::Journal(PersistDirective { job, .. }) => Some(job.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        if jobs.is_empty() {
            break;
        }
        for job in jobs {
            step = machine.step(Input::Persisted(job.ack())).unwrap();
        }
    }

    let mut requests = Vec::with_capacity(batch_items);
    let mut artifacts = Vec::with_capacity(batch_items);
    for chain in 0..batch_items {
        let genesis = machine.profile().protocol().genesis().tips()[chain];
        let header = TransactionBlockHeader::new(
            machine.profile().protocol().epoch(),
            ChainId::new(chain as u32),
            Height::new(1),
            genesis.digest(),
            digest(format!("signed batch identity {chain}").as_bytes()),
        )
        .unwrap();
        let block = Arc::new(SignedTransactionBlock::new(
            header.clone(),
            attestation(chain as u32),
        ));
        requests.push(SignRequest::DaVote(block));
        artifacts.push(Artifact::DaVote(DaVote::new(header, threshold_share(0))));
    }
    let reserved = machine
        .reserve_test_effect(DurableEffect::Sign(SignEffect::new(requests.into())))
        .unwrap();
    let signing = reserved
        .find(|effect| match effect {
            Capability::Released(job)
                if matches!(job.request().sign_many(), Some(requests)
                    if requests.len() == batch_items) =>
            {
                Some(job.clone())
            }
            _ => None,
        })
        .expect("the signing batch must be issued");

    CountingHasher::reset();
    machine
        .step(Input::EffectCompleted(EffectCompletion::signed(
            signing.issued(),
            artifacts.iter().cloned().map(Arc::new).collect(),
        )))
        .unwrap();
    // The completion stages the batch; the durable transition that identifies every artifact
    // runs in the machine-owned work that follows, so both belong in the measured window.
    for _ in 0..1_000 {
        machine.poll(NonZeroUsize::MAX).unwrap();
        if !machine.work_remaining() {
            break;
        }
    }
    CountingHasher::count()
}

/// A signed data-availability batch must identify each artifact once.
///
/// Identification encodes the vote, and a locally created share re-serializes its BLS point on
/// every encode, so the batch's marginal per-artifact hash count is the guard against the
/// transition re-deriving identifiers it already holds.
#[test]
fn signed_batch_identifies_each_artifact_once() {
    let two = signed_batch_hash_calls(2);
    let three = signed_batch_hash_calls(3);
    let six = signed_batch_hash_calls(6);
    let marginal = three - two;

    assert_eq!(
        six - two,
        marginal * 4,
        "the batch transition must cost a fixed amount per artifact"
    );
    assert_eq!(
        marginal, 4,
        "each batch artifact costs a fixed number of hashes through the durable transition"
    );
}

/// Measures serial local V-QC admission, excluding fixture setup and worker preparation.
/// Counts the hashes the core performs completing one locally aggregated V-QC.
fn local_vqc_completion_hashes(participants: usize, payloads: u32, extensions: u32) -> usize {
    let resources = ResourceLimits::new(
        NonZeroUsize::new(16 * 1024 * 1024).unwrap(),
        NonZeroUsize::new(128).unwrap(),
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(4).unwrap(),
        2,
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(128).unwrap(),
        NonZeroUsize::new(64).unwrap(),
    );
    let pipeline_depth = payloads.div_ceil(participants as u32).max(2);
    let extension_bound = extensions.div_ceil(participants as u32).max(1);
    let protocol = TestConfig::new(participants)
        .depth(pipeline_depth)
        .extensions(extension_bound)
        .build();
    let tuning = Tuning {
        view_timeout: Duration::from_secs(1),
        production_interval: Duration::from_millis(100),
        view_retention: retention_for(resources, participants),
        ..Tuning::default()
    };
    let source = Machine::<Sha256, MinPk>::new(
        Profile::with_limits(protocol.clone(), Role::Observer, tuning, resources).unwrap(),
    );
    let codec = protocol.codec_config();
    let empty = leader(&source, 1);
    let proposed = LeaderBlock::new(
        empty.round(),
        empty.parent(),
        empty.history(),
        empty
            .proposals()
            .iter()
            .map(|proposal| {
                let chain = proposal.anchor().chain();
                ChainProposal::new(
                    chain,
                    proposal.anchor().clone(),
                    (0..payloads)
                        .filter(|index| *index as usize % participants == chain.get() as usize)
                        .map(|index| digest(format!("proposal {index}").as_bytes()))
                        .collect(),
                    codec.pipeline_depth(),
                )
                .unwrap()
            })
            .collect(),
        codec,
    )
    .unwrap();
    let body = VoteBody::for_leader(
        DigestedLeader::new::<Sha256>(&proposed),
        proposed
            .proposals()
            .iter()
            .map(|proposal| Position::new(proposal.len() as u32))
            .collect(),
        (0..codec.chains())
            .map(|chain| {
                Extension::new(
                    (0..extensions)
                        .filter(|index| *index as usize % participants == chain)
                        .map(|index| digest(format!("extension {index}").as_bytes()))
                        .collect(),
                    codec.extension_bound(),
                )
                .unwrap()
            })
            .collect(),
        codec,
    )
    .unwrap();
    let profile = Profile::with_limits(protocol, Role::Observer, tuning, resources).unwrap();
    let mut runner = Driver::<CountingHasher, MinPk>::new(profile);
    let start = runner.submit(Input::Start).unwrap();
    runner.drain(
        &mut SymbolicPersistence,
        start.into_capabilities(),
        Until::Step,
    );
    let artifacts = std::iter::once(Artifact::LeaderBlock(SignedLeaderBlock::new(
        proposed.clone(),
        attestation(0),
    )))
    .chain(
        (0..codec.view_quorum())
            .map(|signer| Artifact::Vote(Vote::new(body.clone(), attestation(signer as u32)))),
    );
    let mut aggregate = None;
    for artifact in artifacts {
        let observed = runner
            .submit(cohort::<CountingHasher, _>(vec![artifact]))
            .unwrap();
        let verified = runner.drain(
            &mut SymbolicVerifier::new(true),
            observed.into_capabilities(),
            Until::Step,
        );
        let effects = runner.drain(&mut SymbolicPersistence, verified, Until::Step);
        for effect in effects {
            if let Capability::Crypto(CryptoJob::AggregateVqc(job)) = effect {
                assert!(aggregate.replace(job).is_none());
            }
        }
    }
    let aggregate = aggregate.expect("a unanimous transcript reserves a view certificate");
    let certificate = vqc(&source, proposed, &aggregate.messages().collect::<Vec<_>>());
    let id = Artifact::Vqc(certificate.clone()).id::<Sha256>();
    let completion =
        VqcAggregateCompletion::prepare::<CountingHasher>(&aggregate, certificate, codec).unwrap();
    CountingHasher::reset();
    let submitted = runner
        .submit(Input::Crypto(CryptoCompletion::Vqc(Box::new(completion))))
        .unwrap();
    let completed = runner.settle(submitted, Until::Quiesce);
    let calls = CountingHasher::count();
    assert!(runner.machine().durable.state.local.contains_key(&id));
    assert!(completed.has(Capability::is_journal));
    calls
}

// Host-time measurements of this completion at deployment scale are the
// `vqc_completion` machine benchmarks.
#[test]
fn local_vqc_serial_completion_cost() {
    let calls = local_vqc_completion_hashes(6, 0, 0);
    assert_eq!(
        local_vqc_completion_hashes(6, 0, 0),
        calls,
        "completion hashing is deterministic"
    );
    assert!(
        calls < 28,
        "worker preparation must reduce serial certificate hashing"
    );
}

/// Counts the hashes a verified V-QC claim performs through its finality lifecycle.
fn vqc_finality_hash_calls(with_derivations: bool) -> usize {
    let machine = Machine::new(Harness::observer().participants(6).depth(4).profile());
    let certificate = view_one_vqc(&machine);
    let artifact = Arc::new(Artifact::Vqc(certificate.clone()));
    let resources = TEST_RESOURCES;
    let profile = Harness::observer()
        .participants(6)
        .depth(4)
        .resources(resources)
        .profile_with_hasher::<CountingHasher>();
    let mut finality = FinalityState::new(&profile);
    let id = artifact.id::<Sha256>();
    let observation = Observation::new(1, 0);
    finality
        .claim_finality::<CountingHasher>(id, observation, Arc::clone(&artifact), &profile)
        .unwrap();
    let derivations = with_derivations.then(|| {
        let mut validated =
            validate_vqc::<CountingHasher, MinPk, Digest>(&certificate, profile.codec()).unwrap();
        CertificateDerivations::Vqc {
            leader: validated.leader(),
            votes: validated.take_votes(),
        }
    });

    CountingHasher::reset();
    finality
        .validate_finality_claim::<CountingHasher>(
            id,
            observation,
            &artifact,
            &profile,
            derivations,
        )
        .unwrap();
    CountingHasher::count()
}

/// A verified V-QC must not re-encode its leader block on the control thread.
///
/// The compute pool derives the designated leader digest while it validates the certificate, and
/// the claim lifecycle visits every tallied signer three times, so recomputing the digest per
/// visit would re-encode a whole leader block on each pass.
#[test]
fn verified_vqc_finality_reuses_the_derived_leader_digest() {
    let derived = vqc_finality_hash_calls(true);
    let recomputed = vqc_finality_hash_calls(false);

    assert_eq!(
        derived, 1,
        "a derived certificate must only hash its new pool's proposal paths"
    );
    assert!(
        recomputed > derived,
        "the recovery path derives the digests the compute pool would have supplied"
    );
}
