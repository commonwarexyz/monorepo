//! The persistence pipeline, release ordering, generations, and completion correlation.

use crate::{
    multimmit::{
        config::Role,
        machine::{
            capability::{AggregateId, BuildId, Capability},
            durability::{
                Change, ChangeKind, DurableEffect, ReplayError, SignRequest, TransitionReason,
            },
            input::{
                Aggregated, BlockValidity, BuildCompletion, CryptoCompletion, Input,
                ObservationStatus, Rejection, StepError, StepStatus, TimerFamily,
                ValidationCompletion,
            },
            job::{Generation, Issued, SequenceId as _},
            reducer::{MAX_INFLIGHT_BARRIERS, MAX_STAGED_BARRIERS},
            testing::{
                CapabilitiesExt as _, Drive as _, DriverError, Execution, Executor as _,
                MachineExt as _, SymbolicSigner, SymbolicVerifier, Until, cohort,
                fixtures::{
                    TestDriver, built_body, committee, digest, produce, profile, started, validator,
                },
            },
            verification::VerificationCompletion,
        },
        mocks::Committee,
        types::{Activity, Artifact},
    },
    types::View,
};
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk, sha256::Digest};
use std::{collections::VecDeque, sync::Arc};

/// Returns a broadcast of `committee`'s V-QC for `view`, which any node may publish.
fn broadcast(committee: &Committee<MinPk>, view: u64) -> DurableEffect<MinPk, Digest> {
    DurableEffect::broadcast(Arc::new(Artifact::Vqc(committee.vqc(View::new(view)))))
}

#[test]
fn the_generation_is_durable_before_anything_is_released() {
    let committee = committee(1);
    let mut driver = TestDriver::new(profile(&committee, validator(0)));
    let start = driver.submit(Input::Start).unwrap();
    let job = start.persist_job();
    assert!(job.urgent(), "a generation barrier syncs at once");
    assert!(matches!(
        job.events(),
        [event] if *event.change() == Change::GenerationAdvanced(Generation::new(1))
    ));
    assert!(start.released().is_empty());

    // An effect queued before the generation is durable waits for it, and its batch waits behind
    // the in-flight generation barrier.
    let reserved = driver
        .machine_mut()
        .reserve_test_effect(broadcast(&committee, 1))
        .unwrap();
    driver.record(reserved.capabilities());
    assert!(reserved.released().is_empty());
    assert!(reserved.journals().is_empty());

    let acknowledged = driver.persist(&job, Until::Step);
    assert_eq!(acknowledged.released_publications().len(), 1);
    assert_eq!(acknowledged.journals().len(), 1, "the queued batch follows");
}

#[test]
fn barriers_are_bounded_and_acknowledged_in_order() {
    let committee = committee(2);
    let mut driver = started(&committee, Role::Observer);
    let mut emitted = Vec::new();
    let refused = loop {
        match driver
            .machine_mut()
            .reserve_test_effect(broadcast(&committee, 1))
        {
            Ok(step) => {
                driver.record(step.capabilities());
                emitted.extend(
                    step.journals()
                        .into_iter()
                        .map(|journal| journal.job.clone()),
                );
            }
            Err(error) => break error,
        }
    };
    assert_eq!(refused, StepError::PersistenceCapacity);
    assert!(!driver.machine().has_persistence_capacity());
    assert_eq!(
        emitted.len(),
        MAX_INFLIGHT_BARRIERS,
        "full batches stop at the in-flight bound"
    );
    assert_eq!(driver.machine().pipeline.staged.len(), MAX_STAGED_BARRIERS);

    // Acknowledgements arrive in barrier order only.
    let now = driver.now();
    assert_eq!(
        driver
            .machine_mut()
            .step(Input::Persisted(emitted[1].ack()), now)
            .unwrap_err(),
        StepError::CompletionMismatch
    );
    let first = driver.persist(&emitted[0], Until::Step);
    let next = first.persist_job();
    assert_eq!(
        next.previous(),
        emitted[3].last_cursor(),
        "the next batch follows the pipeline"
    );
    assert!(driver.machine().has_persistence_capacity());
    // A repeated acknowledgement of the newest applied barrier is stale.
    assert_eq!(
        driver
            .submit(Input::Persisted(emitted[0].ack()))
            .unwrap()
            .status(),
        &StepStatus::StaleCompletion
    );

    // Each acknowledgement hands at most the next batch to the journal, in cursor order.
    let mut pending = emitted[1..]
        .iter()
        .cloned()
        .chain([next])
        .collect::<VecDeque<_>>();
    while let Some(job) = pending.pop_front() {
        let step = driver.persist(&job, Until::Step);
        pending.extend(
            step.journals()
                .into_iter()
                .map(|journal| journal.job.clone()),
        );
    }
    assert!(driver.machine().pipeline.staged.is_empty());
    assert!(driver.machine().checkpoint_cut().is_some());
}

#[test]
fn a_signed_header_is_published_only_after_its_record_is_durable() {
    let committee = committee(3);
    let mut driver = started(&committee, validator(0));
    let genesis = committee.genesis().tips()[0];
    let header = committee.header(&genesis, built_body(genesis.digest()));

    // The reservation advances the signing slot when it stages, before anything is signed.
    let reserved = produce(&mut driver);
    assert_eq!(driver.machine().durable.state.produced.get(), 1);
    let [sign] = reserved.released_signing()[..] else {
        panic!("the signing request releases at staging");
    };
    let sign = Capability::Released(sign.clone());
    driver.persist(&reserved.persist_job(), Until::Step);

    let mut signer = SymbolicSigner::new(committee.signers[0].clone());
    let signed = driver
        .execute(&mut signer, &sign)
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(matches!(
        signed.activities.as_slice(),
        [Activity::TransactionProposed { block, .. }] if *block == header.block_ref::<Sha256>()
    ));
    let staged = driver.settle(signed, Until::Persist);
    let job = staged.persist_job();
    assert!(job.urgent(), "a fresh signature syncs at once");
    assert!(matches!(
        job.events(),
        [event] if matches!(event.change(), Change::SignedArtifacts { .. })
    ));
    assert!(
        staged.released().is_empty(),
        "the signature waits for its record"
    );

    let acknowledged = driver.persist(&job, Until::Step);
    let [publication] = acknowledged.released_publications()[..] else {
        panic!("the acknowledgement releases the publication");
    };
    let DurableEffect::Publish(publication) = publication.request() else {
        unreachable!("a released publication publishes");
    };
    assert!(matches!(
        publication.artifacts(),
        [artifact] if matches!(artifact.as_ref(), Artifact::TransactionBlock(block) if block.header() == &header)
    ));
}

#[test]
fn a_forwarded_certificate_is_served_only_once_every_local_signature_is_durable() {
    let committee = committee(5);
    let mut driver = started(&committee, validator(0));
    let reserved = produce(&mut driver);
    let [sign] = reserved.released_signing()[..] else {
        panic!("the signing request releases at staging");
    };
    let sign = Capability::Released(sign.clone());
    driver.persist(&reserved.persist_job(), Until::Step);
    let mut signer = SymbolicSigner::new(committee.signers[0].clone());
    let signed = driver
        .execute(&mut signer, &sign)
        .unwrap()
        .unwrap()
        .unwrap();
    let signature = driver.settle(signed, Until::Persist).persist_job();

    // The certificate may aggregate the signature still in flight, so neither its journal batch
    // nor resolver custody serves it until that signature is durable.
    let vqc = Arc::new(Artifact::Vqc(committee.vqc(View::new(1))));
    let change = driver.machine().forwarding(Arc::clone(&vqc)).unwrap();
    let forwarded = driver.machine_mut().stage_test_change(change).unwrap();
    driver.record(forwarded.capabilities());
    let retained = |capabilities: &[Capability<MinPk, Digest>]| {
        capabilities.iter().any(
            |capability| matches!(capability, Capability::Retain(artifact) if *artifact == vqc),
        )
    };
    assert!(!retained(forwarded.capabilities()));
    assert!(
        driver
            .machine()
            .pipeline
            .staged
            .iter()
            .all(|batch| !batch.staged_retention.contains(&vqc))
    );

    let acknowledged = driver.persist(&signature, Until::Step);
    assert!(retained(acknowledged.capabilities()));
}

#[test]
fn a_signing_slot_is_reserved_once_and_survives_only_durably() {
    let committee = committee(4);
    let mut driver = started(&committee, validator(0));
    let genesis = committee.genesis().tips()[0];
    let request = || {
        DurableEffect::sign(SignRequest::TransactionBlock(
            committee.header(&genesis, digest(b"body")),
        ))
    };

    // A reservation whose barrier never reached the journal is forgotten by a crash.
    let reserved = driver.machine_mut().reserve_test_effect(request()).unwrap();
    driver.record(reserved.capabilities());
    let recovered = driver.crash_and_restore().unwrap();
    assert!(driver.inspect().outbox().is_empty());
    assert_eq!(driver.machine().durable.state.produced.get(), 0);
    driver.persist(&recovered.persist_job(), Until::Step);

    // An appended reservation survives, and only its release is repeated after recovery.
    let reserved = driver.machine_mut().reserve_test_effect(request()).unwrap();
    driver.record(reserved.capabilities());
    let id = reserved.released_signing()[0].issued().id();
    assert_eq!(
        driver
            .machine_mut()
            .reserve_test_effect(request())
            .unwrap_err(),
        StepError::DurableTransition {
            change: ChangeKind::OutboxQueued,
            source: ReplayError::Transition(TransitionReason::ProducerHeight),
        },
        "one header per height"
    );
    driver.append(&reserved.persist_job()).unwrap();
    let recovered = driver.crash_and_restore().unwrap();
    assert!(
        recovered.released().is_empty(),
        "nothing leaves before the generation is durable"
    );
    let acknowledged = driver.persist(&recovered.persist_job(), Until::Step);
    let [released] = acknowledged.released_signing()[..] else {
        panic!("the recovered reservation is released again");
    };
    assert_eq!(released.issued().id(), id);
    assert_eq!(released.issued().generation(), Generation::new(3));
}

#[test]
fn completions_of_an_earlier_generation_are_stale() {
    let committee = committee(5);
    let mut driver = started(&committee, validator(0));
    let observed = driver
        .submit(cohort::<Sha256, _>(vec![Artifact::Vqc(
            committee.vqc(View::new(1)),
        )]))
        .unwrap();
    let verify = observed.verify_job();
    let genesis = committee.genesis().tips()[0];
    let reserved = driver
        .machine_mut()
        .reserve_test_effect(DurableEffect::sign(SignRequest::TransactionBlock(
            committee.header(&genesis, digest(b"body")),
        )))
        .unwrap();
    driver.record(reserved.capabilities());
    let sign = Capability::Released(reserved.released_signing()[0].clone());
    driver.persist(&reserved.persist_job(), Until::Step);

    let old = driver.machine().generation();
    let mut signer = SymbolicSigner::new(committee.signers[0].clone());
    let Some(Execution::Input(stale_signature)) = signer.execute(&sign, old) else {
        unreachable!("signing completes at once");
    };

    let recovered = driver.crash_and_restore().unwrap();
    let acknowledged = driver.persist(&recovered.persist_job(), Until::Step);
    assert_ne!(driver.machine().generation(), old);

    let vqc = committee.vqc(View::new(1));
    let stale = [
        Input::Verified(SymbolicVerifier::new(true).complete(&verify)),
        stale_signature,
        Input::Crypto(CryptoCompletion::Vqc(Box::new(Aggregated::new(
            Issued::new(AggregateId::at(0), old),
            vqc,
        )))),
        Input::Validated(ValidationCompletion::new(
            old,
            genesis,
            BlockValidity::Valid,
        )),
        Input::BlockBuilt(BuildCompletion::new(
            Issued::new(BuildId::at(0), old),
            genesis,
            None,
        )),
    ];
    for input in stale {
        assert_eq!(
            driver.submit(input).unwrap().status(),
            &StepStatus::StaleCompletion
        );
    }

    // The same signature completes the request released under the current generation.
    let released = Capability::Released(acknowledged.released_signing()[0].clone());
    let signed = driver
        .execute(&mut signer, &released)
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(signed.status(), &StepStatus::Accepted);
}

#[test]
fn verification_correlates_tickets_and_drops_invalid_artifacts() {
    let committee = committee(6);
    let mut driver = started(&committee, Role::Observer);
    let artifacts = vec![
        Artifact::Vqc(committee.vqc(View::new(1))),
        Artifact::Vqc(committee.vqc(View::new(2))),
    ];
    let observed = driver.submit(cohort::<Sha256, _>(artifacts)).unwrap();
    let job = observed.verify_job();
    assert_eq!(driver.inspect().pending_artifacts(), 2);

    let completion = SymbolicVerifier::new(false).complete(&job);
    let reordered = VerificationCompletion::new(
        completion.issued(),
        completion.verdicts().iter().rev().copied().collect(),
    );
    assert!(matches!(
        driver.submit(Input::Verified(reordered)),
        Err(DriverError::Step(StepError::CompletionMismatch))
    ));
    let verified = driver.submit(Input::Verified(completion)).unwrap();
    assert_eq!(
        verified.status(),
        &StepStatus::Verified {
            valid: 0,
            invalid: 2
        }
    );
    assert_eq!(driver.inspect().cached_artifacts(), 0);

    // A verdict for a completed job is stale.
    let again = driver.verify(&job, false, Until::Step);
    assert_eq!(again.status(), &StepStatus::StaleCompletion);
}

#[test]
fn observation_applies_the_generic_bounds() {
    let (committee, other) = (committee(7), committee(8));
    let mut driver = started(&committee, Role::Observer);
    let vqc = Artifact::Vqc(committee.vqc(View::new(1)));
    let horizon = driver
        .machine()
        .profile()
        .resources()
        .max_future_view_distance();
    let observed = driver
        .submit(cohort::<Sha256, _>(vec![
            vqc.clone(),
            vqc,
            Artifact::Vqc(other.vqc(View::new(1))),
            Artifact::Vqc(committee.vqc(View::new(2 + horizon))),
        ]))
        .unwrap();
    let StepStatus::Observed(results) = observed.status() else {
        panic!("an observation classifies its cohort");
    };
    let statuses = results
        .iter()
        .map(|result| result.status())
        .collect::<Vec<_>>();
    assert_eq!(
        statuses,
        [
            ObservationStatus::Scheduled,
            ObservationStatus::Duplicate,
            ObservationStatus::Rejected(Rejection::Context),
            ObservationStatus::Rejected(Rejection::TagWindow),
        ]
    );
    // The certificate beyond the window is refused, but its signature is still checked as
    // evidence that this node is far behind.
    assert_eq!(observed.verify_job().items().len(), 2);
}

#[test]
fn a_tick_fires_only_at_the_held_deadline() {
    let committee = committee(9);
    let mut driver = started(&committee, Role::Observer);
    assert_eq!(
        driver
            .submit(Input::Tick(TimerFamily::View))
            .unwrap()
            .status(),
        &StepStatus::StaleCompletion,
        "no deadline is held"
    );
    let at = driver.now().saturating_add(100);
    let armed = driver.machine_mut().arm_timer(TimerFamily::View, at);
    driver.record(&[armed]);
    assert_eq!(driver.clock().deadline(TimerFamily::View), Some(at));
    assert_eq!(
        driver
            .submit(Input::Tick(TimerFamily::View))
            .unwrap()
            .status(),
        &StepStatus::StaleCompletion,
        "an early tick is stale"
    );

    let cancelled = driver.machine_mut().cancel_timer(TimerFamily::View);
    driver.record(&[cancelled]);
    assert_eq!(driver.clock().deadline(TimerFamily::View), None);
    assert!(driver.advance(100).unwrap().is_empty());
    assert_eq!(
        driver
            .submit(Input::Tick(TimerFamily::View))
            .unwrap()
            .status(),
        &StepStatus::StaleCompletion,
        "a cancelled deadline never fires"
    );
}
