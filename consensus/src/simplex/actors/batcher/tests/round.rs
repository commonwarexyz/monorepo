use super::*;

#[test_async]
async fn test_construct_proposal_switch_restores_buffered_finalizes() {
    let mut rng = test_rng();
    let Fixture { schemes, .. } = secp256r1::fixture(&mut rng, b"round_construct_switch", 5);
    let round_id = Round::new(Epoch::zero(), View::new(1));
    let a = Proposal::new(round_id, View::zero(), Sha256::hash(&[b"a"]));
    let b = Proposal::new(round_id, View::zero(), Sha256::hash(&[b"b"]));
    let mut round = super::super::Round::new(
        round_id,
        Arc::new(schemes[0].clone()),
        NoopBlocker,
        NoopReporter(PhantomData),
        false,
    );
    round.set_leader(Participant::new(0));
    round.accept_vote(
        Vote::Notarize(Notarize::sign(&schemes[0], a.clone()).unwrap()),
        false,
    );
    // Run the notarize job first, so the next job takes the finalize votes.
    assert!(
        round
            .try_construct(&mut rng, &Sequential)
            .await
            .unwrap()
            .certificate
            .is_none()
    );
    round.accept_vote(
        Vote::Finalize(Finalize::sign(&schemes[0], a).unwrap()),
        false,
    );
    for scheme in schemes.iter().skip(1).take(3) {
        round.accept_vote(
            Vote::Finalize(Finalize::sign(scheme, b.clone()).unwrap()),
            false,
        );
    }
    let job = round.begin_construct(&mut rng).unwrap().spawn(&Sequential);

    // Our finalize for B sets the proposal to B. This adds back the B votes that A filtered out.
    round.accept_vote(
        Vote::Finalize(Finalize::sign(&schemes[4], b.clone()).unwrap()),
        true,
    );
    assert!(round.begin_construct(&mut rng).is_none());
    let batch = round.finish_construct(job.await);
    assert!(batch.certificate.is_none());
    let batch = round.try_construct(&mut rng, &Sequential).await.unwrap();
    assert_eq!(batch.processed, 3);
    assert!(batch.invalid.is_empty());
    assert!(!batch.fallback);
    let certificate = batch.certificate.unwrap();
    let Certificate::Finalization(finalization) = &certificate else {
        panic!("expected finalization");
    };
    assert_eq!(finalization.proposal, b);
    assert!(certificate.verify(&mut rng, &schemes[0], &Sequential));
    assert!(round.has_certificate(Kind::Finalization));
    assert!(round.begin_construct(&mut rng).is_none());
}
