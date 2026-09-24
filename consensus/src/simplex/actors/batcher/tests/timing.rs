use super::*;
use commonware_utils::futures::Pool;
use std::collections::{BTreeMap, BTreeSet};

// A wall-clock runtime is necessary here: deterministic time does not include inline CPU work.
#[test]
fn inline_construction_latency_includes_submission() {
    tokio::Runner::default().start(|context| async move {
        let mut rng = test_rng();
        let Fixture {
            participants,
            schemes,
            ..
        } = ed25519::fixture(&mut rng, b"batcher_timing", 101);
        let epoch = Epoch::new(0);
        let cfg = test_config(
            schemes[0].clone(),
            NoopBlocker,
            NoopReporter(PhantomData),
            MockRelay::new(),
            epoch,
            BatcherOptions::default(),
        );
        let (mut actor, _mailbox) = Actor::new(context.child("actor"), cfg);
        let (sender, _receiver) = mailbox::new(context.child("voter"), NZUsize!(8));
        let mut voter = voter::Mailbox::new(sender);
        let view = View::new(1);
        let round_id = Round::new(epoch, view);
        let proposal = Proposal::new(round_id, View::zero(), Sha256::hash(&[b"timing"]));
        let mut round = super::super::Round::new(
            round_id,
            Arc::new(schemes[0].clone()),
            NoopBlocker,
            NoopReporter(PhantomData),
            false,
        );
        round.set_leader(Participant::new(0));
        for (participant, scheme) in participants.iter().zip(&schemes) {
            assert!(round.add_network(
                participant.clone(),
                Vote::Notarize(Notarize::sign(scheme, proposal.clone()).unwrap())
            ));
        }
        let mut work = BTreeMap::from([(view, round)]);
        let mut dirty = BTreeSet::from([view]);
        let mut pool = Pool::default();
        let viewport = crate::simplex::Viewport {
            current: view,
            finalized: View::zero(),
            view_retention: ViewDelta::new(10),
            lookahead: Lookahead {
                term_length: TermLength::ONE,
                optimistic_views: ViewDelta::new(0),
            },
        };
        let start = context.current();
        actor.dispatch_ready(&mut pool, &mut work, &mut dirty, &mut voter, viewport);
        let elapsed = context
            .current()
            .duration_since(start)
            .unwrap()
            .as_secs_f64();
        let done = pool.next_completed().await;
        actor.handle_done(&mut voter, &mut work, done);
        let metrics = context.encode();
        let observed: f64 = metrics
            .lines()
            .find_map(|line| line.strip_prefix("actor_construct_latency_sum "))
            .expect("construction histogram missing")
            .parse()
            .unwrap();
        assert!(
            observed >= elapsed * 0.5,
            "inline construction took {elapsed}s but histogram recorded {observed}s"
        );
    });
}
