use super::*;
use commonware_utils::futures::Pool;
use std::collections::{BTreeMap, BTreeSet};

/// The construction timer must start at submission, not when the pool first polls
/// the job: an inline strategy finishes the work during submission, and the time
/// until the completion is handled stands in for slow construction.
#[test]
fn construction_latency_starts_at_submission() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let Fixture {
            participants,
            schemes,
            ..
        } = ed25519::fixture(&mut context, b"batcher_timing", 5);
        let epoch = Epoch::new(0);
        let cfg = with_strategy(
            test_config(
                schemes[0].clone(),
                NoopBlocker,
                NoopReporter(PhantomData),
                MockRelay::new(),
                epoch,
                BatcherOptions::default(),
            ),
            commonware_parallel::mocks::inline(NZUsize!(4)),
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
        actor.dispatch_ready(&mut pool, &mut work, &mut dirty, &mut voter, viewport);
        assert_eq!(pool.len(), 1);

        let delay = Duration::from_millis(50);
        context.sleep(delay).await;
        let done = pool.next_completed().await;
        actor.handle_done(&mut voter, &mut work, done);

        let metrics = context.encode();
        let observed: f64 = metrics
            .lines()
            .find_map(|line| line.strip_prefix("actor_construct_latency_sum "))
            .expect("construction histogram missing")
            .parse()
            .unwrap();
        assert_eq!(observed, delay.as_secs_f64());
    });
}
