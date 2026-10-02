use super::*;
use crate::simplex::Viewport;
use commonware_utils::futures::Pool;
use futures::{FutureExt as _, channel::oneshot};
use std::collections::{BTreeMap, BTreeSet};

/// Completing a full pool must wake skipped views without another vote, and
/// the current view must win the newly available slot over older views.
#[test]
fn completion_revisits_saturated_views_in_current_view_order() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let Fixture {
            schemes,
            participants,
            ..
        } = ed25519::fixture(&mut context, b"dispatch_order", 5);
        let epoch = Epoch::new(1);
        let (mut actor, _mailbox) = Actor::new(
            context.child("batcher"),
            test_config(
                schemes[0].clone(),
                NoopBlocker,
                NoopReporter(PhantomData),
                MockRelay::new(),
                epoch,
                BatcherOptions::default(),
            ),
        );
        let (sender, mut receiver) = mailbox::new(context.child("voter"), NZUsize!(16));
        let mut voter = voter::Mailbox::new(sender);
        let mut work = BTreeMap::new();
        for view in [1, 2, 3].map(View::new) {
            let id = Round::new(epoch, view);
            let mut round = super::super::Round::new(
                id,
                Arc::new(schemes[0].clone()),
                NoopBlocker,
                NoopReporter(PhantomData),
                false,
            );
            for (index, scheme) in schemes.iter().take(quorum(5) as usize).enumerate() {
                assert!(round.add_network(
                    participants[index].clone(),
                    Vote::<_, Sha256Digest>::Nullify(
                        Nullify::sign::<Sha256Digest>(scheme, id).unwrap()
                    )
                ));
            }
            work.insert(view, round);
        }
        let viewport = Viewport {
            finalized: View::zero(),
            current: View::new(2),
            view_retention: ViewDelta::new(10),
            lookahead: BatcherOptions::default().lookahead,
        };
        let mut pool = Pool::default();
        let mut dirty = BTreeSet::from([View::new(3)]);
        actor.dispatch_ready(&mut pool, &mut work, &mut dirty, &mut voter, viewport);
        assert_eq!(pool.len(), 1);
        let done = pool.next_completed().await;
        assert_eq!(done.view, View::new(3));
        let (release, gate) = oneshot::channel();
        pool.push(async move {
            gate.await.unwrap();
            done
        });
        dirty.extend([View::new(1), View::new(2)]);
        actor.dispatch_ready(&mut pool, &mut work, &mut dirty, &mut voter, viewport);
        assert_eq!(pool.len(), 1);
        assert!(dirty.contains(&View::new(1)));
        assert!(dirty.contains(&View::new(2)));
        assert!(pool.next_completed().now_or_never().is_none());
        release.send(()).unwrap();
        for expected in [3, 2, 1].map(View::new) {
            let done = pool.next_completed().await;
            assert_eq!(done.view, expected);
            dirty.insert(actor.handle_done(&mut voter, &mut work, done).unwrap());
            let Some(voter::Message::Verified {
                certificate,
                from_resolver,
                ..
            }) = receiver.recv().await
            else {
                panic!("completion must forward a certificate");
            };
            assert_eq!(certificate.view(), expected);
            assert!(!from_resolver);
            assert!(certificate.verify(&mut context, &schemes[0], &Sequential));
            actor.dispatch_ready(&mut pool, &mut work, &mut dirty, &mut voter, viewport);
            assert!(pool.len() <= 1);
        }
        assert!(pool.is_empty());
        assert!(dirty.is_empty());
    });
}

/// Pruning round state cannot discard a completed certificate or its accounting.
#[test]
fn pruned_completion_forwards_certificate_and_records_fallback() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let Fixture {
            schemes,
            participants,
            ..
        } = ed25519::fixture(&mut context, b"dispatch_pruned", 7);
        let blocked = Arc::new(Mutex::new(Vec::new()));
        let epoch = Epoch::new(1);
        let view = View::new(1);
        let id = Round::new(epoch, view);
        let (mut actor, _mailbox) = Actor::new(
            context.child("batcher"),
            test_config(
                schemes[0].clone(),
                RecordingBlocker(blocked.clone()),
                NoopReporter(PhantomData),
                MockRelay::new(),
                epoch,
                BatcherOptions::default(),
            ),
        );
        let mut round = super::super::Round::new(
            id,
            Arc::new(schemes[0].clone()),
            RecordingBlocker(blocked.clone()),
            NoopReporter(PhantomData),
            false,
        );
        let mut votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Nullify::sign::<Sha256Digest>(scheme, id).unwrap())
            .collect();
        votes[0].attestation.signature = votes.last().unwrap().attestation.signature.clone();
        let count = quorum(7) as usize + 1;
        for (index, vote) in votes.into_iter().take(count).enumerate() {
            assert!(round.add_network(
                participants[index].clone(),
                Vote::<_, Sha256Digest>::Nullify(vote)
            ));
        }
        let mut work = BTreeMap::from([(view, round)]);
        let mut dirty = BTreeSet::from([view]);
        let mut pool = Pool::default();
        let (sender, mut receiver) = mailbox::new(context.child("voter"), NZUsize!(16));
        let mut voter = voter::Mailbox::new(sender);
        actor.dispatch_ready(
            &mut pool,
            &mut work,
            &mut dirty,
            &mut voter,
            Viewport {
                finalized: View::zero(),
                current: view,
                view_retention: ViewDelta::new(10),
                lookahead: BatcherOptions::default().lookahead,
            },
        );
        work.remove(&view).unwrap();
        let done = pool.next_completed().await;
        assert!(done.constructed.batch.fallback);
        assert_eq!(done.constructed.batch.processed, count);
        assert_eq!(actor.handle_done(&mut voter, &mut work, done), None);
        assert!(work.is_empty());
        let Some(voter::Message::Verified { certificate, .. }) = receiver.recv().await else {
            panic!("pruned completion must forward a certificate");
        };
        assert_eq!(certificate.view(), view);
        assert!(certificate.verify(&mut context, &schemes[0], &Sequential));
        assert_eq!(*blocked.lock(), vec![participants[0].clone()]);
        let metrics = context.encode();
        assert!(
            metrics.contains(&format!("batcher_processed_total {count}")),
            "{metrics}"
        );
        assert!(
            metrics.contains("batcher_construct_fallback_total 1"),
            "{metrics}"
        );
        assert!(
            metrics.contains("batcher_construct_latency_count 1"),
            "{metrics}"
        );
        assert!(metrics.contains("batcher_batch_size_count 1"), "{metrics}");
    });
}

/// A quorum whose crypto never completes must not prevent an update and a
/// subsequent leader nullify from reaching the voter.
#[test]
fn pending_crypto_keeps_mailbox_and_network_responsive() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let Fixture {
            schemes,
            participants,
            ..
        } = ed25519::fixture(&mut context, b"dispatch_pending", 5);
        let epoch = Epoch::new(1);
        let me = participants[0].clone();
        let oracle =
            start_test_network_with_peers(context.child("network"), participants.clone()).await;
        let cfg = test_config(
            schemes[0].clone(),
            NoopBlocker,
            NoopReporter(PhantomData),
            MockRelay::new(),
            epoch,
            BatcherOptions::default(),
        );
        let cfg = Config {
            strategy: commonware_parallel::mocks::pending(NZUsize!(2)),
            scheme: cfg.scheme,
            blocker: cfg.blocker,
            reporter: cfg.reporter,
            track_historical_votes: cfg.track_historical_votes,
            relay: cfg.relay,
            view_retention: cfg.view_retention,
            skip: cfg.skip,
            epoch: cfg.epoch,
            mailbox_size: cfg.mailbox_size,
            lookahead: cfg.lookahead,
            forward: cfg.forward,
            floor: cfg.floor,
        };
        let (actor, mut batcher) = Actor::new(context.child("batcher"), cfg);
        let (sender, mut receiver) = mailbox::new(context.child("voter"), NZUsize!(16));
        let (_vote_sender, vote_receiver) = oracle
            .control(me.clone())
            .register(0, TEST_QUOTA)
            .await
            .unwrap();
        let (_cert_sender, cert_receiver) = oracle
            .control(me.clone())
            .register(1, TEST_QUOTA)
            .await
            .unwrap();
        let mut senders = Vec::new();
        for peer in participants.iter().skip(1) {
            senders.push(
                register_and_link_peer(
                    &oracle,
                    peer.clone(),
                    me.clone(),
                    0,
                    Duration::from_millis(1),
                )
                .await,
            );
        }
        track_test_peers(&mut context, &oracle, 1, &participants, &[]).await;
        actor.start(voter::Mailbox::new(sender), vote_receiver, cert_receiver);
        let first = Round::new(epoch, View::new(1));
        batcher.update(
            Span::none(),
            first.view(),
            Participant::from_usize(4),
            View::zero(),
            None,
        );
        batcher.constructed(Vote::<_, Sha256Digest>::Nullify(
            Nullify::sign::<Sha256Digest>(&schemes[0], first).unwrap(),
        ));
        for (index, sender) in senders.iter_mut().take(3).enumerate() {
            sender.send(
                Recipients::One(me.clone()),
                Vote::<_, Sha256Digest>::Nullify(
                    Nullify::sign::<Sha256Digest>(&schemes[index + 1], first).unwrap(),
                )
                .encode(),
                true,
            );
        }
        // Metrics acknowledge the full quorum before the responsiveness probe.
        // The runner's deadline bounds this condition-driven polling loop.
        while !context.encode().contains("batcher_added_total 4") {
            context.sleep(Duration::from_millis(1)).await;
        }
        let next = Round::new(epoch, View::new(2));
        batcher.update(
            Span::none(),
            next.view(),
            Participant::from_usize(1),
            View::zero(),
            None,
        );
        senders[0].send(
            Recipients::One(me),
            Vote::<_, Sha256Digest>::Nullify(
                Nullify::sign::<Sha256Digest>(&schemes[1], next).unwrap(),
            )
            .encode(),
            true,
        );
        expect_timeout(
            &mut context,
            &mut receiver,
            next.view(),
            TimeoutReason::LeaderNullify,
        )
        .await;
        let metrics = context.encode();
        assert!(metrics.contains("batcher_added_total 5"), "{metrics}");
        assert!(metrics.contains("batcher_processed_total 0"), "{metrics}");
        assert!(
            metrics.contains("batcher_construct_latency_count 0"),
            "{metrics}"
        );
    });
}
