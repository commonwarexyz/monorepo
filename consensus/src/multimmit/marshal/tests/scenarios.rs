//! End-to-end scenarios.

use super::harness::*;
use crate::{multimmit::marshal::Error, types::OutputIndex};
use commonware_runtime::{Runner as _, Spawner as _, Supervisor as _};
use std::time::Duration;

#[test]
fn a_node_delivers_its_staged_blocks_in_proven_order() {
    runner(1).start(|context| async move {
        let mut harness = Harness::new(context, 1, 1).await;
        harness.start(0).await;
        harness.script.certify([2, 1]);
        harness.script.certify([1, 3]);
        let mailbox = harness.mailbox(0);
        harness.script.stage(&mailbox, 0).await;
        harness.script.stage(&mailbox, 1).await;
        // Nothing is delivered without a proof.
        harness.settle(Duration::from_millis(200)).await;
        assert!(harness.applications[0].delivered().is_empty());

        harness.script.prove(&mailbox, 0);
        harness.script.prove(&mailbox, 1);
        let expected = harness.script.ordered();
        let delivered = harness.wait_delivered(0, expected.len()).await;
        assert_eq!(stream(&delivered), numbered(1, &expected));
        let progress = harness
            .wait_progress(0, |progress| {
                progress.acknowledged.get() == expected.len() as u64
            })
            .await;
        assert_eq!(progress.delivered.get(), expected.len() as u64);
    });
}

#[test]
fn a_node_fetches_every_body_from_a_peer() {
    runner(2).start(|context| async move {
        let mut harness = Harness::new(context, 2, 2).await;
        harness.start(0).await;
        harness.start(1).await;
        harness.script.certify([3, 2]);
        harness.script.certify([2, 2]);
        let holder = harness.mailbox(0);
        harness.script.stage(&holder, 0).await;
        harness.script.stage(&holder, 1).await;
        let follower = harness.mailbox(1);
        harness.script.prove(&follower, 0);
        harness.script.prove(&follower, 1);
        let expected = harness.script.ordered();
        let delivered = harness.wait_delivered(1, expected.len()).await;
        assert_eq!(stream(&delivered), numbered(1, &expected));
    });
}

#[test]
fn a_restart_redelivers_only_after_the_durable_acknowledgement() {
    runner(3).start(|context| async move {
        let mut harness = Harness::new(context, 3, 1).await;
        harness.applications[0].set_auto(false);
        harness.start(0).await;
        harness.script.certify([2, 2]);
        let mailbox = harness.mailbox(0);
        harness.script.stage(&mailbox, 0).await;
        harness.script.prove(&mailbox, 0);
        let expected = harness.script.ordered();
        harness.wait_delivered(0, expected.len()).await;
        // Acknowledge the first two outputs and wait until that is durable.
        harness.applications[0].acknowledge_next();
        harness.applications[0].acknowledge_next();
        harness
            .wait_progress(0, |progress| progress.acknowledged == OutputIndex::new(2))
            .await;
        harness.crash(0).await;
        harness.applications[0].clear();
        harness.applications[0].set_auto(true);

        harness.start(0).await;
        let delivered = harness.wait_delivered(0, expected.len() - 2).await;
        assert_eq!(stream(&delivered), numbered(3, &expected[2..]));
    });
}

#[test]
fn a_direct_finality_fact_alone_delivers_nothing() {
    runner(4).start(|context| async move {
        let mut harness = Harness::new(context, 4, 1).await;
        harness.start(0).await;
        harness.script.certify([2, 2]);
        let mailbox = harness.mailbox(0);
        harness.script.stage(&mailbox, 0).await;
        // A record alone authenticates nothing to deliver.
        let mut reporter = mailbox.clone();
        let _ = crate::Reporter::report(
            &mut reporter,
            crate::multimmit::types::Activity::Placed {
                view: crate::types::View::new(1),
                evidence: crate::multimmit::types::FinalityId::Direct(
                    <commonware_cryptography::Sha256 as commonware_cryptography::Hasher>::hash(&[
                        b"pool",
                    ]),
                ),
                history: harness.script.views[0]
                    .history
                    .commitment::<commonware_cryptography::Sha256>(),
                placed: Vec::new(),
            },
        );
        harness.settle(Duration::from_millis(300)).await;
        assert!(harness.applications[0].delivered().is_empty());
        let _ = Error::Closed;
    });
}

#[test]
fn a_proof_without_records_walks_the_history_from_peers() {
    runner(5).start(|context| async move {
        let mut harness = Harness::new(context, 5, 2).await;
        harness.start(0).await;
        harness.start(1).await;
        for counts in [[1, 1], [2, 0], [0, 2], [1, 1]] {
            harness.script.certify(counts);
        }
        let holder = harness.mailbox(0);
        for view in 0..4 {
            harness.script.stage(&holder, view).await;
            harness.script.prove(&holder, view);
        }
        let expected = harness.script.ordered();
        harness.wait_delivered(0, expected.len()).await;

        // The follower hears only the newest proof, with no record: it walks the records back
        // from the proof's history to genesis, then fetches every body.
        let follower = harness.mailbox(1);
        harness.script.prove_bare(&follower, 3);
        let delivered = harness.wait_delivered(1, expected.len()).await;
        assert_eq!(stream(&delivered), numbered(1, &expected));
    });
}

#[test]
fn views_that_emit_nothing_still_advance_the_history() {
    runner(6).start(|context| async move {
        let mut harness = Harness::new(context, 6, 1).await;
        harness.start(0).await;
        for counts in [[1, 0], [0, 0], [0, 0], [0, 1]] {
            harness.script.certify(counts);
        }
        let mailbox = harness.mailbox(0);
        for view in 0..4 {
            harness.script.stage(&mailbox, view).await;
            harness.script.prove(&mailbox, view);
        }
        let expected = harness.script.ordered();
        assert_eq!(expected.len(), 2);
        let delivered = harness.wait_delivered(0, 2).await;
        assert_eq!(stream(&delivered), numbered(1, &expected));
    });
}

#[test]
fn a_fresh_node_resumes_from_a_served_floor() {
    runner(7).start(|context| async move {
        let mut harness = Harness::new(context, 7, 2).await;
        harness.start(0).await;
        for counts in [[2, 1], [1, 2], [2, 2]] {
            harness.script.certify(counts);
        }
        let holder = harness.mailbox(0);
        for view in 0..2 {
            harness.script.stage(&holder, view).await;
            harness.script.prove(&holder, view);
        }
        let first = harness.script.views[0].ordered().len() as u64;
        let both = first + harness.script.views[1].ordered().len() as u64;
        harness.wait_delivered(0, both as usize).await;
        harness
            .wait_progress(0, |progress| progress.acknowledged.get() == both)
            .await;

        // The holder serves the floor its first proof anchors.
        let (index, floor) = loop {
            if let Some(found) = holder.floor_at(OutputIndex::new(first)).await.unwrap() {
                break found;
            }
            harness.settle(Duration::from_millis(10)).await;
        };
        assert_eq!(index.get(), first);
        assert_eq!(
            floor.emitted(),
            harness.script.tips[1].as_slice(),
            "the floor's boundary is the first view's tips"
        );

        // A fresh node installs it and delivers only what follows, at the same indices.
        harness.start(1).await;
        let follower = harness.mailbox(1);
        follower.install_floor(floor.clone()).await.unwrap();
        let progress = follower.progress().await.unwrap();
        assert_eq!(progress.acknowledged.get(), first);
        // Installing the same floor again is stale.
        assert!(matches!(
            follower.install_floor(floor).await,
            Err(Error::Rejected(_))
        ));
        harness.script.stage(&holder, 2).await;
        harness.script.prove(&holder, 2);
        harness.script.prove(&follower, 1);
        harness.script.prove(&follower, 2);
        let expected = harness.script.ordered();
        let delivered = harness
            .wait_delivered(1, expected.len() - first as usize)
            .await;
        assert_eq!(
            stream(&delivered),
            numbered(first + 1, &expected[first as usize..])
        );
    });
}

#[test]
fn a_floor_with_a_forged_boundary_is_rejected() {
    runner(8).start(|context| async move {
        let mut harness = Harness::new(context, 8, 2).await;
        harness.start(0).await;
        harness.start(1).await;
        harness.script.certify([2, 1]);
        harness.script.certify([1, 1]);
        let holder = harness.mailbox(0);
        for view in 0..2 {
            harness.script.stage(&holder, view).await;
            harness.script.prove(&holder, view);
        }
        harness
            .wait_delivered(0, harness.script.ordered().len())
            .await;

        let follower = harness.mailbox(1);
        let certified = harness.script.views[0].clone();
        // A boundary above the certificate's sweep.
        let mut high = harness.script.tips[1].clone();
        high[0] = harness.script.tips[2][0];
        assert!(matches!(
            follower.install_floor(certified.floor(high)).await,
            Err(Error::Rejected(_))
        ));
        // A boundary at the right heights but on another branch.
        let mut forged = harness.script.tips[1].clone();
        forged[1] = crate::multimmit::types::BlockRef::new(
            forged[1].chain(),
            forged[1].height(),
            <commonware_cryptography::Sha256 as commonware_cryptography::Hasher>::hash(&[
                b"forged",
            ]),
        );
        assert!(matches!(
            follower.install_floor(certified.floor(forged)).await,
            Err(Error::Rejected(_))
        ));
        let progress = follower.progress().await.unwrap();
        assert_eq!(progress.acknowledged.get(), 0);
        assert_eq!(progress.floor, None);
        // The genuine floor installs.
        follower
            .install_floor(certified.floor(harness.script.tips[1].clone()))
            .await
            .unwrap();
    });
}

#[test]
fn a_floor_whose_chain_emitted_nothing_installs() {
    runner(19).start(|context| async move {
        let mut harness = Harness::new(context, 19, 2).await;
        harness.start(0).await;
        // The second chain emits nothing by the first floor: its boundary is its genesis tip.
        harness.script.certify([2, 0]);
        harness.script.certify([1, 1]);
        let holder = harness.mailbox(0);
        for view in 0..2 {
            harness.script.stage(&holder, view).await;
            harness.script.prove(&holder, view);
        }
        let total = harness.script.ordered().len() as u64;
        harness
            .wait_progress(0, |progress| progress.acknowledged.get() == total)
            .await;
        let first = harness.script.views[0].ordered().len() as u64;
        let (index, floor) = loop {
            if let Some(found) = holder.floor_at(OutputIndex::new(first)).await.unwrap() {
                break found;
            }
            harness.settle(Duration::from_millis(10)).await;
        };
        assert_eq!(index.get(), first);
        assert!(floor.emitted()[1].height().is_zero());

        harness.start(1).await;
        let follower = harness.mailbox(1);
        follower.install_floor(floor).await.unwrap();
        harness.script.prove(&follower, 1);
        let expected = harness.script.ordered();
        let delivered = harness
            .wait_delivered(1, expected.len() - first as usize)
            .await;
        assert_eq!(
            stream(&delivered),
            numbered(first + 1, &expected[first as usize..])
        );
    });
}

#[test]
fn an_unverifiable_floor_is_rejected_and_durable_progress_continues() {
    runner(20).start(|context| async move {
        let mut harness = Harness::new(context, 20, 1).await;
        harness.start(0).await;
        harness.script.certify([2, 1]);
        harness.script.certify([1, 1]);
        let node = harness.mailbox(0);
        for view in 0..2 {
            harness.script.stage(&node, view).await;
        }
        harness.script.prove(&node, 0);
        let first = harness.script.views[0].ordered().len() as u64;
        harness
            .wait_progress(0, |progress| progress.acknowledged.get() == first)
            .await;
        // A floor whose certificate another committee signed.
        let forged = harness.script.forged(1);
        assert!(matches!(
            node.install_floor(forged.floor(harness.script.tips[2].clone()))
                .await,
            Err(Error::Rejected(_))
        ));
        // Acknowledgements keep becoming durable.
        harness.script.prove(&node, 1);
        let total = harness.script.ordered().len() as u64;
        harness
            .wait_progress(0, |progress| progress.acknowledged.get() == total)
            .await;
    });
}

#[test]
fn a_node_without_a_consensus_feed_catches_up_through_peer_proofs() {
    runner(21).start(|context| async move {
        let mut harness = Harness::new(context, 21, 2).await;
        harness.start(0).await;
        for counts in [[2, 1], [1, 2], [2, 2], [1, 1]] {
            harness.script.certify(counts);
        }
        let holder = harness.mailbox(0);
        for view in 0..4 {
            harness.script.stage(&holder, view).await;
            harness.script.prove(&holder, view);
        }
        let total = harness.script.ordered().len() as u64;
        harness
            .wait_progress(0, |progress| progress.acknowledged.get() == total)
            .await;
        let first = harness.script.views[0].ordered().len() as u64;
        let (_, floor) = loop {
            if let Some(found) = holder.floor_at(OutputIndex::new(first)).await.unwrap() {
                break found;
            }
            harness.settle(Duration::from_millis(10)).await;
        };
        // The follower hears nothing from consensus: it asks peers for each later proof.
        harness.start(1).await;
        harness.mailbox(1).install_floor(floor).await.unwrap();
        harness
            .wait_progress(1, |progress| progress.delivered.get() == total)
            .await;
        let expected = harness.script.ordered();
        assert_eq!(
            stream(&harness.applications[1].delivered()),
            numbered(first + 1, &expected[first as usize..])
        );
    });
}

#[test]
fn pruning_drops_old_blocks_but_keeps_the_floor_servable() {
    runner(9).start(|context| async move {
        let mut harness = Harness::new(context, 9, 2).await;
        harness.start(0).await;
        for counts in [[2, 1], [1, 2], [1, 1]] {
            harness.script.certify(counts);
        }
        let mailbox = harness.mailbox(0);
        for view in 0..3 {
            harness.script.stage(&mailbox, view).await;
            harness.script.prove(&mailbox, view);
        }
        let expected = harness.script.ordered();
        harness.wait_delivered(0, expected.len()).await;
        harness
            .wait_progress(0, |progress| {
                progress.acknowledged.get() == expected.len() as u64
            })
            .await;
        // The engine no longer verifies anything below the newest tips.
        let mut reporter = mailbox.clone();
        for tip in harness.script.tips.last().unwrap() {
            let _ = crate::Reporter::report(
                &mut reporter,
                crate::multimmit::types::Activity::CertificateRecorded {
                    certified: *tip,
                    released: tip.height(),
                },
            );
        }
        let second = (harness.script.views[0].ordered().len()
            + harness.script.views[1].ordered().len()) as u64;
        // Wait until the second view's cut entry is durable, then prune to it.
        loop {
            if let Some((index, _)) = mailbox.floor_at(OutputIndex::new(second)).await.unwrap() {
                if index.get() == second {
                    break;
                }
            }
            harness.settle(Duration::from_millis(10)).await;
        }
        mailbox.prune(OutputIndex::new(second)).await.unwrap();
        let progress = mailbox.progress().await.unwrap();
        assert!(progress.floor.is_some());
        // Blocks below the floor's boundary are gone; the boundary blocks stay.
        let first = harness.script.views[0].blocks[0][0].reference();
        assert!(mailbox.get_block(first).await.unwrap().is_none());
        for tip in &harness.script.tips[2] {
            assert!(mailbox.get_block(*tip).await.unwrap().is_some());
        }
        // The floor stays servable, and nothing below it is.
        let (index, _) = mailbox
            .floor_at(OutputIndex::new(second))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(index.get(), second);
        assert!(
            mailbox
                .floor_at(OutputIndex::new(second - 1))
                .await
                .unwrap()
                .is_none()
        );

        // A restart keeps the prune and continues.
        harness.crash(0).await;
        harness.applications[0].clear();
        harness.start(0).await;
        let mailbox = harness.mailbox(0);
        assert!(mailbox.get_block(first).await.unwrap().is_none());
        // The retained floor stays servable after the restart, and a fresh node installs it.
        let (index, floor) = mailbox
            .floor_at(OutputIndex::new(second))
            .await
            .unwrap()
            .expect("the retained floor is servable after a restart");
        assert_eq!(index.get(), second);
        harness.start(1).await;
        harness.mailbox(1).install_floor(floor).await.unwrap();
        harness.script.certify([1, 0]);
        harness.script.stage(&mailbox, 3).await;
        harness.script.prove(&mailbox, 3);
        let expected = harness.script.ordered();
        let delivered = harness.wait_delivered(0, 1).await;
        assert_eq!(
            stream(&delivered),
            numbered(expected.len() as u64, &expected[expected.len() - 1..])
        );
    });
}

#[test]
fn a_stronger_proof_of_the_same_leader_continues_a_shorter_sweep() {
    for strong_first in [false, true] {
        runner(10).start(|context| async move {
            let mut harness = Harness::new(context, 10, 1).await;
            harness.start(0).await;
            harness.script.certify([3, 3]);
            let mailbox = harness.mailbox(0);
            harness.script.stage(&mailbox, 0).await;
            let weak = harness.script.weaker(0, [1, 2]);
            let expected = harness.script.ordered();
            if strong_first {
                harness.script.prove(&mailbox, 0);
                harness.wait_delivered(0, expected.len()).await;
                // A dominated proof arriving later changes nothing.
                harness.script.prove_certified(&mailbox, &weak);
                harness.settle(Duration::from_millis(200)).await;
                assert_eq!(
                    stream(&harness.applications[0].delivered()),
                    numbered(1, &expected)
                );
                return;
            }
            harness.script.prove_certified(&mailbox, &weak);
            // The weak proof finalizes a prefix of each chain's proposal: delivery stops at
            // where its sweep ends.
            harness.settle(Duration::from_millis(300)).await;
            let partial = harness.applications[0].delivered();
            assert!(!partial.is_empty() && partial.len() < expected.len());
            assert_eq!(stream(&partial), numbered(1, &expected[..partial.len()]));
            harness.script.prove(&mailbox, 0);
            let delivered = harness.wait_delivered(0, expected.len()).await;
            assert_eq!(stream(&delivered), numbered(1, &expected));
            // The stronger proof arrived after its history was opened: its end is a floor too.
            let end = expected.len() as u64;
            assert_eq!(wait_floor(&mut harness, &mailbox, end).await, end);
        });
    }
}

/// Waits until the newest floor at or below `index` ends at it, returning where the newest one
/// ends if that never happens.
async fn wait_floor(harness: &mut Harness, mailbox: &TestMailbox, index: u64) -> u64 {
    let mut newest = 0;
    for _ in 0..100 {
        if let Some((at, _)) = mailbox.floor_at(OutputIndex::new(index)).await.unwrap() {
            newest = at.get();
            if newest == index {
                break;
            }
        }
        harness.settle(Duration::from_millis(10)).await;
    }
    newest
}

#[test]
fn a_late_weaker_proof_never_becomes_a_floor_at_a_later_restart_position() {
    runner(13).start(|context| async move {
        let mut harness = Harness::new(context, 13, 1).await;
        harness.applications[0].set_auto(false);
        harness.start(0).await;
        harness.script.certify([3, 3]);
        let weak = harness.script.weaker(0, [1, 2]);
        let mailbox = harness.mailbox(0);
        harness.script.stage(&mailbox, 0).await;
        harness.script.prove(&mailbox, 0);
        let expected = harness.script.ordered();
        harness.wait_delivered(0, expected.len()).await;
        for _ in 0..4 {
            harness.applications[0].acknowledge_next();
        }
        harness
            .wait_progress(0, |progress| progress.acknowledged == OutputIndex::new(4))
            .await;
        // A weaker proof of the same leader arrives after delivery passed where it ends (2).
        harness.script.prove_certified(&mailbox, &weak);
        harness.settle(Duration::from_millis(200)).await;
        harness.crash(0).await;

        // The restarted order stands at output 4, past the weaker proof's end: that end is not
        // closed at the current position, so no floor exists at or below it.
        harness.applications[0].clear();
        harness.start(0).await;
        let mailbox = harness.mailbox(0);
        harness.settle(Duration::from_millis(200)).await;
        assert!(
            mailbox
                .floor_at(OutputIndex::new(4))
                .await
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn every_end_proven_before_a_restart_becomes_a_floor_after_it() {
    const VIEWS: usize = 12;
    runner(12).start(|context| async move {
        let mut harness = Harness::new(context, 12, 1).await;
        harness.start(0).await;
        for _ in 0..VIEWS {
            harness.script.certify([3, 3]);
        }
        // Two weaker proofs of the first history, proven between later views so they share a
        // segment that holds neither that history's record nor the target, and that no read
        // has opened when the history is.
        let weak = [[1, 2], [2, 3]].map(|positions| harness.script.weaker(0, positions));
        // Prove everything before any body is held, so no end is reached before the restart.
        let mailbox = harness.mailbox(0);
        for view in 0..8 {
            harness.script.prove(&mailbox, view);
        }
        for certified in &weak {
            harness.script.prove_certified(&mailbox, certified);
        }
        for view in 8..VIEWS {
            harness.script.prove(&mailbox, view);
        }
        harness.settle(Duration::from_millis(300)).await;
        assert!(harness.applications[0].delivered().is_empty());
        harness.crash(0).await;

        // After the restart every proof is read back from storage while delivery runs.
        harness.start(0).await;
        let mailbox = harness.mailbox(0);
        for view in 0..VIEWS {
            harness.script.stage(&mailbox, view).await;
        }
        let expected = harness.script.ordered();
        let delivered = harness.wait_delivered(0, expected.len()).await;
        assert_eq!(stream(&delivered), numbered(1, &expected));
        let mut end = 0;
        for view in 0..VIEWS {
            let start = end;
            end += harness.script.views[view].ordered().len() as u64;
            assert_eq!(
                wait_floor(&mut harness, &mailbox, end).await,
                end,
                "view {view}"
            );
            if view == 0 {
                // The weaker proofs end two and four outputs into the view's sweep.
                for weak in [start + 2, start + 4] {
                    assert_eq!(wait_floor(&mut harness, &mailbox, weak).await, weak);
                }
            }
        }
    });
}

#[test]
fn crashes_during_catch_up_never_change_the_stream() {
    for seed in 0..4u64 {
        runner(100 + seed).start(|context| async move {
            let mut harness = Harness::new(context, 11, 2).await;
            harness.start(0).await;
            harness.start(1).await;
            for counts in [[2, 1], [1, 2], [0, 3], [2, 2], [1, 0]] {
                harness.script.certify(counts);
            }
            let holder = harness.mailbox(0);
            for view in 0..5 {
                harness.script.stage(&holder, view).await;
                harness.script.prove(&holder, view);
            }
            let expected = harness.script.ordered();
            harness.wait_delivered(0, expected.len()).await;

            let follower = harness.mailbox(1);
            harness.script.prove_bare(&follower, 4);
            let mut seen = Vec::new();
            for crash in 0..3u64 {
                harness
                    .settle(Duration::from_millis(5 + 7 * ((seed + crash) % 5)))
                    .await;
                seen.extend(harness.applications[1].delivered());
                harness.applications[1].clear();
                harness.crash(1).await;
                harness.start(1).await;
                // A restarted engine reports the newest proof again.
                harness.script.prove_bare(&harness.mailbox(1), 4);
            }
            let rest = harness
                .wait_progress(1, |progress| {
                    progress.acknowledged.get() == expected.len() as u64
                })
                .await;
            assert_eq!(rest.delivered.get(), expected.len() as u64);
            seen.extend(harness.applications[1].delivered());
            // Every update ever delivered names the canonical block at its index, and every
            // index is delivered.
            for update in &seen {
                let index = update.index.get() as usize;
                assert_eq!(update.block.reference(), expected[index - 1].reference());
            }
            let mut indices = seen
                .iter()
                .map(|update| update.index.get())
                .collect::<Vec<_>>();
            indices.sort_unstable();
            indices.dedup();
            assert_eq!(indices, (1..=expected.len() as u64).collect::<Vec<_>>());
        });
    }
}

/// One step of a randomized follower schedule.
#[derive(Clone, Copy, Debug)]
enum Step {
    /// Report a view's L-QC with the records consensus placed for it.
    Prove(usize),
    /// Report a view's L-QC alone, so its records are walked from the peer.
    ProveBare(usize),
    /// Report a weaker L-QC of a view's leader.
    ProveWeaker(usize),
    /// Let time pass.
    Settle(u64),
    /// Crash and restart the follower; a restarted engine reports the newest proof again.
    Restart,
    /// Prune below the newest floor at or below an index.
    Prune(u64),
}

#[test]
fn randomized_schedules_deliver_the_reference_stream() {
    use rand::RngExt as _;
    const VIEWS: usize = 8;
    for seed in 0..8u64 {
        runner(300 + seed).start(|context| async move {
            let mut rng = commonware_utils::TestRng::new(seed);
            let mut harness = Harness::new(context, 300 + seed, 2).await;
            harness.start(0).await;
            harness.start(1).await;
            let mut counts = Vec::new();
            for _ in 0..VIEWS {
                let view = [rng.random_range(0..4), rng.random_range(0..4)];
                harness.script.certify(view);
                counts.push(view);
            }
            let holder = harness.mailbox(0);
            for view in 0..VIEWS {
                harness.script.stage(&holder, view).await;
                harness.script.prove(&holder, view);
            }
            let expected = harness.script.ordered();
            let total = expected.len() as u64;
            harness.wait_delivered(0, expected.len()).await;

            // A weaker proof of each leader finalizes at most one block of every chain.
            let weaker = counts
                .iter()
                .enumerate()
                .map(|(view, counts)| {
                    harness
                        .script
                        .weaker(view, counts.map(|count| count.min(1) as u32))
                })
                .collect::<Vec<_>>();
            let steps = (0..24)
                .map(|_| match rng.random_range(0..10) {
                    0..=2 => Step::Prove(rng.random_range(0..VIEWS)),
                    3..=4 => Step::ProveBare(rng.random_range(0..VIEWS)),
                    5 => Step::ProveWeaker(rng.random_range(0..VIEWS)),
                    6..=7 => Step::Settle(rng.random_range(1..40)),
                    8 => Step::Restart,
                    _ => Step::Prune(rng.random_range(0..=total)),
                })
                .collect::<Vec<_>>();

            let mut seen = Vec::new();
            let mut newest = None;
            for step in steps {
                let follower = harness.mailbox(1);
                match step {
                    Step::Prove(view) => {
                        harness.script.prove(&follower, view);
                        newest = newest.max(Some(view));
                    }
                    Step::ProveBare(view) => {
                        harness.script.prove_bare(&follower, view);
                        newest = newest.max(Some(view));
                    }
                    Step::ProveWeaker(view) => {
                        harness.script.prove_certified(&follower, &weaker[view]);
                    }
                    Step::Settle(ms) => harness.settle(Duration::from_millis(ms)).await,
                    Step::Restart => {
                        seen.extend(harness.applications[1].delivered());
                        harness.applications[1].clear();
                        harness.crash(1).await;
                        harness.start(1).await;
                        if let Some(view) = newest {
                            harness.script.prove_bare(&harness.mailbox(1), view);
                        }
                    }
                    Step::Prune(index) => {
                        if let Some((at, _)) =
                            follower.floor_at(OutputIndex::new(index)).await.unwrap()
                        {
                            follower.prune(at).await.unwrap();
                        }
                    }
                }
            }
            // The newest proof alone lets the follower finish.
            harness.script.prove_bare(&harness.mailbox(1), VIEWS - 1);
            harness
                .wait_progress(1, |progress| progress.acknowledged.get() == total)
                .await;
            seen.extend(harness.applications[1].delivered());

            // Every update ever delivered names the canonical block at its index, and every index
            // is delivered at least once.
            for update in &seen {
                let index = update.index.get() as usize;
                assert_eq!(
                    update.block.reference(),
                    expected[index - 1].reference(),
                    "seed {seed}: index {index}"
                );
            }
            let mut indices = seen
                .iter()
                .map(|update| update.index.get())
                .collect::<Vec<_>>();
            indices.sort_unstable();
            indices.dedup();
            assert_eq!(indices, (1..=total).collect::<Vec<_>>(), "seed {seed}");

            // Every floor the follower serves ends where a proof's order ends (a view's, or a
            // weaker proof's inside it), and the newest one is the end of the stream (when the
            // stream emitted anything).
            let mut ends = Vec::new();
            let mut end = 0u64;
            for (view, counts) in counts.iter().enumerate() {
                let weaker = counts.iter().map(|count| count.min(&1)).sum::<usize>() as u64;
                ends.push(end + weaker);
                end += harness.script.views[view].ordered().len() as u64;
                ends.push(end);
            }
            let follower = harness.mailbox(1);
            for index in 0..=total {
                if let Some((at, _)) = follower.floor_at(OutputIndex::new(index)).await.unwrap() {
                    assert!(at.get() <= index && ends.contains(&at.get()), "seed {seed}");
                }
            }
            if total > 0 {
                let mut newest = 0;
                for _ in 0..100 {
                    if let Some((at, _)) = follower.floor_at(OutputIndex::new(total)).await.unwrap()
                    {
                        newest = at.get();
                        if newest == total {
                            break;
                        }
                    }
                    harness.settle(Duration::from_millis(10)).await;
                }
                assert_eq!(newest, total, "seed {seed}");
            }
        });
    }
}

#[test]
fn a_subscription_is_satisfied_by_the_broadcast_buffer() {
    runner(12).start(|context| async move {
        let mut harness = Harness::new(context, 12, 2).await;
        harness.start(0).await;
        harness.start(1).await;
        harness.script.certify([1, 0]);
        let block = harness.script.views[0].blocks[0][0].clone();
        let subscriber = harness.mailbox(1);
        let subscription = {
            let subscriber = subscriber.clone();
            let reference = block.reference();
            harness
                .context
                .child("subscriber")
                .spawn(move |_| async move { subscriber.subscribe_block(reference).await })
        };
        // A peer broadcasts the block; the subscriber never asks peers for it.
        harness.settle(Duration::from_millis(50)).await;
        harness.broadcast(0, &block);
        let received = subscription.await.unwrap().unwrap();
        assert_eq!(received, block);
        // The block is now held durably.
        assert_eq!(
            subscriber.get_block(block.reference()).await.unwrap(),
            Some(block)
        );
    });
}

#[test]
fn a_corrupting_peer_is_blocked_and_never_changes_the_stream() {
    runner(13).start(|context| async move {
        let mut harness = Harness::new(context, 13, 3).await;
        harness.corrupt(1);
        for index in 0..3 {
            harness.start(index).await;
        }
        for counts in [[2, 1], [1, 3], [2, 2]] {
            harness.script.certify(counts);
        }
        let expected = harness.script.ordered();
        for holder in 0..2 {
            let mailbox = harness.mailbox(holder);
            for view in 0..3 {
                harness.script.stage(&mailbox, view).await;
                harness.script.prove(&mailbox, view);
            }
            harness.wait_delivered(holder, expected.len()).await;
        }

        // The follower holds only the last proof. While the honest server is down, only the
        // corrupting server answers its history and body requests.
        harness.crash(0).await;
        harness.script.prove_bare(&harness.mailbox(2), 2);
        let corrupting = (harness.identity(2), harness.identity(1));
        let mut blocked = Vec::new();
        for _ in 0..400 {
            blocked = harness.blocked().await;
            if blocked.contains(&corrupting) {
                break;
            }
            harness.settle(Duration::from_millis(5)).await;
        }
        assert!(
            blocked.contains(&corrupting),
            "the corrupting server is blocked: {blocked:?}"
        );
        assert!(
            harness.applications[2].delivered().is_empty(),
            "nothing a corrupting server sends is delivered"
        );

        // Once the honest server is back, the follower delivers exactly the proven stream.
        harness.start(0).await;
        let delivered = harness.wait_delivered(2, expected.len()).await;
        assert_eq!(stream(&delivered), numbered(1, &expected));
        harness.settle(Duration::from_millis(100)).await;
        assert_eq!(harness.applications[2].delivered().len(), expected.len());
        let blocked = harness.blocked().await;
        assert!(
            !blocked.iter().any(|(_, peer)| *peer == harness.identity(0)),
            "the honest server is never blocked: {blocked:?}"
        );
    });
}

#[test]
fn a_full_fetch_budget_defers_requests_instead_of_losing_them() {
    runner(17).start(|context| async move {
        let mut harness = Harness::new(context, 17, 2).await;
        // Responses of one block and one response in flight at a time: every other request
        // waits for the budget.
        let one = std::num::NonZeroUsize::new(harness.limits.max_block_bytes.get() + 9).unwrap();
        harness.limits.max_response_bytes = one;
        harness.limits.max_fetch_bytes = one;
        harness.start(0).await;
        harness.start(1).await;
        for counts in [[3, 2], [2, 3], [1, 2], [2, 1]] {
            harness.script.certify(counts);
        }
        let holder = harness.mailbox(0);
        for view in 0..4 {
            harness.script.stage(&holder, view).await;
        }
        let follower = harness.mailbox(1);
        for view in 0..4 {
            harness.script.prove(&follower, view);
        }
        let expected = harness.script.ordered();
        let delivered = harness.wait_delivered(1, expected.len()).await;
        assert_eq!(stream(&delivered), numbered(1, &expected));
    });
}

#[test]
fn a_pending_subscription_never_blocks_fetching_a_proven_block() {
    runner(18).start(|context| async move {
        let mut harness = Harness::new(context, 18, 2).await;
        harness.start(0).await;
        harness.start(1).await;
        harness.script.certify([2, 1]);
        let holder = harness.mailbox(0);
        harness.script.stage(&holder, 0).await;
        // The follower subscribes to a block no broadcast will bring it.
        let follower = harness.mailbox(1);
        // The chain's tip: its position resolves by reference alone, so only its own fetch
        // brings it.
        let wanted = harness.script.views[0].blocks[0][1].reference();
        let subscription = {
            let follower = follower.clone();
            harness
                .context
                .child("subscription")
                .spawn(move |_| async move { follower.subscribe_block(wanted).await })
        };
        harness.settle(Duration::from_millis(20)).await;
        // Once a proof needs the block, the follower fetches it from the holder.
        harness.script.prove(&follower, 0);
        let expected = harness.script.ordered();
        let delivered = harness.wait_delivered(1, expected.len()).await;
        assert_eq!(stream(&delivered), numbered(1, &expected));
        let block = subscription.await.unwrap().unwrap();
        assert_eq!(block.reference(), wanted);
    });
}

/// Returns the chain and height of every delivered block.
fn coordinates(delivered: &[Delivered]) -> Vec<(u32, u64)> {
    delivered
        .iter()
        .map(|update| {
            let block = update.block.reference();
            (block.chain().get(), block.height().get())
        })
        .collect()
}

#[test]
fn payment_chains_are_delivered_first_in_every_sweep() {
    runner(21).start(|context| async move {
        let mut harness = Harness::with_payments(context, 21, 1).await;
        harness.start(0).await;
        harness.script.certify([2, 1]);
        harness.script.certify([1, 3]);
        let mailbox = harness.mailbox(0);
        for view in 0..2 {
            harness.script.stage(&mailbox, view).await;
            harness.script.prove(&mailbox, view);
        }
        let expected = harness.script.ordered();
        let delivered = harness.wait_delivered(0, expected.len()).await;
        assert_eq!(stream(&delivered), numbered(1, &expected));
        // Chain 1 is the payment chain: each sweep places all of its blocks before chain 0's.
        assert_eq!(
            coordinates(&delivered),
            vec![(1, 1), (0, 1), (0, 2), (1, 2), (1, 3), (1, 4), (0, 3)]
        );
    });
}

#[test]
fn a_floor_after_a_payment_pass_installs_only_where_payments_are_ordered_first() {
    runner(22).start(|context| async move {
        let mut harness = Harness::with_payments(context, 22, 3).await;
        harness.start(0).await;
        harness.script.certify([3, 3]);
        harness.script.certify([1, 1]);
        let holder = harness.mailbox(0);
        harness.script.stage(&holder, 0).await;
        // Chain 0 finalizes one block of the three it proposed: the sweep places every block of
        // the payment chain, whose anchor jumped three heights, then halts at chain 0's second
        // offset.
        let weak = harness.script.weaker(0, [1, 0]);
        harness.script.prove_certified(&holder, &weak);
        let delivered = harness.wait_delivered(0, 4).await;
        assert_eq!(
            coordinates(&delivered),
            vec![(1, 1), (1, 2), (1, 3), (0, 1)]
        );
        harness
            .wait_progress(0, |progress| progress.acknowledged.get() == 4)
            .await;
        let (index, floor) = loop {
            if let Some(found) = holder.floor_at(OutputIndex::new(4)).await.unwrap() {
                break found;
            }
            harness.settle(Duration::from_millis(10)).await;
        };
        assert_eq!(index.get(), 4);
        assert_eq!(
            floor
                .emitted()
                .iter()
                .map(|block| block.height().get())
                .collect::<Vec<_>>(),
            vec![1, 3]
        );

        // A node ordering without the payment chains ends the certificate's sweep elsewhere.
        harness.order_without_payments(2);
        harness.start(2).await;
        assert!(matches!(
            harness.mailbox(2).install_floor(floor.clone()).await,
            Err(Error::Rejected(reason))
                if reason == "the boundary is not where the certificate's sweep ends"
        ));

        // A node ordering them first installs it and delivers only what follows.
        harness.start(1).await;
        let follower = harness.mailbox(1);
        follower.install_floor(floor).await.unwrap();
        harness.script.stage(&holder, 1).await;
        for view in 0..2 {
            harness.script.prove(&holder, view);
            harness.script.prove(&follower, view);
        }
        let expected = harness.script.ordered();
        let delivered = harness.wait_delivered(1, expected.len() - 4).await;
        assert_eq!(stream(&delivered), numbered(5, &expected[4..]));
        assert_eq!(
            coordinates(&delivered),
            vec![(0, 2), (0, 3), (1, 4), (0, 4)]
        );
    });
}

#[test]
fn engine_neutral_floors_install_at_the_floor_index() {
    use crate::marshal::{Floors, Ledger};

    runner(14).start(|context| async move {
        let mut harness = Harness::new(context, 14, 2).await;
        harness.start(0).await;
        harness.script.certify([2, 1]);
        harness.script.certify([1, 2]);
        let holder = harness.mailbox(0);
        for view in 0..2 {
            harness.script.stage(&holder, view).await;
            harness.script.prove(&holder, view);
        }
        let total = harness.script.ordered().len() as u64;
        harness
            .wait_progress(0, |progress| progress.acknowledged.get() == total)
            .await;

        let first = harness.script.views[0].ordered().len() as u64;
        let (index, floor) = loop {
            if let Some(found) = Floors::floor_at(&holder, OutputIndex::new(first)).await {
                break found;
            }
            harness.settle(Duration::from_millis(10)).await;
        };
        assert_eq!(index.get(), first);

        harness.start(1).await;
        let follower = harness.mailbox(1);
        assert_eq!(Floors::install(&follower, floor.clone()).await, Some(index));
        // A floor the follower is no longer behind is rejected.
        assert_eq!(Floors::install(&follower, floor).await, None);
        assert_eq!(Ledger::ack_window(&follower), follower.max_pending_acks());
    });
}
