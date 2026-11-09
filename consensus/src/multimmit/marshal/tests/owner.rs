//! Marshal's public queue and its owner under load.

use super::harness::*;
use crate::multimmit::{
    actors::util::Completion,
    marshal::{Error, Mailbox, input::Lane, input::Message},
};
use commonware_runtime::{Clock as _, Runner as _, Spawner as _, Supervisor as _};
use commonware_utils::{NZUsize, channel::mpsc};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

/// Sums every series of the counter `name` that `context`'s metrics report.
fn counter(context: &impl commonware_runtime::Metrics, name: &str) -> u64 {
    context
        .encode()
        .lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| {
            let (series, value) = line.rsplit_once(' ')?;
            let family = series.split('{').next()?;
            family.ends_with(name).then(|| value.parse::<f64>().ok())?
        })
        .sum::<f64>() as u64
}

#[test]
fn staging_waits_behind_subscriptions_for_room_in_a_full_queue() {
    runner(40).start(|context| async move {
        let mut script = Script::new(40);
        script.certify([2, 0]);
        let blocks = &script.views[0].blocks[0];
        let (sender, mut queue) = mpsc::channel(1);
        let (lane, _signal) = Lane::new(CHAINS, 1024);
        let mailbox: TestMailbox = Mailbox::new(sender, lane, None, NZUsize!(1));

        // One subscription fills the queue and another waits for room.
        for block in blocks {
            let mailbox = mailbox.clone();
            let reference = block.reference();
            context
                .child("subscriber")
                .spawn(move |_| async move { mailbox.subscribe_block(reference).await });
        }
        context.sleep(Duration::from_millis(1)).await;

        // Staging waits behind them instead of failing while the queue is full.
        let staged = Arc::new(AtomicBool::new(false));
        let stage = {
            let mailbox = mailbox.clone();
            let block = Arc::clone(&blocks[0]);
            let staged = Arc::clone(&staged);
            context.child("stage").spawn(move |_| async move {
                let result = mailbox.stage_block(block).await;
                staged.store(true, Ordering::SeqCst);
                result
            })
        };
        context.sleep(Duration::from_millis(1)).await;
        assert!(!staged.load(Ordering::SeqCst), "staging waits for room");

        // Room goes to the waiting requests in order: both subscriptions, then the stage.
        let mut subscribed = Vec::new();
        for _ in blocks {
            let Some(Message::Subscribe { block, .. }) = queue.recv().await else {
                panic!("the subscriptions come first");
            };
            subscribed.push(block);
        }
        subscribed.sort();
        let mut wanted = blocks.iter().map(|block| block.reference()).collect::<Vec<_>>();
        wanted.sort();
        assert_eq!(subscribed, wanted);
        let Some(Message::Stage { block, reply }) = queue.recv().await else {
            panic!("the stage follows the subscriptions");
        };
        assert_eq!(block.reference(), blocks[0].reference());
        let (token, custody) = Completion::channel(|| Error::Closed);
        let _ = reply.send(Ok(custody));
        let _ = token.send(Ok(()));
        stage.await.unwrap().unwrap().wait().await.unwrap();
    });
}

#[test]
fn the_owner_takes_every_ready_request_in_one_turn() {
    runner(41).start(|context| async move {
        let mut harness = Harness::new(context.child("harness"), 41, 1).await;
        harness.start(0).await;
        harness.settle(Duration::from_millis(50)).await;
        let turns = counter(&context, "ledger_turns_total");
        let inputs = counter(&context, "ledger_inputs_total");

        // Requests that arrive together are taken together, and the owner drives its machines
        // once for all of them rather than once for each.
        const REQUESTS: u64 = 200;
        let mailbox = harness.mailbox(0);
        let requests = (0..REQUESTS)
            .map(|_| {
                let mailbox = mailbox.clone();
                context
                    .child("request")
                    .spawn(move |_| async move { mailbox.progress().await })
            })
            .collect::<Vec<_>>();
        for request in requests {
            request.await.unwrap().unwrap();
        }
        let turns = counter(&context, "ledger_turns_total") - turns;
        let inputs = counter(&context, "ledger_inputs_total") - inputs;
        assert!(inputs >= REQUESTS, "every request is an input: {inputs}");
        assert!(
            turns * 20 < inputs,
            "{inputs} inputs took {turns} turns, so they were not taken together"
        );
    });
}
