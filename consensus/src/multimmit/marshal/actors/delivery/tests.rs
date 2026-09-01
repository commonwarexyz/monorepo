//! Delivery actor tests: cursor durability, batching, caching, and acknowledgement retirement.

use super::{
    acks::{AcknowledgementEvent, PendingAcks},
    actor::Error,
    batch::{DeliveryOutput, DurableBatch, HotOutput},
    cache::DeliveryCache,
    mailbox::{Message, channel},
    metrics::Metrics,
};
use crate::{
    multimmit::{
        marshal::{storage::catalog::StoredRef, types::OutputIndex},
        testing::TestBody,
        types::{ChainId, TransactionBlock, TransactionBlockHeader},
    },
    types::{Epoch, Height},
};
use commonware_actor::Feedback;
use commonware_codec::EncodeSize as _;
use commonware_cryptography::{Digestible as _, Hasher as _, Sha256};
use commonware_runtime::{Runner as _, deterministic};
use commonware_utils::{
    Acknowledgement as _, acknowledgement::Exact, channel::fallible::OneshotExt as _,
};
use futures::FutureExt as _;
use std::{num::NonZeroUsize, sync::Arc};

fn output(index: u64) -> HotOutput<Sha256, TestBody> {
    let body = TestBody::new(
        Sha256::hash(&[b"body parent", &index.to_be_bytes()]),
        Height::new(index.saturating_add(1)),
        index,
    );
    let header = TransactionBlockHeader::new(
        Epoch::new(7),
        ChainId::new(0),
        Height::new(index.saturating_add(1)),
        Sha256::hash(&[b"block parent", &index.to_be_bytes()]),
        body.digest(),
    )
    .unwrap();
    let block = Arc::new(TransactionBlock::new(header, body).unwrap());
    HotOutput {
        stored: StoredRef {
            index: OutputIndex::new(index),
            reference: block.reference(),
            encoded_len: u64::try_from(block.encode_size()).unwrap(),
            floor_generation: 0,
        },
        block,
    }
}

fn durable_batch(
    floor_generation: u64,
    committed: u64,
    outputs: Vec<HotOutput<Sha256, TestBody>>,
    max_bytes: u64,
) -> DurableBatch<Sha256, TestBody> {
    let mut builder =
        DurableBatch::builder(floor_generation, OutputIndex::new(committed), max_bytes);
    for output in outputs {
        assert!(builder.push(DeliveryOutput::Hot(output)).is_ok());
    }
    builder.build()
}

#[test]
fn restart_cursor_is_exactly_after_durable_acknowledgement() {
    let pending = PendingAcks::new(NonZeroUsize::MIN);
    assert_eq!(pending.next(None).unwrap(), Some(OutputIndex::ZERO));
    assert_eq!(
        pending.next(Some(OutputIndex::new(41))).unwrap(),
        Some(OutputIndex::new(42))
    );
    assert!(matches!(
        pending.next(Some(OutputIndex::new(u64::MAX))),
        Err(Error::IndexExhausted)
    ));
}

#[test]
fn batch_builder_rejects_outputs_past_its_budget() {
    let first = output(0);
    let second = output(1);
    let max_bytes = DeliveryOutput::Hot(first.clone()).retained_bytes();
    let mut builder = DurableBatch::builder(0, OutputIndex::new(1), max_bytes);
    assert!(builder.push(DeliveryOutput::Hot(first)).is_ok());
    assert_eq!(builder.bytes(), max_bytes);
    let Err(DeliveryOutput::Hot(rejected)) = builder.push(DeliveryOutput::Hot(second)) else {
        panic!("an output past the budget was accepted");
    };
    assert_eq!(rejected.stored.index, OutputIndex::new(1));
    let batch = builder.build();
    assert_eq!(batch.outputs.len(), 1);
}

#[test]
fn overflow_coalesces_body_handoff_without_losing_committed_progress() {
    deterministic::Runner::default().start(|context| async move {
        let (client, mut receiver) = channel::<Sha256, TestBody>(context);
        let max_bytes = DeliveryOutput::Hot(output(1)).retained_bytes()
            + DeliveryOutput::Hot(output(2)).retained_bytes();
        let batch = |index| durable_batch(0, index, vec![output(index)], max_bytes);

        assert_eq!(client.committed(batch(0)), Feedback::Ok);
        assert_eq!(client.committed(batch(1)), Feedback::Backoff);
        assert_eq!(client.committed(batch(2)), Feedback::Backoff);
        assert_eq!(client.committed(batch(3)), Feedback::Backoff);
        assert!(matches!(receiver.recv().await, Some(Message::Committed(_))));
        let Some(Message::Committed(batch)) = receiver.recv().await else {
            panic!("overflow did not retain the hot delivery handoff");
        };
        assert_eq!(batch.committed, OutputIndex::new(3));
        assert_eq!(
            batch
                .outputs
                .iter()
                .map(|output| output.stored().index)
                .collect::<Vec<_>>(),
            vec![OutputIndex::new(1), OutputIndex::new(2)]
        );
        assert!(receiver.try_recv().is_err());
    });
}

#[test]
fn newest_reset_supersedes_older_overflow() {
    deterministic::Runner::default().start(|context| async move {
        let (client, mut receiver) = channel(context);
        let batch = |index| durable_batch(0, index, vec![output(index)], u64::MAX);

        assert_eq!(client.committed(batch(0)), Feedback::Ok);
        let first = client.reset(1, None).unwrap();
        assert_eq!(client.committed(batch(1)), Feedback::Backoff);
        let second = client.reset(2, Some(OutputIndex::ZERO)).unwrap();
        assert_eq!(client.committed(batch(2)), Feedback::Backoff);
        assert!(matches!(receiver.recv().await, Some(Message::Committed(_))));
        let Some(Message::Reset {
            floor_generation,
            acknowledged,
            waiters,
        }) = receiver.recv().await
        else {
            panic!("newest reset was not retained");
        };
        assert_eq!(floor_generation, 2);
        assert_eq!(acknowledged, Some(OutputIndex::ZERO));
        assert_eq!(waiters.len(), 2);
        for waiter in waiters {
            waiter.send_lossy(Ok(()));
        }
        first.wait().await.unwrap();
        second.wait().await.unwrap();
        let Some(Message::Committed(batch)) = receiver.recv().await else {
            panic!("post-reset publication was not retained");
        };
        assert_eq!(batch.committed, OutputIndex::new(2));
        assert!(receiver.try_recv().is_err());
    });
}

#[test]
fn delivery_cache_retains_the_earliest_byte_bounded_prefix() {
    let first = output(0);
    let second = output(1);
    let third = output(2);
    let max = usize::try_from(first.stored.encoded_len + second.stored.encoded_len).unwrap();
    let mut cache = DeliveryCache::new(NonZeroUsize::new(max).unwrap());
    cache.insert(
        durable_batch(4, 2, vec![first, second, third], u64::MAX),
        OutputIndex::ZERO,
    );

    assert!(cache.take_hot(OutputIndex::ZERO).is_some());
    assert!(cache.take_hot(OutputIndex::new(1)).is_some());
    assert!(cache.take_hot(OutputIndex::new(2)).is_none());
    cache.insert(
        durable_batch(3, 3, vec![output(3)], u64::MAX),
        OutputIndex::new(4),
    );
    assert!(cache.take_hot(OutputIndex::new(3)).is_none());

    let mut cache = DeliveryCache::new(NonZeroUsize::MIN);
    cache.insert(
        durable_batch(4, 0, vec![output(0)], u64::MAX),
        OutputIndex::ZERO,
    );
    assert!(cache.take_hot(OutputIndex::ZERO).is_none());
}

#[test]
fn delivery_cache_takes_descriptors_up_to_the_next_hot_output() {
    let mut builder = DurableBatch::builder(0, OutputIndex::new(3), u64::MAX);
    for index in 0..2 {
        assert!(
            builder
                .push(DeliveryOutput::Descriptor(output(index).stored))
                .is_ok()
        );
    }
    assert!(builder.push(DeliveryOutput::Hot(output(2))).is_ok());
    let mut cache = DeliveryCache::new(NonZeroUsize::new(usize::MAX).unwrap());
    cache.insert(builder.build(), OutputIndex::ZERO);

    assert!(cache.take_hot(OutputIndex::ZERO).is_none());
    let refs = cache.take_refs(
        OutputIndex::ZERO,
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(usize::MAX).unwrap(),
    );
    assert_eq!(
        refs.iter().map(|stored| stored.index).collect::<Vec<_>>(),
        vec![OutputIndex::ZERO, OutputIndex::new(1)]
    );
    assert!(cache.take_hot(OutputIndex::new(2)).is_some());
}

#[test]
fn pending_acknowledgements_are_bounded_and_retire_fifo() {
    let mut pending = PendingAcks::new(NonZeroUsize::new(2).unwrap());
    assert_eq!(pending.next(None).unwrap(), Some(OutputIndex::ZERO));

    let (first, first_waiter) = Exact::handle();
    pending.push(OutputIndex::ZERO, first_waiter);
    let (second, second_waiter) = Exact::handle();
    pending.push(OutputIndex::new(1), second_waiter);
    assert!(!pending.has_capacity());
    assert_eq!(pending.next(None).unwrap(), Some(OutputIndex::new(2)));

    second.acknowledge();
    assert!(pending.try_current().is_none());
    first.acknowledge();
    let result = pending.try_current().unwrap();
    let acknowledged = pending.complete(result).unwrap();
    assert_eq!(acknowledged.through, OutputIndex::new(1));
    assert_eq!(acknowledged.outputs, 2);
    assert!(pending.is_empty());

    let (last, last_waiter) = Exact::handle();
    pending.push(OutputIndex::new(u64::MAX), last_waiter);
    assert_eq!(pending.next(None).unwrap(), None);
    last.acknowledge();
    let result = pending.try_current().unwrap();
    let acknowledged = pending.complete(result).unwrap();
    assert_eq!(acknowledged.through, OutputIndex::new(u64::MAX));
    assert_eq!(acknowledged.outputs, 1);
}

#[test]
fn canceled_acknowledgement_stops_fifo_retirement() {
    let mut pending = PendingAcks::new(NonZeroUsize::MIN);
    let (acknowledgement, waiter) = Exact::handle();
    pending.push(OutputIndex::ZERO, waiter);
    drop(acknowledgement);

    let result = pending.try_current().unwrap();
    assert!(matches!(
        pending.complete(result),
        Err(Error::AcknowledgementCanceled)
    ));
}

#[test]
fn completed_cursor_sync_precedes_ready_application_acknowledgements() {
    deterministic::Runner::default().start(|context| async move {
        let metrics = Metrics::new(&context);
        let mut pending = PendingAcks::new(NonZeroUsize::MIN);
        let (first, waiter) = Exact::handle();
        pending.push(OutputIndex::ZERO, waiter);
        first.acknowledge();
        let result = pending.try_current().unwrap();
        let acknowledged = pending.complete(result).unwrap();
        pending.coalesce_ready(acknowledged, || metrics.completion_timer(&context));
        let ready = pending.take_ready().unwrap();
        pending.start_sync(
            ready,
            metrics.durability_timer(&context),
            futures::future::ready(Ok(())).boxed(),
        );

        let (next, waiter) = Exact::handle();
        pending.push(OutputIndex::new(1), waiter);
        next.acknowledge();
        assert!(matches!(
            pending.next_event().await,
            AcknowledgementEvent::Durable(Ok(()))
        ));
        assert_eq!(
            pending.complete_sync(Ok(())).unwrap().through,
            OutputIndex::ZERO
        );
        assert_eq!(pending.in_flight(), 1);
    });
}

#[test]
fn ready_acknowledgements_release_capacity_during_cursor_sync() {
    deterministic::Runner::default().start(|context| async move {
        let metrics = Metrics::new(&context);
        let mut pending = PendingAcks::new(NonZeroUsize::new(2).unwrap());
        let (first, first_waiter) = Exact::handle();
        pending.push(OutputIndex::ZERO, first_waiter);
        let (second, second_waiter) = Exact::handle();
        pending.push(OutputIndex::new(1), second_waiter);
        first.acknowledge();
        second.acknowledge();

        let result = pending.try_current().unwrap();
        let acknowledged = pending.complete(result).unwrap();
        pending.coalesce_ready(acknowledged, || metrics.completion_timer(&context));
        let ready = pending.take_ready().unwrap();
        pending.start_sync(
            ready,
            metrics.durability_timer(&context),
            futures::future::pending().boxed(),
        );
        assert_eq!(pending.pending_durability(), 2);
        assert!(pending.has_capacity());
        assert_eq!(pending.in_flight(), 0);
        assert_eq!(pending.next(None).unwrap(), Some(OutputIndex::new(2)));

        let (third, third_waiter) = Exact::handle();
        pending.push(OutputIndex::new(2), third_waiter);
        let (fourth, fourth_waiter) = Exact::handle();
        pending.push(OutputIndex::new(3), fourth_waiter);
        assert!(!pending.has_capacity());
        assert_eq!(pending.in_flight(), 2);
        assert_eq!(pending.next(None).unwrap(), Some(OutputIndex::new(4)));

        third.acknowledge();
        fourth.acknowledge();
        let AcknowledgementEvent::Ready(result) = pending.next_event().await else {
            panic!("pending durability prevented ready acknowledgement processing");
        };
        let acknowledged = pending.complete(result).unwrap();
        pending.coalesce_ready(acknowledged, || metrics.completion_timer(&context));
        assert!(pending.has_capacity());
        assert_eq!(pending.in_flight(), 0);
        assert_eq!(pending.pending_durability(), 4);
        assert_eq!(pending.next(None).unwrap(), Some(OutputIndex::new(4)));

        pending.complete_sync(Ok(())).unwrap();
        assert!(pending.has_capacity());
        assert!(!pending.is_empty());
        assert_eq!(pending.pending_durability(), 2);
    });
}
