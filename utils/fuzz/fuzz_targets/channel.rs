#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_utils::{
    channel::{
        fallible::{AsyncFallibleExt, FallibleExt},
        mpsc,
        reservation::ReservationExt,
        ring, tracked,
    },
    NZUsize,
};
use futures::{executor::block_on, stream::FusedStream, SinkExt};
use libfuzzer_sys::fuzz_target;

const BUFFER_SIZE: usize = 2;
const MIN_OPERATIONS: usize = 4;
const MAX_OPERATIONS: usize = 64;

#[derive(Debug)]
enum Operation {
    SendReceive {
        batch: Option<u32>,
        data: Vec<u8>,
    },
    MultipleSends {
        batches: Vec<Option<u32>>,
        data: Vec<Vec<u8>>,
    },
    CloneGuard {
        batch: Option<u32>,
        data: u64,
        num_clones: u8,
    },
    TrySend {
        batch: Option<u32>,
        data: String,
    },
    Ring {
        capacity: u8,
        items: Vec<u32>,
        drop_senders_early: bool,
    },
    Reserve {
        first: u32,
        second: u32,
    },
    Fallible {
        msg: u32,
        bounded: bool,
        disconnect: bool,
    },
}

// Every arm is an independent scenario, so select the variant with one byte:
// the derived u32 selector collapses short, empty-corpus inputs onto variant 0,
// leaving the later arms unreached.
impl<'a> Arbitrary<'a> for Operation {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(match u.int_in_range(0u8..=6)? {
            0 => Operation::SendReceive {
                batch: u.arbitrary()?,
                data: u.arbitrary()?,
            },
            1 => Operation::MultipleSends {
                batches: u.arbitrary()?,
                data: u.arbitrary()?,
            },
            2 => Operation::CloneGuard {
                batch: u.arbitrary()?,
                data: u.arbitrary()?,
                num_clones: u.arbitrary()?,
            },
            3 => Operation::TrySend {
                batch: u.arbitrary()?,
                data: u.arbitrary()?,
            },
            4 => Operation::Ring {
                capacity: u.arbitrary()?,
                items: u.arbitrary()?,
                drop_senders_early: u.arbitrary()?,
            },
            5 => Operation::Reserve {
                first: u.arbitrary()?,
                second: u.arbitrary()?,
            },
            _ => Operation::Fallible {
                msg: u.arbitrary()?,
                bounded: u.arbitrary()?,
                disconnect: u.arbitrary()?,
            },
        })
    }
}

#[derive(Debug)]
struct FuzzInput {
    operations: Vec<Operation>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let num_operations = u.int_in_range(MIN_OPERATIONS..=MAX_OPERATIONS)?;
        let mut operations = Vec::with_capacity(num_operations);
        for _ in 0..num_operations {
            operations.push(Operation::arbitrary(u)?);
        }
        Ok(FuzzInput { operations })
    }
}

fn fuzz(op: Operation) {
    match op {
        Operation::SendReceive { batch, data } => {
            block_on(async {
                let (sender, mut receiver) = tracked::bounded::<Vec<u8>, u32>(10);

                if let Ok(_seq) = sender.send(batch, data.clone()).await {
                    if let Some(b) = batch {
                        // The just-sent, undelivered message counts as pending.
                        assert_eq!(sender.pending(b), 1);
                    }
                    // Watermark never exceeds the number of messages sent.
                    assert!(sender.watermark() <= 1);

                    if let Some(msg) = receiver.recv().await {
                        // The received payload must equal what was sent.
                        assert_eq!(msg.data, data);
                        drop(msg.guard);
                    }
                }
            });
        }

        Operation::MultipleSends { batches, data } => {
            block_on(async {
                let (sender, mut receiver) = tracked::bounded::<Vec<u8>, u32>(BUFFER_SIZE);
                let mut in_flight = 0usize;

                for (batch, d) in batches.iter().zip(data.iter()) {
                    if in_flight >= BUFFER_SIZE {
                        match receiver.recv().await {
                            Some(msg) => {
                                drop(msg);
                                in_flight -= 1;
                            }
                            None => break,
                        }
                    }

                    match sender.send(*batch, d.clone()).await {
                        Ok(_) => in_flight += 1,
                        Err(_) => break,
                    }
                }

                // Watermark never exceeds the number of messages enqueued.
                assert!(sender.watermark() <= data.len() as u64);

                while let Ok(msg) = receiver.try_recv() {
                    drop(msg);
                }
            });
        }

        Operation::CloneGuard {
            batch,
            data,
            num_clones,
        } => {
            block_on(async {
                let (sender, mut receiver) = tracked::bounded::<u64, u32>(10);

                if let Ok(_seq) = sender.send(batch, data).await {
                    if let Some(msg) = receiver.recv().await {
                        let mut guards = vec![msg.guard];
                        for _ in 0..(num_clones % 10) {
                            guards.push(guards[0].clone());
                        }
                        drop(guards);
                        // Dropping every guard clone marks the message delivered.
                        if let Some(b) = batch {
                            assert_eq!(sender.pending(b), 0);
                        }
                    }

                    // Watermark never exceeds the number of messages sent.
                    assert!(sender.watermark() <= 1);
                }
            });
        }

        Operation::TrySend { batch, data } => {
            block_on(async {
                let (sender, mut receiver) = tracked::bounded::<String, u32>(5);

                // A fresh capacity-5 channel accepts the first try_send.
                assert!(sender.try_send(batch, data.clone()).is_ok());
                // Watermark never exceeds the number of messages sent.
                assert!(sender.watermark() <= 1);

                while let Ok(msg) = receiver.try_recv() {
                    drop(msg);
                }
            });
        }

        Operation::Ring {
            capacity,
            items,
            drop_senders_early,
        } => {
            block_on(async {
                let cap = (capacity as usize % 8) + 1;
                let (mut sender, mut receiver) = ring::channel::<u32>(NZUsize!(cap));

                // Newly created channel: receiver alive, not terminated.
                assert!(!sender.is_closed());
                assert!(!receiver.is_terminated());

                // try_recv on an empty channel with a live sender is Empty.
                assert_eq!(receiver.try_recv(), Err(ring::TryRecvError::Empty));

                // Send all items via the Sink (exercises poll_ready/start_send/poll_flush).
                for &item in items.iter() {
                    sender.send(item).await.unwrap();
                }

                // The ring keeps only the most-recent `cap` items.
                let expected: Vec<u32> = items.iter().rev().take(cap).rev().copied().collect();

                if drop_senders_early {
                    drop(sender);
                    // No senders remain; once buffer drains, recv yields None.
                    let mut got = Vec::new();
                    while let Some(v) = receiver.recv().await {
                        got.push(v);
                    }
                    assert_eq!(got, expected);
                    // All senders gone and buffer empty => terminated.
                    assert!(receiver.is_terminated());
                    assert_eq!(receiver.try_recv(), Err(ring::TryRecvError::Disconnected));
                } else {
                    let mut got = Vec::new();
                    for _ in 0..expected.len() {
                        got.push(receiver.recv().await.unwrap());
                    }
                    assert_eq!(got, expected);
                    // Senders still alive but buffer drained.
                    assert_eq!(receiver.try_recv(), Err(ring::TryRecvError::Empty));
                    assert!(!receiver.is_terminated());

                    // Dropping the receiver closes the channel for senders.
                    drop(receiver);
                    assert!(sender.is_closed());
                    assert!(sender.send(0).await.is_err());
                }
            });
        }

        Operation::Reserve { first, second } => {
            block_on(async {
                let (sender, mut receiver) = mpsc::channel::<u32>(1);

                // Capacity 1: first value is sent immediately (no reservation).
                assert!(sender.send_or_reserve(first).unwrap().is_none());

                // Channel now full: second value must be reserved.
                let reservation = sender
                    .send_or_reserve(second)
                    .unwrap()
                    .expect("channel should be full");

                // Drain the first value to free capacity, then deliver the reserved one.
                assert_eq!(receiver.recv().await, Some(first));
                reservation.await.unwrap().send();
                assert_eq!(receiver.recv().await, Some(second));
            });
        }

        Operation::Fallible {
            msg,
            bounded,
            disconnect,
        } => {
            block_on(async {
                if bounded {
                    let (tx, mut rx) = mpsc::channel::<u32>(1);
                    if disconnect {
                        drop(rx);
                        // Receiver gone: lossy send reports failure, no reservation handed back.
                        assert!(!tx.send_lossy(msg).await);
                        assert!(tx.send_or_reserve_lossy(msg).is_none());
                        // request_or returns the supplied default on failure.
                        assert_eq!(tx.request_or(|_resp| msg, msg).await, msg);
                    } else {
                        // Empty channel: lossy send succeeds and value round-trips.
                        assert!(tx.send_lossy(msg).await);
                        assert_eq!(rx.recv().await, Some(msg));
                        // Channel empty again: immediate send leaves no reservation.
                        assert!(tx.send_or_reserve_lossy(msg).is_none());
                        assert_eq!(rx.recv().await, Some(msg));
                    }
                } else {
                    let (tx, rx) = mpsc::unbounded_channel::<u32>();
                    drop(rx);
                    // Unbounded sender, receiver dropped: request_or yields the default.
                    assert_eq!(tx.request_or(|_resp| msg, msg).await, msg);
                }
            });
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    for op in input.operations {
        fuzz(op);
    }
});
