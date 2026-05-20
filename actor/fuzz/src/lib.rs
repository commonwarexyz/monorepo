use arbitrary::{Arbitrary, Unstructured};
use commonware_actor::{mailbox, Feedback};
use commonware_runtime::{deterministic, Clock, Metrics, Runner, Spawner, Supervisor};
use commonware_utils::{sync::Mutex, FuzzRng};
use rand::Rng;
use std::{
    collections::{BTreeSet, VecDeque},
    num::NonZeroUsize,
    sync::Arc,
    time::Duration,
};

const MAX_CAPACITY: usize = 8;
const MAX_OPERATIONS: usize = 64;
const MAX_SENDERS: u8 = 8;
const MAX_SENDER_INDEX: u8 = 15;
const MAX_BATCH_MESSAGES: usize = 8;
const MAX_DRAIN: usize = 8;
const MAX_OPERATION_INDEX: u8 = 8;
const PARK_SLEEP_DURATION: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Retain,
    Reject,
}

#[derive(Clone, Copy, Debug)]
struct EnqueueInput {
    sender: u8,
    kind: Kind,
}

#[derive(Clone, Debug)]
enum Operation {
    Enqueue(EnqueueInput),
    Batch(Vec<EnqueueInput>),
    TryRecv {
        limit: usize,
    },
    Recv {
        limit: usize,
    },
    ParkedRecv {
        sender: u8,
        extra: Vec<EnqueueInput>,
    },
    CloneSender {
        index: u8,
    },
    DropSender {
        index: u8,
    },
    DropReceiver {
        index: u8,
    },
    DropReceiverWithOverflow {
        sender: u8,
    },
}

#[derive(Clone, Copy, Debug)]
struct CoalesceInput {
    sender: u8,
    coalesce: bool,
}

#[derive(Debug)]
pub struct FifoInput {
    capacity: usize,
    raw_bytes: Vec<u8>,
}

#[derive(Debug)]
pub struct CoalesceFuzzInput {
    capacity: usize,
    raw_bytes: Vec<u8>,
}

fn extract_raw_bytes(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<u8>> {
    let remaining = u.len();
    if remaining == 0 {
        Ok(vec![0])
    } else {
        Ok(u.bytes(remaining)?.to_vec())
    }
}

impl<'a> Arbitrary<'a> for FifoInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            capacity: u.int_in_range(1..=MAX_CAPACITY)?,
            raw_bytes: extract_raw_bytes(u)?,
        })
    }
}

impl<'a> Arbitrary<'a> for CoalesceFuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            capacity: u.int_in_range(1..=MAX_CAPACITY)?,
            raw_bytes: extract_raw_bytes(u)?,
        })
    }
}

fn gen_kind(rng: &mut FuzzRng) -> Kind {
    if rng.gen_bool(0.5) {
        Kind::Retain
    } else {
        Kind::Reject
    }
}

fn gen_enqueue_input(rng: &mut FuzzRng) -> EnqueueInput {
    EnqueueInput {
        sender: rng.gen_range(0..MAX_SENDERS),
        kind: gen_kind(rng),
    }
}

fn gen_operation(rng: &mut FuzzRng) -> Operation {
    match rng.gen_range(0..=MAX_OPERATION_INDEX) {
        0 => Operation::Enqueue(gen_enqueue_input(rng)),
        1 => {
            let len = rng.gen_range(1..=MAX_BATCH_MESSAGES);
            let messages = (0..len).map(|_| gen_enqueue_input(rng)).collect();
            Operation::Batch(messages)
        }
        2 => Operation::TryRecv {
            limit: rng.gen_range(0..=MAX_DRAIN),
        },
        3 => Operation::Recv {
            limit: rng.gen_range(0..=MAX_DRAIN),
        },
        4 => {
            let len = rng.gen_range(0..=MAX_BATCH_MESSAGES);
            let extra = (0..len).map(|_| gen_enqueue_input(rng)).collect();
            Operation::ParkedRecv {
                sender: rng.gen_range(0..MAX_SENDERS),
                extra,
            }
        }
        5 => Operation::CloneSender {
            index: rng.gen_range(0..=MAX_SENDER_INDEX),
        },
        6 => Operation::DropSender {
            index: rng.gen_range(0..=MAX_SENDER_INDEX),
        },
        7 => Operation::DropReceiver {
            index: rng.gen_range(0..=MAX_SENDER_INDEX),
        },
        8 => Operation::DropReceiverWithOverflow {
            sender: rng.gen_range(0..MAX_SENDERS),
        },
        _ => unreachable!(),
    }
}

fn gen_operations(rng: &mut FuzzRng) -> Vec<Operation> {
    let len = rng.gen_range(1..=MAX_OPERATIONS);
    (0..len).map(|_| gen_operation(rng)).collect()
}

fn gen_coalesce_input(rng: &mut FuzzRng) -> CoalesceInput {
    CoalesceInput {
        sender: rng.gen_range(0..MAX_SENDERS),
        coalesce: rng.gen_bool(0.5),
    }
}

fn gen_coalesce_inputs(rng: &mut FuzzRng) -> Vec<CoalesceInput> {
    let len = rng.gen_range(1..=MAX_OPERATIONS);
    (0..len).map(|_| gen_coalesce_input(rng)).collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Message {
    sender: u8,
    sequence: u64,
    kind: Kind,
}

impl mailbox::Policy for Message {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut VecDeque<Self>, message: Self) -> bool {
        match message.kind {
            Kind::Retain => {
                overflow.push_back(message);
                true
            }
            Kind::Reject => false,
        }
    }
}

#[derive(Debug)]
struct FifoState {
    expected: Vec<VecDeque<u64>>,
    observed: Vec<Vec<u64>>,
    next_sequence: Vec<u64>,
    backoffs: usize,
    receiver_alive: bool,
}

impl FifoState {
    fn new() -> Self {
        Self {
            expected: vec![VecDeque::new(); MAX_SENDERS as usize],
            observed: vec![Vec::new(); MAX_SENDERS as usize],
            next_sequence: vec![0; MAX_SENDERS as usize],
            backoffs: 0,
            receiver_alive: true,
        }
    }

    fn pending(&self) -> usize {
        self.expected.iter().map(VecDeque::len).sum()
    }

    fn message(&self, input: EnqueueInput) -> Message {
        let sender = input.sender % MAX_SENDERS;
        Message {
            sender,
            sequence: self.next_sequence[sender as usize],
            kind: input.kind,
        }
    }

    fn sent(&mut self, message: Message, feedback: Feedback) {
        match feedback {
            Feedback::Ok | Feedback::Backoff => {
                assert!(feedback.accepted());
                self.expected[message.sender as usize].push_back(message.sequence);
                self.next_sequence[message.sender as usize] += 1;
                if feedback == Feedback::Backoff {
                    self.backoffs += 1;
                }
            }
            Feedback::Rejected => {
                assert!(!feedback.accepted());
            }
            Feedback::Closed => {
                assert!(!self.receiver_alive);
                assert!(!feedback.accepted());
            }
        }
    }

    fn observe(&mut self, message: Message) {
        let sender = message.sender as usize;
        assert_eq!(self.expected[sender].pop_front(), Some(message.sequence));
        if let Some(previous) = self.observed[sender].last() {
            assert!(previous < &message.sequence);
        }
        self.observed[sender].push(message.sequence);
    }

    fn close(&mut self) {
        self.receiver_alive = false;
        for expected in &mut self.expected {
            expected.clear();
        }
    }
}

fn send_fifo(
    senders: &[mailbox::Sender<Message>],
    state: &mut FifoState,
    sender_index: usize,
    input: EnqueueInput,
) {
    if senders.is_empty() {
        return;
    }
    let message = state.message(input);
    let feedback = senders[sender_index % senders.len()].enqueue(message);
    state.sent(message, feedback);
}

fn drain_try_fifo(receiver: &mut mailbox::Receiver<Message>, state: &mut FifoState, limit: usize) {
    for _ in 0..limit {
        match receiver.try_recv() {
            Ok(message) => state.observe(message),
            Err(_) => break,
        }
    }
}

fn metric_value(metrics: &str, name: &str) -> Option<usize> {
    let prefix = format!("{name} ");
    let labeled_prefix = format!("{name}{{");
    let mut value = None;
    for line in metrics.lines().filter(|line| !line.starts_with('#')) {
        assert!(!line.starts_with(&labeled_prefix), "{metrics}");
        if let Some(raw) = line.strip_prefix(&prefix) {
            assert!(value.is_none(), "{metrics}");
            value = Some(raw.parse().expect("invalid metric value"));
        }
    }
    value
}

fn assert_metric(metrics: &str, name: &str, expected: usize) {
    assert_eq!(
        metric_value(metrics, name).expect("missing metric"),
        expected,
        "{metrics}"
    );
}

fn assert_only_mailbox_counter(metrics: &str, prefix: &str, expected: &str) {
    for line in metrics.lines().filter(|line| !line.starts_with('#')) {
        let Some(sample) = line.split_once(' ').map(|(sample, _)| sample) else {
            continue;
        };
        let base = sample.split_once('{').map_or(sample, |(base, _)| base);
        if base.starts_with(prefix) {
            assert_eq!(sample, expected, "{metrics}");
        }
    }
}

async fn drain_recv_fifo(
    receiver: &mut mailbox::Receiver<Message>,
    state: &mut FifoState,
    limit: usize,
) {
    for _ in 0..limit {
        if state.pending() == 0 && state.receiver_alive {
            break;
        }
        match receiver.recv().await {
            Some(message) => state.observe(message),
            None => break,
        }
    }
}

async fn run_fifo<C>(context: C, capacity: usize, operations: Vec<Operation>)
where
    C: Clock + Metrics + Spawner,
{
    let (sender, receiver) = mailbox::new(
        context.child("mailbox"),
        NonZeroUsize::new(capacity).unwrap(),
    );
    let mut receiver = Some(receiver);
    let mut senders = vec![sender];
    // Keep State alive so the backoff counter remains in the registry for assert_metric.
    let anchor = senders[0].clone();
    let mut state = FifoState::new();

    for (round, op) in operations.into_iter().enumerate() {
        match op {
            Operation::Enqueue(input) => {
                send_fifo(&senders, &mut state, round, input);
            }
            Operation::Batch(inputs) => {
                for (offset, input) in inputs.into_iter().enumerate() {
                    send_fifo(&senders, &mut state, round + offset, input);
                }
            }
            Operation::TryRecv { limit } => {
                if let Some(receiver) = receiver.as_mut() {
                    drain_try_fifo(receiver, &mut state, limit);
                }
            }
            Operation::Recv { limit } => {
                if let Some(receiver) = receiver.as_mut() {
                    drain_recv_fifo(receiver, &mut state, limit).await;
                }
            }
            Operation::ParkedRecv { sender, extra } => {
                if !senders.is_empty() {
                    if let Some(mut parked) = receiver.take() {
                        drain_recv_fifo(&mut parked, &mut state, usize::MAX).await;
                        let handle = context
                            .child("parked")
                            .spawn(move |_| async move { (parked.recv().await, parked) });
                        context
                            .sleep(Duration::from_millis(PARK_SLEEP_DURATION))
                            .await;
                        let first = EnqueueInput {
                            sender,
                            kind: Kind::Retain,
                        };
                        send_fifo(&senders, &mut state, round, first);
                        for (offset, input) in extra.into_iter().enumerate() {
                            send_fifo(&senders, &mut state, round + offset + 1, input);
                        }
                        let (received, returned) = handle.await.expect("parked recv failed");
                        if let Some(message) = received {
                            state.observe(message);
                        }
                        receiver = Some(returned);
                    }
                }
            }
            Operation::CloneSender { index } => {
                if !senders.is_empty() {
                    let sender = senders[index as usize % senders.len()].clone();
                    senders.push(sender);
                }
            }
            Operation::DropSender { index } => {
                if !senders.is_empty() {
                    drop(senders.swap_remove(index as usize % senders.len()));
                }
            }
            Operation::DropReceiver { index } => {
                if let Some(receiver) = receiver.take() {
                    drop(receiver);
                    state.close();
                    if !senders.is_empty() {
                        let message = state.message(EnqueueInput {
                            sender: 0,
                            kind: Kind::Retain,
                        });
                        assert_eq!(
                            senders[index as usize % senders.len()].enqueue(message),
                            Feedback::Closed
                        );
                    }
                }
            }
            Operation::DropReceiverWithOverflow { sender } => {
                if let Some(receiver) = receiver.take() {
                    if !senders.is_empty() {
                        let before = state.pending();
                        // Send capacity + 1 retained messages to force at least one into overflow.
                        for offset in 0..=capacity {
                            send_fifo(
                                &senders,
                                &mut state,
                                round + offset,
                                EnqueueInput {
                                    sender,
                                    kind: Kind::Retain,
                                },
                            );
                        }
                        assert!(state.pending() - before > capacity);
                    }
                    drop(receiver);
                    state.close();
                    if let Some(sender) = senders.first() {
                        let message = state.message(EnqueueInput {
                            sender: 0,
                            kind: Kind::Retain,
                        });
                        assert_eq!(sender.enqueue(message), Feedback::Closed);
                    }
                }
            }
        }

        if let Some(receiver) = receiver.as_mut() {
            drain_try_fifo(receiver, &mut state, round % (MAX_DRAIN + 1));
        }
    }

    if let Some(mut receiver) = receiver {
        drop(senders);
        drop(anchor);
        drain_recv_fifo(&mut receiver, &mut state, usize::MAX).await;
        let metrics = context.encode();
        assert_metric(&metrics, "fifo_mailbox_backoff_total", state.backoffs);
        assert_only_mailbox_counter(&metrics, "fifo_mailbox_", "fifo_mailbox_backoff_total");
        drop(receiver);
    } else {
        drop(senders);
        let metrics = context.encode();
        assert_metric(&metrics, "fifo_mailbox_backoff_total", state.backoffs);
        assert_only_mailbox_counter(&metrics, "fifo_mailbox_", "fifo_mailbox_backoff_total");
        drop(anchor);
    }
    assert_eq!(state.pending(), 0);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CoalesceKind {
    Retain,
    Coalesce,
}

#[derive(Clone, Debug)]
struct CoalesceMessage {
    sender: u8,
    id: u64,
    kind: CoalesceKind,
    discarded: Arc<Mutex<Vec<u64>>>,
}

impl mailbox::Policy for CoalesceMessage {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut VecDeque<Self>, message: Self) -> bool {
        if message.kind == CoalesceKind::Coalesce {
            if let Some(index) = overflow.iter().rposition(|pending| {
                pending.sender == message.sender && pending.kind == CoalesceKind::Coalesce
            }) {
                let old = overflow.remove(index).expect("coalesced message missing");
                message.discarded.lock().push(old.id);
            }
        }
        overflow.push_back(message);
        true
    }
}

async fn run_coalesce<C>(context: C, capacity: usize, inputs: Vec<CoalesceInput>)
where
    C: Metrics + Spawner,
{
    let (sender, mut receiver) = mailbox::new(
        context.child("coalesce_mailbox"),
        NonZeroUsize::new(capacity).unwrap(),
    );
    let discarded = Arc::new(Mutex::new(Vec::new()));
    let mut live = BTreeSet::new();
    let mut backoffs = 0usize;

    for (next_id, input) in inputs.into_iter().enumerate() {
        let message = CoalesceMessage {
            sender: input.sender % MAX_SENDERS,
            id: next_id as u64,
            kind: if input.coalesce {
                CoalesceKind::Coalesce
            } else {
                CoalesceKind::Retain
            },
            discarded: discarded.clone(),
        };
        let feedback = sender.enqueue(message.clone());
        assert!(feedback.accepted());
        if feedback == Feedback::Backoff {
            backoffs += 1;
        }
        live.insert(message.id);
        for id in discarded.lock().drain(..) {
            assert!(live.remove(&id));
        }
    }

    drop(sender);
    while let Some(message) = receiver.recv().await {
        assert!(live.remove(&message.id));
    }
    assert!(live.is_empty());
    let metrics = context.encode();
    assert_metric(
        &metrics,
        "coalesce_coalesce_mailbox_backoff_total",
        backoffs,
    );
    assert_only_mailbox_counter(
        &metrics,
        "coalesce_coalesce_mailbox_",
        "coalesce_coalesce_mailbox_backoff_total",
    );
}

pub fn fuzz_fifo(input: FifoInput) {
    let mut rng = FuzzRng::new(input.raw_bytes);
    let operations = gen_operations(&mut rng);
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        run_fifo(context.child("fifo"), input.capacity, operations).await;
    });
}

pub fn fuzz_coalesce(input: CoalesceFuzzInput) {
    let mut rng = FuzzRng::new(input.raw_bytes);
    let coalesce = gen_coalesce_inputs(&mut rng);
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        run_coalesce(context.child("coalesce"), input.capacity, coalesce).await;
    });
}
