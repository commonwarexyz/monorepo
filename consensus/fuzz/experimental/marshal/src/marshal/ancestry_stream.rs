//! Drives the public ancestry API over a block provider the input scripts.
//!
//! Every parent request is answered from a plan drawn once per input: at once,
//! after a release, never, with no parent, or with a block of the wrong height
//! or digest. A model of the stream says what each poll and peek must give.

use arbitrary::{Arbitrary, Unstructured};
use commonware_consensus::{
    Block as _, Heightable as _,
    marshal::{
        ancestry::{self, AncestorStream, Ancestry as _, BlockProvider, BoxedAncestry},
        mocks::block::EmptyBlock,
    },
    types::{Epoch, Height, Round, View},
};
use commonware_consensus_fuzz_core::MAX_RAW_BYTES;
use commonware_cryptography::{Digest as _, Digested, Digestible as _, Sha256, sha256};
use commonware_runtime::{
    Runner as _, Supervisor as _, deterministic, telemetry::metrics::histogram::Timed,
};
use commonware_utils::{FuzzRng, channel::oneshot, sync::Mutex};
use futures::{FutureExt as _, StreamExt as _, future::BoxFuture};
use std::{future::Future, sync::Arc};

type B = EmptyBlock<Sha256>;

/// Blocks in the chain: genesis at height 0 up to height `CHAIN_LEN - 1`.
const CHAIN_LEN: usize = 8;
const MAX_OPS: usize = 24;
/// Timestamp of the chain blocks; a forged block with another digest uses
/// `FORGED_TIMESTAMP`.
const CHAIN_TIMESTAMP: u64 = 0;
const FORGED_TIMESTAMP: u64 = 1;
/// Polls of each final walk: enough to go from the newest block past genesis.
const FINAL_WALK: usize = CHAIN_LEN + 1;
/// Upper bound on the polls of a helper stream.
const MAX_HELPER_POLLS: usize = CHAIN_LEN + 1;

/// How the provider answers every request for the parent of one block.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Answer {
    /// The parent, ready at once.
    #[default]
    Now,
    /// The parent once `Release` names the child.
    Later,
    /// A request that never completes.
    Never,
    /// No parent: the provider can no longer obtain it.
    End,
    /// A block with the child's height instead of its parent's.
    WrongHeight,
    /// A block at the parent's height whose digest the child does not name.
    WrongDigest,
}

impl<'a> Arbitrary<'a> for Answer {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(match u.int_in_range(0..=5)? {
            0 => Self::Now,
            1 => Self::Later,
            2 => Self::Never,
            3 => Self::End,
            4 => Self::WrongHeight,
            _ => Self::WrongDigest,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamOp {
    /// Polls the stream once.
    Next,
    /// Peeks the stream.
    Peek,
    /// Completes the kept `Later` requests of the child at `height % CHAIN_LEN`.
    Release { height: u8 },
    /// Clones the stream, dropping an earlier clone.
    Clone,
    /// Polls the clone once, if there is one.
    NextClone,
    /// Walks `with_prefix` and `from_iter` over a part of the chain.
    Prefix { blocks: u8 },
}

impl<'a> Arbitrary<'a> for StreamOp {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(match u.int_in_range(0..=5)? {
            0 => Self::Next,
            1 => Self::Peek,
            2 => Self::Release {
                height: u.arbitrary()?,
            },
            3 => Self::Clone,
            4 => Self::NextClone,
            _ => Self::Prefix {
                blocks: u.arbitrary()?,
            },
        })
    }
}

#[derive(Debug)]
pub struct AncestryStreamInput {
    /// A copy of the input's first bytes; seeds the runtime.
    pub raw_bytes: Vec<u8>,
    /// Height of the newest initial block.
    pub top: u8,
    /// How many contiguous blocks, from `top` down, start the stream.
    pub initial: u8,
    /// The answer for the parent of each height; index 0 is unused.
    pub plan: [Answer; CHAIN_LEN],
    pub ops: Vec<StreamOp>,
    /// View of the bound the stream passes to every parent request.
    pub bound: Option<u64>,
}

impl<'a> Arbitrary<'a> for AncestryStreamInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // A copy, so the runtime's tape differs between short inputs although
        // the fields below read the same first bytes.
        let raw_bytes = u
            .peek_bytes(u.len().min(MAX_RAW_BYTES))
            .map(<[u8]>::to_vec)
            .unwrap_or_default();
        let top = u.int_in_range(1..=CHAIN_LEN as u8 - 1)?;
        let initial = u.int_in_range(1..=top + 1)?;
        let mut plan = [Answer::Now; CHAIN_LEN];
        for answer in &mut plan {
            *answer = u.arbitrary()?;
        }
        let count = u.int_in_range(1..=MAX_OPS)?;
        let ops = (0..count)
            .map(|_| u.arbitrary())
            .collect::<arbitrary::Result<_>>()?;
        Ok(Self {
            raw_bytes,
            top,
            initial,
            plan,
            ops,
            bound: u.arbitrary()?,
        })
    }
}

fn chain() -> Vec<Digested<B>> {
    let mut blocks: Vec<Digested<B>> = Vec::with_capacity(CHAIN_LEN);
    let mut parent = sha256::Digest::EMPTY;
    for height in 0..CHAIN_LEN as u64 {
        let block = B::new(parent, Height::new(height), CHAIN_TIMESTAMP);
        let digest = block.digest();
        parent = digest;
        blocks.push(Digested::precomputed(block, digest));
    }
    blocks
}

fn digested(block: B) -> Digested<B> {
    let digest = block.digest();
    Digested::precomputed(block, digest)
}

#[derive(Default)]
struct ProviderState {
    /// Kept `Later` requests by child height.
    later: Vec<(Height, oneshot::Sender<Digested<B>>)>,
    /// Kept `Never` requests, never completed.
    never: Vec<oneshot::Sender<Digested<B>>>,
    /// Every request: child height and bound.
    calls: Vec<(Height, Option<Round>)>,
}

/// Answers each parent request from the plan.
#[derive(Clone)]
struct ScriptedProvider {
    chain: Arc<Vec<Digested<B>>>,
    plan: [Answer; CHAIN_LEN],
    state: Arc<Mutex<ProviderState>>,
}

impl ScriptedProvider {
    /// Completes the kept `Later` requests of the child at `height` and
    /// returns how many there were.
    fn release(&self, height: Height) -> usize {
        let mut state = self.state.lock();
        let (released, kept) = std::mem::take(&mut state.later)
            .into_iter()
            .partition::<Vec<_>, _>(|(child, _)| *child == height);
        state.later = kept;
        let count = released.len();
        if let Some(parent) = height.previous() {
            for (_, sender) in released {
                // A dropped stream no longer waits for its parent.
                let _ = sender.send(self.chain[parent.get() as usize].clone());
            }
        }
        count
    }
}

impl BlockProvider for ScriptedProvider {
    type Block = B;

    fn subscribe_parent(
        &self,
        block: &Digested<B>,
        bound: Option<Round>,
    ) -> impl Future<Output = Option<Digested<B>>> + Send + 'static {
        let child = block.height();
        let mut state = self.state.lock();
        state.calls.push((child, bound));
        let height = child.get() as usize;
        let parent = &self.chain[height - 1];
        let answer: BoxFuture<'static, Option<Digested<B>>> = match self.plan[height] {
            Answer::Now => futures::future::ready(Some(parent.clone())).boxed(),
            Answer::Later => {
                let (sender, receiver) = oneshot::channel();
                state.later.push((child, sender));
                receiver.map(Result::ok).boxed()
            }
            Answer::Never => {
                let (sender, receiver) = oneshot::channel();
                state.never.push(sender);
                receiver.map(Result::ok).boxed()
            }
            Answer::End => futures::future::ready(None).boxed(),
            Answer::WrongHeight => {
                let forged = B::new(parent.parent(), child, CHAIN_TIMESTAMP);
                futures::future::ready(Some(digested(forged))).boxed()
            }
            Answer::WrongDigest => {
                let forged = B::new(parent.parent(), parent.height(), FORGED_TIMESTAMP);
                futures::future::ready(Some(digested(forged))).boxed()
            }
        };
        answer
    }
}

/// Why a modeled stream has no more blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ended {
    Genesis,
    End,
    Wrong,
}

/// The parent fetch of a modeled stream with nothing buffered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fetch {
    /// Blocks are buffered, no fetch runs.
    Idle,
    /// Waiting on the parent of `child`; `released` once a `Later` request
    /// was completed.
    Waiting {
        child: Height,
        answer: Answer,
        released: bool,
    },
    Ended(Ended),
}

/// What an `AncestorStream` over the plan must do.
#[derive(Clone, Debug)]
struct StreamModel {
    /// Heights ready to yield; the newest is last.
    buffered: Vec<Height>,
    fetch: Fetch,
}

/// Outcome of one poll with `now_or_never`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum PollOutcome {
    Pending,
    Ended,
    Yielded(Height),
}

impl StreamModel {
    fn new(heights: impl Iterator<Item = Height>) -> Self {
        let mut buffered: Vec<_> = heights.collect();
        buffered.sort();
        Self {
            buffered,
            fetch: Fetch::Idle,
        }
    }

    fn peek(&self) -> Option<Height> {
        self.buffered.last().copied()
    }

    /// Starts the parent fetch of `child`, as a stream does once its buffer is
    /// empty; ready answers resolve at once.
    fn walk_parent(&mut self, child: Height, plan: &[Answer; CHAIN_LEN]) {
        let Some(parent) = child.previous() else {
            self.fetch = Fetch::Ended(Ended::Genesis);
            return;
        };
        let answer = plan[child.get() as usize];
        self.fetch = match answer {
            Answer::Now => {
                self.buffered.push(parent);
                Fetch::Idle
            }
            Answer::Later | Answer::Never => Fetch::Waiting {
                child,
                answer,
                released: false,
            },
            Answer::End => Fetch::Ended(Ended::End),
            Answer::WrongHeight | Answer::WrongDigest => Fetch::Ended(Ended::Wrong),
        };
    }

    /// The outcome the next poll must have, with the model advanced past it.
    fn poll(&mut self, plan: &[Answer; CHAIN_LEN]) -> PollOutcome {
        if let Some(height) = self.buffered.pop() {
            if self.buffered.is_empty() {
                self.walk_parent(height, plan);
            }
            return PollOutcome::Yielded(height);
        }
        match self.fetch {
            Fetch::Waiting {
                child,
                released: true,
                ..
            } => {
                let parent = child.previous().expect("a waiting child has a parent");
                self.walk_parent(parent, plan);
                PollOutcome::Yielded(parent)
            }
            Fetch::Waiting { .. } => PollOutcome::Pending,
            Fetch::Idle | Fetch::Ended(_) => PollOutcome::Ended,
        }
    }

    fn release(&mut self, height: Height) {
        if let Fetch::Waiting {
            child,
            answer: Answer::Later,
            released,
        } = &mut self.fetch
            && *child == height
        {
            *released = true;
        }
    }
}

/// Which stream an event is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum StreamKind {
    Original,
    Clone,
    Prefixed,
    FromIter,
}

/// One event of a run, recorded for the crate's tests.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum StreamEvent {
    TimedRegistered {
        label: &'static str,
    },
    Poll {
        stream: StreamKind,
        outcome: PollOutcome,
    },
    Peek {
        stream: StreamKind,
        height: Option<Height>,
    },
    Released {
        height: Height,
        requests: usize,
    },
    /// Every parent request of the run: child height and bound.
    ProviderCalls(Vec<(Height, Option<Round>)>),
    /// The final sequences: the original's since the latest clone, the
    /// clone's, and whether each ended.
    Sequences {
        original: Vec<Height>,
        original_ended: bool,
        clone: Option<(Vec<Height>, bool)>,
    },
}

/// Events of a run. Only test builds record them.
#[derive(Debug, Default)]
pub(crate) struct StreamTrace(#[cfg(test)] pub(crate) Vec<StreamEvent>);

impl StreamTrace {
    #[cfg_attr(not(test), allow(unused_variables))]
    fn record(&mut self, event: impl FnOnce() -> StreamEvent) {
        #[cfg(test)]
        self.0.push(event());
    }
}

/// Polls `stream` once without waiting.
fn poll_once<S: futures::Stream<Item = Digested<B>> + Unpin>(
    stream: &mut S,
) -> Option<Option<Digested<B>>> {
    stream.next().now_or_never()
}

fn outcome(polled: &Option<Option<Digested<B>>>) -> PollOutcome {
    match polled {
        None => PollOutcome::Pending,
        Some(None) => PollOutcome::Ended,
        Some(Some(block)) => PollOutcome::Yielded(block.height()),
    }
}

/// A stream the run polls, with what it has yielded and whether it ended.
struct Walked<S> {
    stream: S,
    yields: Vec<Height>,
    ended: bool,
}

impl<S: futures::Stream<Item = Digested<B>> + Unpin> Walked<S> {
    fn new(stream: S) -> Self {
        Self {
            stream,
            yields: Vec::new(),
            ended: false,
        }
    }

    fn poll(&mut self) -> Option<Option<Digested<B>>> {
        let polled = poll_once(&mut self.stream);
        match &polled {
            Some(Some(block)) => self.yields.push(block.height()),
            Some(None) => self.ended = true,
            None => {}
        }
        polled
    }
}

/// Checks a poll of the original stream against its model.
fn check_original(
    polled: &Option<Option<Digested<B>>>,
    model: &mut StreamModel,
    chain: &[Digested<B>],
    plan: &[Answer; CHAIN_LEN],
) {
    let state = model.fetch;
    let buffered = model.peek();
    let expected = model.poll(plan);
    let actual = outcome(polled);
    let id = match (buffered, state) {
        (Some(_), _) => "RB-6",
        (None, Fetch::Ended(Ended::Genesis)) => "RB-7",
        (None, Fetch::Ended(Ended::Wrong)) => "RB-8",
        (None, Fetch::Ended(Ended::End) | Fetch::Idle) => "RB-9",
        (
            None,
            Fetch::Waiting {
                released: false, ..
            },
        ) => "RB-10",
        (None, Fetch::Waiting { released: true, .. }) => "RB-11",
    };
    assert_eq!(
        actual, expected,
        "{id} violated: the poll gave {actual:?}, the model {expected:?}",
    );
    if let (PollOutcome::Yielded(height), Some(Some(block))) = (expected, polled) {
        assert_eq!(
            block.digest(),
            chain[height.get() as usize].digest(),
            "{id} violated: the block at height {} is not the chain's",
            height.get(),
        );
    }
}

/// Checks a clone's yield: after its first, each is the direct parent of the
/// one before. Where the clone starts and when it is ready is RB-13's.
fn check_clone_yield(previous: Option<Height>, block: &Digested<B>, chain: &[Digested<B>]) {
    let Some(previous) = previous else {
        return;
    };
    let expected = previous.previous();
    assert_eq!(
        Some(block.height()),
        expected,
        "RB-6 violated: the clone yielded height {} after height {}",
        block.height().get(),
        previous.get(),
    );
    assert_eq!(
        block.digest(),
        chain[block.height().get() as usize].digest(),
        "RB-6 violated: the clone's block at height {} is not the chain's",
        block.height().get(),
    );
}

/// The clone's sequence against the original's since the clone point: as far
/// as both go they agree, and once both ended they are equal.
fn check_clone_sequence(original: &[Height], original_ended: bool, clone: &[Height], ended: bool) {
    let common = original.len().min(clone.len());
    assert_eq!(
        original[..common],
        clone[..common],
        "RB-13 violated: the clone yielded {clone:?}, the original {original:?} since the clone",
    );
    if original_ended && ended {
        assert_eq!(
            original, clone,
            "RB-13 violated: both ended, the clone yielded {clone:?}, the original {original:?}",
        );
    }
}

/// Crypto: none (digests only). Marshal: the ancestry stream and its helpers
/// over a scripted block provider. Cluster: none. Liveness: not checked. App:
/// none.
pub fn fuzz_marshal_ancestry_stream(input: AncestryStreamInput) {
    let _ = run_ancestry_stream(input);
}

/// Runs one input and returns its trace (empty outside tests).
pub(crate) fn run_ancestry_stream(input: AncestryStreamInput) -> StreamTrace {
    let cfg = deterministic::Config::new().with_rng(FuzzRng::new(input.raw_bytes));
    let executor = deterministic::Runner::new(cfg);
    let AncestryStreamInput {
        top,
        initial,
        plan,
        ops,
        bound,
        ..
    } = input;

    executor.start(|context| async move {
        let mut trace = StreamTrace::default();
        let chain = Arc::new(chain());
        let provider = ScriptedProvider {
            chain: chain.clone(),
            plan,
            state: Arc::default(),
        };
        let ancestry_context = context.child("ancestry");
        let timed = Timed::register(
            &ancestry_context,
            "ancestor_fetch_duration",
            "Time to fetch a parent through the ancestry stream",
        );
        trace.record(|| StreamEvent::TimedRegistered { label: "ancestry" });
        let clock = Arc::new(ancestry_context);
        let bound = bound.map(|view| Round::new(Epoch::zero(), View::new(view)));

        let top = Height::new(u64::from(top));
        let heights = (0..u64::from(initial)).map(|i| Height::new(top.get() - i));
        let mut model = StreamModel::new(heights.clone());
        let mut original = Walked::new(AncestorStream::new(
            clock.clone(),
            provider.clone(),
            heights.map(|height| chain[height.get() as usize].clone()),
            bound,
            timed.clone(),
        ));
        let mut clone = None;
        let mut clone_point = 0;

        for op in ops {
            match op {
                StreamOp::Next => {
                    let polled = original.poll();
                    trace.record(|| StreamEvent::Poll {
                        stream: StreamKind::Original,
                        outcome: outcome(&polled),
                    });
                    check_original(&polled, &mut model, &chain, &plan);
                }
                StreamOp::Peek => {
                    let peeked = original.stream.peek().map(|block| block.height());
                    trace.record(|| StreamEvent::Peek {
                        stream: StreamKind::Original,
                        height: peeked,
                    });
                    assert_eq!(
                        peeked,
                        model.peek(),
                        "RB-12 violated: peek gave {peeked:?}, the next ready block is {:?}",
                        model.peek(),
                    );
                    if let Some(peeked) = original.stream.peek() {
                        assert_eq!(
                            peeked.digest(),
                            chain[peeked.height().get() as usize].digest(),
                            "RB-12 violated: peek gave a block that is not the chain's",
                        );
                    }
                }
                StreamOp::Release { height } => {
                    let height = Height::new(u64::from(height) % CHAIN_LEN as u64);
                    let requests = provider.release(height);
                    trace.record(|| StreamEvent::Released { height, requests });
                    model.release(height);
                }
                StreamOp::Clone => {
                    drop(clone.take());
                    clone = Some(Walked::new(original.stream.clone()));
                    clone_point = original.yields.len();
                }
                StreamOp::NextClone => {
                    if let Some(clone) = &mut clone {
                        let previous = clone.yields.last().copied();
                        let polled = clone.poll();
                        trace.record(|| StreamEvent::Poll {
                            stream: StreamKind::Clone,
                            outcome: outcome(&polled),
                        });
                        if let Some(Some(block)) = &polled {
                            check_clone_yield(previous, block, &chain);
                        }
                    }
                }
                StreamOp::Prefix { blocks } => {
                    walk_helpers(blocks, &provider, &clock, bound, &timed, &mut trace);
                }
            }
        }

        // The final walks reach genesis whatever the ops did, with no release
        // in between.
        for _ in 0..FINAL_WALK {
            let polled = original.poll();
            trace.record(|| StreamEvent::Poll {
                stream: StreamKind::Original,
                outcome: outcome(&polled),
            });
            check_original(&polled, &mut model, &chain, &plan);
        }
        if let Some(clone) = &mut clone {
            for _ in 0..FINAL_WALK {
                let previous = clone.yields.last().copied();
                let polled = clone.poll();
                trace.record(|| StreamEvent::Poll {
                    stream: StreamKind::Clone,
                    outcome: outcome(&polled),
                });
                if let Some(Some(block)) = &polled {
                    check_clone_yield(previous, block, &chain);
                }
            }
        }

        let since_clone = &original.yields[clone_point..];
        if let Some(clone) = &clone {
            check_clone_sequence(since_clone, original.ended, &clone.yields, clone.ended);
        }
        trace.record(|| StreamEvent::Sequences {
            original: since_clone.to_vec(),
            original_ended: original.ended,
            clone: clone
                .as_ref()
                .map(|clone| (clone.yields.clone(), clone.ended)),
        });
        trace.record(|| StreamEvent::ProviderCalls(provider.state.lock().calls.clone()));
        trace
    })
}

/// Walks `with_prefix` over a fresh tail, then `from_iter`, over the chain
/// heights `k + n` down to `k + 1` that `blocks` selects.
fn walk_helpers(
    blocks: u8,
    provider: &ScriptedProvider,
    clock: &Arc<deterministic::Context>,
    bound: Option<Round>,
    timed: &Timed,
    trace: &mut StreamTrace,
) {
    let chain = provider.chain.as_slice();
    let plan = &provider.plan;
    let n = usize::from(blocks) % 3 + 1;
    let k = (usize::from(blocks) / 3) % (CHAIN_LEN - n);
    let prefix: Vec<_> = (k + 1..=k + n).rev().map(|h| chain[h].clone()).collect();

    let tail_start = Height::new(k as u64);
    let tail = AncestorStream::new(
        clock.clone(),
        provider.clone(),
        [chain[k].clone()],
        bound,
        timed.clone(),
    );
    let mut tail_model = StreamModel::new(std::iter::once(tail_start));
    let mut pending: Vec<Height> = prefix.iter().map(|block| block.height()).collect();
    let mut prefixed = ancestry::with_prefix(prefix.clone(), BoxedAncestry::new(tail));
    for _ in 0..MAX_HELPER_POLLS {
        let expected_peek = pending.first().copied().or_else(|| tail_model.peek());
        let peeked = prefixed.peek().map(|block| block.height());
        trace.record(|| StreamEvent::Peek {
            stream: StreamKind::Prefixed,
            height: peeked,
        });
        assert_eq!(
            peeked, expected_peek,
            "RB-14 violated: the prefixed stream peeked {peeked:?}, expected {expected_peek:?}",
        );
        let polled = poll_once(&mut prefixed);
        let expected = if pending.is_empty() {
            tail_model.poll(plan)
        } else {
            PollOutcome::Yielded(pending.remove(0))
        };
        let actual = outcome(&polled);
        trace.record(|| StreamEvent::Poll {
            stream: StreamKind::Prefixed,
            outcome: actual,
        });
        assert_eq!(
            actual, expected,
            "RB-14 violated: the prefixed stream gave {actual:?}, expected {expected:?}",
        );
        match polled {
            Some(Some(block)) => assert_eq!(
                block.digest(),
                chain[block.height().get() as usize].digest(),
                "RB-14 violated: the prefixed stream's block at height {} is not the chain's",
                block.height().get(),
            ),
            Some(None) | None => break,
        }
    }
    drop(prefixed);

    let mut fixed = ancestry::from_iter(prefix.clone());
    let mut expected = prefix.iter();
    for _ in 0..MAX_HELPER_POLLS {
        let want = expected.as_slice().first();
        let peeked = fixed.peek().map(|block| block.digest());
        trace.record(|| StreamEvent::Peek {
            stream: StreamKind::FromIter,
            height: fixed.peek().map(|block| block.height()),
        });
        assert_eq!(
            peeked,
            want.map(|block| block.digest()),
            "RB-15 violated: the fixed stream peeked another block than the next one",
        );
        let polled = poll_once(&mut fixed);
        trace.record(|| StreamEvent::Poll {
            stream: StreamKind::FromIter,
            outcome: outcome(&polled),
        });
        let want = expected.next();
        assert_eq!(
            polled
                .as_ref()
                .map(|polled| polled.as_ref().map(|block| block.digest())),
            Some(want.map(|block| block.digest())),
            "RB-15 violated: the fixed stream did not yield its blocks in order and then end",
        );
        if want.is_none() {
            break;
        }
    }
}

#[cfg(test)]
#[path = "../../tests/ancestry_acceptance/stream.rs"]
mod ancestry_acceptance;

#[cfg(test)]
mod tests {
    use super::*;

    fn input(
        top: u8,
        initial: u8,
        answers: &[(usize, Answer)],
        ops: Vec<StreamOp>,
    ) -> AncestryStreamInput {
        let mut plan = [Answer::Now; CHAIN_LEN];
        for (height, answer) in answers {
            plan[*height] = *answer;
        }
        AncestryStreamInput {
            raw_bytes: Vec::new(),
            top,
            initial,
            plan,
            ops,
            bound: None,
        }
    }

    fn polls(events: &[StreamEvent], kind: StreamKind) -> Vec<PollOutcome> {
        events
            .iter()
            .filter_map(|event| match event {
                StreamEvent::Poll { stream, outcome } if *stream == kind => Some(*outcome),
                _ => None,
            })
            .collect()
    }

    fn peeks(events: &[StreamEvent], kind: StreamKind) -> Vec<Option<u64>> {
        events
            .iter()
            .filter_map(|event| match event {
                StreamEvent::Peek { stream, height } if *stream == kind => {
                    Some(height.map(Height::get))
                }
                _ => None,
            })
            .collect()
    }

    /// A sequence of heights and whether its stream ended.
    type Walk = (Vec<u64>, bool);

    fn sequences(events: &[StreamEvent]) -> (Walk, Option<Walk>) {
        let heights = |heights: &[Height]| heights.iter().map(|h| h.get()).collect::<Vec<_>>();
        events
            .iter()
            .find_map(|event| match event {
                StreamEvent::Sequences {
                    original,
                    original_ended,
                    clone,
                } => Some((
                    (heights(original), *original_ended),
                    clone
                        .as_ref()
                        .map(|(clone, ended)| (heights(clone), *ended)),
                )),
                _ => None,
            })
            .expect("a run records its sequences")
    }

    fn yielded(heights: &[u64]) -> Vec<PollOutcome> {
        heights
            .iter()
            .map(|height| PollOutcome::Yielded(Height::new(*height)))
            .collect()
    }

    /// `outcomes`, then `Ended` up to `len` polls.
    fn then_ended(mut outcomes: Vec<PollOutcome>, len: usize) -> Vec<PollOutcome> {
        outcomes.resize(len, PollOutcome::Ended);
        outcomes
    }

    /// Ready parents: two initial blocks, then each fetched parent down to
    /// genesis, then the end.
    #[test]
    fn ready_parents_reach_genesis() {
        let events = run_ancestry_stream(input(3, 2, &[], vec![StreamOp::Peek, StreamOp::Next])).0;
        assert_eq!(peeks(&events, StreamKind::Original), vec![Some(3)]);
        assert_eq!(
            polls(&events, StreamKind::Original),
            then_ended(yielded(&[3, 2, 1, 0]), 1 + FINAL_WALK),
        );
    }

    /// A held parent waits until it is released, then the walk goes on.
    #[test]
    fn released_parent_is_yielded() {
        let ops = vec![
            StreamOp::Next,
            StreamOp::Next,
            StreamOp::Peek,
            StreamOp::Release { height: 3 },
            StreamOp::Next,
        ];
        let events = run_ancestry_stream(input(3, 1, &[(3, Answer::Later)], ops)).0;
        assert_eq!(peeks(&events, StreamKind::Original), vec![None]);
        assert!(events.contains(&StreamEvent::Released {
            height: Height::new(3),
            requests: 1,
        }));
        let mut expected = yielded(&[3]);
        expected.push(PollOutcome::Pending);
        expected.extend(yielded(&[2, 1, 0]));
        assert_eq!(
            polls(&events, StreamKind::Original),
            then_ended(expected, 3 + FINAL_WALK),
        );
    }

    /// A request that never completes keeps the stream pending, release or not.
    #[test]
    fn unanswered_parent_stays_pending() {
        let ops = vec![
            StreamOp::Next,
            StreamOp::Next,
            StreamOp::Release { height: 3 },
            StreamOp::Next,
        ];
        let events = run_ancestry_stream(input(3, 1, &[(3, Answer::Never)], ops)).0;
        let mut expected = yielded(&[3]);
        expected.resize(3 + FINAL_WALK, PollOutcome::Pending);
        assert_eq!(polls(&events, StreamKind::Original), expected);
    }

    /// A provider with no parent ends the stream after the current block.
    #[test]
    fn missing_parent_ends_the_stream() {
        let events = run_ancestry_stream(input(3, 1, &[(3, Answer::End)], vec![StreamOp::Next])).0;
        assert_eq!(
            polls(&events, StreamKind::Original),
            then_ended(yielded(&[3]), 1 + FINAL_WALK),
        );
    }

    /// A parent at the child's height is never yielded; the stream ends.
    #[test]
    fn parent_with_wrong_height_ends_the_stream() {
        let events = run_ancestry_stream(input(
            3,
            1,
            &[(3, Answer::WrongHeight)],
            vec![StreamOp::Next],
        ))
        .0;
        assert_eq!(
            polls(&events, StreamKind::Original),
            then_ended(yielded(&[3]), 1 + FINAL_WALK),
        );
    }

    /// A parent whose digest the child does not name is never yielded; the
    /// stream ends.
    #[test]
    fn parent_with_wrong_digest_ends_the_stream() {
        let events = run_ancestry_stream(input(
            3,
            1,
            &[(3, Answer::WrongDigest)],
            vec![StreamOp::Next],
        ))
        .0;
        assert_eq!(
            polls(&events, StreamKind::Original),
            then_ended(yielded(&[3]), 1 + FINAL_WALK),
        );
    }

    /// A clone of a stream with two buffered blocks yields what the original
    /// yields after the clone point.
    #[test]
    fn clone_of_buffered_stream_matches_original() {
        let ops = vec![StreamOp::Clone, StreamOp::Next, StreamOp::NextClone];
        let events = run_ancestry_stream(input(3, 2, &[], ops)).0;
        assert_eq!(
            sequences(&events),
            ((vec![3, 2, 1, 0], true), Some((vec![3, 2, 1, 0], true))),
        );
    }

    /// A prefix over a fresh tail yields the prefix, then the tail; the fixed
    /// stream yields only the prefix.
    #[test]
    fn prefix_then_tail() {
        let events = run_ancestry_stream(input(1, 1, &[], vec![StreamOp::Prefix { blocks: 3 }])).0;
        assert_eq!(
            polls(&events, StreamKind::Prefixed),
            then_ended(yielded(&[2, 1, 0]), 4),
        );
        assert_eq!(
            peeks(&events, StreamKind::Prefixed),
            vec![Some(2), Some(1), Some(0), None],
        );
        assert_eq!(
            polls(&events, StreamKind::FromIter),
            then_ended(yielded(&[2]), 2),
        );
        assert_eq!(peeks(&events, StreamKind::FromIter), vec![Some(2), None]);
    }

    /// A clone made while the original waits sends its own request; one
    /// release completes both, and both walk to genesis.
    #[test]
    fn clone_of_waiting_stream_matches_original() {
        let ops = vec![
            StreamOp::Next,
            StreamOp::Clone,
            StreamOp::Release { height: 3 },
            StreamOp::Next,
        ];
        let events = run_ancestry_stream(input(3, 1, &[(3, Answer::Later)], ops)).0;
        assert!(events.contains(&StreamEvent::Released {
            height: Height::new(3),
            requests: 2,
        }));
        assert_eq!(
            sequences(&events),
            ((vec![2, 1, 0], true), Some((vec![2, 1, 0], true))),
        );
    }

    /// The shortest inputs decode to one initial block, ready answers and one
    /// poll, and the final walk reaches genesis.
    #[test]
    fn short_inputs_walk_to_genesis() {
        for bytes in [&[][..], &[0][..]] {
            let input = AncestryStreamInput::arbitrary(&mut Unstructured::new(bytes)).unwrap();
            assert_eq!(input.raw_bytes, bytes);
            assert_eq!((input.top, input.initial), (1, 1));
            assert_eq!(input.plan, [Answer::Now; CHAIN_LEN]);
            assert_eq!(input.ops, vec![StreamOp::Next]);
            let events = run_ancestry_stream(input).0;
            assert_eq!(
                polls(&events, StreamKind::Original),
                then_ended(yielded(&[1, 0]), 1 + FINAL_WALK),
            );
        }
    }
}
