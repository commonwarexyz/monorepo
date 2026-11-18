#![no_main]

//! Poll clones of a [Shared] by hand and check its wake, completion, and release contract
//! against a model.
//!
//! The input scripts the inner future: while a clone polls it, it can wake itself and poll,
//! clone, or drop other clones, and it then waits, resolves, or panics. Each clone polls with
//! one of two counting wakers. After every operation the harness checks that:
//! - the inner future is polled exactly when a clone is polled after it was woken, and never
//!   while another clone polls it or after it resolved or panicked,
//! - while the inner future can make progress (it was woken, resolved, or panicked), every
//!   clone that returned [Poll::Pending] was woken since,
//! - a poll of the inner future during which another clone found it busy wakes every other
//!   waiting clone once it returns pending,
//! - every clone resolves to the one output, the inner future's panic reaches the clone
//!   polling it, and every later poll panics,
//! - the inner future and its output are dropped exactly when it finishes or the last clone
//!   drops, and a [WeakShared] upgrades exactly while a clone is alive.

use arbitrary::Arbitrary;
use commonware_utils::{
    futures::{Shared, WeakShared},
    sync::Mutex,
    vec::NonEmptyVec,
};
use futures::task::ArcWake;
use libfuzzer_sys::fuzz_target;
use std::{
    future::Future,
    panic::{self, AssertUnwindSafe},
    pin::Pin,
    ptr,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst},
    },
    task::{Context, Poll, Waker},
};

/// Maximum number of operations run per input.
const MAX_OPERATIONS: usize = 64;
/// Maximum number of live clones, enough to wake more clones than fit inline.
const MAX_CLONES: usize = 12;
/// Maximum number of weak handles.
const MAX_WEAKS: usize = 4;
/// Maximum number of actions the inner future takes per poll.
const MAX_ACTIONS: usize = 4;

/// Message of the inner future's scripted panic.
const INNER_PANIC: &str = "inner future failed";
/// Message of a poll after the inner future panicked.
const POISONED: &str = "Shared future polled after its inner future panicked";

#[derive(Arbitrary, Debug)]
enum Outcome {
    Pending,
    Ready(u64),
    Panic,
}

/// What the inner future does while a clone polls it, before its outcome.
#[derive(Arbitrary, Debug)]
enum Action {
    /// Wake itself through the waker it was polled with.
    Wake,
    /// Poll another clone, which finds the inner future busy.
    Poll { clone: u8, second: bool },
    /// Clone another clone.
    Clone { clone: u8 },
    /// Drop another clone.
    Drop { clone: u8 },
}

/// The inner future's next poll, should the polled clone reach it.
#[derive(Arbitrary, Debug)]
struct Script {
    outcome: Outcome,
    actions: Vec<Action>,
}

#[derive(Arbitrary, Debug)]
enum Operation {
    /// Poll a clone with its first or second waker.
    Poll {
        clone: u8,
        second: bool,
        script: Script,
    },
    Clone {
        clone: u8,
    },
    Drop {
        clone: u8,
    },
    Downgrade {
        clone: u8,
    },
    CloneWeak {
        weak: u8,
    },
    Upgrade {
        weak: u8,
    },
    /// Wake the inner future through the waker of its latest poll, as its event source would.
    Wake,
    /// Drop the waker of the inner future's latest poll, as an event source that gives up would.
    Forget,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    clones: u8,
    operations: NonEmptyVec<Operation>,
}

/// A waker that counts its wakes.
struct Counter(AtomicUsize);

impl ArcWake for Counter {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        arc_self.0.fetch_add(1, SeqCst);
    }
}

/// A clone of the future under test and the wakers it polls with.
struct Handle {
    /// The clone, taken out while it is polled.
    shared: Option<Shared<Scripted>>,
    wakers: [(Arc<Counter>, Waker); 2],
    /// The waker the clone registered when it last returned pending, and that waker's wakes
    /// before the poll.
    asleep: Option<(usize, usize)>,
}

impl Handle {
    fn new(shared: Shared<Scripted>) -> Self {
        let waker = || {
            let counter = Arc::new(Counter(AtomicUsize::new(0)));
            (counter.clone(), futures::task::waker(counter))
        };
        Self {
            shared: Some(shared),
            wakers: [waker(), waker()],
            asleep: None,
        }
    }

    fn wakes(&self, which: usize) -> usize {
        self.wakers[which].0.0.load(SeqCst)
    }
}

/// A clone taken out of its handle to be polled.
struct Taken {
    index: usize,
    shared: Shared<Scripted>,
    /// Which of the handle's wakers it is polled with.
    which: usize,
    waker: Waker,
    /// Wakes of that waker before the poll.
    before: usize,
}

/// How the inner future finished.
enum Finished {
    Ready { value: u64, output: Weak<u64> },
    Poisoned,
}

/// What a correct [Shared] must have done so far.
struct Model {
    /// Whether the inner future was woken since its latest poll started, or was never polled.
    woken: bool,
    /// Whether a clone is polling the inner future.
    polling: bool,
    /// Whether another clone found the inner future busy during its latest poll.
    contended: bool,
    /// Polls of the inner future.
    polls: usize,
    finished: Option<Finished>,
}

/// The clones in creation order (`None` once dropped) and the model.
struct World {
    handles: Vec<Option<Handle>>,
    model: Model,
}

impl World {
    /// The index of the `choice`-th live clone that is not being polled, if any.
    fn pick(&self, choice: u8) -> Option<usize> {
        let idle: Vec<usize> = self
            .handles
            .iter()
            .enumerate()
            .filter(|(_, handle)| handle.as_ref().is_some_and(|h| h.shared.is_some()))
            .map(|(index, _)| index)
            .collect();
        (!idle.is_empty()).then(|| idle[usize::from(choice) % idle.len()])
    }

    fn live(&self) -> usize {
        self.handles.iter().flatten().count()
    }

    fn shared(&self, index: usize) -> &Shared<Scripted> {
        self.handles[index]
            .as_ref()
            .and_then(|handle| handle.shared.as_ref())
            .expect("picked clone is idle")
    }

    fn clone_handle(&mut self, choice: u8) {
        if self.live() >= MAX_CLONES {
            return;
        }
        let Some(index) = self.pick(choice) else {
            return;
        };
        let source = self.shared(index);
        let clone = source.clone();
        assert!(clone.ptr_eq(source));
        self.handles.push(Some(Handle::new(clone)));
    }

    /// Take a clone out of the world, for the caller to drop after releasing the lock.
    fn remove(&mut self, choice: u8) -> Option<Handle> {
        let index = self.pick(choice)?;
        self.handles[index].take()
    }

    fn take(&mut self, choice: u8, second: bool) -> Option<Taken> {
        let index = self.pick(choice)?;
        let handle = self.handles[index].as_mut()?;
        let which = usize::from(second);
        let before = handle.wakes(which);
        Some(Taken {
            index,
            shared: handle.shared.take()?,
            which,
            waker: handle.wakers[which].1.clone(),
            before,
        })
    }

    /// Return a clone taken out by [World::take], waiting on its waker if it returned pending.
    fn put(&mut self, taken: Taken, pending: bool) {
        let handle = self.handles[taken.index]
            .as_mut()
            .expect("a clone being polled stays live");
        handle.shared = Some(taken.shared);
        handle.asleep = pending.then_some((taken.which, taken.before));
    }
}

/// State shared by the harness and the inner future.
struct Env {
    world: Mutex<World>,
    /// The waker of the inner future's latest poll.
    waker: Mutex<Option<Waker>>,
    /// The script of the inner future's next poll.
    script: Mutex<Option<Script>>,
    polls: AtomicUsize,
    dropped: AtomicBool,
    /// The output the inner future resolved to.
    output: Mutex<Weak<u64>>,
}

impl Env {
    fn new() -> Self {
        Self {
            world: Mutex::new(World {
                handles: Vec::new(),
                model: Model {
                    woken: true,
                    polling: false,
                    contended: false,
                    polls: 0,
                    finished: None,
                },
            }),
            waker: Mutex::new(None),
            script: Mutex::new(None),
            polls: AtomicUsize::new(0),
            dropped: AtomicBool::new(false),
            output: Mutex::new(Weak::new()),
        }
    }

    /// Take `action` from within a poll of the inner future, which was given `waker`.
    fn act(&self, action: Action, waker: &Waker) {
        match action {
            Action::Wake => {
                waker.wake_by_ref();
                self.world.lock().model.woken = true;
            }
            Action::Poll { clone, second } => {
                let taken = {
                    let mut world = self.world.lock();
                    let taken = world.take(clone, second);
                    world.model.contended |= taken.is_some();
                    taken
                };
                let Some(mut taken) = taken else {
                    return;
                };
                let poll = Pin::new(&mut taken.shared).poll(&mut Context::from_waker(&taken.waker));
                assert!(
                    poll.is_pending(),
                    "a clone polled while another polls the inner future must wait"
                );
                self.world.lock().put(taken, true);
            }
            Action::Clone { clone } => self.world.lock().clone_handle(clone),
            Action::Drop { clone } => {
                let handle = self.world.lock().remove(clone);
                drop(handle);
            }
        }
    }
}

/// The inner future, which follows the script of each poll and waits without one.
struct Scripted(Arc<Env>);

impl Future for Scripted {
    type Output = Arc<u64>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let env = &self.0;
        env.polls.fetch_add(1, SeqCst);
        let previous = env.waker.lock().replace(cx.waker().clone());
        drop(previous);
        let script = env.script.lock().take();
        let Some(Script { outcome, actions }) = script else {
            return Poll::Pending;
        };
        for action in actions.into_iter().take(MAX_ACTIONS) {
            env.act(action, cx.waker());
        }
        match outcome {
            Outcome::Pending => Poll::Pending,
            Outcome::Ready(value) => {
                let output = Arc::new(value);
                *env.output.lock() = Arc::downgrade(&output);
                Poll::Ready(output)
            }
            Outcome::Panic => panic::panic_any(INNER_PANIC),
        }
    }
}

impl Drop for Scripted {
    fn drop(&mut self) {
        self.0.dropped.store(true, SeqCst);
    }
}

/// What polling a clone must return.
#[derive(Debug)]
enum Expected {
    Pending,
    /// The output the inner future resolves to in this poll.
    Resolve(u64),
    /// The output the inner future already resolved to.
    Ready(u64, Weak<u64>),
    /// A panic with this message.
    Panic(&'static str),
}

/// Run `f`, returning the message of its panic instead of aborting.
fn catch<R>(f: impl FnOnce() -> R) -> Result<R, String> {
    let hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let result = panic::catch_unwind(AssertUnwindSafe(f));
    panic::set_hook(hook);
    result.map_err(|payload| {
        payload
            .downcast_ref::<&str>()
            .map(|message| message.to_string())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_default()
    })
}

/// Poll a clone, scripting the inner future's poll should the clone reach it, and check the
/// result against the model.
fn poll(env: &Env, choice: u8, second: bool, script: Script) {
    let (mut taken, expected, reached) = {
        let mut world = env.world.lock();
        let Some(taken) = world.take(choice, second) else {
            return;
        };
        let model = &mut world.model;
        let expected = match &model.finished {
            Some(Finished::Ready { value, output }) => Expected::Ready(*value, output.clone()),
            Some(Finished::Poisoned) => Expected::Panic(POISONED),
            None if model.woken => {
                model.woken = false;
                model.polling = true;
                model.contended = false;
                model.polls += 1;
                let expected = match script.outcome {
                    Outcome::Pending => Expected::Pending,
                    Outcome::Ready(value) => Expected::Resolve(value),
                    Outcome::Panic => Expected::Panic(INNER_PANIC),
                };
                *env.script.lock() = Some(script);
                expected
            }
            None => Expected::Pending,
        };
        let reached = model.polling;
        (taken, expected, reached)
    };

    let mut cx = Context::from_waker(&taken.waker);
    let result = match expected {
        Expected::Panic(_) => catch(|| Pin::new(&mut taken.shared).poll(&mut cx)),
        _ => Ok(Pin::new(&mut taken.shared).poll(&mut cx)),
    };
    env.script.lock().take();

    let mut world = env.world.lock();
    world.model.polling = false;
    let pending = match (expected, result) {
        (Expected::Pending, Ok(Poll::Pending)) => {
            if reached && world.model.contended {
                let others = world.handles.iter().enumerate();
                for (_, handle) in others.filter(|&(index, _)| index != taken.index) {
                    if let Some(handle) = handle
                        && let Some((which, before)) = handle.asleep
                    {
                        assert!(
                            handle.wakes(which) > before,
                            "a clone waiting through a contended poll was not woken"
                        );
                    }
                }
            }
            true
        }
        (Expected::Resolve(value), Ok(Poll::Ready(output))) => {
            assert_eq!(*output, value);
            let produced = env.output.lock().clone();
            assert!(ptr::eq(produced.as_ptr(), Arc::as_ptr(&output)));
            world.model.finished = Some(Finished::Ready {
                value,
                output: produced,
            });
            false
        }
        (Expected::Ready(value, produced), Ok(Poll::Ready(output))) => {
            assert_eq!(*output, value);
            assert!(
                ptr::eq(produced.as_ptr(), Arc::as_ptr(&output)),
                "clone resolved to another output"
            );
            false
        }
        (Expected::Panic(expected), Err(message)) => {
            assert_eq!(message, expected, "unexpected panic");
            if expected == INNER_PANIC {
                world.model.finished = Some(Finished::Poisoned);
            }
            false
        }
        (expected, result) => panic!("expected {expected:?}, polled {result:?}"),
    };
    world.put(taken, pending);
}

/// Check the state of the future under test against the model.
fn check(env: &Env) {
    let world = env.world.lock();
    let model = &world.model;
    assert!(!model.polling);
    assert_eq!(
        env.polls.load(SeqCst),
        model.polls,
        "inner future polled a different number of times"
    );
    let live = world.live();
    assert_eq!(
        env.dropped.load(SeqCst),
        model.finished.is_some() || live == 0,
        "inner future dropped at the wrong time"
    );
    if let Some(Finished::Ready { output, .. }) = &model.finished {
        assert_eq!(
            output.strong_count() > 0,
            live > 0,
            "output dropped at the wrong time"
        );
    }
    if model.woken || model.finished.is_some() {
        for handle in world.handles.iter().flatten() {
            if let Some((which, before)) = handle.asleep {
                assert!(
                    handle.wakes(which) > before,
                    "a waiting clone was not woken"
                );
            }
        }
    }
}

fn fuzz(input: FuzzInput) {
    let env = Arc::new(Env::new());
    let stranger = Shared::new(Scripted(Arc::new(Env::new())));
    {
        let shared = Shared::new(Scripted(env.clone()));
        let mut world = env.world.lock();
        for _ in 0..usize::from(input.clones) % MAX_CLONES {
            world.handles.push(Some(Handle::new(shared.clone())));
        }
        world.handles.push(Some(Handle::new(shared)));
    }
    let mut weaks: Vec<WeakShared<Scripted>> = Vec::new();

    for operation in input.operations.into_iter().take(MAX_OPERATIONS) {
        match operation {
            Operation::Poll {
                clone,
                second,
                script,
            } => poll(&env, clone, second, script),
            Operation::Clone { clone } => env.world.lock().clone_handle(clone),
            Operation::Drop { clone } => {
                let handle = env.world.lock().remove(clone);
                drop(handle);
            }
            Operation::Downgrade { clone } => {
                let world = env.world.lock();
                if weaks.len() < MAX_WEAKS
                    && let Some(index) = world.pick(clone)
                {
                    weaks.push(world.shared(index).downgrade());
                }
            }
            Operation::CloneWeak { weak } => {
                if !weaks.is_empty() && weaks.len() < MAX_WEAKS {
                    weaks.push(weaks[usize::from(weak) % weaks.len()].clone());
                }
            }
            Operation::Upgrade { weak } => {
                if weaks.is_empty() {
                    continue;
                }
                let upgraded = weaks[usize::from(weak) % weaks.len()].upgrade();
                let mut world = env.world.lock();
                assert_eq!(
                    upgraded.is_some(),
                    world.live() > 0,
                    "upgrade must succeed exactly while a clone is alive"
                );
                let Some(upgraded) = upgraded else {
                    continue;
                };
                assert!(!upgraded.ptr_eq(&stranger));
                if let Some(index) = world.pick(0) {
                    assert!(upgraded.ptr_eq(world.shared(index)));
                }
                if world.live() < MAX_CLONES {
                    world.handles.push(Some(Handle::new(upgraded)));
                } else {
                    drop(world);
                    drop(upgraded);
                }
            }
            Operation::Wake => {
                let waker = env.waker.lock().clone();
                if let Some(waker) = waker {
                    waker.wake();
                    env.world.lock().model.woken = true;
                }
            }
            Operation::Forget => {
                let waker = env.waker.lock().take();
                drop(waker);
            }
        }
        check(&env);
    }

    // Dropping every clone releases the inner future or its output, which also breaks the
    // cycle through the inner future's handle to the world.
    let handles = std::mem::take(&mut env.world.lock().handles);
    drop(handles);
    check(&env);
    for weak in &weaks {
        assert!(weak.upgrade().is_none());
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
