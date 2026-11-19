#![no_main]

//! Check [Cached] and [thread_local_cache] against a model of each slot's cached value.
//!
//! A take on an empty slot must call `create` once and not `reset`; a take on a filled slot must
//! call `reset` once and not `create`. Either closure's error must come back from the take and
//! leave the slot free, with a failed reset keeping the cached value. A guard must read the
//! created or reset value, follow every write made through it, and return its value to the slot
//! when dropped. Guards on two slots held at once must never change each other's values.

use arbitrary::{Arbitrary, Unstructured};
use commonware_utils::{Cached, FuzzRng, thread_local_cache};
use libfuzzer_sys::fuzz_target;
use rand_core::Rng as _;
use std::{
    cell::{Cell, RefCell},
    thread::{self, LocalKey},
};

/// Bytes of the stream an input is sampled from, several times the largest input, and of the
/// input's head that seeds the stream.
const STREAM_BYTES: usize = 1 << 12;
const SEED_BYTES: usize = 8;

/// Fewest and most operations an input applies.
const MIN_OPS: usize = 1;
const MAX_OPS: usize = 32;

/// Longest value a `create` closure returns.
const MAX_CREATED: usize = 8;

/// Most bytes written through one guard.
const MAX_WRITES: usize = 4;

thread_local_cache!(static FIRST: Vec<u8>);
thread_local_cache!(static SECOND: Vec<u8>);

type Slot = LocalKey<RefCell<(bool, Option<Vec<u8>>)>>;

/// The error a failing closure returns, naming the closure that failed.
#[derive(Debug, PartialEq, Eq)]
enum Failure {
    Create,
    Reset,
}

#[derive(Arbitrary, Clone, Copy, Debug)]
enum Which {
    First,
    Second,
}

#[derive(Debug)]
enum Create {
    Value(Vec<u8>),
    Fail,
}

impl<'a> Arbitrary<'a> for Create {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        if u.ratio(1, 4)? {
            return Ok(Self::Fail);
        }
        let len = u.int_in_range(0..=MAX_CREATED)?;
        Ok(Self::Value(u.bytes(len)?.to_vec()))
    }
}

#[derive(Clone, Copy, Debug)]
enum Reset {
    Keep,
    Clear,
    Push(u8),
    Fail,
}

impl<'a> Arbitrary<'a> for Reset {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        if u.ratio(1, 4)? {
            return Ok(Self::Fail);
        }
        Ok(match u.int_in_range(0..=2)? {
            0 => Self::Keep,
            1 => Self::Clear,
            _ => Self::Push(u.arbitrary()?),
        })
    }
}

/// One take of a slot, the writes made through its guard, and the guard's drop.
#[derive(Debug)]
struct Use {
    create: Create,
    reset: Reset,
    writes: Vec<u8>,
}

impl<'a> Arbitrary<'a> for Use {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let create = u.arbitrary()?;
        let reset = u.arbitrary()?;
        let len = u.int_in_range(0..=MAX_WRITES)?;
        Ok(Self {
            create,
            reset,
            writes: u.bytes(len)?.to_vec(),
        })
    }
}

#[derive(Arbitrary, Debug)]
enum Op {
    /// Use one slot.
    Single { which: Which, held: Use },
    /// Hold guards on both slots at once.
    Both {
        first: Use,
        second: Use,
        first_taken_first: bool,
        first_dropped_first: bool,
    },
}

#[derive(Debug)]
struct FuzzInput {
    ops: Vec<Op>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // The input's head seeds a fixed-size stream that the rest of the input overwrites from
        // its start, so even the empty input samples a whole sequence of operations.
        let seed = u.bytes(u.len().min(SEED_BYTES))?.to_vec();
        let mut stream = vec![0; STREAM_BYTES.max(u.len())];
        FuzzRng::new(seed).fill_bytes(&mut stream);
        let literal = u.bytes(u.len())?;
        stream[..literal.len()].copy_from_slice(literal);
        let u = &mut Unstructured::new(&stream);

        Ok(Self {
            ops: (0..u.int_in_range(MIN_OPS..=MAX_OPS)?)
                .map(|_| u.arbitrary())
                .collect::<arbitrary::Result<_>>()?,
        })
    }
}

/// The value each slot caches, `None` until a guard on it is first dropped.
#[derive(Default)]
struct Model {
    first: Option<Vec<u8>>,
    second: Option<Vec<u8>>,
}

impl Model {
    const fn cached(&mut self, which: Which) -> &mut Option<Vec<u8>> {
        match which {
            Which::First => &mut self.first,
            Which::Second => &mut self.second,
        }
    }
}

const fn slot(which: Which) -> &'static Slot {
    match which {
        Which::First => &FIRST,
        Which::Second => &SECOND,
    }
}

/// A guard and the value the model expects it to hold.
struct Held {
    which: Which,
    guard: Cached<Vec<u8>>,
    expected: Vec<u8>,
}

impl Held {
    fn write(&mut self, writes: &[u8]) {
        for &byte in writes {
            self.guard.push(byte);
            self.expected.push(byte);
            assert_eq!(*self.guard, self.expected);
        }
    }

    fn release(self, model: &mut Model) {
        drop(self.guard);
        *model.cached(self.which) = Some(self.expected);
    }
}

/// Takes `which` as `held` asks, checking which closure ran and what the take returned.
fn take(which: Which, held: &Use, model: &mut Model) -> Option<Held> {
    let created = Cell::new(0u32);
    let reset = Cell::new(0u32);
    let result = Cached::take(
        slot(which),
        || {
            created.set(created.get() + 1);
            match &held.create {
                Create::Value(value) => Ok(value.clone()),
                Create::Fail => Err(Failure::Create),
            }
        },
        |value| {
            reset.set(reset.get() + 1);
            match held.reset {
                Reset::Keep => {}
                Reset::Clear => value.clear(),
                Reset::Push(byte) => value.push(byte),
                Reset::Fail => return Err(Failure::Reset),
            }
            Ok(())
        },
    );

    let cached = model.cached(which);
    let expected = match cached.take() {
        None => {
            assert_eq!((created.get(), reset.get()), (1, 0), "a miss must create");
            match &held.create {
                Create::Value(value) => value.clone(),
                Create::Fail => {
                    assert_eq!(result.err(), Some(Failure::Create));
                    return None;
                }
            }
        }
        Some(mut value) => {
            assert_eq!((created.get(), reset.get()), (0, 1), "a hit must reset");
            match held.reset {
                Reset::Keep => {}
                Reset::Clear => value.clear(),
                Reset::Push(byte) => value.push(byte),
                Reset::Fail => {
                    assert_eq!(result.err(), Some(Failure::Reset));
                    *cached = Some(value);
                    return None;
                }
            }
            value
        }
    };
    let guard = result.expect("take must succeed when its closure does");
    assert_eq!(*guard, expected);
    Some(Held {
        which,
        guard,
        expected,
    })
}

fn run(ops: &[Op]) {
    let mut model = Model::default();
    for op in ops {
        match op {
            Op::Single { which, held } => {
                if let Some(mut guard) = take(*which, held, &mut model) {
                    guard.write(&held.writes);
                    guard.release(&mut model);
                }
            }
            Op::Both {
                first,
                second,
                first_taken_first,
                first_dropped_first,
            } => {
                let (one, two) = if *first_taken_first {
                    let one = take(Which::First, first, &mut model);
                    (one, take(Which::Second, second, &mut model))
                } else {
                    let two = take(Which::Second, second, &mut model);
                    (take(Which::First, first, &mut model), two)
                };
                let mut guards = [(one, first), (two, second)];
                for (guard, held) in &mut guards {
                    if let Some(guard) = guard {
                        guard.write(&held.writes);
                    }
                }
                for guard in guards.iter().flat_map(|(guard, _)| guard) {
                    assert_eq!(*guard.guard, guard.expected);
                }
                if !*first_dropped_first {
                    guards.reverse();
                }
                for (guard, _) in guards {
                    if let Some(guard) = guard {
                        guard.release(&mut model);
                    }
                }
            }
        }
    }
}

fn fuzz(input: FuzzInput) {
    // Slots outlive one iteration of the fuzzing thread, so each input runs on a new thread that
    // starts with both slots empty and destroys them when it ends.
    thread::scope(|scope| {
        scope
            .spawn(|| run(&input.ops))
            .join()
            .expect("input thread panicked");
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
