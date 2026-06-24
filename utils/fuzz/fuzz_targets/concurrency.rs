#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_utils::concurrency::{KeyedLimiter, KeyedReservation, Limiter, Reservation};
use libfuzzer_sys::fuzz_target;
use std::{collections::HashSet, num::NonZeroU32};

const MIN_OPERATIONS: usize = 4;
const MAX_OPERATIONS: usize = 64;

#[derive(Debug)]
enum Op {
    AcquireLimiter,
    DropLimiter(u8),
    AcquireKey(u8),
    DropKey(u8),
}

/// Keys are confined to `[0, keyed_max]` so distinct acquisitions reach
/// saturation and repeats collide, exercising both `try_acquire` rejection
/// branches.
#[derive(Debug)]
struct Plan {
    limiter_max: u32,
    keyed_max: u32,
    ops: Vec<Op>,
}

impl<'a> Arbitrary<'a> for Plan {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let limiter_max: u32 = u.int_in_range(1..=8)?;
        let keyed_max: u32 = u.int_in_range(1..=4)?;
        let key_space = keyed_max as u8 + 1;

        let num_operations = u.int_in_range(MIN_OPERATIONS..=MAX_OPERATIONS)?;
        let mut ops = Vec::with_capacity(num_operations);
        for _ in 0..num_operations {
            // AcquireKey is variant 0 so the zero-padded tail of an exhausted
            // input keeps acquiring key 0, driving the repeated keyed
            // acquisitions that reach the saturation and duplicate rejections.
            let op = match u8::arbitrary(u)? % 4 {
                0 => Op::AcquireKey(u8::arbitrary(u)? % key_space),
                1 => Op::AcquireLimiter,
                2 => Op::DropKey(u8::arbitrary(u)?),
                _ => Op::DropLimiter(u8::arbitrary(u)?),
            };
            ops.push(op);
        }

        Ok(Plan {
            limiter_max,
            keyed_max,
            ops,
        })
    }
}

fn run(plan: Plan) {
    let limiter_max = plan.limiter_max;
    let keyed_max = plan.keyed_max;
    let limiter = Limiter::new(NonZeroU32::new(limiter_max).unwrap());
    let keyed: KeyedLimiter<u8> = KeyedLimiter::new(NonZeroU32::new(keyed_max).unwrap());

    // Oracles: a count of live limiter reservations and the set of live keys.
    let mut held: Vec<Reservation> = Vec::new();
    let mut held_keyed: Vec<(u8, KeyedReservation<u8>)> = Vec::new();
    let mut keys: HashSet<u8> = HashSet::new();

    for op in plan.ops {
        match op {
            Op::AcquireLimiter => {
                let reservation = limiter.try_acquire();
                assert_eq!(reservation.is_some(), (held.len() as u32) < limiter_max);
                if let Some(reservation) = reservation {
                    held.push(reservation);
                }
            }
            Op::DropLimiter(idx) => {
                if !held.is_empty() {
                    drop(held.remove(idx as usize % held.len()));
                    // A freed slot must be immediately reusable.
                    let reservation = limiter.try_acquire();
                    assert!(reservation.is_some());
                }
            }
            Op::AcquireKey(key) => {
                let reservation = keyed.try_acquire(key);
                let expected = (keys.len() as u32) < keyed_max && !keys.contains(&key);
                assert_eq!(reservation.is_some(), expected);
                if let Some(reservation) = reservation {
                    keys.insert(key);
                    held_keyed.push((key, reservation));
                }
            }
            Op::DropKey(idx) => {
                if !held_keyed.is_empty() {
                    let (key, reservation) = held_keyed.remove(idx as usize % held_keyed.len());
                    drop(reservation);
                    keys.remove(&key);
                    // Dropping a key releases it: it (and the freed slot) can be reused.
                    let reacquired = keyed.try_acquire(key);
                    assert!(reacquired.is_some());
                    drop(reacquired);
                }
            }
        }

        assert!(held.len() as u32 <= limiter_max);
        assert!(keys.len() as u32 <= keyed_max);
    }
}

fuzz_target!(|plan: Plan| {
    run(plan);
});
