#![no_main]

use arbitrary::Arbitrary;
use commonware_utils::concurrency::{KeyedLimiter, KeyedReservation, Limiter, Reservation};
use libfuzzer_sys::fuzz_target;
use std::{collections::HashSet, num::NonZeroU32};

/// Keys are confined to a small space so the keyed limiter sees duplicate-key
/// reservations and saturation, exercising both rejection branches.
const KEY_SPACE: u8 = 8;

#[derive(Arbitrary, Debug)]
enum Op {
    AcquireLimiter,
    DropLimiter(u8),
    AcquireKey(u8),
    DropKey(u8),
}

/// `first` guarantees the op list is never empty.
#[derive(Arbitrary, Debug)]
struct Plan {
    limiter_max: u8,
    keyed_max: u8,
    first: Op,
    rest: Vec<Op>,
}

fn run(plan: Plan) {
    let limiter_max = (plan.limiter_max % 8) as u32 + 1;
    let keyed_max = (plan.keyed_max % 8) as u32 + 1;
    let limiter = Limiter::new(NonZeroU32::new(limiter_max).unwrap());
    let keyed: KeyedLimiter<u8> = KeyedLimiter::new(NonZeroU32::new(keyed_max).unwrap());

    // Oracles: a count of live limiter reservations and the set of live keys.
    let mut held: Vec<Reservation> = Vec::new();
    let mut held_keyed: Vec<(u8, KeyedReservation<u8>)> = Vec::new();
    let mut keys: HashSet<u8> = HashSet::new();

    for op in core::iter::once(plan.first).chain(plan.rest) {
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
                let key = key % KEY_SPACE;
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
