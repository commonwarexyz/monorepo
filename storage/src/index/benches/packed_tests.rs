#[path = "packed.rs"]
mod packed;

use crate::{
    index::{Cursor as _, Ordered as _, Unordered as _, partitioned::ordered::Index},
    translator::OneCap,
};
use commonware_runtime::{Runner, Supervisor as _, deterministic};
use commonware_utils::test_rng;
use packed::{Error, MASK, PackedLocation, WINDOW_SIZE, Window};
use rand::Rng;

#[test]
fn test_window_boundaries() {
    assert_eq!(size_of::<PackedLocation>(), 5);
    assert_eq!(align_of::<PackedLocation>(), 1);
    assert!(matches!(Window::new(2, 1), Err(Error::InvalidWindow)));
    assert!(matches!(
        Window::new(0, WINDOW_SIZE + 1),
        Err(Error::InvalidWindow)
    ));
    let empty = Window::new(7, 7).unwrap();
    assert_eq!(empty.encode(7), Err(Error::OutsideWindow));
    assert_eq!(
        empty.decode(PackedLocation([7, 0, 0, 0, 0])),
        Err(Error::OutsideWindow)
    );

    for floor in [0, WINDOW_SIZE - 3, WINDOW_SIZE + 7, (1 << 62) - WINDOW_SIZE] {
        let window = Window::new(floor, floor + WINDOW_SIZE).unwrap();
        for delta in [0, 1, 17, WINDOW_SIZE - 1] {
            let location = floor + delta;
            assert_eq!(
                window.decode(window.encode(location).unwrap()),
                Ok(location)
            );
        }
        assert_eq!(
            window.encode(floor + WINDOW_SIZE),
            Err(Error::OutsideWindow)
        );
        if floor > 0 {
            assert_eq!(window.encode(floor - 1), Err(Error::OutsideWindow));
        }
    }

    let near_max = Window::new(u64::MAX - 10, u64::MAX).unwrap();
    assert_eq!(
        near_max.decode(PackedLocation([0; 5])),
        Err(Error::OutsideWindow)
    );
    let last = near_max.encode(u64::MAX - 1).unwrap();
    assert_eq!(near_max.decode(last), Ok(u64::MAX - 1));
}

#[test]
fn test_floor_advances_without_reencoding() {
    let mut rng = test_rng();
    for _ in 0..10_000 {
        let floor = rng.next_u64() >> 2;
        let delta = rng.next_u64() & MASK;
        let location = floor + delta;
        let before = Window::new(floor, floor + WINDOW_SIZE).unwrap();
        let stored = before.encode(location).unwrap();
        let after = Window::new(location, floor + WINDOW_SIZE).unwrap();
        assert_eq!(after.encode(location).unwrap(), stored);
        assert_eq!(after.decode(stored), Ok(location));
    }

    // A codec cannot validate that an old indexed value was removed before changing floors.
    let before = Window::new(0, WINDOW_SIZE).unwrap();
    let old = before.encode(0).unwrap();
    let after = Window::new(1, WINDOW_SIZE + 1).unwrap();
    assert_eq!(after.decode(old), Ok(WINDOW_SIZE));
}

#[test]
fn test_transition_window_checked_before_updates() {
    let old_floor = 0;
    let final_window = Window::new(WINDOW_SIZE, WINDOW_SIZE + 10).unwrap();
    assert!(final_window.encode(WINDOW_SIZE).is_ok());
    assert!(matches!(
        Window::new(old_floor, WINDOW_SIZE + 10),
        Err(Error::InvalidWindow)
    ));
}

#[test]
fn test_index_updates_collisions_deletes_and_spills() {
    deterministic::Runner::default().start(|context| async move {
        for (label, count) in [("inline", 32u64), ("spilled", 600)] {
            let mut index = Index::<_, PackedLocation, 1>::new(context.child(label), OneCap);
            let floor = 3 * WINDOW_SIZE - count / 2;
            let before = Window::new(floor, floor + count).unwrap();
            // Distinct keys share a translated key; the larger case also spills.
            let key = |i: u64| [0, (i % 16) as u8, (i / 16) as u8];
            for i in 0..count {
                index.insert(&key(i), before.encode(floor + i).unwrap());
            }
            assert!(
                index
                    .first_translated_key()
                    .unwrap()
                    .all(|&value| (before.decode(value).unwrap() - floor).is_multiple_of(16))
            );
            assert!(
                index
                    .last_translated_key()
                    .unwrap()
                    .all(|&value| { (before.decode(value).unwrap() - floor) % 16 == 15 })
            );
            let during = Window::new(floor, floor + 2 * count).unwrap();
            for i in 0..count {
                let mut cursor = index.get_mut(&key(i)).unwrap();
                assert!(cursor.find(|&value| during.decode(value).unwrap() == floor + i));
                cursor.update(during.encode(floor + count + i).unwrap());
            }
            let after = Window::new(floor + count, floor + 2 * count).unwrap();
            for i in 0..count {
                assert!(
                    index
                        .get(&key(i))
                        .any(|&value| { after.decode(value).unwrap() == floor + count + i })
                );
                let mut cursor = index.get_mut(&key(i)).unwrap();
                assert!(cursor.find(|&value| after.decode(value).unwrap() == floor + count + i));
                cursor.delete();
            }
            assert!(index.first_translated_key().is_none());
            assert_eq!(index.items(), 0);
        }
    });
}
