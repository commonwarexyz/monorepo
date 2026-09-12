//! Opt-in comparison of decoded locations and replacements in the pooled ordered index.

use super::{
    DummyMetrics, SEED,
    packed::{PackedLocation, Window},
};
use commonware_storage::{
    index::{Cursor, Unordered, partitioned::ordered::Index},
    translator::Cap,
};
use commonware_utils::TestRng;
use rand::Rng;
use std::{hint::black_box, time::Instant};

trait Value: Copy + Send + Sync {
    fn encode(window: Window, location: u64) -> Self;
    fn decode(self, window: Window) -> u64;
}

impl Value for u64 {
    #[inline]
    fn encode(_: Window, location: u64) -> Self {
        location
    }

    #[inline]
    fn decode(self, _: Window) -> u64 {
        self
    }
}

impl Value for PackedLocation {
    #[inline]
    fn encode(window: Window, location: u64) -> Self {
        window.encode(location).expect("location fits the window")
    }

    #[inline]
    fn decode(self, window: Window) -> u64 {
        window
            .decode(self)
            .expect("stored location fits the window")
    }
}

fn measure<V: Value, const P: usize>(items: u64) {
    assert!(items > 0 && items <= (1 << 38));
    // Cross the 40-bit boundary during initialization, with nonzero absolute high bits.
    let floor = (3 << 40) - items / 2;
    let before = black_box(Window::new(floor, floor + items).unwrap());
    let during = black_box(Window::new(floor, floor + 2 * items).unwrap());
    let after = black_box(Window::new(floor + items, floor + 2 * items).unwrap());
    let mut index = Index::<_, V, P>::new(DummyMetrics, Cap::<5>::new());

    let report = |operation: &str, start: Instant| {
        println!(
            "{}::{operation}/items={items} p={P} value_bytes={} ns/op={:.2}",
            module_path!(),
            size_of::<V>(),
            start.elapsed().as_nanos() as f64 / items as f64,
        );
    };

    let mut rng = TestRng::new(SEED);
    let start = Instant::now();
    for i in 0..items {
        index.insert(&rng.next_u64().to_be_bytes(), V::encode(before, floor + i));
    }
    report("build", start);

    let lookup = |window, base| {
        let mut rng = TestRng::new(SEED);
        for i in 0..items {
            assert!(black_box(
                index
                    .get(&rng.next_u64().to_be_bytes())
                    .any(|&value| black_box(value.decode(window)) == base + i)
            ));
        }
    };
    let start = Instant::now();
    lookup(before, floor);
    report("lookup", start);

    let mut rng = TestRng::new(SEED);
    let start = Instant::now();
    for i in 0..items {
        let key = rng.next_u64().to_be_bytes();
        let mut cursor = index.get_mut(&key).expect("inserted key exists");
        assert!(cursor.find(|&value| value.decode(during) == floor + i));
        cursor.update(V::encode(during, floor + items + i));
    }
    report("replace", start);

    // All old locations were replaced; publishing the new floor touches no stored values.
    let mut rng = TestRng::new(SEED);
    let start = Instant::now();
    for i in 0..items {
        assert!(black_box(index.get(&rng.next_u64().to_be_bytes()).any(
            |&value| black_box(value.decode(after)) == floor + items + i
        )));
    }
    report("lookup_after_floor", start);
}

pub(super) fn run(items: u64, only: &[String]) {
    // Explicit selection keeps this experiment out of the default scale tiers.
    for name in only {
        match name.as_str() {
            "locations_u64_2" => measure::<u64, 2>(items),
            "locations_packed_2" => measure::<PackedLocation, 2>(items),
            "locations_u64_3" => measure::<u64, 3>(items),
            "locations_packed_3" => measure::<PackedLocation, 3>(items),
            _ => {}
        }
    }
}
