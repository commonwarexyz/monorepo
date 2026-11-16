#![no_main]

//! Translate fuzzed keys with each cap translator and check every translated key against the
//! key's capped bytes: it must equal them, order like them, and group with exactly the keys that
//! share them in a map hashed by the translator, as the unordered index stores them. Arrays too
//! wide to compare as one word must still order like their bytes.

use arbitrary::Arbitrary;
use commonware_storage::translator::{
    Cap, EightCap, FourCap, OneCap, OrderedTranslator, TwoCap, UnhashedArray,
};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::{BTreeSet, HashMap},
    fmt::Debug,
};

/// Keys and arrays past this count are ignored, so the pairwise checks stay cheap.
const MAX_KEYS: usize = 64;

/// One byte wider than the word an [UnhashedArray] compares as.
const WIDE: usize = 9;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    keys: Vec<Vec<u8>>,
    wide: Vec<[u8; WIDE]>,
}

/// The first `N` bytes of `key`, zero-padded on the right.
fn cap<const N: usize>(key: &[u8]) -> [u8; N] {
    let mut capped = [0; N];
    let len = key.len().min(N);
    capped[..len].copy_from_slice(&key[..len]);
    capped
}

/// Check the default `T` against the `N`-byte cap of each key, where `matches` compares a
/// translated key with the cap it should hold.
fn check<T, const N: usize>(keys: &[Vec<u8>], matches: impl Fn(&T::Key, &[u8; N]) -> bool)
where
    T: OrderedTranslator + Default,
    T::Key: Debug,
{
    let translator = T::default();
    let capped: Vec<[u8; N]> = keys.iter().map(|key| cap(key)).collect();
    let translated: Vec<T::Key> = keys.iter().map(|key| translator.transform(key)).collect();
    for ((key, t), c) in keys.iter().zip(&translated).zip(&capped) {
        assert!(
            matches(t, c),
            "{key:?} translated to {t:?}, not its cap {c:?}"
        );
    }

    // Ordered indices rely on translated keys ordering like the capped bytes they hold.
    for (a, ca) in translated.iter().zip(&capped) {
        for (b, cb) in translated.iter().zip(&capped) {
            assert_eq!(
                a.cmp(b),
                ca.cmp(cb),
                "{a:?} and {b:?} order unlike their caps"
            );
            assert_eq!(a.partial_cmp(b), Some(ca.cmp(cb)));
        }
    }

    // A map hashed by the translator must hold one entry per distinct cap.
    let mut groups = HashMap::with_hasher(translator.clone());
    for (t, c) in translated.iter().zip(&capped) {
        if let Some(previous) = groups.insert(*t, *c) {
            assert_eq!(previous, *c, "{t:?} grouped distinct caps");
        }
    }
    let distinct: BTreeSet<_> = capped.iter().collect();
    assert_eq!(
        groups.len(),
        distinct.len(),
        "equal translated keys hashed apart"
    );
    for (t, c) in translated.iter().zip(&capped) {
        assert_eq!(groups.get(t), Some(c), "{t:?} not found under its own hash");
    }
}

fn fuzz(input: FuzzInput) {
    let keys = &input.keys[..input.keys.len().min(MAX_KEYS)];
    check::<OneCap, 1>(keys, |t, c| *t == u8::from_be_bytes(*c));
    check::<TwoCap, 2>(keys, |t, c| *t == u16::from_be_bytes(*c));
    check::<FourCap, 4>(keys, |t, c| *t == u32::from_be_bytes(*c));
    check::<EightCap, 8>(keys, |t, c| *t == u64::from_be_bytes(*c));
    check::<Cap<1>, 1>(keys, |t, c| t == c);
    check::<Cap<3>, 3>(keys, |t, c| t == c);
    check::<Cap<5>, 5>(keys, |t, c| t == c);
    check::<Cap<8>, 8>(keys, |t, c| t == c);

    let wide: Vec<_> = input
        .wide
        .iter()
        .take(MAX_KEYS)
        .map(|&inner| UnhashedArray { inner })
        .collect();
    for a in &wide {
        for b in &wide {
            assert_eq!(
                a.cmp(b),
                a.inner.cmp(&b.inner),
                "{a:?} and {b:?} order unlike their bytes"
            );
            assert_eq!(a.partial_cmp(b), Some(a.inner.cmp(&b.inner)));
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
