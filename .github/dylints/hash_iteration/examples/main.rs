// These fixtures compile against the real std, hashbrown, and ahash collections so
// the lint sees their actual types and iterator implementations.

use rayon::prelude::*;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, hash_map::Keys};

mod lookalike {
    pub struct HashMap;

    impl HashMap {
        pub fn iter(&self) -> std::ops::Range<u8> {
            0..1
        }
    }
}

/// A trait that implies `IntoIterator`, with a method that iterates its receiver.
trait Rows: IntoIterator + Sized {
    fn first(self) -> Option<Self::Item> {
        self.into_iter().next()
    }
}

impl Rows for HashMap<u8, u8> {}

fn first_row<I: Rows>(rows: I) -> Option<I::Item> {
    rows.into_iter().next()
}

fn first_by_ref<T>(items: &T) -> usize
where
    for<'a> &'a T: IntoIterator,
{
    items.into_iter().count()
}

/// A tuple struct with an `IntoIterator` bound.
struct Holder<I: IntoIterator>(I);

impl<I: IntoIterator> Holder<I> {
    /// A method whose impl bounds the held collection and iterates it, with no argument of
    /// the collection's type.
    fn visit(self) -> std::vec::IntoIter<I::Item> {
        self.0.into_iter().collect::<Vec<_>>().into_iter()
    }
}

/// A collection behind an accessor that hides its type.
struct Opaque(HashSet<u8>);

impl Opaque {
    fn all(&self) -> impl IntoIterator<Item = &u8> + '_ {
        &self.0
    }
}

fn main() {
    let mut map: HashMap<u8, u8> = HashMap::new();
    let mut set: HashSet<u8> = HashSet::new();
    let other: HashSet<u8> = HashSet::new();

    // Iterating methods, also where the outcome cannot depend on the order.
    let _ = map.iter().next();
    let _ = map.iter().count();
    let _ = map.keys().last();
    let _: Vec<_> = map.values().collect();
    let _: BTreeSet<_> = map.keys().copied().collect();
    map.values_mut().for_each(|value| *value += 1);
    map.iter_mut().for_each(|(_, value)| *value += 1);
    map.retain(|key, _| *key > 0);
    let _ = set.iter().all(|&item| item > 0);
    let _ = set.difference(&other).next();
    let _ = set.union(&other).min_by_key(|item| **item % 2);
    let _: Vec<_> = set.drain().collect();
    let _ = HashMap::iter(&map).next();
    let _ = map.extract_if(|key, _| *key > 0).count();
    let _ = map.clone().into_keys().count();
    let mut sorted: Vec<_> = set.iter().collect();
    sorted.sort_unstable();

    // `IntoIterator`, directly and through `for` loops.
    for _ in &map {}
    for _ in &mut map {}
    for _ in map.clone() {}
    let _: Vec<_> = map.clone().into_iter().collect();

    // Collections passed for parameters bounded by `IntoIterator`.
    let mut pairs = Vec::new();
    pairs.extend(&map);
    let _ = Vec::from_iter(set.clone());
    let _ = [1u8].iter().chain(&other).next();
    let _ = std::iter::zip(&other, 0..).next();
    let mut whole: BTreeSet<u8> = BTreeSet::new();
    whole.extend(&set);
    let _ = BTreeMap::from_iter(map.clone());
    let _ = Holder(map.clone()).visit().count();

    // Other hash collections.
    let brown: hashbrown::HashMap<u8, u8> = hashbrown::HashMap::new();
    let _ = brown.keys().next();
    for _ in &brown {}
    let fast: ahash::AHashMap<u8, u8> = ahash::AHashMap::new();
    let _ = fast.values().next();
    for _ in &fast {}

    // HashTable traversals, function values, implied, inherited, and higher-ranked bounds,
    // items that `flatten` visits, Rayon, and opaque return types.
    let table: hashbrown::HashTable<u8> = hashbrown::HashTable::new();
    let _ = table.iter_buckets().next();
    let _ = table.iter_hash(0).next();
    let _ = table.get_bucket(0);
    let keys: fn(&HashMap<u8, u8>) -> Keys<'_, u8, u8> = HashMap::keys;
    let _ = keys(&map).next();
    let _ = [&map].into_iter().flat_map(HashMap::keys).next();
    let rows: fn(HashMap<u8, u8>) -> Option<(u8, u8)> = first_row::<HashMap<u8, u8>>;
    let _ = rows(map.clone());
    let _ = first_row(map.clone());
    let _ = map.clone().first();
    let _ = first_by_ref(&map);
    let _ = std::iter::once(&map).flatten().next();
    let _: Vec<_> = map.par_iter().map(|(key, _)| *key).collect();
    let _ = map.par_iter().count();
    let mut parallel_pairs: Vec<(u8, u8)> = Vec::new();
    parallel_pairs.par_extend(map.clone());
    for _ in Opaque(set.clone()).all() {}

    // Lookups, ordered collections, constructors, and lookalike types are not flagged.
    let _ = map.get(&1);
    let _ = map.len();
    let _ = set.contains(&1);
    let ordered: BTreeMap<u8, u8> = BTreeMap::new();
    let _ = ordered.iter().next();
    for _ in &ordered {}
    let _ = lookalike::HashMap.iter().next();
    let _ = Holder(map.clone());

    // An expectation keeps a hash collection when the order cannot matter for a reason the
    // lint cannot see.
    #[cfg_attr(
        dylint_lib = "hash_iteration",
        expect(hash_iteration, reason = "every value is overwritten")
    )]
    for value in map.values_mut() {
        *value = 0;
    }
}
