// run-rustfix
#![allow(dead_code)]

use std::collections::BTreeMap;

pub trait Write {
    fn write(&self, buf: &mut Vec<u8>);
}
pub trait Read: Sized {
    type Cfg: Clone + Send + Sync + 'static;
    fn read(cfg: &Self::Cfg) -> Self;
}
pub trait Encode: Write {}
pub trait Decode: Read {}
pub trait Codec: Encode + Decode {}

// `Eq` is a supertrait of `Ord`.
pub struct Map<K, V>(BTreeMap<K, V>);
impl<K: Ord + Eq + Write, V: Write> Write for Map<K, V> {
    fn write(&self, buf: &mut Vec<u8>) {
        for (k, v) in &self.0 {
            k.write(buf);
            v.write(buf);
        }
    }
}

// `Clone` is a supertrait of `Copy`.
pub fn copy_clone<T: Copy + Clone>(t: T) -> T {
    t
}

// `Encode` is a supertrait of `Codec`.
pub fn codec_encode<O: Codec + Encode>(o: &O, buf: &mut Vec<u8>) {
    o.write(buf)
}

// `Read::Cfg` already declares `Clone` and `'static`.
pub struct Setup<G>(G);
impl<G: Read> Read for Setup<G>
where
    G::Cfg: Clone + 'static,
{
    type Cfg = G::Cfg;
    fn read(cfg: &Self::Cfg) -> Self {
        Setup(G::read(cfg))
    }
}

// A method bound implied by the enclosing impl's bound.
pub struct Wrap<T>(T);
impl<T: Copy> Wrap<T> {
    pub fn get(&self) -> T
    where
        T: Clone,
    {
        self.0
    }
}

// A supertrait implied by another supertrait.
pub trait Ordered: Ord + PartialEq {}

// A trait method bound on `Self` is kept because it decides dyn compatibility.
pub trait Keyed: Ord {
    fn key(&self) -> u8
    where
        Self: Eq;
}

// A trait method bound declared on the trait's own associated type.
pub trait Source {
    type Item: Clone;
    fn item(&self) -> Self::Item
    where
        Self::Item: Clone;
}

// An associated type bound implied by another of its bounds.
pub trait Store {
    type Key: Ord + Eq;
}

// An exact duplicate across an inline bound and a where clause.
pub fn dup<T: Clone>(t: &T) -> T
where
    T: Clone,
{
    t.clone()
}

// Implied through an associated type of a generic.
pub fn items<I: Iterator>(i: I) -> Vec<I::Item>
where
    I::Item: Copy + Clone,
{
    i.collect()
}

// Several implied bounds in one list, followed by a kept bound.
pub fn run<T: Ord + PartialOrd + Eq + PartialEq + Send>(t: T) -> T {
    t
}

// Several implied bounds at the end of a list.
pub fn tail<T: Send + Ord + Eq + PartialEq>(t: T) -> T {
    t
}

// Several where clause predicates removed whole.
pub fn both<T: Ord>(t: T) -> T
where
    T: Eq,
    T: PartialOrd,
{
    t
}

// Where clause predicates removed around one that stays.
pub fn around<T: Ord, U: Clone>(t: T, u: &U) -> (T, U)
where
    T: Eq,
    U: Send,
    T: PartialOrd,
{
    (t, u.clone())
}

// Implied on a struct definition.
pub struct Sorted<T: Ord + Eq>(Vec<T>);

// Implied by a bound that carries a constraint.
pub fn unit<G: Read<Cfg = ()>>() -> G
where
    G: Read,
{
    G::read(&())
}

// Independent bounds are kept.
pub fn partial_eq<T: PartialOrd + Eq>(a: T, b: T) -> bool {
    a == b && a <= b
}
pub fn send_clone<T: Clone + Send>(t: &T) -> T {
    t.clone()
}
pub fn two_into<T: Into<u64> + Into<u32> + Copy>(t: T) -> (u64, u32) {
    (t.into(), t.into())
}
pub fn higher_ranked<F: for<'a> Fn(&'a u8) -> &'a u8>(f: F) -> u8 {
    *f(&1)
}
pub fn unsized_ref<T: ?Sized + std::fmt::Debug>(t: &T) -> String {
    format!("{t:?}")
}

// A bound the associated type does not declare is kept.
pub fn default_cfg<G: Read>() -> G
where
    G::Cfg: Default,
{
    G::read(&Default::default())
}

// A bound on a projection that normalizes is kept.
pub fn pinned<G: Read<Cfg = C>, C>(c: &C) -> C
where
    G::Cfg: Clone,
{
    c.clone()
}

// A declared bound with type parameters is kept because the where clause guides
// inference.
pub trait Convert {
    type Out: Into<u64> + Into<u32>;
}
pub fn wide<G: Convert>(out: G::Out) -> u32
where
    G::Out: Into<u64>,
{
    out.into().count_ones()
}

// Derive-generated bounds are skipped.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Derived<T>(T);
#[derive(Clone)]
pub struct DerivedBound<T: Clone>(T);

// Macro-generated items are skipped.
macro_rules! generated {
    () => {
        pub fn generated<T: Ord + Eq>(t: T) -> T {
            t
        }
    };
}
generated!();

// A bound that carries a constraint is kept even when its trait is declared.
pub trait Subject {
    type Namespace;
}
pub trait Verifier {
    type Subject: Subject;
}
pub fn sign<V: Verifier, N>(s: V::Subject) -> V::Subject
where
    V::Subject: Subject<Namespace = N>,
{
    s
}

fn main() {}
