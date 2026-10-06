#![allow(dead_code)]

// A removal that would delete a comment has no suggestion.
pub fn commented<T: Ord /* total */ + Eq>(t: T) -> T {
    t
}

// A bound list cannot drop its last bound, so it has no suggestion.
pub trait Copyable: Clone
where
    Self: Copy,
{
}

// A nested associated type bound has no suggestion.
pub fn nested<I: Iterator<Item: Copy + Clone>>(mut i: I) -> Option<I::Item> {
    i.next()
}

fn main() {}
