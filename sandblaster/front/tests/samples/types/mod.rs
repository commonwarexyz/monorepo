//! Structs, enums, generics, lifetimes, constants, aliases, modules.
#![forbid(unsafe_code)]

use sandblaster::prelude::*;

mod inner;
pub mod shapes;

pub use shapes::Tree;

pub const TABLE: [u32; 4] = [1, 2, 3, 4];
pub const MASK: u32 = (1u32 << 4u32) - 1;
pub type Pair = (u32, u32);

/// A cursor over bytes.
#[derive(Clone, Copy)]
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Reader<'a> {
        Reader { data, pos: 0 }
    }

    pub fn byte(self) -> Option<(u8, Reader<'a>)> {
        let b = self.data.get(self.pos)?;
        Some((*b, Reader { pos: self.pos + 1, ..self }))
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }
}

pub fn read2(s: &[u8]) -> Option<(u8, u8, usize)> {
    let r = Reader::new(s);
    let (a, r) = r.byte()?;
    let (b, r) = r.byte()?;
    Some((a, b, r.remaining()))
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Wrap<T: Copy>(pub T);

impl<T: Copy> Wrap<T> {
    pub fn get(self) -> T {
        self.0
    }
}

pub fn wraps(x: u32) -> u32 {
    let w = Wrap(x);
    let v = Wrap(w);
    v.get().get() + Wrap::<u32>(1).0
}

pub fn pair_sum(p: Pair) -> u32 {
    let (a, b) = p;
    a + b + TABLE[3] + MASK + inner::helper(a) + inner::K
}

pub fn trees(t: Tree) -> u32 {
    t.weight()
}

pub fn tree_eq(a: Tree, b: Tree) -> bool {
    a == b
}

pub fn endian(x: u32) -> [u8; 4] {
    let be = x.to_be_bytes();
    let le = x.to_le_bytes();
    [be[0], le[0], be[3], le[3]]
}

pub fn chunks(s: &[u8]) -> u32 {
    let (c, r) = s.as_chunks::<4>();
    let mut acc: u32 = 0;
    for i in 0..c.len() {
        acc = acc.wrapping_add(u32::from_le_bytes(c[i]));
    }
    match s.first_chunk::<2>() {
        Some(h) => acc ^ (h[1] as u32) ^ (r.len() as u32),
        None => acc,
    }
}
