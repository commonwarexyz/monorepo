//! Generators, reference models and input types of the properties.
//!
//! Every generator is valid by construction: no filters and no discards.
//! `checks.rs` verifies them.

use ephyra::prelude::*;
use std::ops::{Bound, ControlFlow};

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

/// A `u128` whose bit length is uniform in 0..=128, so every varint length and
/// every 7-bit group boundary is drawn often.
pub fn wide() -> impl Gen<Value = u128> {
    (|g: &mut Source| {
        let bits = g.int(0u32..=128);
        let raw = (u128::from(g.int::<u64>(..)) << 64) | u128::from(g.int::<u64>(..));
        let value = if bits == 0 { 0 } else { raw >> (128 - bits) };
        match g.int(0u8..=3) {
            // 2^bits - 1 and 2^bits: the two sides of a length boundary.
            0 if bits > 0 && bits < 128 => (1u128 << bits) - 1,
            1 if bits < 128 => 1u128 << bits,
            _ => value,
        }
    })
    .with_shrink(shrink_wide)
}

/// Shrinks toward zero: zero itself, the value without its lowest 7 bits or
/// its lowest bit, then the value with its lowest set bit cleared. Every
/// candidate is smaller in (bit length, number of set bits), so a chain is
/// at most a few hundred steps long.
pub fn shrink_wide(v: &u128, visit: &mut dyn FnMut(u128) -> ControlFlow<()>) -> ControlFlow<()> {
    if *v == 0 {
        return ControlFlow::Continue(());
    }
    visit(0)?;
    if *v >> 7 != 0 {
        visit(*v >> 7)?;
    }
    if *v >> 1 != 0 && *v >> 1 != *v >> 7 {
        visit(*v >> 1)?;
    }
    let cleared = *v & (*v - 1);
    if cleared != 0 && cleared != *v >> 1 && cleared != *v >> 7 {
        visit(cleared)?;
    }
    ControlFlow::Continue(())
}

/// The measure the shrink candidates of `wide()` get smaller in.
pub fn wide_size(v: &u128) -> u64 {
    u64::from(128 - v.leading_zeros()) * 256 + u64::from(v.count_ones())
}

/// Bytes that look like a varint stream: mostly continuation bytes, some
/// terminators, some boundary bytes.
pub fn varint_like() -> impl Gen<Value = Vec<u8>> {
    gens::vec(gens::frequency(vec![
        (6, gens::int(0x80u8..=0xFF).boxed()),
        (3, gens::int(0x00u8..=0x7F).boxed()),
        (
            1,
            gens::pick_from(vec![0x00u8, 0x01, 0x7F, 0x80, 0x81, 0xFF]).boxed(),
        ),
    ]))
    .len(0..=24)
}

/// Exactly `n` arbitrary bytes.
pub fn raw(n: usize) -> impl Gen<Value = Vec<u8>> {
    gens::vec(any::<u8>()).len(n..=n)
}

pub fn bound() -> impl Gen<Value = Bound<usize>> {
    |g: &mut Source| match g.int(0u8..=2) {
        0 => Bound::Unbounded,
        1 => Bound::Included(g.int(0usize..=45)),
        _ => Bound::Excluded(g.int(0usize..=45)),
    }
}

// ---------------------------------------------------------------------------
// Reference models of the varint encoding
// ---------------------------------------------------------------------------

/// Reference encoder: LEB128, least significant group first.
pub fn leb128(mut v: u128) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let group = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            out.push(group);
            return out;
        }
        out.push(group | 0x80);
    }
}

#[derive(Debug, PartialEq)]
pub enum Model {
    /// A complete varint: its value and the bytes it used.
    Value(u128, usize),
    /// A zero byte after the first byte: the value has a shorter encoding.
    NonCanonical,
    /// The value needs more bits than the type has, or the varint is too long.
    Overflow,
    /// The bytes ended before a byte without the continuation bit.
    Truncated,
}

/// Reference decoder of one varint into an unsigned integer of `bits` bits.
pub fn model_decode(bytes: &[u8], bits: u32) -> Model {
    let last = (bits as usize).div_ceil(7) - 1;
    let mut value = 0u128;
    for (i, &b) in bytes.iter().enumerate() {
        if b == 0 && i > 0 {
            return Model::NonCanonical;
        }
        let shift = 7 * i as u32;
        if i == last {
            // Only `room` bits are left; a continuation bit does not fit either.
            let room = bits - shift;
            if 8 - b.leading_zeros() > room {
                return Model::Overflow;
            }
        }
        value |= u128::from(b & 0x7F) << shift;
        if b & 0x80 == 0 {
            return Model::Value(value, i + 1);
        }
    }
    Model::Truncated
}

// ---------------------------------------------------------------------------
// Inputs of the properties
// ---------------------------------------------------------------------------

/// Input of properties 2 and 5.
#[derive(Debug, Clone, ephyra::Arbitrary)]
pub struct Sample {
    pub ints: (u8, u16, u32, u64, i8, i16, i32, i64),
    #[ephyra(gen = wide())]
    pub big: u128,
    pub floats: (u32, u64),
    pub flag: bool,
    #[ephyra(gen = gens::vec(any::<u8>()).len(0..=300))]
    pub blob: Vec<u8>,
    #[ephyra(gen = gens::vec(gens::option(any::<u32>())).len(0..=24))]
    pub opts: Vec<Option<u32>>,
    #[ephyra(gen = gens::vec(gens::vec(any::<u16>()).len(0..=6)).len(0..=6))]
    pub nested: Vec<Vec<u16>>,
    #[ephyra(gen = gens::vec((any::<u16>(), gens::vec(any::<u8>()).len(0..=5))).len(0..=12))]
    pub pairs: Vec<(u16, Vec<u8>)>,
    #[ephyra(gen = gens::vec(any::<u32>()).len(0..=16))]
    pub keys: Vec<u32>,
    #[ephyra(gen = raw(16))]
    pub ip: Vec<u8>,
    pub v6: bool,
    pub port: u16,
    #[ephyra(gen = gens::vec(gens::frequency(vec![
        (1, gens::constant(0u8).boxed()),
        (2, gens::int(0u8..=0x7F).boxed()),
    ])).len(4..=4))]
    pub modes: Vec<u8>,
    #[ephyra(gen = gens::vec(any::<u8>()).len(0..=3))]
    pub extra: Vec<u8>,
}

/// Input of property 3.
#[derive(Debug, Clone, ephyra::Arbitrary)]
pub struct Limits {
    #[ephyra(gen = gens::int(0usize..=40))]
    pub n: usize,
    #[ephyra(gen = bound())]
    pub start: Bound<usize>,
    #[ephyra(gen = bound())]
    pub end: Bound<usize>,
    pub salt: u16,
}

/// The length limit property 4 decodes with.
pub const LIMIT: usize = 64;

/// One edit of a valid message (property 4). `Keep` comes first: derived
/// enums shrink toward their first variant.
#[derive(Debug, Clone, ephyra::Arbitrary)]
pub enum Mutation {
    Keep,
    Truncate(#[ephyra(gen = gens::int(1usize..=40))] usize),
    Flip(
        #[ephyra(gen = gens::int(0usize..=4095))] usize,
        #[ephyra(gen = gens::int(0u8..=7))] u8,
    ),
    Set(#[ephyra(gen = gens::int(0usize..=4095))] usize, u8),
    Insert(#[ephyra(gen = gens::int(0usize..=4095))] usize, u8),
    Remove(#[ephyra(gen = gens::int(0usize..=4095))] usize),
    Append(#[ephyra(gen = gens::vec(any::<u8>()).len(1..=6))] Vec<u8>),
}

/// Input of property 4.
#[derive(Debug, Clone, ephyra::Arbitrary)]
pub struct Hostile {
    #[ephyra(gen = gens::vec(gens::option(any::<u32>())).len(0..=8))]
    pub opts: Vec<Option<u32>>,
    #[ephyra(gen = gens::vec((any::<u16>(), gens::vec(any::<u8>()).len(0..=4))).len(0..=6))]
    pub pairs: Vec<(u16, Vec<u8>)>,
    #[ephyra(gen = gens::vec(any::<u32>()).len(0..=6))]
    pub keys: Vec<u32>,
    #[ephyra(gen = gens::vec(any::<u8>()).len(0..=40))]
    pub blob: Vec<u8>,
    #[ephyra(gen = raw(16))]
    pub ip: Vec<u8>,
    pub addr: (bool, bool, u16),
    pub scalars: (u64, i32, bool),
    #[ephyra(gen = gens::int(0usize..=LIMIT))]
    pub count: usize,
    #[ephyra(gen = gens::vec(any::<Mutation>()).len(0..=4))]
    pub mutations: Vec<Mutation>,
    #[ephyra(gen = gens::frequency(vec![
        (3, gens::int(0u32..=64).boxed()),
        (2, gens::int(0u32..=u32::MAX).boxed()),
        (1, gens::edges(0u32..=u32::MAX).boxed()),
    ]))]
    pub forged_len: u32,
    #[ephyra(gen = gens::vec(any::<u8>()).len(0..=24))]
    pub tail: Vec<u8>,
}

/// Input of property 5.
#[derive(Debug, Clone, ephyra::Arbitrary)]
pub struct Sized {
    pub sample: Sample,
    #[ephyra(gen = gens::int(0usize..=300))]
    pub slack: usize,
    // Arguments of `max_items_size`: any `len` up to `u32::MAX` ("Panics if
    // `len` exceeds `u32::MAX`"), any `item_size`.
    #[ephyra(gen = gens::frequency(vec![
        (4, gens::int(0u32..=4096).boxed()),
        (2, gens::int(0u32..=u32::MAX).boxed()),
        (1, gens::edges(0u32..=u32::MAX).boxed()),
    ]))]
    pub bound_len: u32,
    #[ephyra(gen = gens::frequency(vec![
        (12, gens::int(0usize..=4096).boxed()),
        (3, gens::int(0usize..=u32::MAX as usize).boxed()),
        (1, gens::int(0usize..=usize::MAX).boxed()),
    ]))]
    pub bound_item: usize,
}
