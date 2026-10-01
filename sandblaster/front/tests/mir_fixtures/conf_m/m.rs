//! The MMR track's lift features in one module.

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pos(u64);

impl Pos {
    pub const fn new(x: u64) -> Self {
        Self(x)
    }
}

impl core::ops::Add<u64> for Pos {
    type Output = Self;
    fn add(self, r: u64) -> Self {
        Self(self.0.wrapping_add(r))
    }
}

impl core::ops::Deref for Pos {
    type Target = u64;
    fn deref(&self) -> &u64 {
        &self.0
    }
}

impl PartialEq<u64> for Pos {
    fn eq(&self, o: &u64) -> bool {
        self.0 == *o
    }
}

impl PartialEq<Pos> for u64 {
    fn eq(&self, o: &Pos) -> bool {
        *self == o.0
    }
}

pub fn next(p: Pos) -> u64 {
    let q = p + 1;
    *q
}

pub fn is_at(p: Pos, x: u64) -> bool {
    p == x
}

pub fn at_is(x: u64, p: Pos) -> bool {
    x == p
}

pub fn zero() -> u64 {
    let z = Pos::default();
    *z
}

pub fn dec2(x: Option<u64>) -> Option<u64> {
    x.and_then(|v| v.checked_sub(2))
}

pub fn half_or_zero(x: Option<u64>) -> u64 {
    x.map_or(0u64, |v| v / 2)
}

pub fn shl_or_zero(x: u64, s: u32) -> u64 {
    match x.checked_shl(s) {
        Some(v) => v,
        None => 0,
    }
}

pub fn ones(x: u64) -> u32 {
    x.trailing_ones()
}

pub fn tripled(n: u32) -> u64 {
    let f = |k: u64| k * 3;
    f(n as u64)
}

pub fn halved(x: u64) -> u64 {
    assert!(x / 2 <= x, "halving never grows");
    x / 2
}

pub struct Down {
    n: u32,
}

impl Iterator for Down {
    type Item = u32;
    fn next(&mut self) -> Option<u32> {
        if self.n == 0 {
            return None;
        }
        self.n -= 1;
        Some(self.n)
    }
}

impl Down {
    pub fn new(n: u32) -> Self {
        Self { n }
    }
}

pub fn down(n: u16) -> impl Iterator<Item = u32> {
    Down::new(n as u32)
}

pub fn count(n: u16) -> u64 {
    let mut acc = 0u64;
    for _i in down(n) {
        acc += 1;
    }
    acc
}
