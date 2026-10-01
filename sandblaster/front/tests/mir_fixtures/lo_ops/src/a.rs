
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pos(u64);

impl Pos {
    pub const fn new(x: u64) -> Self {
        Self(x)
    }
}

impl core::ops::Add<u64> for Pos {
    type Output = Self;
    fn add(self, r: u64) -> Self {
        Self(self.0 + r)
    }
}

impl core::ops::Deref for Pos {
    type Target = u64;
    fn deref(&self) -> &u64 {
        &self.0
    }
}

pub fn next(p: Pos) -> u64 {
    let q = p + 1;
    *q
}

pub fn zero() -> u64 {
    let z = Pos::default();
    *z
}
