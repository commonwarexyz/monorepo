#[derive(Clone, Copy)]
pub struct Pos(u64);

#[derive(Clone, Copy)]
pub struct Loc(u64);

impl Pos {
    pub const fn new(x: u64) -> Self {
        Self(x)
    }
}

impl Loc {
    pub const fn new(x: u64) -> Self {
        Self(x)
    }
}

impl From<Pos> for u64 {
    fn from(pos: Pos) -> Self {
        pos.0
    }
}

impl From<Loc> for u64 {
    fn from(loc: Loc) -> Self {
        loc.0
    }
}

impl PartialEq<Pos> for u64 {
    fn eq(&self, other: &Pos) -> bool {
        *self == other.0
    }
}

pub fn half(x: u64) -> u64 {
    x / 2
}
