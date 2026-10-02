mod child;

#[derive(Clone, Copy)]
pub struct Pos(u64);

impl Pos {
    pub const fn new(x: u64) -> Self {
        Self(x)
    }

    pub(crate) fn halve(self) -> u64 {
        self.0 / 2
    }

    fn third(self) -> u64 {
        self.0 / 3
    }
}

#[derive(Clone, Copy)]
pub struct Hidden(u64);

impl Hidden {
    pub fn get(self) -> u64 {
        self.0
    }
}

fn quarter(x: u64) -> u64 {
    x / 4
}

pub fn down(h: u32) -> u32 {
    if h == 0 { 0 } else { down(h - 1) }
}
