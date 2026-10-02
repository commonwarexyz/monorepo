mod sealed {
    pub trait Halve: Copy {
        fn halve(self) -> Self;
    }

    impl Halve for u32 {
        fn halve(self) -> Self {
            self / 2
        }
    }
}

use sealed::Halve;

#[derive(Clone, Copy)]
pub struct Pos(u64);

impl Pos {
    pub const fn new(x: u64) -> Self {
        Self(x)
    }
}

pub fn third(x: u64) -> u64 {
    x / 3
}

pub(crate) fn quarter(x: u64) -> u64 {
    x / 4
}

fn eighth(x: u64) -> u64 {
    x / 8
}

pub fn sixteenth(x: u64) -> u64 {
    eighth(x) / 2
}

pub fn half_of(x: u32) -> u32 {
    x.halve()
}
