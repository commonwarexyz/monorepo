#[derive(Clone, Copy)]
pub struct Pos(u64);

impl Pos {
    pub const fn new(x: u64) -> Self {
        Self(x)
    }

    pub fn left_out(self, h: u32) -> u32 {
        depth(h)
    }
}

fn depth(h: u32) -> u32 {
    if h == 0 { 0 } else { depth(h - 1) | 1 }
}
