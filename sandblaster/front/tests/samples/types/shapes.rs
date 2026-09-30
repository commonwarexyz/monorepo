//! A public module with an enum.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tree {
    Leaf(u32),
    Pair { l: u32, r: u32 },
    Nil,
}

impl Tree {
    pub fn weight(&self) -> u32 {
        match self {
            Tree::Leaf(v) => *v,
            Tree::Pair { l, r } => l.wrapping_add(*r),
            Tree::Nil => 0,
        }
    }
}
