//! Shapes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Shape {
    Square(u32),
    Rect { w: u32, h: u32 },
    Empty,
}

impl Shape {
    pub fn area(&self) -> u64 {
        match *self {
            Shape::Square(s) => (s as u64) * (s as u64),
            Shape::Rect { w, h } => (w as u64) * (h as u64),
            Shape::Empty => 0,
        }
    }
}
