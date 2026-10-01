#[derive(Default)]
pub struct S {
    x: u64,
}

pub fn zero() -> u64 {
    let s = S::default();
    s.x
}
