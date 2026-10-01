use super::helper;

pub struct S;

impl S {
    pub fn helper(x: u64) -> u64 {
        x / 2
    }
}

pub fn f(x: u64) -> u64 {
    S::helper(x)
}
