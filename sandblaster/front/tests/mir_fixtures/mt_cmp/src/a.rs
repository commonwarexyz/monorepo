use core::cmp::Ordering;

pub fn order(a: u64, b: u64) -> Option<Ordering> {
    a.partial_cmp(&b)
}

pub fn lt(a: u64, b: u64) -> bool {
    a < b
}
