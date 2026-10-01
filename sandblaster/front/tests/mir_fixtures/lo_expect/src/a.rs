pub fn half_of_double(x: u64) -> u64 {
    x.checked_mul(2).expect("small") / 2
}
