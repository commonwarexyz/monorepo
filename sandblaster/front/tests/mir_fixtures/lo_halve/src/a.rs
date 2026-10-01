
pub fn halve(mut x: u64, mut k: u64) -> u64 {
    while k != 0 {
        x = x / 2 + 1;
        k -= 1;
    }
    x
}
