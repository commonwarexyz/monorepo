
pub fn check(x: u64) -> u64 {
    assert_eq!(x % 2, 0, "even");
    assert_ne!(x, 1);
    debug_assert!(x != 3);
    x / 2
}
