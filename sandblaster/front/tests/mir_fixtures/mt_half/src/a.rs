pub fn half(x: u64) -> u64 {
    x / 2
}

pub fn use_half(x: u64) -> u64 {
    let r = half(x);
    assert!(r <= x && r <= x / 2);
    r
}
