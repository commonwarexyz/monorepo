fn depth(h: u32) -> u32 {
    if h == 0 {
        0
    } else {
        depth(h - 1) | 1
    }
}

pub fn depth8() -> u32 {
    depth(8)
}
