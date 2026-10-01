
pub struct Down {
    n: u32,
}

impl Iterator for Down {
    type Item = u32;
    fn next(&mut self) -> Option<u32> {
        if self.n == 0 {
            return None;
        }
        self.n -= 1;
        Some(self.n)
    }
}

impl Down {
    pub fn new(n: u32) -> Self {
        Self { n }
    }
}

pub fn down(n: u32) -> impl Iterator<Item = u32> {
    Down::new(n)
}

pub fn heights(k: u32) -> impl Iterator<Item = u32> {
    1..=k
}

pub fn count(n: u32) -> u64 {
    let mut acc = 0u64;
    for _i in down(n) {
        acc += 1;
    }
    acc
}
