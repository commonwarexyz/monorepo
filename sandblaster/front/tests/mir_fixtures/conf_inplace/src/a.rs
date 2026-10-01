pub struct Acc {
    total: u32,
    count: u8,
}

impl Acc {
    pub fn new() -> Self {
        Self { total: 0, count: 0 }
    }

    pub fn add(&mut self, b: u8) -> bool {
        if self.count >= 100 {
            return false;
        }
        self.total = self.total.wrapping_add(b as u32);
        self.count += 1;
        true
    }
}

pub fn inc(x: u32) -> u32 {
    x + 1
}

pub fn half(x: i32) -> i32 {
    x >> 1
}
