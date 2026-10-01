
pub trait Mix: Clone + Send + Sync {
    fn base(&self, x: u64) -> u64;
    fn flip(&self, x: u64) -> u64 {
        self.base(x) ^ 1
    }
    fn low(&self, x: u64) -> u64 {
        self.base(x) & 15
    }
}

#[derive(Clone)]
pub struct Std {
    k: u64,
}

impl Std {
    pub fn new(k: u64) -> Self {
        Self { k }
    }
    pub fn base(&self, x: u64) -> u64 {
        x ^ self.k
    }
    pub fn low(&self, x: u64) -> u64 {
        self.base(x) & 15
    }
}

impl Mix for Std {
    fn base(&self, x: u64) -> u64 {
        Self::base(self, x)
    }
}

pub fn run<M: Mix>(m: &M, x: u64) -> u64 {
    m.flip(x) | m.low(x)
}
