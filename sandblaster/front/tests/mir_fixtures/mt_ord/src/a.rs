#[derive(Clone, Copy)]
pub struct P(u64);

impl P {
    pub const fn new(x: u64) -> Self {
        Self(x)
    }
}

impl PartialEq for P {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for P {}

impl PartialOrd for P {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for P {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}
