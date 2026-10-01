
pub struct Keep(pub u64);

impl Keep {
    pub fn get(self) -> u64 {
        self.0
    }
}

pub struct Skip(pub u64);

impl Skip {
    pub fn dec(self) -> u64 {
        self.0 - 1
    }
}

pub fn helper(x: u64) -> u64 {
    x - 1
}

pub fn uses_helper() -> u64 {
    helper(5)
}
