pub struct T(u64);

impl T {
    pub fn get(&self) -> u64 {
        self.bump()
    }
    pub fn bump(&self) -> u64 {
        self.0 + 1
    }
}
