
pub struct Walk {
    pos: u64,
    step: u64,
}

impl Walk {
    pub fn go(&mut self, limit: u64) -> u64 {
        while self.step > 1 {
            if self.pos < limit {
                self.pos += self.step - 1;
                assert!(self.pos >= limit);
                return self.pos;
            }
            self.step >>= 1;
        }
        0
    }
}
