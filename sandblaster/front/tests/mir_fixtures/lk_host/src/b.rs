#[derive(Clone, Copy)]
pub struct Tick(u64);

impl Tick {
    pub const fn new(x: u64) -> Self {
        Self(x)
    }

    fn fifth(self) -> u64 {
        self.0 / 5
    }

    fn sixth(self) -> u64 {
        self.0 / 6
    }

    pub fn left_out(self) -> u64 {
        self.sixth()
    }
}

fn seventh(x: u64) -> u64 {
    x / 7
}

#[cfg(test)]
mod tests {
    #[test]
    fn seventh_of_fourteen() {
        assert_eq!(super::seventh(14), 2);
    }
}
