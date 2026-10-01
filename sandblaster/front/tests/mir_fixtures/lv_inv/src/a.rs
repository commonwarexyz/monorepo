
#[derive(thiserror::Error, Debug)]
pub enum Oops {
    #[error("too big")]
    TooBig,
    #[error("too small")]
    TooSmall,
}

#[derive(Copy, Clone)]
pub struct Span {
    lo: u64,
    hi: u64,
}

impl Span {
    pub fn new(lo: u64, hi: u64) -> Option<Self> {
        if lo <= hi {
            Some(Self { lo, hi })
        } else {
            None
        }
    }
    pub fn width(&self) -> Result<u64, Oops> {
        if self.hi - self.lo > 100 {
            return Err(Oops::TooBig);
        }
        Ok(self.hi - self.lo)
    }
}
