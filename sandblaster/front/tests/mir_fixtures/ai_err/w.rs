use crate::Error;
pub fn fail(n: usize) -> Error { if n == 0 { Error::EndOfBuffer } else { Error::InvalidVarint(n) } }
