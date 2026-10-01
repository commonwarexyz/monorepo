#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    EndOfBuffer,
    InvalidVarint(usize),
}
