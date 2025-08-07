use bytes::{Buf, BufMut};
use commonware_codec::{util::at_least, EncodeSize, Error, Read, Write};

/// A type that represents a sequence of zero bytes.
///
/// This is useful for padding or zeroing out a buffer.
pub struct Zeroed {
    n: usize,
}

impl Zeroed {
    /// Create a new [Zeroed] with the given number of zero bytes.
    pub fn new(n: usize) -> Self {
        Self { n }
    }
}

impl Read for Zeroed {
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, n: &Self::Cfg) -> Result<Self, Error> {
        at_least(buf, *n)?;
        let mut bytes = vec![0; *n];
        buf.copy_to_slice(&mut bytes);
        if bytes.iter().any(|&b| b != 0) {
            return Err(Error::Invalid("Zeroed", "bytes are not zero"));
        }
        Ok(Self { n: *n })
    }
}

impl Write for Zeroed {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_bytes(0, self.n);
    }
}

impl EncodeSize for Zeroed {
    fn encode_size(&self) -> usize {
        self.n
    }
}
