use blake3::BLOCK_LEN;
use bytes::Buf;
use rand_core::{
    impls::{next_u32_via_fill, next_u64_via_fill},
    CryptoRng, CryptoRngCore, RngCore,
};

fn encode_u61(x: u64) -> (usize, [u8; 8]) {
    assert!(x < (1 << 61));
    let chunks = (64 - x.leading_zeros() as usize) / 8;
    let mut out = (x << 3).to_le_bytes();
    out[0] |= chunks as u8;
    (chunks, out)
}

struct Rng {
    inner: blake3::OutputReader,
    buf: [u8; BLOCK_LEN],
    remaining: usize,
}

impl Rng {
    fn new(inner: blake3::OutputReader) -> Self {
        Self {
            inner,
            buf: [0u8; BLOCK_LEN],
            remaining: 0,
        }
    }
}

impl RngCore for Rng {
    fn next_u32(&mut self) -> u32 {
        next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let dest_len = dest.len();
        if self.remaining >= dest_len {
            dest.copy_from_slice(&self.buf[..dest_len]);
            self.remaining -= dest_len;
            return;
        }

        let (start, mut dest) = dest.split_at_mut(self.remaining);
        start.copy_from_slice(&self.buf[..self.remaining]);
        self.remaining = 0;

        while dest.len() >= BLOCK_LEN {
            let (block, rest) = dest.split_at_mut(BLOCK_LEN);
            self.inner.fill(block);
            dest = rest;
        }

        let dest_len = dest.len();
        if dest_len > 0 {
            self.inner.fill(&mut self.buf[..]);
            dest.copy_from_slice(&self.buf[..dest_len]);
            self.remaining = BLOCK_LEN - dest_len;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for Rng {}

#[repr(u8)]
enum StartTag {
    New = 0,
    Resume = 1,
    Fork = 2,
    Noise = 3,
}

/// This struct provides a convenient abstraction over hashing data and deriving randomness.
///
/// It automatically takes care of details like:
/// - correctly segmenting packets of data,
/// - domain separating different uses of tags and randomness,
/// - making sure that secret state is zeroized as necessary.
pub struct Transcript {
    hasher: blake3::Hasher,
    pending: u64,
}

impl Transcript {
    fn start(tag: StartTag, initial_data: Option<&[u8]>) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&[tag as u8]);
        let mut out = Self { hasher, pending: 0 };
        if let Some(data) = initial_data {
            out.commit(data);
        }
        out
    }

    fn flush(&mut self) {
        let (n, bytes) = encode_u61(self.pending);
        self.hasher.update(&bytes[..n]);
        self.pending = 0;
    }

    fn do_append(&mut self, data: &[u8]) {
        self.hasher.update(data);
        self.pending += data.len() as u64;
    }

    fn assert_committed(&self) {
        assert!(self.pending == 0, "transcript had uncommitted data");
    }
}

impl Transcript {
    /// Create a new transcript.
    ///
    /// The namespace serves to disamiguate two transcripts, so that even if they record
    /// the same information, the results will be different:
    /// ```
    /// let s1 = Transcript::new(b"n1").record(b"A").summarize();
    /// let s2 = Transcript::new(b"n2").record(b"A").summarize();
    /// assert_ne!(s1, s2);
    /// ```
    pub fn new(namespace: &[u8]) -> Self {
        Self::start(StartTag::New, Some(namespace))
    }

    /// Start a transcript from a summary.
    ///
    /// Note that this will not produce the same result as if the transcript
    /// were never summarized to begin with.
    /// ```
    /// let s1 = Transcript::new(b"test").record(b"A").summarize();
    /// let s2 = Transcript::resume(s1).summarize();
    /// assert_ne!(s1, s2);
    /// ```
    pub fn resume(summary: Summary) -> Self {
        Self::start(StartTag::Resume, Some(summary.hash.as_bytes()))
    }

    /// Record data in this transcript.
    ///
    /// Calls to record automatically separate out data:
    /// ```
    /// let s1 = Transcript::new(b"test").record(b"A").record(b"B").summarize();
    /// let s2 = Transcript::new(b"test").record(b"AB").summarize();
    /// assert_ne!(s1, s2);
    /// ```
    ///
    /// In particular, even a call with an empty string matters:
    /// ```
    /// let s1 = Transcript::new(b"test").summarize();
    /// let s2 = Transcript::new(b"test").record(b"").summarize();
    /// assert_ne!(s1, s2);
    /// ```
    ///
    /// If you want to provide data incrementally, use [Self::record_partial].
    pub fn commit(&mut self, data: impl Buf) -> &mut Self {
        self.append(data);
        self.flush();
        self
    }

    /// Like [Self::record], except that subsequent calls are considered part of the same message.
    ///
    /// ```
    /// let s1 = Transcript::new(b"test").record_partial(b"A").record(b"B").summarize();
    /// let s2 = Transcript::new(b"test").record(b"AB").summarize();
    /// assert_eq!(s1, s2);
    /// ```
    ///
    /// A subsequent call to a destructive operation, like [Self::summarize] will
    /// be treated with an implicit call to [Self::record]:
    /// ```
    /// let s1 = Transcript::new(b"test").record_partial(b"AB").record(b"").summarize();
    /// let s2 = Transcript::new(b"test").record_partial(b"AB").summarize();
    /// assert_eq!(s1, s2);
    /// ```
    pub fn append(&mut self, mut data: impl Buf) -> &mut Self {
        while data.has_remaining() {
            let chunk = data.chunk();
            self.do_append(chunk);
            data.advance(chunk.len());
        }
        self
    }

    /// Fork.
    pub fn fork(&self, label: &'static [u8]) -> Self {
        let mut out = Self::start(StartTag::Fork, Some(self.summarize().hash.as_bytes()));
        out.commit(label);
        out
    }

    /// Pull out some noise from this transript.
    pub fn noise(&self, label: &'static [u8]) -> impl CryptoRngCore {
        let mut out = Self::start(StartTag::Noise, Some(self.summarize().hash.as_bytes()));
        out.commit(label);
        Rng::new(out.hasher.finalize_xof())
    }

    /// Compress this transcript into a summary.
    ///
    /// This can be used to compare transcripts for equality:
    /// ```
    /// let s1 = Transcript::new(b"test").record(b"DATA").summarize();
    /// let s2 = Transcript::new(b"test").record(b"DATA").summarize();
    /// assert_eq!(s1, s2);
    /// ```
    ///
    /// This can also be used to turn a transcript into a serializable object, to resume later.
    /// ```
    /// // This can be encoded, and, e.g. saved to disk.
    /// let s = Transcript::new(b"test").record(b"DATA").summarize();
    /// let t = Transcript::resume(s);
    /// ```
    pub fn summarize(&self) -> Summary {
        self.assert_committed();
        Summary {
            hash: self.hasher.finalize(),
        }
    }
}

/// Represents a summary of a transcript.
///
/// This is the primary way to compare two transcripts for equality.
/// You can think of this as a hash over the transcript, providing a commitment
/// to the data it recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    hash: blake3::Hash,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_namespace_affects_summary() {
        let s1 = Transcript::new(b"Test-A").summarize();
        let s2 = Transcript::new(b"Test-B").summarize();
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_namespace_doesnt_leak_into_data() {
        let s1 = Transcript::new(b"Test-A").summarize();
        let s2 = Transcript::new(b"Test-").commit(b"".as_slice()).summarize();
        assert_ne!(s1, s2);
    }
}
