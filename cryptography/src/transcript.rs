//! This module provides a [Transcript] abstraction.
//!
//! This is useful for hashing data, committing to it, and extracting secure
//! randomness from it. The API evades common footguns when doing these things
//! in an ad hoc way.
use crate::{Signer, Verifier};
use blake3::BLOCK_LEN;
use bytes::Buf;
use commonware_codec::{varint::UInt, EncodeSize, FixedSize, Read, ReadExt, Write};
use commonware_utils::{Array, Span};
use core::{fmt::Display, ops::Deref};
use rand_core::{
    impls::{next_u32_via_fill, next_u64_via_fill},
    CryptoRng, CryptoRngCore, RngCore,
};
use zeroize::ZeroizeOnDrop;

/// Provides an implementation of [CryptoRngCore].
///
/// We intentionally don't expose this struct, to make the impl returned by
/// [Transcript::noise] completely opaque.
#[derive(ZeroizeOnDrop)]
struct Rng {
    inner: blake3::OutputReader,
    buf: [u8; BLOCK_LEN],
    start: usize,
}

impl Rng {
    const fn new(inner: blake3::OutputReader) -> Self {
        Self {
            inner,
            buf: [0u8; BLOCK_LEN],
            start: BLOCK_LEN,
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
        let remaining = &self.buf[self.start..];
        if remaining.len() >= dest_len {
            dest.copy_from_slice(&remaining[..dest_len]);
            self.start += dest_len;
            return;
        }

        let (start, mut dest) = dest.split_at_mut(remaining.len());
        start.copy_from_slice(remaining);
        self.start = BLOCK_LEN;

        while dest.len() >= BLOCK_LEN {
            let (block, rest) = dest.split_at_mut(BLOCK_LEN);
            self.inner.fill(block);
            dest = rest;
        }

        let dest_len = dest.len();
        if dest_len > 0 {
            self.inner.fill(&mut self.buf[..]);
            dest.copy_from_slice(&self.buf[..dest_len]);
            self.start = dest_len;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for Rng {}

/// Ensures different [Transcript] initializations are unique.
#[repr(u8)]
enum StartTag {
    New = 0,
    Resume = 1,
    Fork = 2,
    Noise = 3,
}

/// Provides a convenient abstraction over hashing data and deriving randomness.
///
/// It automatically takes care of details like:
/// - correctly segmenting packets of data,
/// - domain separating different uses of tags and randomness,
/// - making sure that secret state is zeroized as necessary.
#[derive(ZeroizeOnDrop)]
pub struct Transcript {
    hasher: blake3::Hasher,
    pending: u64,
}

impl Transcript {
    fn start(tag: StartTag, summary: Option<Summary>) -> Self {
        // By starting with an optional key, we basically get to hash in 32 bytes
        // for free, since they won't affect the number of bytes we can process without
        // a call to the compression function. So, in many cases where we want to
        // link a new transcript to a previous history, we take an optional summary.
        let mut hasher = summary.map_or_else(blake3::Hasher::new, |s| {
            blake3::Hasher::new_keyed(s.hash.as_bytes())
        });
        hasher.update(&[tag as u8]);
        Self { hasher, pending: 0 }
    }

    fn flush(&mut self) {
        let mut pending_bytes = [0u8; 9];
        let pending = UInt(self.pending);
        pending.write(&mut &mut pending_bytes[..]);
        self.hasher.update(&pending_bytes[..pending.encode_size()]);
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
    /// The namespace serves to disambiguate two transcripts, so that even if they record
    /// the same information, the results will be different:
    /// ```
    /// # use commonware_cryptography::transcript::Transcript;
    /// let s1 = Transcript::new(b"n1").commit(b"A".as_slice()).summarize();
    /// let s2 = Transcript::new(b"n2").commit(b"A".as_slice()).summarize();
    /// assert_ne!(s1, s2);
    /// ```
    pub fn new(namespace: &[u8]) -> Self {
        let mut out = Self::start(StartTag::New, None);
        out.commit(namespace);
        out
    }

    /// Start a transcript from a summary.
    ///
    /// Note that this will not produce the same result as if the transcript
    /// were never summarized to begin with.
    /// ```
    /// # use commonware_cryptography::transcript::Transcript;
    /// let s1 = Transcript::new(b"test").commit(b"A".as_slice()).summarize();
    /// let s2 = Transcript::resume(s1.clone()).summarize();
    /// assert_ne!(s1, s2);
    /// ```
    pub fn resume(summary: Summary) -> Self {
        Self::start(StartTag::Resume, Some(summary))
    }

    /// Record data in this transcript.
    ///
    /// Calls to record automatically separate out data:
    /// ```
    /// # use commonware_cryptography::transcript::Transcript;
    /// let s1 = Transcript::new(b"test").commit(b"A".as_slice()).commit(b"B".as_slice()).summarize();
    /// let s2 = Transcript::new(b"test").commit(b"AB".as_slice()).summarize();
    /// assert_ne!(s1, s2);
    /// ```
    ///
    /// In particular, even a call with an empty string matters:
    /// ```
    /// # use commonware_cryptography::transcript::Transcript;
    /// let s1 = Transcript::new(b"test").summarize();
    /// let s2 = Transcript::new(b"testt").commit(b"".as_slice()).summarize();
    /// assert_ne!(s1, s2);
    /// ```
    ///
    /// If you want to provide data incrementally, use [Self::append].
    pub fn commit(&mut self, data: impl Buf) -> &mut Self {
        self.append(data);
        self.flush();
        self
    }

    /// Like [Self::commit], except that subsequent calls to [Self::append] or [Self::commit] are
    /// considered part of the same message.
    ///
    /// [Self::commit] needs to be called before calling any other method, besides [Self::append],
    /// in order to avoid having uncommitted data.
    ///
    /// ```
    /// # use commonware_cryptography::transcript::Transcript;
    /// let s1 = Transcript::new(b"test").append(b"A".as_slice()).commit(b"B".as_slice()).summarize();
    /// let s2 = Transcript::new(b"test").commit(b"AB".as_slice()).summarize();
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

    /// Create a new instance sharing the same history.
    ///
    /// This instance will commit to the same data, but it will produce a different
    /// summary and noise:
    /// ```
    /// # use commonware_cryptography::transcript::Transcript;
    /// let t = Transcript::new(b"test");
    /// assert_ne!(t.summarize(), t.fork(b"A").summarize());
    /// assert_ne!(t.fork(b"A").summarize(), t.fork(b"B").summarize());
    /// ```
    pub fn fork(&self, label: &'static [u8]) -> Self {
        let mut out = Self::start(StartTag::Fork, Some(self.summarize()));
        out.commit(label);
        out
    }

    /// Pull out some noise from this transript.
    ///
    /// This noise will depend on all of the messages committed to the transcript
    /// so far, and can be used as a secure source of randomness, for generating
    /// keys, and other things.
    ///
    /// The label will also affect the noise. Changing the label will change
    /// the stream of bytes generated.
    pub fn noise(&self, label: &'static [u8]) -> impl CryptoRngCore {
        let mut out = Self::start(StartTag::Noise, Some(self.summarize()));
        out.commit(label);
        Rng::new(out.hasher.finalize_xof())
    }

    /// Extract a compact summary from this transcript.
    ///
    /// This can be used to compare transcripts for equality:
    /// ```
    /// # use commonware_cryptography::transcript::Transcript;
    /// let s1 = Transcript::new(b"test").commit(b"DATA".as_slice()).summarize();
    /// let s2 = Transcript::new(b"test").commit(b"DATA".as_slice()).summarize();
    /// assert_eq!(s1, s2);
    /// ```
    pub fn summarize(&self) -> Summary {
        self.assert_committed();
        Summary {
            hash: self.hasher.finalize(),
        }
    }
}

// Utility methods which can be created using the other methods.
impl Transcript {
    /// Use a signer to create a signature over this transcript.
    ///
    /// Conceptually, this is the same as:
    /// - signing the operations that have been performed on the transcript,
    /// - or, equivalently, signing randomness or a summary extracted from the transcript.
    pub fn sign<S: Signer>(&self, s: &S) -> <S as Signer>::Signature {
        // Note: We pass an empty namespace here, since the namespace may be included
        // within the transcript summary already via `Self::new`.
        s.sign(b"", self.summarize().hash.as_bytes())
    }

    /// Verify a signature produced by [Transcript::sign].
    pub fn verify<V: Verifier>(&self, v: &V, sig: &<V as Verifier>::Signature) -> bool {
        // Note: We pass an empty namespace here, since the namespace may be included
        // within the transcript summary already via `Self::new`.
        v.verify(b"", self.summarize().hash.as_bytes(), sig)
    }
}

/// Represents a summary of a transcript.
///
/// This is the primary way to compare two transcripts for equality.
/// You can think of this as a hash over the transcript, providing a commitment
/// to the data it recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Summary {
    hash: blake3::Hash,
}

impl FixedSize for Summary {
    const SIZE: usize = blake3::OUT_LEN;
}

impl Write for Summary {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.hash.as_bytes().write(buf)
    }
}

impl Read for Summary {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            hash: blake3::Hash::from_bytes(ReadExt::read(buf)?),
        })
    }
}

impl AsRef<[u8]> for Summary {
    fn as_ref(&self) -> &[u8] {
        self.hash.as_bytes().as_slice()
    }
}

impl Deref for Summary {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl PartialOrd for Summary {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Summary {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.as_ref().cmp(other.as_ref())
    }
}

impl Display for Summary {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", commonware_utils::hex(self.as_ref()))
    }
}

impl Span for Summary {}
impl Array for Summary {}

impl crate::Digest for Summary {
    fn random<R: CryptoRngCore>(rng: &mut R) -> Self {
        let mut bytes = [0u8; blake3::OUT_LEN];
        rng.fill_bytes(&mut bytes[..]);
        Self {
            hash: blake3::Hash::from_bytes(bytes),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Summary {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let bytes: [u8; blake3::OUT_LEN] = u.arbitrary()?;
        Ok(Self {
            hash: blake3::Hash::from_bytes(bytes),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use commonware_codec::{DecodeExt as _, Encode};

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

    #[test]
    fn test_commit_separates_data() {
        let s1 = Transcript::new(b"").commit(b"AB".as_slice()).summarize();
        let s2 = Transcript::new(b"")
            .commit(b"A".as_slice())
            .commit(b"B".as_slice())
            .summarize();
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_append_commit_works() {
        let s1 = Transcript::new(b"")
            .append(b"A".as_slice())
            .commit(b"B".as_slice())
            .summarize();
        let s2 = Transcript::new(b"").commit(b"AB".as_slice()).summarize();
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_fork_returns_different_result() {
        let t1 = Transcript::new(b"");
        let t2 = t1.fork(b"");
        assert_ne!(t1.summarize(), t2.summarize());
    }

    #[test]
    fn test_fork_label_matters() {
        let t1 = Transcript::new(b"");
        let t2 = t1.fork(b"A");
        let t3 = t2.fork(b"B");
        assert_ne!(t2.summarize(), t3.summarize());
    }

    #[test]
    fn test_noise_and_summarize_are_different() {
        let t1 = Transcript::new(b"");
        let mut s1_bytes = [0u8; 32];
        t1.noise(b"foo").fill_bytes(&mut s1_bytes[..]);
        let s1 = Summary {
            hash: blake3::Hash::from_bytes(s1_bytes),
        };
        let s2 = t1.summarize();
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_noise_stream_chunking_doesnt_matter() {
        let mut s = [0u8; 2 * BLOCK_LEN];
        Transcript::new(b"test")
            .noise(b"NOISE")
            .fill_bytes(&mut s[..]);
        // Split up the bytes into two chunks
        for i in 0..s.len() {
            let mut s_prime = [0u8; 2 * BLOCK_LEN];
            let mut noise = Transcript::new(b"test").noise(b"NOISE");
            noise.fill_bytes(&mut s_prime[..i]);
            noise.fill_bytes(&mut s_prime[i..]);
            assert_eq!(s, s_prime);
        }
    }

    #[test]
    fn test_noise_label_matters() {
        let mut s1 = [0u8; 32];
        let mut s2 = [0u8; 32];
        let t1 = Transcript::new(b"test");
        t1.noise(b"A").fill_bytes(&mut s1);
        t1.noise(b"B").fill_bytes(&mut s2);
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_summarize_resume_is_different_than_new() {
        let s = Transcript::new(b"test").summarize();
        let s1 = Transcript::new(s.hash.as_bytes()).summarize();
        let s2 = Transcript::resume(s).summarize();
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_summary_encode_roundtrip() {
        let s = Transcript::new(b"test").summarize();
        assert_eq!(&s, &Summary::decode(s.encode()).unwrap());
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;

        commonware_codec::conformance_tests! {
            Summary,
        }
    }
}
