//! This module provides a [Transcript] abstraction.
//!
//! This is useful for hashing data, committing to it, and extracting secure
//! randomness from it. The API evades common footguns when doing these things
//! in an ad hoc way.
use crate::{BatchVerifier, Signer, Verifier};
use blake3::BLOCK_LEN;
use bytes::Buf;
use commonware_codec::{
    EncodeSize, FixedArray, FixedSize, Read, ReadExt, Write,
    varint::{MAX_U64_VARINT_SIZE, UInt},
};
use commonware_math::algebra::Random;
#[commonware_macros::stability(ALPHA)]
use commonware_utils::NZU64;
use commonware_utils::{Array, Span};
#[commonware_macros::stability(ALPHA)]
use core::num::NonZeroU64;
use core::{convert::Infallible, fmt::Display, ops::Deref};
use rand_core::{CryptoRng, TryCryptoRng, TryRng};
use zeroize::ZeroizeOnDrop;

/// Provides an implementation of [CryptoRng].
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

impl TryRng for Rng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        let dest_len = dest.len();
        let remaining = &self.buf[self.start..];
        if remaining.len() >= dest_len {
            dest.copy_from_slice(&remaining[..dest_len]);
            self.start += dest_len;
            return Ok(());
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

        Ok(())
    }
}

impl TryCryptoRng for Rng {}

fn flush(hasher: &mut blake3::Hasher, pending: u64, version: Version) {
    let mut pending_bytes = [0u8; MAX_U64_VARINT_SIZE];
    let pending = UInt(pending);
    pending.write(&mut &mut pending_bytes[..]);
    let length = &mut pending_bytes[..pending.encode_size()];
    version.frame_length(length);
    hasher.update(length);
}

/// Domain-separates transcript construction operations.
#[repr(u8)]
#[derive(Clone, Copy)]
enum StartTag {
    New = 0,
    Resume = 1,
    Fork = 2,
    Noise = 3,
}

/// The packet framing used by a [`Transcript`].
///
/// The version is an immutable part of a protocol's definition.
/// [`Version::V0`] uses schema-dependent framing and requires the protocol's complete
/// packet-history language to be uniquely decodable. [`Version::V1`] provides injective framing
/// for arbitrary byte packets.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Version {
    /// Use schema-dependent suffix-length framing.
    ///
    /// V0 commits `data || varint(length(data))`. This suffix is ambiguous for unrestricted
    /// packet histories because packet data can imitate an earlier packet's length.
    ///
    /// # Safety
    ///
    /// A protocol may use V0 only when its complete set of accepted histories is uniquely
    /// decodable. One sufficient condition is:
    ///
    /// - the namespace is one fixed value;
    /// - every history has a fixed packet count and order; and
    /// - the payload language accepted at each position is prefix-free, such as one fixed-size
    ///   value or a canonical self-delimiting encoding.
    ///
    /// A history containing only one arbitrary packet is also unambiguous because
    /// `n + varint_size(n)` is strictly increasing. This is why a one-packet namespace may be
    /// summarized before a fixed-schema protocol continues from the resulting summary.
    ///
    /// The proof applies to the complete packet schema, not to each payload in isolation.
    /// Fixed-size encodings alone do not make optional, repeated, or reordered packets safe.
    /// Changing a packet's encoding, when it may appear, or how often it may repeat requires
    /// checking unique decodability for the full set of accepted histories again.
    ///
    /// This fixed schema is safe: every accepted history contains the same namespace, one 8-byte
    /// round, and one 32-byte public key.
    ///
    /// ```
    /// # use commonware_cryptography::transcript::{Summary, Transcript, Version};
    /// fn summarize(round: u64, public_key: [u8; 32]) -> Summary {
    ///     let round = round.to_be_bytes();
    ///     Transcript::new(b"_COMMONWARE_CRYPTOGRAPHY_TRANSCRIPT_V0_FIXED", Version::V0)
    ///         .commit(round.as_slice())
    ///         .commit(public_key.as_slice())
    ///         .summarize()
    /// }
    /// assert_ne!(summarize(7, [1; 32]), summarize(8, [1; 32]));
    /// ```
    ///
    /// By contrast, unrestricted packet boundaries are unsafe. These distinct V0 histories commit
    /// the same bytes.
    ///
    /// ```
    /// # use commonware_cryptography::transcript::{Transcript, Version};
    /// let zeros = [0u8; 127];
    /// let split = Transcript::new(b"", Version::V0)
    ///     .commit(zeros.as_slice())
    ///     .commit([0x80].as_slice())
    ///     .summarize();
    ///
    /// let mut merged = zeros.to_vec();
    /// merged.push(0x7f);
    /// let merged = Transcript::new(b"", Version::V0)
    ///     .commit(merged.as_slice())
    ///     .summarize();
    ///
    /// assert_eq!(split, merged);
    /// ```
    V0,
    /// Use injective packet framing for arbitrary packet contents.
    ///
    /// V1 commits `data || reverse(varint(length(data)))`. Canonical varints are prefix-free, so
    /// their reversals are suffix-free. Starting at the end of a history, the final length and then
    /// its exact payload can be recovered repeatedly. Packet data cannot alter those boundaries.
    /// Empty packets remain distinct from no packet, and [`Transcript::append`] retains constant
    /// framing memory because only the pending length is stored.
    ///
    /// # Safety
    ///
    /// V1 is safe for arbitrary byte packets, variable packet lengths, optional or repeated
    /// packets, and schemas that evolve to include them. It binds byte packets and their
    /// boundaries; it cannot repair a non-injective application encoding where two semantic values
    /// already produce the same packet bytes.
    ///
    /// The V0 collision above is separated under V1:
    ///
    /// ```
    /// # use commonware_cryptography::transcript::{Transcript, Version};
    /// let zeros = [0u8; 127];
    /// let split = Transcript::new(b"", Version::V1)
    ///     .commit(zeros.as_slice())
    ///     .commit([0x80].as_slice())
    ///     .summarize();
    ///
    /// let mut merged = zeros.to_vec();
    /// merged.push(0x7f);
    /// let merged = Transcript::new(b"", Version::V1)
    ///     .commit(merged.as_slice())
    ///     .summarize();
    ///
    /// assert_ne!(split, merged);
    /// ```
    V1,
}

impl Version {
    /// Transform a canonical varint into the version's suffix framing.
    const fn frame_length(self, length: &mut [u8]) {
        match self {
            Self::V0 => {}
            Self::V1 => length.reverse(),
        }
    }
}

/// Provides a convenient abstraction over hashing data and deriving randomness.
///
/// It automatically takes care of details like:
/// - segmenting packets according to the selected framing scheme,
/// - domain separating different uses of tags and randomness,
/// - making sure that secret state is zeroized as necessary.
#[derive(ZeroizeOnDrop)]
pub struct Transcript {
    hasher: blake3::Hasher,
    pending: u64,
    #[zeroize(skip)]
    version: Version,
}

impl Transcript {
    fn start(tag: StartTag, summary: Option<Summary>, version: Version) -> Self {
        // By starting with an optional key, we basically get to hash in 32 bytes
        // for free, since they won't affect the number of bytes we can process without
        // a call to the compression function. So, in many cases where we want to
        // link a new transcript to a previous history, we take an optional summary.
        let mut hasher = summary.map_or_else(blake3::Hasher::new, |s| {
            blake3::Hasher::new_keyed(s.hash.as_bytes())
        });
        hasher.update(&[tag as u8]);
        Self {
            hasher,
            pending: 0,
            version,
        }
    }

    fn flush(&mut self) {
        flush(&mut self.hasher, self.pending, self.version);
        self.pending = 0;
    }

    const fn unflushed(&self) -> bool {
        self.pending != 0
    }
}

impl Transcript {
    /// Create a new transcript.
    ///
    /// The namespace serves to disambiguate two transcripts, so that even if they record
    /// the same information, the results will be different:
    /// ```
    /// # use commonware_cryptography::transcript::{Transcript, Version};
    /// let s1 = Transcript::new(b"n1", Version::V1).commit(b"A".as_slice()).summarize();
    /// let s2 = Transcript::new(b"n2", Version::V1).commit(b"A".as_slice()).summarize();
    /// assert_ne!(s1, s2);
    /// ```
    pub fn new(namespace: &[u8], version: Version) -> Self {
        let mut out = Self::start(StartTag::New, None, version);
        out.commit(namespace);
        out
    }

    /// Start a transcript from a summary.
    ///
    /// Note that this will not produce the same result as if the transcript
    /// were never summarized to begin with.
    /// ```
    /// # use commonware_cryptography::transcript::{Transcript, Version};
    /// let s1 = Transcript::new(b"test", Version::V1).commit(b"A".as_slice()).summarize();
    /// let s2 = Transcript::resume(s1.clone(), Version::V1).summarize();
    /// assert_ne!(s1, s2);
    /// ```
    pub fn resume(summary: Summary, version: Version) -> Self {
        Self::start(StartTag::Resume, Some(summary), version)
    }

    /// Record data in this transcript.
    ///
    /// Consecutive calls are treated as separate packets:
    /// ```
    /// # use commonware_cryptography::transcript::{Transcript, Version};
    /// let s1 = Transcript::new(b"test", Version::V1).commit(b"A".as_slice()).commit(b"B".as_slice()).summarize();
    /// let s2 = Transcript::new(b"test", Version::V1).commit(b"AB".as_slice()).summarize();
    /// assert_ne!(s1, s2);
    /// ```
    ///
    /// In particular, even a call with an empty string matters:
    /// ```
    /// # use commonware_cryptography::transcript::{Transcript, Version};
    /// let s1 = Transcript::new(b"test", Version::V1).summarize();
    /// let s2 = Transcript::new(b"testt", Version::V1).commit(b"".as_slice()).summarize();
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
    /// The packet length is checked before any bytes are hashed. This method panics without
    /// changing the transcript if the pending packet would exceed `u64::MAX` bytes.
    ///
    /// ```
    /// # use commonware_cryptography::transcript::{Transcript, Version};
    /// let s1 = Transcript::new(b"test", Version::V1).append(b"A".as_slice()).commit(b"B".as_slice()).summarize();
    /// let s2 = Transcript::new(b"test", Version::V1).commit(b"AB".as_slice()).summarize();
    /// assert_eq!(s1, s2);
    /// ```
    pub fn append(&mut self, mut data: impl Buf) -> &mut Self {
        let length =
            u64::try_from(data.remaining()).expect("transcript packet length does not fit in u64");
        let pending = self
            .pending
            .checked_add(length)
            .expect("transcript packet exceeds u64::MAX bytes");

        while data.has_remaining() {
            let chunk = data.chunk();
            self.hasher.update(chunk);
            data.advance(chunk.len());
        }
        self.pending = pending;
        self
    }

    /// Create a new instance sharing the same history.
    ///
    /// This instance will commit to the same data, but it will produce a different
    /// summary and noise:
    /// ```
    /// # use commonware_cryptography::transcript::{Transcript, Version};
    /// let t = Transcript::new(b"test", Version::V1);
    /// assert_ne!(t.summarize(), t.fork(b"A").summarize());
    /// assert_ne!(t.fork(b"A").summarize(), t.fork(b"B").summarize());
    /// ```
    pub fn fork(&self, label: &'static [u8]) -> Self {
        let mut out = Self::start(StartTag::Fork, Some(self.summarize()), self.version);
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
    pub fn noise(&self, label: &'static [u8]) -> impl CryptoRng + use<> {
        let mut out = Self::start(StartTag::Noise, Some(self.summarize()), self.version);
        out.commit(label);
        Rng::new(out.hasher.finalize_xof())
    }

    /// Shuffle a slice deterministically, based on this transcript.
    ///
    /// The permutation will depend on all of the messages committed to the
    /// transcript so far. This is a Fisher-Yates shuffle over [Transcript::noise].
    ///
    /// The label will also affect the permutation. Changing the label will
    /// change the resulting order:
    /// ```
    /// # use commonware_cryptography::transcript::{Transcript, Version};
    /// let t = Transcript::new(b"test", Version::V1);
    /// let mut a = [0u32, 1, 2, 3, 4, 5, 6, 7];
    /// let mut b = a;
    /// t.shuffle(b"A", &mut a);
    /// t.shuffle(b"B", &mut b);
    /// assert_ne!(a, b);
    /// ```
    #[commonware_macros::stability(ALPHA)]
    pub fn shuffle<T>(&self, label: &'static [u8], items: &mut [T]) {
        let mut rng = self.noise(label);
        for i in (1..items.len()).rev() {
            let j = sample(&mut rng, NZU64!(i as u64 + 1));
            items.swap(i, j as usize);
        }
    }

    /// Sample a uniform value in `0..bound`, based on this transcript.
    ///
    /// The value is unbiased, and will depend on all of the messages committed
    /// to the transcript so far. The label will also affect the value:
    /// ```
    /// # use commonware_cryptography::transcript::{Transcript, Version};
    /// # use commonware_utils::NZU64;
    /// let t = Transcript::new(b"test", Version::V1);
    /// assert_eq!(t.sample(b"A", NZU64!(100)), t.sample(b"A", NZU64!(100)));
    /// assert!(t.sample(b"A", NZU64!(100)) < 100);
    /// ```
    #[commonware_macros::stability(ALPHA)]
    pub fn sample(&self, label: &'static [u8], bound: NonZeroU64) -> u64 {
        sample(self.noise(label), bound)
    }

    /// Extract a compact summary from this transcript.
    ///
    /// This can be used to compare transcripts for equality:
    /// ```
    /// # use commonware_cryptography::transcript::{Transcript, Version};
    /// let s1 = Transcript::new(b"test", Version::V1).commit(b"DATA".as_slice()).summarize();
    /// let s2 = Transcript::new(b"test", Version::V1).commit(b"DATA".as_slice()).summarize();
    /// assert_eq!(s1, s2);
    /// ```
    pub fn summarize(&self) -> Summary {
        let hash = if self.unflushed() {
            let mut hasher = self.hasher.clone();
            flush(&mut hasher, self.pending, self.version);
            hasher.finalize()
        } else {
            self.hasher.finalize()
        };
        Summary { hash }
    }
}

/// Sample a uniform value in `0..bound` from an infallible RNG.
#[commonware_macros::stability(ALPHA)]
fn sample(mut rng: impl CryptoRng, bound: NonZeroU64) -> u64 {
    let bound = bound.get();

    // Accept only draws below the largest multiple of `bound`, so that the
    // modulo is unbiased. Fewer than two draws are needed on average.
    let zone = bound * (u64::MAX / bound);
    loop {
        let v = rng.next_u64();
        if v < zone {
            return v % bound;
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
        self.summarize().sign(s)
    }

    /// Verify a signature produced by [Transcript::sign].
    pub fn verify<V: Verifier>(&self, v: &V, sig: &<V as Verifier>::Signature) -> bool {
        self.summarize().verify(v, sig)
    }

    /// Append a signature produced by [Transcript::sign] to a batch verifier.
    pub fn add_to_batch<B: BatchVerifier>(
        &self,
        batch: &mut B,
        public_key: &B::PublicKey,
        signature: &<B::PublicKey as Verifier>::Signature,
    ) -> bool {
        self.summarize().add_to_batch(batch, public_key, signature)
    }
}

impl Summary {
    /// Use a signer to create a signature over this summary.
    pub fn sign<S: Signer>(&self, s: &S) -> <S as Signer>::Signature {
        // Note: We pass an empty namespace here, since the namespace may be included
        // within the transcript summary already via `Transcript::new`.
        s.sign(b"", self.as_ref())
    }

    /// Verify a signature produced by [Summary::sign].
    pub fn verify<V: Verifier>(&self, v: &V, sig: &<V as Verifier>::Signature) -> bool {
        // Note: We pass an empty namespace here, since the namespace may be included
        // within the transcript summary already via `Transcript::new`.
        v.verify(b"", self.as_ref(), sig)
    }

    /// Append a signature produced by [Summary::sign] to a batch verifier.
    pub fn add_to_batch<B: BatchVerifier>(
        &self,
        batch: &mut B,
        public_key: &B::PublicKey,
        signature: &<B::PublicKey as Verifier>::Signature,
    ) -> bool {
        // Note: We pass an empty namespace here, since the namespace may be included
        // within the transcript summary already via `Transcript::new`.
        batch.add(b"", self.as_ref(), public_key, signature)
    }
}

/// Represents a summary of a transcript.
///
/// This is the primary way to compare two transcripts for equality.
/// You can think of this as a hash over the transcript, providing a commitment
/// to the data it recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, FixedArray)]
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
        write!(f, "{}", commonware_formatting::Hex(self.as_ref()))
    }
}

impl Span for Summary {}

impl Array for Summary {}

impl crate::Digest for Summary {
    const EMPTY: Self = Self {
        hash: blake3::Hash::from_bytes([0u8; blake3::OUT_LEN]),
    };
}

impl Random for Summary {
    fn random(mut rng: impl CryptoRng) -> Self {
        let mut bytes = [0u8; blake3::OUT_LEN];
        rng.fill_bytes(&mut bytes[..]);
        Self {
            hash: blake3::Hash::from_bytes(bytes),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
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
    use crate::ed25519;
    use commonware_codec::{DecodeExt as _, Encode};
    use commonware_parallel::Sequential;
    use commonware_utils::test_rng;
    use rand_core::Rng;

    const V0_VERSION: Version = Version::V0;

    fn v0(namespace: &[u8]) -> Transcript {
        Transcript::new(namespace, V0_VERSION)
    }

    fn v1(namespace: &[u8]) -> Transcript {
        Transcript::new(namespace, Version::V1)
    }

    #[test]
    fn test_namespace_affects_summary() {
        let s1 = v0(b"Test-A").summarize();
        let s2 = v0(b"Test-B").summarize();
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_namespace_doesnt_leak_into_data() {
        let s1 = v0(b"Test-A").summarize();
        let s2 = v0(b"Test-").commit(b"".as_slice()).summarize();
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_commit_separates_data() {
        let s1 = v0(b"").commit(b"AB".as_slice()).summarize();
        let s2 = v0(b"")
            .commit(b"A".as_slice())
            .commit(b"B".as_slice())
            .summarize();
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_v1_separates_adversarial_data() {
        let zeros = [0u8; 127];
        let split_v0 = v0(b"")
            .commit(zeros.as_slice())
            .commit([0x80].as_slice())
            .summarize();

        let mut merged = zeros.to_vec();
        merged.push(0x7f);
        let merged_v0 = v0(b"").commit(merged.as_slice()).summarize();
        assert_eq!(split_v0, merged_v0);

        let split_v1 = v1(b"")
            .commit(zeros.as_slice())
            .commit([0x80].as_slice())
            .summarize();
        let merged_v1 = v1(b"").commit(merged.as_slice()).summarize();

        assert_ne!(split_v1, merged_v1);
    }

    #[test]
    fn test_flush_supports_maximum_packet_length() {
        for version in [V0_VERSION, Version::V1] {
            let mut actual = blake3::Hasher::new();
            flush(&mut actual, u64::MAX, version);

            let mut length = [0u8; MAX_U64_VARINT_SIZE];
            let pending = UInt(u64::MAX);
            pending.write(&mut &mut length[..]);
            let length = &mut length[..pending.encode_size()];
            match version {
                Version::V0 => {}
                Version::V1 => length.reverse(),
            }

            let mut expected = blake3::Hasher::new();
            expected.update(length);
            assert_eq!(actual.finalize(), expected.finalize());
        }
    }

    #[test]
    fn test_start_tags() {
        for (tag, expected) in [
            (StartTag::New, 0),
            (StartTag::Resume, 1),
            (StartTag::Fork, 2),
            (StartTag::Noise, 3),
        ] {
            assert_eq!(tag as u8, expected);
        }
    }

    #[test]
    fn test_versions_match_for_single_byte_lengths() {
        let v0 = v0(b"test");
        let v1 = v1(b"test");
        assert_eq!(v0.summarize(), v1.summarize());
        assert_eq!(v0.fork(b"fork").summarize(), v1.fork(b"fork").summarize());

        let summary = v0.summarize();
        let resumed_v0 = Transcript::resume(summary, Version::V0)
            .commit(b"x".as_slice())
            .summarize();
        let resumed_v1 = Transcript::resume(summary, Version::V1)
            .commit(b"x".as_slice())
            .summarize();
        assert_eq!(resumed_v0, resumed_v1);

        let mut noise_v0 = [0u8; 32];
        let mut noise_v1 = [0u8; 32];
        v0.noise(b"noise").fill_bytes(&mut noise_v0);
        v1.noise(b"noise").fill_bytes(&mut noise_v1);
        assert_eq!(noise_v0, noise_v1);
    }

    #[test]
    fn test_version_frames_derived_labels() {
        const LONG_LABEL: &[u8] = &[0; 128];

        let v0 = v0(b"test");
        let v1 = v1(b"test");
        assert_ne!(
            v0.fork(LONG_LABEL).summarize(),
            v1.fork(LONG_LABEL).summarize()
        );

        let mut noise_v0 = [0u8; 32];
        let mut noise_v1 = [0u8; 32];
        v0.noise(LONG_LABEL).fill_bytes(&mut noise_v0);
        v1.noise(LONG_LABEL).fill_bytes(&mut noise_v1);
        assert_ne!(noise_v0, noise_v1);
    }

    #[test]
    fn test_append_overflow_does_not_hash() {
        let mut transcript = Transcript::start(StartTag::New, None, Version::V1);
        transcript.pending = u64::MAX - 1;
        let before = transcript.hasher.finalize();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            transcript.append(b"A".as_slice().chain(b"B".as_slice()));
        }));

        assert!(result.is_err());
        assert_eq!(transcript.pending, u64::MAX - 1);
        assert_eq!(transcript.hasher.finalize(), before);
    }

    #[test]
    fn test_append_commit_works() {
        let s1 = v0(b"")
            .append(b"A".as_slice())
            .commit(b"B".as_slice())
            .summarize();
        let s2 = v0(b"").commit(b"AB".as_slice()).summarize();
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_fork_returns_different_result() {
        let t1 = v0(b"");
        let t2 = t1.fork(b"");
        assert_ne!(t1.summarize(), t2.summarize());
    }

    #[test]
    fn test_fork_label_matters() {
        let t1 = v0(b"");
        let t2 = t1.fork(b"A");
        let t3 = t2.fork(b"B");
        assert_ne!(t2.summarize(), t3.summarize());
    }

    #[test]
    fn test_noise_and_summarize_are_different() {
        let t1 = v0(b"");
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
        v0(b"test").noise(b"NOISE").fill_bytes(&mut s[..]);
        // Split up the bytes into two chunks
        for i in 0..s.len() {
            let mut s_prime = [0u8; 2 * BLOCK_LEN];
            let mut noise = v0(b"test").noise(b"NOISE");
            noise.fill_bytes(&mut s_prime[..i]);
            noise.fill_bytes(&mut s_prime[i..]);
            assert_eq!(s, s_prime);
        }
    }

    #[test]
    fn test_noise_label_matters() {
        let mut s1 = [0u8; 32];
        let mut s2 = [0u8; 32];
        let t1 = v0(b"test");
        t1.noise(b"A").fill_bytes(&mut s1);
        t1.noise(b"B").fill_bytes(&mut s2);
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_summarize_resume_is_different_than_new() {
        let s = v0(b"test").summarize();
        let s1 = v0(s.hash.as_bytes()).summarize();
        let s2 = Transcript::resume(s, V0_VERSION).summarize();
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_summary_encode_roundtrip() {
        let s = v0(b"test").summarize();
        assert_eq!(&s, &Summary::decode(s.encode()).unwrap());
    }

    #[test]
    fn test_summary_sign_verify_matches_transcript() {
        let sk = ed25519::PrivateKey::from_seed(7);
        let pk = sk.public_key();
        let mut transcript = v0(b"test");
        transcript.commit(b"DATA".as_slice());
        let summary = transcript.summarize();

        let sig = summary.sign(&sk);
        assert_eq!(sig, transcript.sign(&sk));
        assert!(summary.verify(&pk, &sig));
        assert!(transcript.verify(&pk, &sig));
    }

    #[test]
    fn test_summary_add_to_batch_matches_transcript() {
        let sk = ed25519::PrivateKey::from_seed(7);
        let pk = sk.public_key();
        let mut transcript = v0(b"test");
        transcript.commit(b"DATA".as_slice());
        let summary = transcript.summarize();
        let sig = transcript.sign(&sk);

        let mut summary_batch = ed25519::Batch::new(1);
        assert!(summary.add_to_batch(&mut summary_batch, &pk, &sig));
        let mut transcript_batch = ed25519::Batch::new(1);
        assert!(transcript.add_to_batch(&mut transcript_batch, &pk, &sig));

        assert!(summary_batch.verify(&mut test_rng(), &Sequential));
        assert!(transcript_batch.verify(&mut test_rng(), &Sequential));
    }

    #[test]
    fn test_shuffle_is_permutation() {
        let t = v0(b"test");
        let mut items: Vec<u32> = (0..1000).collect();
        t.shuffle(b"shuffle", &mut items);
        assert_ne!(items, (0..1000).collect::<Vec<_>>());
        items.sort_unstable();
        assert_eq!(items, (0..1000).collect::<Vec<_>>());
    }

    #[test]
    fn test_shuffle_is_deterministic() {
        let mut t = v0(b"test");
        t.commit(b"DATA".as_slice());
        let mut s1: Vec<u32> = (0..100).collect();
        let mut s2 = s1.clone();
        t.shuffle(b"shuffle", &mut s1);
        t.shuffle(b"shuffle", &mut s2);
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_shuffle_label_and_history_matter() {
        let t1 = v0(b"test");
        let mut t2 = v0(b"test");
        t2.commit(b"DATA".as_slice());
        let mut base: Vec<u32> = (0..100).collect();
        let (mut a, mut b, mut c) = (base.clone(), base.clone(), base.clone());
        t1.shuffle(b"A", &mut a);
        t1.shuffle(b"B", &mut b);
        t2.shuffle(b"A", &mut c);
        base.clear();
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_sample_within_bound() {
        let t = v0(b"test");
        let mut rng = t.noise(b"sample");
        for bound in [1, 2, 3, 7, 100, 1 << 40, u64::MAX] {
            assert!(sample(&mut rng, NZU64!(bound)) < bound);
        }
        assert_eq!(t.sample(b"sample", NZU64!(1)), 0);
        assert_eq!(
            t.sample(b"one shot", NZU64!(1000)),
            sample(t.noise(b"one shot"), NZU64!(1000))
        );
    }

    #[test]
    fn test_missing_append() {
        let s1 = v0(b"foo").append(b"AB".as_slice()).summarize();
        let s2 = v0(b"foo")
            .append(b"A".as_slice())
            .commit(b"B".as_slice())
            .summarize();
        assert_eq!(s1, s2)
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;
        use commonware_conformance::Conformance;

        #[allow(clippy::unused_async)]
        async fn transcript_ops(seed: u64, version: Version) -> Vec<u8> {
            let seed_bytes = seed.to_le_bytes();
            let namespace = seed_bytes[..(seed as usize % seed_bytes.len()) + 1].to_vec();
            let data: Vec<_> = (0..seed as usize % 256)
                .map(|i| (seed as u8).wrapping_add((3 * i) as u8))
                .collect();
            let split = data.len() / 2;

            let mut transcript = Transcript::new(&namespace, version);
            transcript.append(&data[..split]);
            transcript.commit(&data[split..]);

            let mut log = transcript.summarize().encode().to_vec();
            log.extend(
                Transcript::new(&namespace, version)
                    .commit(&data[..split])
                    .commit(&data[split..])
                    .summarize()
                    .encode(),
            );
            log.extend(
                Transcript::new(&namespace, version)
                    .append(data.as_slice())
                    .commit([].as_slice())
                    .summarize()
                    .encode(),
            );
            let resumed = Transcript::resume(transcript.summarize(), version);
            log.extend(resumed.summarize().encode());
            log.extend(transcript.fork(b"left").summarize().encode());
            log.extend(transcript.fork(b"right").summarize().encode());

            let mut noise = [0u8; 80];
            let mut rng = transcript.noise(b"noise");
            log.extend(rng.next_u32().encode());
            log.extend(rng.next_u64().encode());
            rng.fill_bytes(&mut noise[..31]);
            rng.fill_bytes(&mut noise[31..]);
            log.extend(noise);

            let mut indices: Vec<u32> = (0..(seed % 100) as u32).collect();
            transcript.shuffle(b"shuffle", &mut indices);
            for index in &indices {
                log.extend(index.encode());
            }
            log.extend(transcript.sample(b"sample", NZU64!(seed | 1)).encode());

            let private_key = ed25519::PrivateKey::from_seed(seed);
            let public_key = private_key.public_key();
            let summary = transcript.summarize();
            let summary_sig = summary.sign(&private_key);
            let transcript_sig = transcript.sign(&private_key);
            log.extend(summary_sig.encode());
            log.extend(transcript_sig.encode());
            log.extend(summary.verify(&public_key, &summary_sig).encode());
            log.extend(transcript.verify(&public_key, &transcript_sig).encode());

            let mut summary_batch = ed25519::Batch::new(1);
            log.extend(
                summary
                    .add_to_batch(&mut summary_batch, &public_key, &summary_sig)
                    .encode(),
            );
            log.extend(
                summary_batch
                    .verify(&mut transcript.noise(b"summary batch"), &Sequential)
                    .encode(),
            );

            let mut transcript_batch = ed25519::Batch::new(1);
            log.extend(
                transcript
                    .add_to_batch(&mut transcript_batch, &public_key, &transcript_sig)
                    .encode(),
            );
            log.extend(
                transcript_batch
                    .verify(&mut transcript.noise(b"transcript batch"), &Sequential)
                    .encode(),
            );

            let mut pending = Transcript::new(&namespace, version);
            pending.append(data.as_slice());
            let pending_summary = pending.summarize();
            log.extend(pending_summary.encode());
            log.extend(pending.fork(b"pending fork").summarize().encode());

            let mut pending_noise = [0u8; 37];
            pending
                .noise(b"pending noise")
                .fill_bytes(&mut pending_noise);
            log.extend(pending_noise);

            let pending_sig = pending.sign(&private_key);
            log.extend(pending_sig.encode());
            log.extend(pending.verify(&public_key, &pending_sig).encode());

            log
        }

        struct TranscriptV0Ops;

        impl Conformance for TranscriptV0Ops {
            async fn commit(seed: u64) -> Vec<u8> {
                transcript_ops(seed, V0_VERSION).await
            }
        }

        struct TranscriptV1Ops;

        impl Conformance for TranscriptV1Ops {
            async fn commit(seed: u64) -> Vec<u8> {
                transcript_ops(seed, Version::V1).await
            }
        }

        commonware_conformance::conformance_tests! {
            TranscriptV0Ops => 4096,
            TranscriptV1Ops => 4096,
            CodecConformance<Summary>,
        }
    }
}
