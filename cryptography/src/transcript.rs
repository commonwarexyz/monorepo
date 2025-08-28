use bytes::Buf;
use rand_core::{CryptoRngCore, OsRng};

/// This struct provides a convenient abstraction over hashing data and deriving randomness.
///
/// It automatically takes care of details like:
/// - correctly segmenting packets of data,
/// - domain separating different uses of tags and randomness,
/// - making sure that secret state is zeroized as necessary.
struct Transcript {}

impl Transcript {
    /// Create a new transcript.
    ///
    /// The namespace serves to disamiguate two transcripts, so that even if they record
    /// the same information, the results will be different:
    /// ```
    /// let s1 = Transcript::new(b"n1").record(b"A").summarize();
    /// let s2 = Transcript::new(b"n2").record(b"A").summarize();
    /// assert_neq!(s1, s2);
    /// ```
    pub fn new(namespace: &[u8]) -> Self {
        todo!()
    }

    /// Start a transcript from a summary.
    ///
    /// Note that this will not produce the same result as if the transcript
    /// were never summarized to begin with.
    /// ```
    /// let s1 = Transcript::new(b"test").record(b"A").summarize();
    /// let s2 = Transcript::resume(s1).summarize();
    /// assert_neq!(s1, s2);
    /// ```
    pub fn resume(summary: Summary) -> Self {
        todo!()
    }

    /// Record data in this transcript.
    ///
    /// Calls to record automatically separate out data:
    /// ```
    /// let s1 = Transcript::new(b"test").record(b"A").record(b"B").summarize();
    /// let s2 = Transcript::new(b"test").record(b"AB").summarize();
    /// assert_neq!(s1, s2);
    /// ```
    ///
    /// In particular, even a call with an empty string matters:
    /// ```
    /// let s1 = Transcript::new(b"test").summarize();
    /// let s2 = Transcript::new(b"test").record(b"").summarize();
    /// assert_neq!(s1, s2);
    /// ```
    ///
    /// If you want to provide data incrementally, use [Self::record_partial].
    pub fn record(&mut self, data: impl Buf) -> &mut Self {
        todo!()
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
    pub fn record_partial(&mut self, data: impl Buf) -> &mut Self {
        todo!()
    }

    /// Split this transcript into two independent transcripts.
    ///
    /// These transcripts are both linked to the same history, but will produce different
    /// randomness, and can be updated without affecting the other one.
    /// This is often useful as a pre-requisite to methods like [Self::summarize] or
    /// [Self::noise], which consume the transcript. It can be useful to extract
    /// randomness, or a summary, while still continuing to feed data, and this method
    /// allows you to do that.
    pub fn split(self) -> (Self, Self) {
        todo!()
    }

    /// Turn this transcript into a source of random bytes.
    pub fn noise(self) -> impl CryptoRngCore {
        // TODO: This is just to compile
        OsRng
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
    pub fn summarize(self) -> Summary {
        todo!()
    }
}

/// Represents a summary of a transcript.
///
/// This is the primary way to compare two transcripts for equality.
/// You can think of this as a hash over the transcript, providing a commitment
/// to the data it recorded.
#[derive(PartialEq, Eq)]
pub struct Summary {}
