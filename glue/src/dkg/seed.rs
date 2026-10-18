//! Secret seed for a dealer's random number generator.

use bytes::BufMut;
use commonware_codec::{Buf, Copying, Error as CodecError, FixedSize, Read, ReadExt as _, Write};
use commonware_cryptography::{Secret, transcript::Summary};
use commonware_math::algebra::Random;
use rand_core::CryptoRng;
use std::fmt;
use zeroize::Zeroizing;

/// Number of bytes in a [`Seed`].
const SIZE: usize = 32;

/// Secret seed for a dealer's random number generator.
///
/// A seed determines the dealer polynomial and so every share the dealer distributes. It is
/// zeroized on drop, cannot be copied or displayed, and prints as redacted in debug output.
/// Persist it only in a [`SecretStore`](super::SecretStore).
///
/// The encoding is the 32 raw seed bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct Seed(Secret<[u8; SIZE]>);

impl Seed {
    /// Returns the summary a dealer resumes its transcript from.
    ///
    /// The returned [`Summary`] is not zeroized.
    pub(super) fn to_summary(&self) -> Summary {
        let bytes = Zeroizing::new(self.0.expose(|bytes| *bytes));
        Summary::read(&mut Copying(bytes.as_slice())).expect("a seed has the size of a summary")
    }
}

impl Random for Seed {
    fn random(mut rng: impl CryptoRng) -> Self {
        let mut bytes = Zeroizing::new([0u8; SIZE]);
        rng.fill_bytes(bytes.as_mut_slice());
        Self(Secret::new(*bytes))
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Seed([REDACTED])")
    }
}

impl FixedSize for Seed {
    const SIZE: usize = SIZE;
}

impl Write for Seed {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.expose(|bytes| bytes.write(buf));
    }
}

impl Read for Seed {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let bytes = Zeroizing::new(<[u8; SIZE]>::read(buf)?);
        Ok(Self(Secret::new(*bytes)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt as _, Encode as _};
    use commonware_cryptography::transcript::{Transcript, Version};
    use commonware_utils::test_rng;
    use rand_core::Rng as _;

    /// Deterministic seed whose bytes are all `byte`.
    pub(crate) fn seed(byte: u8) -> Seed {
        Seed::decode(Copying(&[byte; SIZE])).expect("valid seed")
    }

    #[test]
    fn codec_round_trip() {
        let original = Seed::random(test_rng());
        let encoded = original.encode();
        assert_eq!(encoded.len(), Seed::SIZE);
        assert_eq!(Seed::decode(encoded).expect("valid seed"), original);

        // Truncated and oversized encodings are rejected.
        assert!(Seed::decode(Copying(&[0u8; SIZE - 1])).is_err());
        assert!(Seed::decode(Copying(&[0u8; SIZE + 1])).is_err());
    }

    #[test]
    fn debug_is_redacted() {
        let seed = seed(0xAB);
        let debug = format!("{seed:?}");
        assert_eq!(debug, "Seed([REDACTED])");
        assert!(!debug.to_lowercase().contains("ab"));
    }

    /// A seed encodes identically to the summary it replaces, so stored seeds stay readable
    /// and seed the same dealer randomness.
    #[test]
    fn encoding_matches_summary() {
        let summary = Summary::random(test_rng());
        let seed = Seed::decode(summary.encode()).expect("valid seed");
        assert_eq!(seed.encode(), summary.encode());
        assert_eq!(seed.to_summary(), summary);

        let rng_stream = |summary: Summary| {
            let mut rng = Transcript::resume(summary, Version::V1).noise(b"dealer-rng");
            let mut out = [0u8; 64];
            rng.fill_bytes(&mut out);
            out
        };
        assert_eq!(rng_stream(seed.to_summary()), rng_stream(summary));
    }
}
