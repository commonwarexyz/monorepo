use alloc::vec::Vec;
use bytes::{Buf, Bytes};
use commonware_codec::Error;
use commonware_cryptography::PublicKey;

const MAX_CACHED_PUBLIC_KEYS: usize = 18;

pub(super) struct PublicKeyReader<P: PublicKey> {
    decoded: Vec<(Bytes, P)>,
}

impl<P: PublicKey> PublicKeyReader<P> {
    pub(super) const fn new() -> Self {
        Self {
            decoded: Vec::new(),
        }
    }

    pub(super) fn read(&mut self, buf: &mut impl Buf) -> Result<P, Error> {
        // Public keys are fixed-size arrays, so short input is known to be truncated before any
        // allocation or scheme-specific validation.
        if buf.remaining() < P::SIZE {
            return Err(Error::EndOfBuffer);
        }

        let raw = buf.copy_to_bytes(P::SIZE);
        if let Some((_, key)) = self.decoded.iter().find(|(decoded, _)| decoded == &raw) {
            return Ok(key.clone());
        }

        let key = P::read(&mut raw.clone())?;

        // Eighteen is the maximum number of key occurrences in any Challenge grammar. Larger
        // standalone values remain decodable after the cache fills; they simply stop adding keys.
        if self.decoded.len() == MAX_CACHED_PUBLIC_KEYS {
            return Ok(key);
        }
        let result = key.clone();
        self.decoded.push((raw, key));
        Ok(result)
    }
}

pub(super) trait ReadWithPublicKeys<P: PublicKey>: Sized {
    fn read_with_public_keys(
        buf: &mut impl Buf,
        public_keys: &mut PublicKeyReader<P>,
    ) -> Result<Self, Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{BufMut as _, BytesMut};
    use commonware_codec::{Encode as _, FixedSize, Read, Write};
    use commonware_cryptography::{
        Signer as _,
        curve25519::{Signature, SigningKey, VerifyingKey},
    };
    use core::{
        fmt,
        ops::Deref,
        sync::atomic::{AtomicUsize, Ordering},
    };

    static STRICT_DECODES: AtomicUsize = AtomicUsize::new(0);
    static ZERO_DECODES: AtomicUsize = AtomicUsize::new(0);

    #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    struct StrictKey(VerifyingKey);

    impl fmt::Display for StrictKey {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            fmt::Display::fmt(&self.0, formatter)
        }
    }

    impl Deref for StrictKey {
        type Target = [u8];

        fn deref(&self) -> &Self::Target {
            self.0.deref()
        }
    }

    impl AsRef<[u8]> for StrictKey {
        fn as_ref(&self) -> &[u8] {
            self.0.as_ref()
        }
    }

    impl Write for StrictKey {
        fn write(&self, buf: &mut impl bytes::BufMut) {
            self.0.write(buf);
        }
    }

    impl FixedSize for StrictKey {
        const SIZE: usize = VerifyingKey::SIZE;
    }

    impl Read for StrictKey {
        type Cfg = ();

        fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
            STRICT_DECODES.fetch_add(1, Ordering::Relaxed);
            VerifyingKey::read_cfg(buf, &()).map(Self)
        }
    }

    impl commonware_utils::Span for StrictKey {}
    impl commonware_utils::Array for StrictKey {}

    impl commonware_cryptography::Verifier for StrictKey {
        type Signature = Signature;

        fn verify(&self, namespace: &[u8], message: &[u8], signature: &Signature) -> bool {
            commonware_cryptography::Verifier::verify(&self.0, namespace, message, signature)
        }
    }

    impl PublicKey for StrictKey {}

    #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    struct ZeroKey;

    impl fmt::Display for ZeroKey {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("zero")
        }
    }

    impl Deref for ZeroKey {
        type Target = [u8];

        fn deref(&self) -> &Self::Target {
            &[]
        }
    }

    impl AsRef<[u8]> for ZeroKey {
        fn as_ref(&self) -> &[u8] {
            &[]
        }
    }

    impl Write for ZeroKey {
        fn write(&self, _: &mut impl bytes::BufMut) {}
    }

    impl FixedSize for ZeroKey {
        const SIZE: usize = 0;
    }

    impl Read for ZeroKey {
        type Cfg = ();

        fn read_cfg(_: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
            ZERO_DECODES.fetch_add(1, Ordering::Relaxed);
            Ok(Self)
        }
    }

    impl commonware_utils::Span for ZeroKey {}
    impl commonware_utils::Array for ZeroKey {}

    impl commonware_cryptography::Verifier for ZeroKey {
        type Signature = Signature;

        fn verify(&self, _: &[u8], _: &[u8], _: &Signature) -> bool {
            false
        }
    }

    impl PublicKey for ZeroKey {}

    #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    struct HugeKey;

    impl fmt::Display for HugeKey {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("huge")
        }
    }

    impl Deref for HugeKey {
        type Target = [u8];

        fn deref(&self) -> &Self::Target {
            &[]
        }
    }

    impl AsRef<[u8]> for HugeKey {
        fn as_ref(&self) -> &[u8] {
            &[]
        }
    }

    impl Write for HugeKey {
        fn write(&self, _: &mut impl bytes::BufMut) {}
    }

    impl FixedSize for HugeKey {
        const SIZE: usize = usize::MAX;
    }

    impl Read for HugeKey {
        type Cfg = ();

        fn read_cfg(_: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
            Err(Error::EndOfBuffer)
        }
    }

    impl commonware_utils::Span for HugeKey {}
    impl commonware_utils::Array for HugeKey {}

    impl commonware_cryptography::Verifier for HugeKey {
        type Signature = Signature;

        fn verify(&self, _: &[u8], _: &[u8], _: &Signature) -> bool {
            false
        }
    }

    impl PublicKey for HugeKey {}

    #[test]
    fn cache_is_exact_success_only_bounded_and_size_safe() {
        let key = SigningKey::from_seed(1).public_key();
        let raw = key.encode();
        let repeated = [raw.as_ref(), raw.as_ref()].concat();
        let mut segmented = Bytes::copy_from_slice(&repeated[..7])
            .chain(Bytes::copy_from_slice(&repeated[7..41]))
            .chain(Bytes::copy_from_slice(&repeated[41..]));
        let mut public_keys = PublicKeyReader::<StrictKey>::new();
        STRICT_DECODES.store(0, Ordering::Relaxed);

        assert_eq!(public_keys.read(&mut segmented).unwrap().0, key);
        assert_eq!(public_keys.read(&mut segmented).unwrap().0, key);
        assert_eq!(STRICT_DECODES.load(Ordering::Relaxed), 1);
        assert_eq!(segmented.remaining(), 0);

        let mut noncanonical = [0xff; VerifyingKey::SIZE];
        noncanonical[0] = 0xee;
        noncanonical[VerifyingKey::SIZE - 1] = 0x7f;
        let mut identity = [0; VerifyingKey::SIZE];
        identity[0] = 1;
        for invalid in [identity, noncanonical] {
            let repeated = [invalid.as_slice(), invalid.as_slice()].concat();
            let mut encoded = repeated.as_slice();
            let mut public_keys = PublicKeyReader::<StrictKey>::new();
            STRICT_DECODES.store(0, Ordering::Relaxed);
            assert!(public_keys.read(&mut encoded).is_err());
            assert!(public_keys.read(&mut encoded).is_err());
            assert_eq!(STRICT_DECODES.load(Ordering::Relaxed), 2);
        }

        let mut segmented_invalid = Bytes::copy_from_slice(&noncanonical[..7])
            .chain(Bytes::copy_from_slice(&noncanonical[7..]));
        let mut public_keys = PublicKeyReader::<StrictKey>::new();
        STRICT_DECODES.store(0, Ordering::Relaxed);
        assert!(matches!(
            public_keys.read(&mut segmented_invalid),
            Err(Error::Invalid(_, _))
        ));
        assert_eq!(STRICT_DECODES.load(Ordering::Relaxed), 1);

        let interleaved = [raw.as_ref(), noncanonical.as_slice(), raw.as_ref()].concat();
        let mut interleaved = interleaved.as_slice();
        let mut public_keys = PublicKeyReader::<StrictKey>::new();
        STRICT_DECODES.store(0, Ordering::Relaxed);
        assert_eq!(public_keys.read(&mut interleaved).unwrap().0, key);
        assert!(public_keys.read(&mut interleaved).is_err());
        assert_eq!(public_keys.read(&mut interleaved).unwrap().0, key);
        assert_eq!(STRICT_DECODES.load(Ordering::Relaxed), 2);

        let mut truncated = &raw[..VerifyingKey::SIZE - 1];
        let mut public_keys = PublicKeyReader::<StrictKey>::new();
        STRICT_DECODES.store(0, Ordering::Relaxed);
        assert!(matches!(
            public_keys.read(&mut truncated),
            Err(Error::EndOfBuffer)
        ));
        assert_eq!(STRICT_DECODES.load(Ordering::Relaxed), 0);

        let keys = (0..=MAX_CACHED_PUBLIC_KEYS)
            .map(|seed| SigningKey::from_seed(seed as u64 + 10).public_key())
            .collect::<Vec<_>>();
        let mut encoded = BytesMut::new();
        for key in &keys {
            encoded.put_slice(key.as_ref());
        }
        let mut encoded = encoded.freeze();
        let mut public_keys = PublicKeyReader::<StrictKey>::new();
        STRICT_DECODES.store(0, Ordering::Relaxed);
        for expected in &keys {
            assert_eq!(public_keys.read(&mut encoded).unwrap().0, *expected);
        }
        assert_eq!(STRICT_DECODES.load(Ordering::Relaxed), keys.len());

        let mut repeated = BytesMut::new();
        repeated.put_slice(keys[0].as_ref());
        repeated.put_slice(keys[MAX_CACHED_PUBLIC_KEYS].as_ref());
        let mut repeated = repeated.freeze();
        assert_eq!(public_keys.read(&mut repeated).unwrap().0, keys[0]);
        assert_eq!(
            public_keys.read(&mut repeated).unwrap().0,
            keys[MAX_CACHED_PUBLIC_KEYS]
        );
        assert_eq!(STRICT_DECODES.load(Ordering::Relaxed), keys.len() + 1);

        let mut empty = Bytes::new();
        let mut public_keys = PublicKeyReader::<ZeroKey>::new();
        ZERO_DECODES.store(0, Ordering::Relaxed);
        assert_eq!(public_keys.read(&mut empty).unwrap(), ZeroKey);
        assert_eq!(public_keys.read(&mut empty).unwrap(), ZeroKey);
        assert_eq!(ZERO_DECODES.load(Ordering::Relaxed), 1);

        let mut byte = Bytes::from_static(&[0]);
        let mut public_keys = PublicKeyReader::<HugeKey>::new();
        assert!(matches!(
            public_keys.read(&mut byte),
            Err(Error::EndOfBuffer)
        ));
    }
}
