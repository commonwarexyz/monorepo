//! Codec implementations for the unsigned integers of [ruint].
//!
//! A [Uint] encodes as its value in big-endian over the fewest bytes that hold its bits, so a
//! 256-bit integer encodes as 32 bytes. Decoding refuses an encoding with a bit set beyond the
//! integer's width, so every value has exactly one encoding.

use crate::{Buf, Error, FixedSize, Read, Write, util::at_least};
use bytes::BufMut;
use ruint::Uint;

impl<const BITS: usize, const LIMBS: usize> FixedSize for Uint<BITS, LIMBS> {
    const SIZE: usize = Self::BYTES;
}

/// Returns how many bytes of the most significant limb the encoding holds.
const fn top<const BITS: usize, const LIMBS: usize>() -> usize {
    Uint::<BITS, LIMBS>::BYTES - 8 * LIMBS.saturating_sub(1)
}

impl<const BITS: usize, const LIMBS: usize> Write for Uint<BITS, LIMBS> {
    fn write(&self, buf: &mut impl BufMut) {
        let Some((most, rest)) = self.as_limbs().split_last() else {
            return;
        };
        buf.put_slice(&most.to_be_bytes()[8 - top::<BITS, LIMBS>()..]);
        for limb in rest.iter().rev() {
            buf.put_u64(*limb);
        }
    }
}

impl<const BITS: usize, const LIMBS: usize> Read for Uint<BITS, LIMBS> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        at_least(buf, Self::SIZE)?;
        let mut limbs = [0u64; LIMBS];
        if let Some((most, rest)) = limbs.split_last_mut() {
            let mut bytes = [0u8; 8];
            buf.copy_to_slice(&mut bytes[8 - top::<BITS, LIMBS>()..]);
            *most = u64::from_be_bytes(bytes);
            for limb in rest.iter_mut().rev() {
                *limb = buf.get_u64();
            }
        }
        Self::checked_from_limbs_slice(&limbs)
            .ok_or(Error::Invalid("Uint", "a bit is set beyond the width"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Copying, DecodeExt as _, Encode as _};
    use ruint::aliases::{U256, U512};

    #[test]
    fn test_round_trips_as_big_endian() {
        for value in [
            U256::ZERO,
            U256::from(1u64),
            U256::MAX,
            U256::from(1u64) << 200,
        ] {
            let encoded = value.encode();
            assert_eq!(encoded.len(), U256::SIZE);
            assert_eq!(encoded.as_ref(), value.to_be_bytes::<32>());
            assert_eq!(U256::decode(encoded).unwrap(), value);
        }
        let value = U512::MAX - U512::from(7u64);
        assert_eq!(value.encode().as_ref(), value.to_be_bytes::<64>());
        assert_eq!(U512::decode(value.encode()).unwrap(), value);
    }

    #[test]
    fn test_partial_limbs_encode_their_bytes_only() {
        type U40 = Uint<40, 1>;
        assert_eq!(U40::SIZE, 5);
        assert_eq!(U40::MAX.encode().as_ref(), [0xff; 5]);
        assert_eq!(U40::decode(U40::MAX.encode()).unwrap(), U40::MAX);
        assert!(matches!(
            U40::decode(Copying(&[0xff; 6])),
            Err(Error::ExtraData(1))
        ));
        assert!(matches!(
            U40::decode(Copying(&[0xff; 4])),
            Err(Error::EndOfBuffer)
        ));
    }

    #[test]
    fn test_rejects_bits_beyond_the_width() {
        type U36 = Uint<36, 1>;
        assert!(matches!(
            U36::decode(Copying(&[0xff; 5])),
            Err(Error::Invalid("Uint", _))
        ));
        let encoded = [0x0f, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(U36::decode(Copying(&encoded)).unwrap(), U36::MAX);
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use crate::conformance::CodecConformance;
        use ruint::aliases::U256;

        commonware_conformance::conformance_tests! {
            CodecConformance<U256>,
        }
    }
}
