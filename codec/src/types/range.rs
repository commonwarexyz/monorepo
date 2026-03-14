//! Codec implementations for range types ([`Range`], [`RangeFrom`], [`RangeTo`],
//! [`RangeInclusive`], [`RangeToInclusive`], [`RangeFull`]).

use crate::{EncodeSize, Error, FixedSize, Read, Write};
use bytes::{Buf, BufMut};
use core::ops::{Range, RangeFrom, RangeFull, RangeInclusive, RangeTo, RangeToInclusive};

impl<T: Write> Write for Range<T> {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        self.start.write(buf);
        self.end.write(buf);
    }
}

impl<T: EncodeSize> EncodeSize for Range<T> {
    #[inline]
    fn encode_size(&self) -> usize {
        self.start.encode_size() + self.end.encode_size()
    }
}

impl<T: Read + PartialOrd> Read for Range<T> {
    type Cfg = T::Cfg;

    #[inline]
    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let start = T::read_cfg(buf, cfg)?;
        let end = T::read_cfg(buf, cfg)?;
        if start > end {
            return Err(Error::Invalid("Range", "start must be <= end"));
        }
        Ok(start..end)
    }
}

impl<T: Write> Write for RangeInclusive<T> {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        self.start().write(buf);
        self.end().write(buf);
    }
}

impl<T: EncodeSize> EncodeSize for RangeInclusive<T> {
    #[inline]
    fn encode_size(&self) -> usize {
        self.start().encode_size() + self.end().encode_size()
    }
}

impl<T: Read + PartialOrd> Read for RangeInclusive<T> {
    type Cfg = T::Cfg;

    #[inline]
    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let start = T::read_cfg(buf, cfg)?;
        let end = T::read_cfg(buf, cfg)?;
        if start > end {
            return Err(Error::Invalid("RangeInclusive", "start must be <= end"));
        }
        Ok(start..=end)
    }
}

impl<T: Write> Write for RangeFrom<T> {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        self.start.write(buf);
    }
}

impl<T: EncodeSize> EncodeSize for RangeFrom<T> {
    #[inline]
    fn encode_size(&self) -> usize {
        self.start.encode_size()
    }
}

impl<T: Read> Read for RangeFrom<T> {
    type Cfg = T::Cfg;

    #[inline]
    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let start = T::read_cfg(buf, cfg)?;
        Ok(start..)
    }
}

impl<T: Write> Write for RangeTo<T> {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        self.end.write(buf);
    }
}

impl<T: EncodeSize> EncodeSize for RangeTo<T> {
    #[inline]
    fn encode_size(&self) -> usize {
        self.end.encode_size()
    }
}

impl<T: Read> Read for RangeTo<T> {
    type Cfg = T::Cfg;

    #[inline]
    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let end = T::read_cfg(buf, cfg)?;
        Ok(..end)
    }
}

impl<T: Write> Write for RangeToInclusive<T> {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        self.end.write(buf);
    }
}

impl<T: EncodeSize> EncodeSize for RangeToInclusive<T> {
    #[inline]
    fn encode_size(&self) -> usize {
        self.end.encode_size()
    }
}

impl<T: Read> Read for RangeToInclusive<T> {
    type Cfg = T::Cfg;

    #[inline]
    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let end = T::read_cfg(buf, cfg)?;
        Ok(..=end)
    }
}

impl Write for RangeFull {
    #[inline]
    fn write(&self, _buf: &mut impl BufMut) {}
}

impl FixedSize for RangeFull {
    const SIZE: usize = 0;
}

impl Read for RangeFull {
    type Cfg = ();

    #[inline]
    fn read_cfg(_buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(..)
    }
}

#[cfg(test)]
mod tests {
    use crate::{DecodeExt, Encode, FixedSize};
    use core::ops::{Range, RangeFrom, RangeFull, RangeInclusive, RangeTo, RangeToInclusive};

    #[test]
    fn test_range() {
        let range: Range<u32> = 10..20;
        let encoded = range.encode();
        assert_eq!(encoded.len(), u32::SIZE * 2);
        let decoded = Range::<u32>::decode(encoded).unwrap();
        assert_eq!(range, decoded);
    }

    #[test]
    fn test_range_inclusive() {
        let range: RangeInclusive<u32> = 10..=20;
        let encoded = range.encode();
        assert_eq!(encoded.len(), u32::SIZE * 2);
        let decoded = RangeInclusive::<u32>::decode(encoded).unwrap();
        assert_eq!(range, decoded);
    }

    #[test]
    fn test_range_from() {
        let range: RangeFrom<u32> = 10..;
        let encoded = range.encode();
        assert_eq!(encoded.len(), u32::SIZE);
        let decoded = RangeFrom::<u32>::decode(encoded).unwrap();
        assert_eq!(range, decoded);
    }

    #[test]
    fn test_range_to() {
        let range: RangeTo<u32> = ..20;
        let encoded = range.encode();
        assert_eq!(encoded.len(), u32::SIZE);
        let decoded = RangeTo::<u32>::decode(encoded).unwrap();
        assert_eq!(range, decoded);
    }

    #[test]
    fn test_range_to_inclusive() {
        let range: RangeToInclusive<u32> = ..=20;
        let encoded = range.encode();
        assert_eq!(encoded.len(), u32::SIZE);
        let decoded = RangeToInclusive::<u32>::decode(encoded).unwrap();
        assert_eq!(range, decoded);
    }

    #[test]
    fn test_range_full() {
        let encoded = RangeFull.encode();
        assert_eq!(encoded.len(), 0);
        assert_eq!(RangeFull::SIZE, 0);
        let decoded = RangeFull::decode(encoded).unwrap();
        assert_eq!(.., decoded);
    }

    #[test]
    fn test_range_invalid() {
        let range: Range<u32> = 20..10;
        let encoded = range.encode();
        assert!(matches!(
            Range::<u32>::decode(encoded),
            Err(crate::Error::Invalid("Range", "start must be <= end"))
        ));
    }

    #[test]
    fn test_range_inclusive_invalid() {
        let range: RangeInclusive<u32> = 20..=10;
        let encoded = range.encode();
        assert!(matches!(
            RangeInclusive::<u32>::decode(encoded),
            Err(crate::Error::Invalid(
                "RangeInclusive",
                "start must be <= end"
            ))
        ));
    }

    #[test]
    fn test_conformity() {
        assert_eq!(
            (0x0102u16..0x0304u16).encode(),
            &[0x01, 0x02, 0x03, 0x04][..]
        );
        assert_eq!(
            (0x0102u16..=0x0304u16).encode(),
            &[0x01, 0x02, 0x03, 0x04][..]
        );
        assert_eq!((0x0102u16..).encode(), &[0x01, 0x02][..]);
        assert_eq!((..0x0304u16).encode(), &[0x03, 0x04][..]);
        assert_eq!((..=0x0304u16).encode(), &[0x03, 0x04][..]);
        assert_eq!((..).encode(), &[][..]);
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use crate::conformance::CodecConformance;
        use core::ops::{Range, RangeFrom, RangeInclusive, RangeTo, RangeToInclusive};

        commonware_conformance::conformance_tests! {
            CodecConformance<Range<u32>>,
            CodecConformance<Range<u64>>,
            CodecConformance<RangeInclusive<u32>>,
            CodecConformance<RangeInclusive<u64>>,
            CodecConformance<RangeFrom<u32>>,
            CodecConformance<RangeTo<u32>>,
            CodecConformance<RangeToInclusive<u32>>,
        }
    }
}
