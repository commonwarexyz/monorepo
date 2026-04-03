//! Codec implementations for range types ([`Range`], [`RangeFrom`], [`RangeTo`],
//! [`RangeInclusive`], [`RangeToInclusive`], [`RangeFull`]).

use crate::{BufsMut, EncodeSize, Error, FixedSize, Read, Write};
use bytes::{Buf, BufMut};
use core::ops::{Range, RangeFrom, RangeFull, RangeInclusive, RangeTo, RangeToInclusive};

impl<T: Write + PartialOrd> Write for Range<T> {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        assert!(
            self.start.partial_cmp(&self.end).is_some_and(|o| o.is_le()),
            "start must be <= end"
        );
        self.start.write(buf);
        self.end.write(buf);
    }

    #[inline]
    fn write_bufs(&self, buf: &mut impl BufsMut) {
        assert!(
            self.start.partial_cmp(&self.end).is_some_and(|o| o.is_le()),
            "start must be <= end"
        );
        self.start.write_bufs(buf);
        self.end.write_bufs(buf);
    }
}

impl<T: EncodeSize> EncodeSize for Range<T> {
    #[inline]
    fn encode_size(&self) -> usize {
        self.start.encode_size() + self.end.encode_size()
    }

    #[inline]
    fn encode_inline_size(&self) -> usize {
        self.start.encode_inline_size() + self.end.encode_inline_size()
    }
}

impl<T: Read + PartialOrd> Read for Range<T> {
    type Cfg = T::Cfg;

    #[inline]
    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let start = T::read_cfg(buf, cfg)?;
        let end = T::read_cfg(buf, cfg)?;
        if !start.partial_cmp(&end).is_some_and(|o| o.is_le()) {
            return Err(Error::Invalid("Range", "start must be <= end"));
        }
        Ok(start..end)
    }
}

impl<T: Write + PartialOrd> Write for RangeInclusive<T> {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        assert!(
            self.start()
                .partial_cmp(self.end())
                .is_some_and(|o| o.is_le()),
            "start must be <= end"
        );
        self.start().write(buf);
        self.end().write(buf);
    }

    #[inline]
    fn write_bufs(&self, buf: &mut impl BufsMut) {
        assert!(
            self.start()
                .partial_cmp(self.end())
                .is_some_and(|o| o.is_le()),
            "start must be <= end"
        );
        self.start().write_bufs(buf);
        self.end().write_bufs(buf);
    }
}

impl<T: EncodeSize> EncodeSize for RangeInclusive<T> {
    #[inline]
    fn encode_size(&self) -> usize {
        self.start().encode_size() + self.end().encode_size()
    }

    #[inline]
    fn encode_inline_size(&self) -> usize {
        self.start().encode_inline_size() + self.end().encode_inline_size()
    }
}

impl<T: Read + PartialOrd> Read for RangeInclusive<T> {
    type Cfg = T::Cfg;

    #[inline]
    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let start = T::read_cfg(buf, cfg)?;
        let end = T::read_cfg(buf, cfg)?;
        if !start.partial_cmp(&end).is_some_and(|o| o.is_le()) {
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

    #[inline]
    fn write_bufs(&self, buf: &mut impl BufsMut) {
        self.start.write_bufs(buf);
    }
}

impl<T: EncodeSize> EncodeSize for RangeFrom<T> {
    #[inline]
    fn encode_size(&self) -> usize {
        self.start.encode_size()
    }

    #[inline]
    fn encode_inline_size(&self) -> usize {
        self.start.encode_inline_size()
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

    #[inline]
    fn write_bufs(&self, buf: &mut impl BufsMut) {
        self.end.write_bufs(buf);
    }
}

impl<T: EncodeSize> EncodeSize for RangeTo<T> {
    #[inline]
    fn encode_size(&self) -> usize {
        self.end.encode_size()
    }

    #[inline]
    fn encode_inline_size(&self) -> usize {
        self.end.encode_inline_size()
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

    #[inline]
    fn write_bufs(&self, buf: &mut impl BufsMut) {
        self.end.write_bufs(buf);
    }
}

impl<T: EncodeSize> EncodeSize for RangeToInclusive<T> {
    #[inline]
    fn encode_size(&self) -> usize {
        self.end.encode_size()
    }

    #[inline]
    fn encode_inline_size(&self) -> usize {
        self.end.encode_inline_size()
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
    #[should_panic(expected = "start must be <= end")]
    fn test_range_encode_invalid() {
        let range = Range {
            start: 20u32,
            end: 10u32,
        };
        let _ = range.encode();
    }

    #[test]
    fn test_range_decode_invalid() {
        // Manually encode start=20, end=10 to bypass the write panic
        let mut buf = Vec::new();
        buf.extend_from_slice(&20u32.to_be_bytes());
        buf.extend_from_slice(&10u32.to_be_bytes());
        assert!(matches!(
            Range::<u32>::decode(bytes::Bytes::from(buf)),
            Err(crate::Error::Invalid("Range", "start must be <= end"))
        ));
    }

    #[test]
    #[should_panic(expected = "start must be <= end")]
    fn test_range_inclusive_encode_invalid() {
        let range = RangeInclusive::new(20u32, 10u32);
        let _ = range.encode();
    }

    #[test]
    fn test_range_inclusive_decode_invalid() {
        // Manually encode start=20, end=10 to bypass the write panic
        let mut buf = Vec::new();
        buf.extend_from_slice(&20u32.to_be_bytes());
        buf.extend_from_slice(&10u32.to_be_bytes());
        assert!(matches!(
            RangeInclusive::<u32>::decode(bytes::Bytes::from(buf)),
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
