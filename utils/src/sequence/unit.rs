use crate::{Array, Span};
use bytes::{Buf, BufMut};
use commonware_codec::{FixedSize, Read, Write};
use core::{
    fmt::{Debug, Display},
    ops::Deref,
};

/// An `Array` implementation for the unit type `()`.
#[derive(Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Unit;

impl Write for Unit {
    fn write(&self, _: &mut impl BufMut) {}
}

impl FixedSize for Unit {
    const SIZE: usize = 0;
}

impl Read for Unit {
    type Cfg = ();

    fn read_cfg(_buf: &mut impl Buf, _: &()) -> Result<Self, commonware_codec::Error> {
        Ok(Self)
    }
}

impl Debug for Unit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "()")
    }
}

impl Display for Unit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "()")
    }
}

impl Deref for Unit {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &[]
    }
}

impl AsRef<[u8]> for Unit {
    fn as_ref(&self) -> &[u8] {
        &[]
    }
}

impl Span for Unit {}
impl Array for Unit {}

#[cfg(test)]
mod test {
    use super::*;
    use commonware_codec::Encode;

    #[test]
    fn test_debug_display() {
        let unit = Unit;
        assert_eq!(format!("{unit:?}"), "()");
        assert_eq!(unit.to_string(), "()");
    }

    #[test]
    fn test_deref_asref() {
        let unit = Unit;
        assert_eq!(unit.deref(), &[]);
        assert_eq!(unit.as_ref(), &[]);
    }

    #[test]
    fn test_codec() {
        let mut encoded = Unit.encode();
        assert_eq!(encoded.len(), 0);

        let decoded = Unit::read_cfg(&mut encoded, &()).unwrap();
        assert_eq!(decoded, Unit);
    }
}
