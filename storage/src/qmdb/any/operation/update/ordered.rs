use crate::qmdb::any::{
    encoding::{Encoding, Fixed, FixedVal, VariableVal, VariableValue},
    operation::{update::sealed::Sealed, Update as UpdateTrait},
};
use commonware_codec::{
    Encode as _, EncodeSize, Error as CodecError, FixedSize, Read, ReadExt as _, Write,
};
use commonware_runtime::{Buf, BufMut};
use commonware_utils::{hex, Array};
use std::fmt;

#[derive(Clone, PartialEq, Debug, Eq)]
pub struct Update<E: Encoding>
where
    E::Key: Array + Ord,
{
    pub key: E::Key,
    pub value: E::Value,
    pub next_key: E::Key,
}

#[cfg(feature = "arbitrary")]
impl<E: Encoding> arbitrary::Arbitrary<'_> for Update<E>
where
    E::Key: Array + Ord + for<'a> arbitrary::Arbitrary<'a>,
    E::Value: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            key: u.arbitrary()?,
            value: u.arbitrary()?,
            next_key: u.arbitrary()?,
        })
    }
}

impl<E: Encoding> Sealed for Update<E> where E::Key: Array {}

impl<E: Encoding> UpdateTrait<E> for Update<E>
where
    E::Key: Array,
{
    fn key(&self) -> &E::Key {
        &self.key
    }

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[key:{} next_key:{} value:{}]",
            self.key,
            self.next_key,
            hex(&self.value.encode())
        )
    }
}

impl<E: Encoding> Write for Update<E>
where
    E::Key: Array + Write,
    E::Value: Write,
{
    fn write(&self, buf: &mut impl BufMut) {
        self.key.write(buf);
        self.value.write(buf);
        self.next_key.write(buf);
    }
}

impl<K: Array, V: FixedVal> FixedSize for Update<Fixed<K, V>> {
    const SIZE: usize = K::SIZE + V::SIZE + K::SIZE;
}

impl<K: Array, V: FixedVal> Read for Update<Fixed<K, V>> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let key = K::read(buf)?;
        let value = V::read_cfg(buf, cfg)?;
        let next_key = K::read(buf)?;
        Ok(Self {
            key,
            value,
            next_key,
        })
    }
}

impl<K: Array, V: VariableVal> EncodeSize for Update<VariableValue<K, V>> {
    fn encode_size(&self) -> usize {
        K::SIZE + self.value.encode_size() + K::SIZE
    }
}

impl<K: Array, V: VariableVal> Read for Update<VariableValue<K, V>> {
    type Cfg = <V as Read>::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let key = K::read(buf)?;
        let value = V::read_cfg(buf, cfg)?;
        let next_key = K::read(buf)?;
        Ok(Self {
            key,
            value,
            next_key,
        })
    }
}
