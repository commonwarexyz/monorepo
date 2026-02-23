use crate::qmdb::{
    any::{
        encoding::{
            Encoding, Fixed, FixedVal, VariableBoth, VariableEncoding, VariableKey, VariableVal,
            VariableValue,
        },
        operation::{update::sealed::Sealed, Update as UpdateTrait},
    },
    operation::Key,
};
use commonware_codec::{
    Encode as _, EncodeSize, Error as CodecError, FixedSize, Read, ReadExt as _, Write,
};
use commonware_runtime::{Buf, BufMut};
use commonware_utils::{hex, Array};
use std::fmt;

#[derive(Clone, PartialEq, Debug, Eq)]
pub struct Update<E: Encoding>(pub E::Key, pub E::Value);

#[cfg(feature = "arbitrary")]
impl<E: Encoding> arbitrary::Arbitrary<'_> for Update<E>
where
    E::Key: for<'a> arbitrary::Arbitrary<'a>,
    E::Value: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self(u.arbitrary()?, u.arbitrary()?))
    }
}

impl<E: Encoding> Sealed for Update<E> {}

impl<E: Encoding> UpdateTrait<E> for Update<E> {
    fn key(&self) -> &E::Key {
        &self.0
    }

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[key:{} value:{}]", hex(&self.0), hex(&self.1.encode()))
    }
}

// --- Write: shared across all encoding types ---

impl<E> Write for Update<E>
where
    E: Encoding,
    E::Key: Write,
    E::Value: Write,
{
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
        self.1.write(buf);
    }
}

impl<E> EncodeSize for Update<E>
where
    E: VariableEncoding,
    E::Key: EncodeSize,
    E::Value: EncodeSize,
{
    fn encode_size(&self) -> usize {
        self.0.encode_size() + self.1.encode_size()
    }
}

impl<K: Array, V: FixedVal> FixedSize for Update<Fixed<K, V>> {
    const SIZE: usize = K::SIZE + V::SIZE;
}

impl<K: Array, V: FixedVal> Read for Update<Fixed<K, V>> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let key = K::read(buf)?;
        let value = V::read_cfg(buf, cfg)?;
        Ok(Self(key, value))
    }
}

impl<K: Array, V: VariableVal> Read for Update<VariableValue<K, V>> {
    type Cfg = <V as Read>::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let key = K::read(buf)?;
        let value = V::read_cfg(buf, cfg)?;
        Ok(Self(key, value))
    }
}

impl<K, V> Read for Update<VariableBoth<K, V>>
where
    K: Key + Read,
    V: VariableVal,
{
    type Cfg = (<K as Read>::Cfg, <V as Read>::Cfg);

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let key = K::read_cfg(buf, &cfg.0)?;
        let value = V::read_cfg(buf, &cfg.1)?;
        Ok(Self(key, value))
    }
}

impl<K, V> Read for Update<VariableKey<K, V>>
where
    K: Key + Read,
    V: FixedVal,
{
    type Cfg = <K as Read>::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let key = K::read_cfg(buf, cfg)?;
        let value = V::read(buf)?;
        Ok(Self(key, value))
    }
}
