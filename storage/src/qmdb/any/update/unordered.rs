use crate::qmdb::any::{
    update::Update,
    value::{FixedEncoding, ValueEncoding, VariableEncoding},
    FixedValue, VariableValue,
};
use bytes::{Buf, BufMut};
use commonware_codec::{
    Encode as _, EncodeSize, Error as CodecError, FixedSize, Read, ReadExt as _, Write,
};
use commonware_utils::{hex, Array};
use std::fmt;

#[derive(Clone, PartialEq, Debug)]
pub struct UnorderedUpdate<K: Array, V: ValueEncoding>(pub K, pub V::Value);

impl<K: Array, V: ValueEncoding> Update<K, V> for UnorderedUpdate<K, V> {
    fn key(&self) -> &K {
        &self.0
    }

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[key:{} value:{}]", self.0, hex(&self.1.encode()))
    }
}

impl<K: Array, V: FixedValue> FixedSize for UnorderedUpdate<K, FixedEncoding<V>> {
    const SIZE: usize = K::SIZE + V::SIZE;
}

impl<K: Array, V: VariableValue> EncodeSize for UnorderedUpdate<K, VariableEncoding<V>> {
    fn encode_size(&self) -> usize {
        K::SIZE + self.1.encode_size()
    }
}

impl<K: Array, V: FixedValue> Write for UnorderedUpdate<K, FixedEncoding<V>> {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
        self.1.write(buf);
    }
}

impl<K: Array, V: VariableValue> Write for UnorderedUpdate<K, VariableEncoding<V>> {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
        self.1.write(buf);
    }
}

impl<K: Array, V: FixedValue> Read for UnorderedUpdate<K, FixedEncoding<V>> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let key = K::read(buf)?;
        let value = V::read_cfg(buf, cfg)?;
        Ok(Self(key, value))
    }
}

impl<K: Array, V: VariableValue> Read for UnorderedUpdate<K, VariableEncoding<V>> {
    type Cfg = <V as Read>::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let key = K::read(buf)?;
        let value = V::read_cfg(buf, cfg)?;
        Ok(Self(key, value))
    }
}
