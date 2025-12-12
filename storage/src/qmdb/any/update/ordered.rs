use crate::qmdb::any::{
    ordered::KeyData,
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
pub struct OrderedUpdate<K: Array, V: ValueEncoding>(pub KeyData<K, V::Value>);

impl<K: Array, V: ValueEncoding> Update<K, V> for OrderedUpdate<K, V> {
    fn key(&self) -> &K {
        &self.0.key
    }

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[key:{} next_key:{} value:{}]",
            self.0.key,
            self.0.next_key,
            hex(&self.0.value.encode())
        )
    }
}

impl<K: Array, V: FixedValue> FixedSize for OrderedUpdate<K, FixedEncoding<V>> {
    const SIZE: usize = K::SIZE + V::SIZE + K::SIZE;
}

impl<K: Array, V: FixedValue> Write for OrderedUpdate<K, FixedEncoding<V>> {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.key.write(buf);
        self.0.value.write(buf);
        self.0.next_key.write(buf);
    }
}

impl<K: Array, V: FixedValue> Read for OrderedUpdate<K, FixedEncoding<V>> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let key = K::read(buf)?;
        let value = V::read_cfg(buf, cfg)?;
        let next_key = K::read(buf)?;
        Ok(Self(KeyData {
            key,
            value,
            next_key,
        }))
    }
}

impl<K: Array, V: VariableValue> EncodeSize for OrderedUpdate<K, VariableEncoding<V>> {
    fn encode_size(&self) -> usize {
        K::SIZE + self.0.value.encode_size() + K::SIZE
    }
}

impl<K: Array, V: VariableValue> Write for OrderedUpdate<K, VariableEncoding<V>> {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.key.write(buf);
        self.0.value.write(buf);
        self.0.next_key.write(buf);
    }
}

impl<K: Array, V: VariableValue> Read for OrderedUpdate<K, VariableEncoding<V>> {
    type Cfg = <V as Read>::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let key = K::read(buf)?;
        let value = V::read_cfg(buf, cfg)?;
        let next_key = K::read(buf)?;
        Ok(Self(KeyData {
            key,
            value,
            next_key,
        }))
    }
}
