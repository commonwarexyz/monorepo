//! Core codec traits and implementations

use crate::{
    buffer::{ReadBuffer, WriteBuffer},
    error::Error,
};
use bytes::Bytes;

/// Trait for types that can be encoded to and decoded from bytes
pub trait Codec: Sized {
    /// Encodes this value to a writer.
    fn write(&self, writer: &mut impl Writer);

    /// Decodes a value from a reader.
    fn read(reader: &mut impl Reader) -> Result<Self, Error>;

    /// Returns the encoded length of this value.
    fn len_encoded(&self) -> usize;

    /// Encodes a value to bytes.
    fn encode(&self) -> Vec<u8> {
        let len = self.len_encoded();
        let mut buffer = WriteBuffer::new(len);
        self.write(&mut buffer);
        assert!(buffer.len() == len);
        buffer.into()
    }

    /// Decodes a value from bytes.
    /// Returns an error if there is extra data after decoding the value.
    fn decode(bytes: impl Into<Bytes>) -> Result<Self, Error> {
        let mut reader = ReadBuffer::new(bytes.into());
        let result = Self::read(&mut reader);
        let remaining = reader.remaining();
        if remaining > 0 {
            return Err(Error::ExtraData(remaining));
        }
        result
    }
}

/// Trait for types that have a fixed-length encoding
pub trait SizedCodec: Codec {
    /// The encoded length of this value.
    const LEN_ENCODED: usize;

    /// Returns the encoded length of this value.
    ///
    /// Should not be overridden by implementations.
    fn len_encoded(&self) -> usize {
        Self::LEN_ENCODED
    }

    /// Encodes a value to fixed-size bytes.
    fn encode_fixed<const N: usize>(&self) -> [u8; N] {
        // Ideally this is a compile-time check, but we can't do that in the current Rust version
        // without adding a new generic parameter to the trait.
        assert_eq!(
            N,
            Self::LEN_ENCODED,
            "Can't encode {} bytes into {} bytes",
            Self::LEN_ENCODED,
            N
        );

        self.encode().try_into().unwrap()
    }
}

/// Trait for codec read operations
pub trait Reader {
    /// Reads a u8 value
    fn read_u8(&mut self) -> Result<u8, Error>;

    /// Reads a u16 value
    fn read_u16(&mut self) -> Result<u16, Error>;

    /// Reads a u32 value
    fn read_u32(&mut self) -> Result<u32, Error>;

    /// Reads a u64 value
    fn read_u64(&mut self) -> Result<u64, Error>;

    /// Reads a u128 value
    fn read_u128(&mut self) -> Result<u128, Error>;

    /// Reads a i8 value
    fn read_i8(&mut self) -> Result<i8, Error>;

    /// Reads a i16 value
    fn read_i16(&mut self) -> Result<i16, Error>;

    /// Reads a i32 value
    fn read_i32(&mut self) -> Result<i32, Error>;

    /// Reads a i64 value
    fn read_i64(&mut self) -> Result<i64, Error>;

    /// Reads a i128 value
    fn read_i128(&mut self) -> Result<i128, Error>;

    /// Reads a f32 value
    fn read_f32(&mut self) -> Result<f32, Error>;

    /// Reads a f64 value
    fn read_f64(&mut self) -> Result<f64, Error>;

    /// Reads a varint-encoded integer
    fn read_varint(&mut self) -> Result<u64, Error>;

    /// Reads bytes with a length prefix
    fn read_bytes(&mut self) -> Result<Bytes, Error>;

    /// Reads bytes with a length prefix, with a limit on the number of bytes
    fn read_bytes_lte(&mut self, max: usize) -> Result<Bytes, Error>;

    /// Reads a fixed number of bytes
    fn read_n_bytes(&mut self, n: usize) -> Result<Bytes, Error>;

    /// Reads a fixed number of bytes into a fixed-size byte array
    fn read_fixed<const N: usize>(&mut self) -> Result<[u8; N], Error>;

    /// Reads a boolean value
    fn read_bool(&mut self) -> Result<bool, Error>;

    /// Reads an option value
    fn read_option<T: Codec>(&mut self) -> Result<Option<T>, Error>;

    /// Reads a vector with a length prefix
    fn read_vec<T: Codec>(&mut self) -> Result<Vec<T>, Error>;

    /// Reads a vector with a length prefix, with a limit on the number of elements
    fn read_vec_lte<T: Codec>(&mut self, max: usize) -> Result<Vec<T>, Error>;
}

/// Trait for codec write operations
pub trait Writer {
    /// Writes a u8 value
    fn write_u8(&mut self, value: u8);

    /// Writes a u16 value
    fn write_u16(&mut self, value: u16);

    /// Writes a u32 value
    fn write_u32(&mut self, value: u32);

    /// Writes a u64 value
    fn write_u64(&mut self, value: u64);

    /// Writes a u128 value
    fn write_u128(&mut self, value: u128);

    /// Writes a i8 value
    fn write_i8(&mut self, value: i8);

    /// Writes a i16 value
    fn write_i16(&mut self, value: i16);

    /// Writes a i32 value
    fn write_i32(&mut self, value: i32);

    /// Writes a i64 value
    fn write_i64(&mut self, value: i64);

    /// Writes a i128 value
    fn write_i128(&mut self, value: i128);

    /// Writes a f32 value
    fn write_f32(&mut self, value: f32);

    /// Writes a f64 value
    fn write_f64(&mut self, value: f64);

    /// Writes a varint-encoded integer
    fn write_varint(&mut self, value: u64);

    /// Writes bytes with a length prefix
    fn write_bytes(&mut self, bytes: &[u8]);

    /// Writes a fixed-size byte array
    fn write_fixed(&mut self, bytes: &[u8]);

    /// Writes a boolean value
    fn write_bool(&mut self, value: bool);

    /// Writes an option value
    fn write_option<T: Codec>(&mut self, value: &Option<T>);

    /// Writes a vector with a length prefix
    fn write_vec<T: Codec>(&mut self, values: &[T]);
}

// Implement Reader for ReadBuffer
impl Reader for ReadBuffer {
    fn read_u8(&mut self) -> Result<u8, Error> {
        self.get_u8()
    }

    fn read_u16(&mut self) -> Result<u16, Error> {
        self.get_u16()
    }

    fn read_u32(&mut self) -> Result<u32, Error> {
        self.get_u32()
    }

    fn read_u64(&mut self) -> Result<u64, Error> {
        self.get_u64()
    }

    fn read_u128(&mut self) -> Result<u128, Error> {
        self.get_u128()
    }

    fn read_i8(&mut self) -> Result<i8, Error> {
        self.get_i8()
    }

    fn read_i16(&mut self) -> Result<i16, Error> {
        self.get_i16()
    }

    fn read_i32(&mut self) -> Result<i32, Error> {
        self.get_i32()
    }

    fn read_i64(&mut self) -> Result<i64, Error> {
        self.get_i64()
    }

    fn read_i128(&mut self) -> Result<i128, Error> {
        self.get_i128()
    }

    fn read_f32(&mut self) -> Result<f32, Error> {
        self.get_f32()
    }

    fn read_f64(&mut self) -> Result<f64, Error> {
        self.get_f64()
    }

    fn read_varint(&mut self) -> Result<u64, Error> {
        self.read_varint()
    }

    fn read_bytes(&mut self) -> Result<Bytes, Error> {
        let len = self.read_varint()? as usize;
        self.read_n_bytes(len)
    }

    fn read_n_bytes(&mut self, n: usize) -> Result<Bytes, Error> {
        let bytes = self.split_to(n)?;
        Ok(bytes)
    }

    fn read_bytes_lte(&mut self, max: usize) -> Result<Bytes, Error> {
        let len = self.read_varint()? as usize;
        if len > max {
            return Err(Error::LengthExceeded(len, max));
        }
        self.read_n_bytes(len)
    }

    fn read_fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let mut bytes = [0u8; N];
        self.copy_to_slice(&mut bytes)?;
        Ok(bytes)
    }

    fn read_bool(&mut self) -> Result<bool, Error> {
        let b = self.read_u8()?;
        if b > 1 {
            return Err(Error::InvalidBool);
        }
        Ok(b != 0)
    }

    fn read_option<T: Codec>(&mut self) -> Result<Option<T>, Error> {
        let has_value = self.read_bool()?;

        if has_value {
            Ok(Some(T::read(self)?))
        } else {
            Ok(None)
        }
    }

    fn read_vec<T: Codec>(&mut self) -> Result<Vec<T>, Error> {
        let len = self.read_varint()? as usize;
        let mut items = Vec::with_capacity(len);
        for _ in 0..len {
            items.push(T::read(self)?);
        }
        Ok(items)
    }

    fn read_vec_lte<T: Codec>(&mut self, max: usize) -> Result<Vec<T>, Error> {
        let len = self.read_varint()? as usize;

        if len > max {
            return Err(Error::LengthExceeded(len, max));
        }

        let mut items = Vec::with_capacity(len);
        for _ in 0..len {
            items.push(T::read(self)?);
        }
        Ok(items)
    }
}

// Implement Writer for WriteBuffer
impl Writer for WriteBuffer {
    fn write_u8(&mut self, value: u8) {
        self.put_u8(value)
    }

    fn write_u16(&mut self, value: u16) {
        self.put_u16(value)
    }

    fn write_u32(&mut self, value: u32) {
        self.put_u32(value)
    }

    fn write_u64(&mut self, value: u64) {
        self.put_u64(value)
    }

    fn write_u128(&mut self, value: u128) {
        self.put_u128(value)
    }

    fn write_i8(&mut self, value: i8) {
        self.put_i8(value)
    }

    fn write_i16(&mut self, value: i16) {
        self.put_i16(value)
    }

    fn write_i32(&mut self, value: i32) {
        self.put_i32(value)
    }

    fn write_i64(&mut self, value: i64) {
        self.put_i64(value)
    }

    fn write_i128(&mut self, value: i128) {
        self.put_i128(value)
    }

    fn write_f32(&mut self, value: f32) {
        self.put_f32(value)
    }

    fn write_f64(&mut self, value: f64) {
        self.put_f64(value)
    }

    fn write_varint(&mut self, value: u64) {
        self.write_varint(value)
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        self.write_varint(bytes.len() as u64);
        self.write_fixed(bytes);
    }

    fn write_fixed(&mut self, bytes: &[u8]) {
        self.put_slice(bytes);
    }

    fn write_bool(&mut self, value: bool) {
        self.put_u8(if value { 1 } else { 0 });
    }

    fn write_option<T: Codec>(&mut self, value: &Option<T>) {
        match value {
            Some(v) => {
                self.write_bool(true);
                v.write(self);
            }
            None => {
                self.write_bool(false);
            }
        }
    }

    fn write_vec<T: Codec>(&mut self, values: &[T]) {
        self.write_varint(values.len() as u64);
        for value in values {
            value.write(self);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{varint::varint_size, Codec, Error, ReadBuffer, WriteBuffer};
    use bytes::Bytes;

    #[test]
    fn test_insufficient_buffer() {
        let mut reader = ReadBuffer::new(Bytes::from_static(&[0x01, 0x02]));
        assert!(matches!(u32::read(&mut reader), Err(Error::EndOfBuffer)));
    }

    #[test]
    fn test_extra_data() {
        let encoded = Bytes::from_static(&[0x01, 0x02]);
        assert!(matches!(u8::decode(encoded), Err(Error::ExtraData(1))));
    }

    #[test]
    fn test_invalid_bool() {
        let encoded = Bytes::from_static(&[0x02]);
        assert!(matches!(bool::decode(encoded), Err(Error::InvalidBool)));
    }

    #[test]
    fn test_varint() {
        let value = u64::MAX / 2;
        let mut writer = WriteBuffer::new(varint_size(value));
        writer.write_varint(value);
        let mut reader = ReadBuffer::new(writer.freeze());
        let result = reader.read_varint().unwrap();
        assert_eq!(result, value);
    }

    #[test]
    fn test_length_limit_exceeded() {
        let mut writer = WriteBuffer::new(10);
        writer.write_bytes(&[1, 2, 3, 4, 5, 6]);
        let mut reader = ReadBuffer::new(writer.freeze());
        assert!(matches!(
            reader.read_bytes_lte(5),
            Err(Error::LengthExceeded(6, 5))
        ));
    }
    #[test]
    fn test_bytes_lte_success() {
        let mut writer = WriteBuffer::new(10);
        writer.write_bytes(&[1, 2, 3]);
        let mut reader = ReadBuffer::new(writer.freeze());
        let result = reader.read_bytes_lte(5).unwrap();
        assert_eq!(result, Bytes::from_static(&[1, 2, 3]));
    }

    #[test]
    fn test_bytes_lte_exceeded() {
        let mut writer = WriteBuffer::new(10);
        writer.write_bytes(&[1, 2, 3, 4, 5, 6]);
        let mut reader = ReadBuffer::new(writer.freeze());
        assert!(matches!(
            reader.read_bytes_lte(5),
            Err(Error::LengthExceeded(6, 5))
        ));
    }

    #[test]
    fn test_vec_lte_success() {
        let mut writer = WriteBuffer::new(10);
        writer.write_vec(&[1u8, 2u8]);
        let mut reader = ReadBuffer::new(writer.freeze());
        let result = reader.read_vec_lte::<u8>(3).unwrap();
        assert_eq!(result, vec![1u8, 2u8]);
    }

    #[test]
    fn test_vec_lte_exceeded() {
        let mut writer = WriteBuffer::new(10);
        writer.write_vec(&[1u8, 2u8, 3u8]);
        let mut reader = ReadBuffer::new(writer.freeze());
        assert!(matches!(
            reader.read_vec_lte::<u8>(2),
            Err(Error::LengthExceeded(3, 2))
        ));
    }

    #[test]
    fn test_encode_fixed() {
        let value = 42u32;
        let encoded: [u8; 4] = value.encode_fixed();
        let decoded = u32::decode(Bytes::copy_from_slice(&encoded)).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    #[should_panic(expected = "Can't encode 4 bytes into 5 bytes")]
    fn test_encode_fixed_panic() {
        let _: [u8; 5] = 42u32.encode_fixed();
    }
}
