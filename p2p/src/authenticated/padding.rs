use crate::authenticated::Error;
use bytes::{Bytes, BytesMut};

/// Represents the padding configuration for a channel.
#[derive(Clone, Debug, Default)]
pub enum Padding {
    /// No padding is applied.
    #[default]
    None,

    /// Pads to a fixed size. Any data larger than this will be split into chunks.
    Fixed(usize),

    /// Pads to the next multiple of the given value.
    MultipleOf(usize),

    /// Pads to the next power of two.
    PowerOfTwo,
}

impl Padding {
    pub fn pad(&self, data: Bytes) -> Result<Bytes, Error> {
        match self {
            Padding::None => Ok(data),
            Padding::Fixed(target_size) => {
                if data.len() > *target_size {
                    return Err(Error::PaddingFailed);
                }
                let mut padded = BytesMut::with_capacity(*target_size);
                padded.extend_from_slice(&data);
                padded.resize(*target_size, 0);
                Ok(padded.into())
            }
            Padding::MultipleOf(multiple) => {
                let target_size = data.len().div_ceil(*multiple) * multiple;
                let mut padded = BytesMut::with_capacity(target_size);
                padded.extend_from_slice(&data);
                padded.resize(target_size, 0);
                Ok(padded.into())
            }
            Padding::PowerOfTwo => {
                let target_size = data.len().next_power_of_two();
                let mut padded = BytesMut::with_capacity(target_size);
                padded.extend_from_slice(&data);
                padded.resize(target_size, 0);
                Ok(padded.into())
            }
        }
    }

    pub fn unpad(&self, data: Bytes) -> Result<Bytes, Error> {
        match self {
            Padding::None => Ok(data),
            Padding::Fixed(size) => {
                if data.len() != *size {
                    return Err(Error::UnpaddingFailed);
                }
                Ok(data)
            }
            Padding::MultipleOf(multiple) => {
                if data.len() % multiple != 0 {
                    return Err(Error::UnpaddingFailed);
                }
                Ok(data)
            }
            Padding::PowerOfTwo => {
                let size = data.len().next_power_of_two();
                if data.len() != size {
                    return Err(Error::UnpaddingFailed);
                }
                Ok(data)
            }
        }
    }
}
