use crate::authenticated::Error;
use bytes::{Bytes, BytesMut};
use commonware_codec::{EncodeSize, RangeCfg, Read, Write};

/// Represents the padding configuration for a channel.
#[derive(Clone, Debug, Default)]
pub enum Padding {
    /// No padding is applied.
    #[default]
    None,

    /// Pads to a fixed size. Any data larger than this will be rejected.
    Fixed(usize),

    /// Pads to the next multiple of the given value.
    MultipleOf(usize),

    /// Pads to the next power of two.
    PowerOfTwo,
}

/// Helper function to pad data to a specific target size. Since the recipient does not know how
/// much of the original data is padded, the length of the original data must be prepended as part
/// of the padded data. This means that the target size must be large enough to accommodate both the
/// original data as well as its encoded length.
///
/// Returns an error if the encoded data is larger than the target size.
fn pad_to(data: Bytes, target_size: usize) -> Result<Bytes, Error> {
    // Before allocating, check if the data is already larger than the target size
    if data.encode_size() > target_size {
        return Err(Error::PaddingFailed);
    }

    // Create a new mutable buffer and write the data into it
    let mut padded = BytesMut::with_capacity(target_size);
    data.write(&mut padded);

    // Pad with zeroes, asserting that we are never shrinking the data
    assert!(padded.len() <= target_size);
    padded.resize(target_size, 0);
    Ok(padded.into())
}

/// Helper function to extract the original data from padded data. Also checks that any remaining
/// data is zeroed, which is a requirement for the padding scheme.
fn unpad(data: &mut Bytes, max_size: usize) -> Result<Bytes, Error> {
    // Read the original data
    let result =
        Bytes::read_cfg(data, &RangeCfg::from(..=max_size)).map_err(|_| Error::UnpaddingFailed)?;

    // Assert that the remaining data is zeroed
    if !data.iter().all(|&byte| byte == 0) {
        return Err(Error::UnpaddingFailed);
    }

    Ok(result)
}

impl Padding {
    /// Pads the given data according to the padding configuration.
    ///
    /// Returns the padded data or an error if padding fails.
    pub fn pad(&self, data: Bytes) -> Result<Bytes, Error> {
        if matches!(self, Padding::None) {
            return Ok(data);
        }

        match self {
            Padding::None => unreachable!(),
            Padding::Fixed(target_size) => pad_to(data, *target_size),
            Padding::MultipleOf(multiple) => {
                let target_size = data.encode_size().div_ceil(*multiple) * multiple;
                pad_to(data, target_size)
            }
            Padding::PowerOfTwo => {
                let target_size = data.encode_size().next_power_of_two();
                pad_to(data, target_size)
            }
        }
    }

    /// Unpads the given data according to the padding configuration. Checks that all padding rules
    /// are satisfied, including that the padded data is zeroed.
    ///
    /// Returns the unpadded data or an error if unpadding fails.
    pub fn unpad(&self, data: &mut Bytes, max_size: usize) -> Result<Bytes, Error> {
        match self {
            Padding::None => Ok(data.clone()),
            Padding::Fixed(size) => {
                if data.len() != *size {
                    return Err(Error::UnpaddingFailed);
                }
                unpad(data, max_size)
            }
            Padding::MultipleOf(multiple) => {
                if data.len() % multiple != 0 {
                    return Err(Error::UnpaddingFailed);
                }
                unpad(data, max_size)
            }
            Padding::PowerOfTwo => {
                if !data.len().is_power_of_two() {
                    return Err(Error::UnpaddingFailed);
                }
                unpad(data, max_size)
            }
        }
    }
}
