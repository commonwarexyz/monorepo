use crate::Error;
use chacha20poly1305::Nonce;

/// A struct that holds the nonce information. Holds a counter value that is incremented each time
/// the nonce is used. Is able to be incremented up-to 96 bits (12 bytes) before overflowing.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Info {
    counter: u128,
}

/// If the counter is greater-than-or-equal to this value, it is considered to have overflowed.
/// This is 2^96 or, in binary, one followed by 96 zeros.
const OVERFLOW_VALUE: u128 = 1 << 96;

impl Info {
    /// Encodes the nonce information into a 12-byte array and increments the nonce by 1 (to prevent
    /// reuse).
    ///
    /// An error is returned if-and-only-if the nonce cannot be encoded.
    pub fn next(&mut self) -> Result<Nonce, Error> {
        let result = self.encode()?;
        self.inc();
        Ok(result)
    }

    /// Increments the nonce by 1.
    ///
    /// Silently fails (does not increment) once the nonce has already overflowed 96 bits. This
    /// prevents the nonce from overflowing back to 0.
    fn inc(&mut self) {
        // If the nonce has already overflowed, do not increment it.
        if self.counter >= OVERFLOW_VALUE {
            return;
        }

        // Increment the counter (does not need to check for u128 overflow).
        self.counter += 1;
    }

    /// Encodes the nonce information into a 12-byte array.
    ///
    /// An error is returned if-and-only-if the nonce has overflowed 12 bytes.
    pub fn encode(&self) -> Result<Nonce, Error> {
        // Check for overflow over 96 bits (12 bytes)
        if self.counter >= OVERFLOW_VALUE {
            return Err(Error::NonceOverflow);
        }

        // 16 bytes, big-endian
        let bytes = self.counter.to_be_bytes();

        // The output is a 12-byte array
        let mut result = Nonce::default();

        // Copy the least-significant 12 bytes (96 bits)
        result.copy_from_slice(&bytes[4..16]);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode() {
        let mut expected = [0u8; 12];

        // 0
        let nonce = Info::default();
        assert_eq!(nonce.encode().unwrap()[..], expected[..]);

        // 1
        let nonce = Info { counter: 1 };
        expected = [0u8; 12];
        expected[11] = 1;
        assert_eq!(nonce.encode().unwrap()[..], expected[..]);

        // Two bytes are set
        let two_byte = Info { counter: 0x0102 };
        expected = [0u8; 12];
        expected[10] = 1;
        expected[11] = 2;
        assert_eq!(two_byte.encode().unwrap()[..], expected[..]);

        // Every byte is set
        let mut value: u128 = 0;
        for (i, exp) in expected.iter_mut().enumerate() {
            let val = (i + 1) as u128;
            *exp = val as u8;
            value += val << ((11 - i) * 8);
        }
        let odd = Info { counter: value };
        assert_eq!(odd.encode().unwrap()[..], expected[..]);
    }

    #[test]
    fn test_inc() {
        let mut nonce = Info::default();

        // Incrementing should succeed
        nonce.inc();
        assert_eq!(nonce.counter, 1);

        // Incrementing again should succeed
        nonce.inc();
        assert_eq!(nonce.counter, 2);
    }

    #[test]
    fn test_inc_overflow() {
        let initial = OVERFLOW_VALUE - 2;
        let mut nonce = Info { counter: initial };

        // Encoding should succeed before the boundary
        assert!(nonce.encode().is_ok());

        // Incrementing should succeed
        nonce.inc();
        assert_eq!(nonce.counter, OVERFLOW_VALUE - 1);

        // Encoding should succeed at exactly OVERFLOW_VALUE - 1 (the last valid value)
        assert!(nonce.encode().is_ok());

        // Incrementing again should silently fail (no change to counter)
        nonce.inc();
        assert_eq!(nonce.counter, OVERFLOW_VALUE - 1);

        // Create a nonce that's at overflow to test encode failure
        let overflow_nonce = Info {
            counter: OVERFLOW_VALUE,
        };
        assert!(matches!(overflow_nonce.encode(), Err(Error::NonceOverflow)));
    }
}
