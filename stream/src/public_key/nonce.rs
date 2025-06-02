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
    /// Increments the nonce by 1.
    ///
    /// An error is returned if-and-only-if the nonce overflows 96 bits.
    pub fn inc(&mut self) -> Result<(), Error> {
        // This line does not need to check for u128 overflow as the counter should be initialized
        // to 0.
        let new_counter = self.counter + 1;

        // Check for overflow over 96 bits (12 bytes)
        if new_counter >= OVERFLOW_VALUE {
            return Err(Error::NonceOverflow);
        }

        self.counter = new_counter;
        Ok(())
    }

    /// Encodes the nonce information into a 12-byte array.
    pub fn encode(&self) -> Nonce {
        // 16 bytes, big-endian
        let bytes = self.counter.to_be_bytes();

        // The output is a 12-byte array
        let mut result = Nonce::default();

        // Copy the least-significant 12 bytes (96 bits)
        result.copy_from_slice(&bytes[4..16]);
        result
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
        assert_eq!(nonce.encode()[..], expected[..]);

        // 1
        let nonce = Info { counter: 1 };
        expected = [0u8; 12];
        expected[11] = 1;
        assert_eq!(nonce.encode()[..], expected[..]);

        // Two bytes are set
        let two_byte = Info { counter: 0x0102 };
        expected = [0u8; 12];
        expected[10] = 1;
        expected[11] = 2;
        assert_eq!(two_byte.encode()[..], expected[..]);

        // Every byte is set
        let mut value: u128 = 0;
        for (i, exp) in expected.iter_mut().enumerate() {
            let val = (i + 1) as u128;
            *exp = val as u8;
            value += val << ((11 - i) * 8);
        }
        let odd = Info { counter: value };
        assert_eq!(odd.encode()[..], expected[..]);
    }

    #[test]
    fn test_inc() {
        let mut nonce = Info::default();

        // Incrementing should succeed
        assert!(nonce.inc().is_ok());
        assert_eq!(nonce.counter, 1);

        // Incrementing again should succeed
        assert!(nonce.inc().is_ok());
        assert_eq!(nonce.counter, 2);
    }

    #[test]
    fn test_inc_overflow() {
        let initial = OVERFLOW_VALUE - 2;
        let mut nonce = Info { counter: initial };

        // Incrementing should succeed
        assert!(nonce.inc().is_ok());

        // Incrementing again should overflow
        assert!(matches!(nonce.inc(), Err(Error::NonceOverflow)));
        assert_eq!(nonce.counter, initial + 1);

        // Incrementing again should not change the counter
        assert!(matches!(nonce.inc(), Err(Error::NonceOverflow)));
        assert_eq!(nonce.counter, initial + 1);
    }
}
