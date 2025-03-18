use crate::Error;
use chacha20poly1305::Nonce;

/// A struct that holds the nonce information.
///
/// Holds a counter value that is incremented by 2 each time the nonce is used.
/// The least-significant bit does not change, allowing for two disjoint nonce spaces (one for each
/// side of a connection).
///
/// Is able to be incremented up-to 96 bits (12 bytes) before overflowing.
pub struct Info {
    counter: u128,
}

/// If the counter is greater-than-or-equal to this value, it is considered to have overflowed.
/// This is 2^96 or, in binary, one followed by 96 zeros.
const OVERFLOW_VALUE: u128 = 1 << 96;

impl Info {
    /// Creates a new `Info` struct.
    ///
    /// The `dialer` parameter indicates whether the sender is the dialer or not.
    /// For example, if the client was the dialer, this is set to true for your own nonces, but
    /// false for the peer's nonces.
    pub fn new(dialer: bool) -> Self {
        Self {
            counter: if dialer { 1 } else { 0 },
        }
    }

    /// Increments the nonce.
    ///
    /// The counter is incremented by 2, which prevents nonce reuse while also maintaining the value
    /// of the least-significant bit. This ensures that the nonce space is disjoint for two nonces
    /// initialized with different boolean values.
    ///
    /// An error is returned if-and-only-if the nonce overflows 96 bits.
    pub fn inc(&mut self) -> Result<(), Error> {
        // This line does not need to check for overflow as the counter should not be initialized
        // to a value greater than 2^96.
        let new_counter = self.counter + 2;

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

        // Even
        let even = Info::new(false);
        assert_eq!(even.encode()[..], expected[..]);

        // Odd
        let odd = Info::new(true);
        expected = [0u8; 12];
        expected[11] = 1;
        assert_eq!(odd.encode()[..], expected[..]);

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
    fn test_even() {
        let mut even = Info::new(false);
        assert_eq!(even.counter, 0);

        even.inc().unwrap();
        assert_eq!(even.counter, 2);

        even.inc().unwrap();
        assert_eq!(even.counter, 4);
    }

    #[test]
    fn test_odd() {
        let mut odd = Info::new(true);
        assert_eq!(odd.counter, 1);

        odd.inc().unwrap();
        assert_eq!(odd.counter, 3);

        odd.inc().unwrap();
        assert_eq!(odd.counter, 5);
    }

    #[test]
    fn test_inc_overflow_even() {
        let initial = (1 << 96) - 2;
        let mut nonce = Info { counter: initial };

        assert!(matches!(nonce.inc(), Err(Error::NonceOverflow)));
        assert_eq!(nonce.counter, initial);
    }

    #[test]
    fn test_inc_overflow_odd() {
        let initial = (1 << 96) - 1;
        let mut nonce = Info { counter: initial };

        assert!(matches!(nonce.inc(), Err(Error::NonceOverflow)));
        assert_eq!(nonce.counter, initial);
    }
}
