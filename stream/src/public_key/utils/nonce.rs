use crate::public_key::Error;
use chacha20poly1305::Nonce;

/// A struct that holds the nonce information.
///
/// The nonce contains:
/// - `dialer`: a boolean that is true if the nonce is for the dialer side.
/// - `iter` and `seq`: combined, an 80-bit value that can be incremented.
pub struct Info {
    dialer: bool,
    iter: u16,
    seq: u64,
}

impl Info {
    pub fn new(dialer: bool) -> Self {
        Self {
            dialer,
            iter: 0,
            seq: 0,
        }
    }

    /// Increments the nonce.
    ///
    /// `seq` holds the least significant 64 bits of the nonce, and `iter` holds the most significant 16 bits.
    /// An error is returned if-and-only-if the nonce overflows.
    pub fn inc(&mut self) -> Result<(), Error> {
        if self.seq == u64::MAX {
            if self.iter == u16::MAX {
                return Err(Error::NonceOverflow);
            }
            self.iter += 1;
            self.seq = 0;
            return Ok(());
        }
        self.seq += 1;
        Ok(())
    }

    /// Encodes the nonce information into a 12-byte array.
    pub fn encode(&self) -> Nonce {
        let mut result = Nonce::default();
        if self.dialer {
            result[0] = 0b10000000; // Set the first bit of the byte
        }
        if self.iter > 0 {
            result[2..4].copy_from_slice(&self.iter.to_be_bytes());
        }
        result[4..].copy_from_slice(&self.seq.to_be_bytes());
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode() {
        // Test case 1: dialer is true
        let ni = Info {
            dialer: true,
            iter: 1,
            seq: 1,
        };
        let nonce = ni.encode();
        assert_eq!(nonce[0], 0b10000000);
        assert_eq!(&nonce[2..4], &1u16.to_be_bytes());
        assert_eq!(&nonce[4..], &1u64.to_be_bytes());

        // Test case 2: dialer is false
        let ni = Info {
            dialer: false,
            iter: 1,
            seq: 1,
        };
        let nonce = ni.encode();
        assert_eq!(nonce[0], 0b00000000);
        assert_eq!(&nonce[2..4], &1u16.to_be_bytes());
        assert_eq!(&nonce[4..], &1u64.to_be_bytes());

        // Test case 3: different iter and seq values
        let ni = Info {
            dialer: true,
            iter: 65535,
            seq: 123456789,
        };
        let nonce = ni.encode();
        assert_eq!(nonce[0], 0b10000000);
        assert_eq!(&nonce[2..4], &65535u16.to_be_bytes());
        assert_eq!(&nonce[4..], &123456789u64.to_be_bytes());

        // Test case 4: iter is 0
        let ni = Info {
            dialer: true,
            iter: 0,
            seq: 123456789,
        };
        let nonce = ni.encode();
        assert_eq!(nonce[0], 0b10000000);
        assert_eq!(&nonce[2..4], &0u16.to_be_bytes());
        assert_eq!(&nonce[4..], &123456789u64.to_be_bytes());
    }

    #[test]
    fn test_inc() {
        const ITER: u16 = 5;
        let mut ni = Info {
            dialer: true,
            iter: ITER,
            seq: 0,
        };

        // Increment once
        ni.inc().unwrap();
        assert_eq!(ni.seq, 1);
        assert_eq!(ni.iter, ITER);
        assert!(ni.dialer);

        // Increment again
        ni.inc().unwrap();
        assert_eq!(ni.seq, 2);
        assert_eq!(ni.iter, ITER);
        assert_eq!(ni.dialer, true);
    }

    #[test]
    fn test_inc_seq_overflow() {
        const ITER: u16 = 5;
        let mut ni = Info {
            dialer: true,
            iter: ITER,
            seq: u64::MAX,
        };
        ni.inc().unwrap();
        assert_eq!(ni.seq, 0);
        assert_eq!(ni.iter, ITER + 1);
    }

    #[test]
    fn test_inc_seq_iter_overflow() {
        let mut ni = Info {
            dialer: true,
            iter: u16::MAX,
            seq: u64::MAX,
        };
        let result = ni.inc();
        assert!(matches!(result, Err(Error::NonceOverflow)));
    }
}
