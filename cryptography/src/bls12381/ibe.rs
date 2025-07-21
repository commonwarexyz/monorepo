//! Identity-Based Encryption (IBE) implementation for BLS12-381.
//!
//! This module provides timelock encryption functionality using identity-based
//! encryption on the BLS12-381 elliptic curve.

use super::primitives::{
    group::{Element, Scalar, GT},
    ops::hash_message,
    variant::Variant,
    Error,
};
use bytes::{Buf, BufMut};
use commonware_codec::{varint::UInt, EncodeSize, Read, ReadExt, Write};
use rand::{CryptoRng, Rng};

/// Block size for encryption operations.
const BLOCK_SIZE: usize = 32;

/// Ciphertext structure for IBE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext<V: Variant> {
    /// First group element U = r * Public::one().
    pub u: V::Public,
    /// Encrypted random value V = sigma XOR H2(e(Q_id, r * P_pub)).
    pub v: [u8; 16],
    /// Encrypted message W = M XOR H4(sigma).
    pub w: Vec<u8>,
}

impl<V: Variant> Write for Ciphertext<V> {
    fn write(&self, buf: &mut impl BufMut) {
        self.u.write(buf);
        buf.put_slice(&self.v);
        UInt(self.w.len() as u64).write(buf);
        buf.put_slice(&self.w);
    }
}

impl<V: Variant> Read for Ciphertext<V> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, commonware_codec::Error> {
        let u = V::Public::read(buf)?;
        let mut v = [0u8; 16];
        if buf.remaining() < 16 {
            return Err(commonware_codec::Error::EndOfBuffer);
        }
        buf.copy_to_slice(&mut v);
        let w_len: u64 = UInt::read(buf)?.0;
        if buf.remaining() < w_len as usize {
            return Err(commonware_codec::Error::EndOfBuffer);
        }
        let mut w = vec![0u8; w_len as usize];
        buf.copy_to_slice(&mut w);
        Ok(Self { u, v, w })
    }
}

impl<V: Variant> EncodeSize for Ciphertext<V> {
    fn encode_size(&self) -> usize {
        self.u.encode_size() + 16 + UInt(self.w.len() as u64).encode_size() + self.w.len()
    }
}

/// Hash functions for IBE.
mod hash {
    use super::*;

    /// H2: GT -> [u8; 16]
    /// Used to mask the random sigma value.
    pub fn h2(gt: &GT) -> [u8; 16] {
        let mut input = b"h2".to_vec();
        input.extend_from_slice(&gt.to_bytes());
        let digest = crate::sha256::hash(&input);
        let mut result = [0u8; 16];
        result.copy_from_slice(&digest[..16]);
        result
    }

    /// H3: (sigma, M) -> Scalar
    /// Used to derive the random scalar r.
    pub fn h3(sigma: &[u8; 16], message: &[u8]) -> Scalar {
        let mut input = b"h3".to_vec();
        input.extend_from_slice(sigma);
        input.extend_from_slice(message);
        let digest = crate::sha256::hash(&input);
        // Convert hash to scalar
        // Use the hash as IKM (input keying material) for scalar generation
        let mut ikm = [0u8; 64];
        ikm[..32].copy_from_slice(&digest);
        ikm[32..].copy_from_slice(&digest);
        Scalar::from_ikm(&ikm)
    }

    /// H4: sigma -> [u8; 32]
    /// Used to mask the message.
    pub fn h4(sigma: &[u8; 16]) -> [u8; BLOCK_SIZE] {
        let mut input = b"h4".to_vec();
        input.extend_from_slice(sigma);
        let digest = crate::sha256::hash(&input);
        let mut result = [0u8; BLOCK_SIZE];
        result.copy_from_slice(&digest);
        result
    }
}

/// XOR two byte arrays of the same length.
fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len(), "XOR operands must have the same length");
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

/// Encrypt a message using identity-based encryption.
///
/// # Arguments
/// * `rng` - Random number generator
/// * `public` - Master public key
/// * `message` - Message to encrypt (max 32 bytes)
/// * `target` - Identity/target to encrypt for
///
/// # Returns
/// * `Result<Ciphertext>` - The encrypted ciphertext
pub fn encrypt<R: Rng + CryptoRng, V: Variant>(
    rng: &mut R,
    public: V::Public,
    message: &[u8],
    target: &[u8],
) -> Result<Ciphertext<V>, Error> {
    // Security check: message must be exactly 32 bytes
    if message.len() != BLOCK_SIZE {
        return Err(Error::InvalidSignature); // TODO: Add better error variant
    }

    // Hash target to get Q_id in signature group using the variant's message DST
    let q_id = hash_message::<V>(V::MESSAGE, target);

    // Generate random 16-byte sigma
    let mut sigma = [0u8; 16];
    rng.fill_bytes(&mut sigma);

    // Derive scalar r from sigma and message
    let r = hash::h3(&sigma, message);

    // Compute U = r * Public::one()
    let mut u = V::Public::one();
    u.mul(&r);

    // Compute e(r * P_pub, Q_id)
    let mut r_pub = public;
    r_pub.mul(&r);
    let gt = V::pairing(&r_pub, &q_id);

    // Compute V = sigma XOR H2(e(Q_id, r * P_pub))
    let h2_value = hash::h2(&gt);
    let v: [u8; 16] = xor(&sigma, &h2_value)
        .try_into()
        .expect("XOR result should be 16 bytes");

    // Compute W = M XOR H4(sigma)
    let h4_value = hash::h4(&sigma);
    let w = xor(message, &h4_value);

    Ok(Ciphertext { u, v, w })
}

/// Decrypt a ciphertext using identity-based encryption.
///
/// # Arguments
/// * `private` - Private key for the identity
/// * `ciphertext` - Ciphertext to decrypt
///
/// # Returns
/// * `Result<Vec<u8>>` - The decrypted message
pub fn decrypt<V: Variant>(
    private: V::Signature,
    ciphertext: &Ciphertext<V>,
) -> Result<Vec<u8>, Error> {
    // Compute e(U, private)
    let gt = V::pairing(&ciphertext.u, &private);

    // Recover sigma = V XOR H2(e(U, private))
    let h2_value = hash::h2(&gt);
    let sigma: [u8; 16] = xor(&ciphertext.v, &h2_value)
        .try_into()
        .expect("XOR result should be 16 bytes");

    // Recover M = W XOR H4(sigma)
    let h4_value = hash::h4(&sigma);
    let message = xor(&ciphertext.w, &h4_value);

    // Verify integrity: recompute r and check U = r * Public::one()
    let r = hash::h3(&sigma, &message);
    let mut expected_u = V::Public::one();
    expected_u.mul(&r);

    if ciphertext.u != expected_u {
        return Err(Error::InvalidSignature); // TODO: Add better error variant
    }

    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::primitives::{
        ops::keypair,
        variant::{MinPk, MinSig},
    };
    use rand::thread_rng;

    #[test]
    fn test_encrypt_decrypt_minpk() {
        let mut rng = thread_rng();

        // Generate master keypair
        let (master_secret, master_public) = keypair::<_, MinPk>(&mut rng);

        // Identity and message
        let identity = b"alice@example.com";
        let message = b"Hello, IBE! This is exactly 32b!"; // 32 bytes

        // Generate private key for identity
        let id_point = hash_message::<MinPk>(MinPk::MESSAGE, identity);
        let mut private_key = id_point;
        private_key.mul(&master_secret);

        // Encrypt
        let ciphertext = encrypt::<_, MinPk>(&mut rng, master_public, message, identity)
            .expect("Encryption should succeed");

        // Decrypt
        let decrypted =
            decrypt::<MinPk>(private_key, &ciphertext).expect("Decryption should succeed");

        assert_eq!(message, &decrypted[..]);
    }

    #[test]
    fn test_encrypt_decrypt_minsig() {
        let mut rng = thread_rng();

        // Generate master keypair
        let (master_secret, master_public) = keypair::<_, MinSig>(&mut rng);

        // Identity and message
        let identity = b"bob@example.com";
        let message = b"Testing MinSig variant - 32 byte";

        // Generate private key for identity
        let id_point = hash_message::<MinSig>(MinSig::MESSAGE, identity);
        let mut private_key = id_point;
        private_key.mul(&master_secret);

        // Encrypt
        let ciphertext = encrypt::<_, MinSig>(&mut rng, master_public, message, identity)
            .expect("Encryption should succeed");

        // Decrypt
        let decrypted =
            decrypt::<MinSig>(private_key, &ciphertext).expect("Decryption should succeed");

        assert_eq!(message, &decrypted[..]);
    }

    #[test]
    fn test_message_too_long() {
        let mut rng = thread_rng();
        let (_, master_public) = keypair::<_, MinPk>(&mut rng);

        let identity = b"test@example.com";
        let message = vec![0u8; 33]; // Not exactly 32

        let result = encrypt::<_, MinPk>(&mut rng, master_public, &message, identity);
        assert!(result.is_err());
        // Just check it's an error
    }

    #[test]
    fn test_wrong_private_key() {
        let mut rng = thread_rng();

        // Generate two different master keypairs
        let (_, master_public1) = keypair::<_, MinPk>(&mut rng);
        let (master_secret2, _) = keypair::<_, MinPk>(&mut rng);

        let identity = b"charlie@example.com";
        let message = b"Secret message padded to 32bytes";

        // Encrypt with first master public key
        let ciphertext = encrypt::<_, MinPk>(&mut rng, master_public1, message, identity)
            .expect("Encryption should succeed");

        // Try to decrypt with private key from second master
        let id_point = hash_message::<MinPk>(MinPk::MESSAGE, identity);
        let mut wrong_private = id_point;
        wrong_private.mul(&master_secret2);
        let result = decrypt::<MinPk>(wrong_private, &ciphertext);

        assert!(result.is_err());
        // Error type doesn't have Display implementation, just check it's an error
    }

    #[test]
    fn test_tampered_ciphertext() {
        let mut rng = thread_rng();

        let (master_secret, master_public) = keypair::<_, MinPk>(&mut rng);
        let identity = b"dave@example.com";
        let message = b"Tamper test padded to 32 bytes.."; // 32 bytes

        // Generate private key
        let id_point = hash_message::<MinPk>(MinPk::MESSAGE, identity);
        let mut private_key = id_point;
        private_key.mul(&master_secret);

        // Encrypt
        let mut ciphertext = encrypt::<_, MinPk>(&mut rng, master_public, message, identity)
            .expect("Encryption should succeed");

        // Tamper with ciphertext
        ciphertext.w[0] ^= 0xFF;

        // Try to decrypt
        let result = decrypt::<MinPk>(private_key, &ciphertext);
        assert!(result.is_err());
        // Error type doesn't have Display implementation, just check it's an error
    }

    #[test]
    fn test_empty_message() {
        let mut rng = thread_rng();

        let (master_secret, master_public) = keypair::<_, MinPk>(&mut rng);
        let identity = b"empty@example.com";
        let message = [0u8; 32]; // 32 zero bytes

        let id_point = hash_message::<MinPk>(MinPk::MESSAGE, identity);
        let mut private_key = id_point;
        private_key.mul(&master_secret);

        let ciphertext = encrypt::<_, MinPk>(&mut rng, master_public, &message, identity)
            .expect("Encryption should succeed");

        let decrypted =
            decrypt::<MinPk>(private_key, &ciphertext).expect("Decryption should succeed");

        assert_eq!(message, &decrypted[..]);
    }

    #[test]
    fn test_max_size_message() {
        let mut rng = thread_rng();

        let (master_secret, master_public) = keypair::<_, MinPk>(&mut rng);
        let identity = b"maxsize@example.com";
        let message = vec![0xAB; 32]; // Maximum allowed size

        let id_point = hash_message::<MinPk>(MinPk::MESSAGE, identity);
        let mut private_key = id_point;
        private_key.mul(&master_secret);

        let ciphertext = encrypt::<_, MinPk>(&mut rng, master_public, &message, identity)
            .expect("Encryption should succeed");

        let decrypted =
            decrypt::<MinPk>(private_key, &ciphertext).expect("Decryption should succeed");

        assert_eq!(message, decrypted);
    }
}
