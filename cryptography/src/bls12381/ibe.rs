//! Identity-Based Encryption (IBE) implementation for BLS12-381.
//!
//! This module provides timelock encryption functionality using identity-based
//! encryption on the BLS12-381 elliptic curve. The implementation uses the
//! Fujisaki-Okamoto transform to achieve CCA-security.

use crate::{bls12381::primitives::ops::hash_message_namespace, sha256::Digest};

use super::primitives::{
    group::{Element, Scalar, GT},
    ops::hash_message,
    variant::Variant,
    Error,
};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, FixedSize, Read, ReadExt, Write};
use commonware_utils::array::FixedBytes;
use rand::{CryptoRng, Rng};

/// Block size for encryption operations.
const BLOCK_SIZE: usize = Digest::SIZE;

/// Type alias for 32-byte blocks using FixedBytes.
type Block = FixedBytes<BLOCK_SIZE>;

/// Ciphertext structure for IBE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext<V: Variant> {
    /// First group element U = r * Public::one().
    pub u: V::Public,
    /// Encrypted random value V = sigma XOR H2(e(Q_id, r * P_pub)).
    pub v: Block,
    /// Encrypted message W = M XOR H4(sigma).
    pub w: Block,
}

impl<V: Variant> Write for Ciphertext<V> {
    fn write(&self, buf: &mut impl BufMut) {
        self.u.write(buf);
        buf.put_slice(self.v.as_ref());
        buf.put_slice(self.w.as_ref());
    }
}

impl<V: Variant> Read for Ciphertext<V> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, commonware_codec::Error> {
        let u = V::Public::read(buf)?;
        let v = Block::read(buf)?;
        let w = Block::read(buf)?;
        Ok(Self { u, v, w })
    }
}

impl<V: Variant> EncodeSize for Ciphertext<V> {
    fn encode_size(&self) -> usize {
        self.u.encode_size() + self.v.encode_size() + self.w.encode_size()
    }
}

/// Hash functions for IBE.
mod hash {
    use super::*;

    /// H2: GT -> Block
    /// Used to mask the random sigma value.
    pub fn h2(gt: &GT) -> Block {
        let mut input = b"h2".to_vec();
        input.extend_from_slice(&gt.to_bytes());
        let digest = crate::sha256::hash(&input);
        // Convert Digest to Block
        Block::new(*digest.as_ref())
    }

    /// H3: (sigma, M) -> Scalar
    /// Used to derive the random scalar r.
    pub fn h3(sigma: &Block, message: &[u8]) -> Scalar {
        let mut input = b"h3".to_vec();
        input.extend_from_slice(sigma.as_ref());
        input.extend_from_slice(message);
        let digest = crate::sha256::hash(&input);
        // Convert hash to scalar
        // Use the hash as IKM (input keying material) for scalar generation
        let mut ikm = [0u8; 64];
        ikm[..32].copy_from_slice(&digest);
        ikm[32..].copy_from_slice(&digest);
        Scalar::from_ikm(&ikm)
    }

    /// H4: sigma -> Block
    /// Used to mask the message.
    pub fn h4(sigma: &Block) -> Block {
        let mut input = b"h4".to_vec();
        input.extend_from_slice(sigma.as_ref());
        let digest = crate::sha256::hash(&input);
        // Convert Digest to Block
        Block::new(*digest.as_ref())
    }
}

/// XOR two blocks together.
fn xor_blocks(a: &Block, b: &Block) -> Block {
    let mut result = [0u8; BLOCK_SIZE];
    for (i, (a, b)) in a.as_ref().iter().zip(b.as_ref().iter()).enumerate() {
        result[i] = a ^ b;
    }
    Block::new(result)
}

/// Encrypt a message using identity-based encryption with CCA-security.
///
/// This implements the Fujisaki-Okamoto transform for CCA-security by:
/// 1. Generating random sigma
/// 2. Deriving encryption randomness r = H3(sigma || message)
/// 3. Creating commitment U = r * G
/// 4. Masking sigma with the pairing result
/// 5. Masking the message with H4(sigma)
///
/// # Arguments
/// * `rng` - Random number generator
/// * `public` - Master public key
/// * `message` - Message to encrypt (must be exactly 32 bytes)
/// * `target` - Identity/target to encrypt for
///
/// # Returns
/// * `Result<Ciphertext>` - The encrypted ciphertext
pub fn encrypt<R: Rng + CryptoRng, V: Variant>(
    rng: &mut R,
    public: V::Public,
    message: &Block,
    target: (Option<&[u8]>, &[u8]),
) -> Result<Ciphertext<V>, Error> {
    // Hash target to get Q_id in signature group using the variant's message DST
    let q_id = match target {
        (None, target) => hash_message::<V>(V::MESSAGE, target),
        (Some(namespace), target) => hash_message_namespace::<V>(V::MESSAGE, namespace, target),
    };

    // Generate random sigma
    let mut sigma_array = [0u8; BLOCK_SIZE];
    rng.fill_bytes(&mut sigma_array);
    let sigma = Block::new(sigma_array);

    // Derive scalar r from sigma and message
    let r = hash::h3(&sigma, message.as_ref());

    // Compute U = r * Public::one()
    let mut u = V::Public::one();
    u.mul(&r);

    // Compute e(r * P_pub, Q_id)
    let mut r_pub = public;
    r_pub.mul(&r);
    let gt = V::pairing(&r_pub, &q_id);

    // Compute V = sigma XOR H2(e(Q_id, r * P_pub))
    let h2_value = hash::h2(&gt);
    let v = xor_blocks(&sigma, &h2_value);

    // Compute W = M XOR H4(sigma)
    let h4_value = hash::h4(&sigma);
    let w = xor_blocks(message, &h4_value);

    Ok(Ciphertext { u, v, w })
}

/// Decrypt a ciphertext using identity-based encryption with CCA-security.
///
/// The decryption verifies the ciphertext integrity by:
/// 1. Recovering sigma from the pairing
/// 2. Recovering the message
/// 3. Recomputing r = H3(sigma || message)
/// 4. Verifying that U = r * G matches the ciphertext
///
/// # Arguments
/// * `private` - Private key for the identity
/// * `ciphertext` - Ciphertext to decrypt
///
/// # Returns
/// * `Result<Block>` - The decrypted message
pub fn decrypt<V: Variant>(
    private: V::Signature,
    ciphertext: &Ciphertext<V>,
) -> Result<Block, Error> {
    // Compute e(U, private)
    let gt = V::pairing(&ciphertext.u, &private);

    // Recover sigma = V XOR H2(e(U, private))
    let h2_value = hash::h2(&gt);
    let sigma = xor_blocks(&ciphertext.v, &h2_value);

    // Recover M = W XOR H4(sigma)
    let h4_value = hash::h4(&sigma);
    let message = xor_blocks(&ciphertext.w, &h4_value);

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

    // Helper function to create a Block from a byte literal
    fn block_from_bytes(bytes: &[u8; BLOCK_SIZE]) -> Block {
        Block::new(*bytes)
    }

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
        let message_block = block_from_bytes(message);
        let ciphertext = encrypt::<_, MinPk>(&mut rng, master_public, &message_block, (None, identity))
            .expect("Encryption should succeed");

        // Decrypt
        let decrypted =
            decrypt::<MinPk>(private_key, &ciphertext).expect("Decryption should succeed");

        assert_eq!(message.as_ref(), decrypted.as_ref());
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
        let message_block = block_from_bytes(message);
        let ciphertext =
            encrypt::<_, MinSig>(&mut rng, master_public, &message_block, (None, identity))
                .expect("Encryption should succeed");

        // Decrypt
        let decrypted =
            decrypt::<MinSig>(private_key, &ciphertext).expect("Decryption should succeed");

        assert_eq!(message.as_ref(), decrypted.as_ref());
    }

    #[test]
    fn test_message_size_enforcement() {
        // This test verifies that Block enforces 32-byte size at the type level
        // Since encrypt now takes Block, we can't pass wrong-sized data
        let message_33 = vec![0u8; 33];
        let message_32 = [0u8; 32];
        
        // We can create a Block from a 32-byte array
        let _block = block_from_bytes(&message_32);
        
        // But we can't create a Block from a 33-byte vec at compile time
        // The type system enforces this
        assert_eq!(message_33.len(), 33);
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
        let message_block = block_from_bytes(message);
        let ciphertext =
            encrypt::<_, MinPk>(&mut rng, master_public1, &message_block, (None, identity))
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
        let message_block = block_from_bytes(message);
        let ciphertext = encrypt::<_, MinPk>(&mut rng, master_public, &message_block, (None, identity))
            .expect("Encryption should succeed");

        // Tamper with ciphertext by creating a modified w
        let mut w_bytes = [0u8; BLOCK_SIZE];
        w_bytes.copy_from_slice(ciphertext.w.as_ref());
        w_bytes[0] ^= 0xFF;
        let tampered_ciphertext = Ciphertext {
            u: ciphertext.u,
            v: ciphertext.v,
            w: Block::new(w_bytes),
        };

        // Try to decrypt
        let result = decrypt::<MinPk>(private_key, &tampered_ciphertext);
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

        let message_block = block_from_bytes(&message);
        let ciphertext =
            encrypt::<_, MinPk>(&mut rng, master_public, &message_block, (None, identity))
                .expect("Encryption should succeed");

        let decrypted =
            decrypt::<MinPk>(private_key, &ciphertext).expect("Decryption should succeed");

        assert_eq!(message.as_ref(), decrypted.as_ref());
    }

    #[test]
    fn test_max_size_message() {
        let mut rng = thread_rng();

        let (master_secret, master_public) = keypair::<_, MinPk>(&mut rng);
        let identity = b"maxsize@example.com";
        let message = [0xAB; 32]; // Maximum allowed size

        let id_point = hash_message::<MinPk>(MinPk::MESSAGE, identity);
        let mut private_key = id_point;
        private_key.mul(&master_secret);

        let message_block = block_from_bytes(&message);
        let ciphertext =
            encrypt::<_, MinPk>(&mut rng, master_public, &message_block, (None, identity))
                .expect("Encryption should succeed");

        let decrypted =
            decrypt::<MinPk>(private_key, &ciphertext).expect("Decryption should succeed");

        assert_eq!(message.as_ref(), decrypted.as_ref());
    }

    #[test]
    fn test_cca_security_modified_u() {
        let mut rng = thread_rng();

        let (master_secret, master_public) = keypair::<_, MinPk>(&mut rng);
        let identity = b"cca@example.com";
        let message = b"CCA security test message 32 byt"; // 32 bytes

        // Generate private key
        let id_point = hash_message::<MinPk>(MinPk::MESSAGE, identity);
        let mut private_key = id_point;
        private_key.mul(&master_secret);

        // Encrypt
        let message_block = block_from_bytes(message);
        let mut ciphertext =
            encrypt::<_, MinPk>(&mut rng, master_public, &message_block, (None, identity))
                .expect("Encryption should succeed");

        // Modify U component (this should make decryption fail due to FO transform)
        let mut modified_u = ciphertext.u;
        modified_u.mul(&Scalar::from_ikm(&[1u8; 64]));
        ciphertext.u = modified_u;

        // Try to decrypt - should fail
        let result = decrypt::<MinPk>(private_key, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_cca_security_modified_v() {
        let mut rng = thread_rng();

        let (master_secret, master_public) = keypair::<_, MinPk>(&mut rng);
        let identity = b"cca2@example.com";
        let message = b"Another CCA test message 32bytes"; // 32 bytes

        // Generate private key
        let id_point = hash_message::<MinPk>(MinPk::MESSAGE, identity);
        let mut private_key = id_point;
        private_key.mul(&master_secret);

        // Encrypt
        let message_block = block_from_bytes(message);
        let ciphertext = encrypt::<_, MinPk>(&mut rng, master_public, &message_block, (None, identity))
            .expect("Encryption should succeed");

        // Modify V component (encrypted sigma)
        let mut v_bytes = [0u8; BLOCK_SIZE];
        v_bytes.copy_from_slice(ciphertext.v.as_ref());
        v_bytes[0] ^= 0x01;
        let tampered_ciphertext = Ciphertext {
            u: ciphertext.u,
            v: Block::new(v_bytes),
            w: ciphertext.w,
        };

        // Try to decrypt - should fail due to verification
        let result = decrypt::<MinPk>(private_key, &tampered_ciphertext);
        assert!(result.is_err());
    }
}
