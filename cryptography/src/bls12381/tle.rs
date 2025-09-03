//! Timelock Encryption (TLE) over BLS12-381.
//!
//! This crate implements Timelock Encryption (TLE) over BLS12-381 using
//! Identity-Based Encryption (IBE) with the Boneh-Franklin scheme. TLE enables
//! encrypting messages that can only be decrypted when a valid signature over
//! a specific target (e.g., timestamp or round number) becomes available.
//!
//! # Security
//!
//! To achieve CCA-security (resistance against chosen-ciphertext attacks), this
//! implementation employs the Fujisaki-Okamoto transform, which converts the
//! underlying CPA-secure IBE scheme into a CCA-secure scheme through:
//!
//! * Deriving encryption randomness deterministically from the message and a
//!   random value (sigma)
//! * Including integrity checks to detect ciphertext tampering
//!
//! # Architecture
//!
//! The encryption process involves (for [crate::bls12381::primitives::variant::MinPk]):
//! 1. Generating a random sigma value
//! 2. Deriving encryption randomness r = H3(sigma || message)
//! 3. Computing the ciphertext components:
//!    - U = r * G (commitment in G1)
//!    - V = sigma ⊕ H2(e(r * P_pub, Q_id)) (masked random value)
//!    - W = M ⊕ H4(sigma) (masked message)
//!
//! Where Q_id = H1(target) maps the target to a point in G2.
//!
//! # Example
//!
//! _It is recommended to use a threshold signature scheme to generate decrypting
//! signatures in production (where no single party owns the private key)._
//!
//! ```rust
//! use commonware_cryptography::bls12381::{
//!     tle::{encrypt, decrypt, Block},
//!     primitives::{
//!         ops::{keypair, sign_message},
//!         variant::MinPk,
//!     },
//! };
//! use rand::rngs::OsRng;
//!
//! // Generate keypair
//! let (master_secret, master_public) = keypair::<_, MinPk>(&mut OsRng);
//!
//! // Define a target (e.g., a timestamp or round number)
//! let target = 12345u64.to_be_bytes();
//!
//! // Create a 32-byte message
//! let message_bytes = b"This is a secret message 32bytes";
//! let message = Block::new(*message_bytes);
//!
//! // Encrypt the message for the target
//! let ciphertext = encrypt::<_, MinPk>(
//!     &mut OsRng,
//!     master_public,
//!     (None, &target),
//!     &message,
//! );
//!
//! // Later, when someone has a signature over the target...
//! let signature = sign_message::<MinPk>(&master_secret, None, &target);
//!
//! // They can decrypt the message
//! let decrypted = decrypt::<MinPk>(&signature, &ciphertext)
//!     .expect("Decryption should succeed with valid signature");
//!
//! assert_eq!(message.as_ref(), decrypted.as_ref());
//! ```
//!
//! # Acknowledgements
//!
//! The following resources were used as references when implementing this crate:
//!
//! * <https://crypto.stanford.edu/~dabo/papers/bfibe.pdf>: Identity-Based Encryption from the Weil Pairing
//! * <https://eprint.iacr.org/2023/189>: tlock: Practical Timelock Encryption from Threshold BLS
//! * <https://github.com/thibmeu/tlock-rs>: tlock-rs: Practical Timelock Encryption/Decryption in Rust
//! * <https://github.com/drand/tlock> tlock: Timelock Encryption/Decryption Made Practical

use crate::{
    bls12381::primitives::{
        group::{Element, Scalar, DST, GT},
        ops::{hash_message, hash_message_namespace},
        variant::Variant,
    },
    sha256::Digest,
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, FixedSize, Read, ReadExt, Write};
use commonware_utils::sequence::FixedBytes;
use rand_core::CryptoRngCore;

/// Domain separation tag for hashing the `h3` message to a scalar.
const DST: DST = b"TLE_BLS12381_XMD:SHA-256_SSWU_RO_H3_";

/// Block size for encryption operations.
const BLOCK_SIZE: usize = Digest::SIZE;

/// Block type for IBE.
pub type Block = FixedBytes<BLOCK_SIZE>;

impl From<Digest> for Block {
    fn from(digest: Digest) -> Self {
        Block::new(digest.0)
    }
}

/// Encrypted message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext<V: Variant> {
    /// First group element U = r * Public::one().
    pub u: V::Public,
    /// Encrypted random value V = sigma XOR H2(e(r * P_pub, Q_id)).
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
    use crate::{Hasher, Sha256};

    /// H2: GT -> Block
    ///
    /// Used to mask the random sigma value.
    pub fn h2(gt: &GT) -> Block {
        let mut hasher = Sha256::new();
        hasher.update(b"h2");
        hasher.update(&gt.as_slice());
        hasher.finalize().into()
    }

    /// H3: (sigma, M) -> Scalar
    ///
    /// Used to derive the random scalar r using RFC9380 hash-to-field.
    pub fn h3(sigma: &Block, message: &[u8]) -> Scalar {
        // Combine sigma and message
        let mut combined = Vec::with_capacity(sigma.len() + message.len());
        combined.extend_from_slice(sigma.as_ref());
        combined.extend_from_slice(message);

        // Map the combined bytes to a scalar via RFC9380 hash-to-field
        Scalar::map(DST, &combined)
    }

    /// H4: sigma -> Block
    ///
    /// Used to mask the message.
    pub fn h4(sigma: &Block) -> Block {
        let mut hasher = Sha256::new();
        hasher.update(b"h4");
        hasher.update(sigma.as_ref());
        hasher.finalize().into()
    }
}

/// XOR two [Block]s together.
///
/// This function takes advantage of the fixed-size nature of blocks
/// to enable better compiler optimizations. Since we know blocks are
/// exactly 32 bytes, we can unroll the operation completely.
#[inline]
fn xor(a: &Block, b: &Block) -> Block {
    let a_bytes = a.as_ref();
    let b_bytes = b.as_ref();

    // Since Block is exactly 32 bytes, we can use array initialization
    // with const generics to let the compiler fully optimize this
    Block::new([
        a_bytes[0] ^ b_bytes[0],
        a_bytes[1] ^ b_bytes[1],
        a_bytes[2] ^ b_bytes[2],
        a_bytes[3] ^ b_bytes[3],
        a_bytes[4] ^ b_bytes[4],
        a_bytes[5] ^ b_bytes[5],
        a_bytes[6] ^ b_bytes[6],
        a_bytes[7] ^ b_bytes[7],
        a_bytes[8] ^ b_bytes[8],
        a_bytes[9] ^ b_bytes[9],
        a_bytes[10] ^ b_bytes[10],
        a_bytes[11] ^ b_bytes[11],
        a_bytes[12] ^ b_bytes[12],
        a_bytes[13] ^ b_bytes[13],
        a_bytes[14] ^ b_bytes[14],
        a_bytes[15] ^ b_bytes[15],
        a_bytes[16] ^ b_bytes[16],
        a_bytes[17] ^ b_bytes[17],
        a_bytes[18] ^ b_bytes[18],
        a_bytes[19] ^ b_bytes[19],
        a_bytes[20] ^ b_bytes[20],
        a_bytes[21] ^ b_bytes[21],
        a_bytes[22] ^ b_bytes[22],
        a_bytes[23] ^ b_bytes[23],
        a_bytes[24] ^ b_bytes[24],
        a_bytes[25] ^ b_bytes[25],
        a_bytes[26] ^ b_bytes[26],
        a_bytes[27] ^ b_bytes[27],
        a_bytes[28] ^ b_bytes[28],
        a_bytes[29] ^ b_bytes[29],
        a_bytes[30] ^ b_bytes[30],
        a_bytes[31] ^ b_bytes[31],
    ])
}

/// Encrypt a message for a given target.
///
/// # Steps
/// 1. Generate random sigma
/// 2. Derive encryption randomness r = H3(sigma || message)
/// 3. Create commitment U = r * G
/// 4. Mask sigma with the pairing result
/// 5. Mask the message with H4(sigma)
///
/// # Arguments
/// * `rng` - Random number generator
/// * `public` - Master public key
/// * `target` - Payload over which a signature will decrypt the message
/// * `message` - Message to encrypt
///
/// # Returns
/// * `Ciphertext<V>` - The encrypted ciphertext
pub fn encrypt<R: CryptoRngCore, V: Variant>(
    rng: &mut R,
    public: V::Public,
    target: (Option<&[u8]>, &[u8]),
    message: &Block,
) -> Ciphertext<V> {
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

    // Compute V = sigma XOR H2(e(r * P_pub, Q_id))
    let h2_value = hash::h2(&gt);
    let v = xor(&sigma, &h2_value);

    // Compute W = M XOR H4(sigma)
    let h4_value = hash::h4(&sigma);
    let w = xor(message, &h4_value);

    Ciphertext { u, v, w }
}

/// Decrypt a ciphertext with a signature over the target specified
/// during [encrypt].
///
/// # Steps
/// 1. Recover sigma from the pairing
/// 2. Recover the message
/// 3. Recompute r = H3(sigma || message)
/// 4. Verify that U = r * G matches the ciphertext
///
/// # Arguments
/// * `signature` - Signature over the target payload
/// * `ciphertext` - Ciphertext to decrypt
///
/// # Returns
/// * `Option<Block>` - The decrypted message
pub fn decrypt<V: Variant>(signature: &V::Signature, ciphertext: &Ciphertext<V>) -> Option<Block> {
    // Compute e(U, signature)
    let gt = V::pairing(&ciphertext.u, signature);

    // Recover sigma = V XOR H2(e(U, signature))
    let h2_value = hash::h2(&gt);
    let sigma = xor(&ciphertext.v, &h2_value);

    // Recover M = W XOR H4(sigma)
    let h4_value = hash::h4(&sigma);
    let message = xor(&ciphertext.w, &h4_value);

    // Recompute r and verify U = r * Public::one()
    let r = hash::h3(&sigma, &message);
    let mut expected_u = V::Public::one();
    expected_u.mul(&r);
    if ciphertext.u != expected_u {
        return None;
    }

    Some(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::primitives::{
        ops::{keypair, sign_message},
        variant::{MinPk, MinSig},
    };
    use rand::thread_rng;

    #[test]
    fn test_encrypt_decrypt_minpk() {
        let mut rng = thread_rng();

        // Generate master keypair
        let (master_secret, master_public) = keypair::<_, MinPk>(&mut rng);

        // Target and message
        let target = 10u64.to_be_bytes();
        let message = b"Hello, IBE! This is exactly 32b!"; // 32 bytes

        // Generate signature over the target
        let signature = sign_message::<MinPk>(&master_secret, None, &target);

        // Encrypt
        let ciphertext = encrypt::<_, MinPk>(
            &mut rng,
            master_public,
            (None, &target),
            &Block::new(*message),
        );

        // Decrypt
        let decrypted =
            decrypt::<MinPk>(&signature, &ciphertext).expect("Decryption should succeed");

        assert_eq!(message.as_ref(), decrypted.as_ref());
    }

    #[test]
    fn test_encrypt_decrypt_minsig() {
        let mut rng = thread_rng();

        // Generate master keypair
        let (master_secret, master_public) = keypair::<_, MinSig>(&mut rng);

        // Target and message
        let target = 20u64.to_be_bytes();
        let message = b"Testing MinSig variant - 32 byte";

        // Generate signature over the target
        let signature = sign_message::<MinSig>(&master_secret, None, &target);

        // Encrypt
        let ciphertext = encrypt::<_, MinSig>(
            &mut rng,
            master_public,
            (None, &target),
            &Block::new(*message),
        );

        // Decrypt
        let decrypted =
            decrypt::<MinSig>(&signature, &ciphertext).expect("Decryption should succeed");

        assert_eq!(message.as_ref(), decrypted.as_ref());
    }

    #[test]
    fn test_wrong_private_key() {
        let mut rng = thread_rng();

        // Generate two different master keypairs
        let (_, master_public1) = keypair::<_, MinPk>(&mut rng);
        let (master_secret2, _) = keypair::<_, MinPk>(&mut rng);

        let target = 30u64.to_be_bytes();
        let message = b"Secret message padded to 32bytes";

        // Encrypt with first master public key
        let ciphertext = encrypt::<_, MinPk>(
            &mut rng,
            master_public1,
            (None, &target),
            &Block::new(*message),
        );

        // Try to decrypt with signature from second master
        let wrong_signature = sign_message::<MinPk>(&master_secret2, None, &target);
        let result = decrypt::<MinPk>(&wrong_signature, &ciphertext);

        assert!(result.is_none());
    }

    #[test]
    fn test_tampered_ciphertext() {
        let mut rng = thread_rng();

        let (master_secret, master_public) = keypair::<_, MinPk>(&mut rng);
        let target = 40u64.to_be_bytes();
        let message = b"Tamper test padded to 32 bytes.."; // 32 bytes

        // Generate signature over the target
        let signature = sign_message::<MinPk>(&master_secret, None, &target);

        // Encrypt
        let ciphertext = encrypt::<_, MinPk>(
            &mut rng,
            master_public,
            (None, &target),
            &Block::new(*message),
        );

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
        let result = decrypt::<MinPk>(&signature, &tampered_ciphertext);
        assert!(result.is_none());
    }

    #[test]
    fn test_encrypt_decrypt_with_namespace() {
        let mut rng = thread_rng();

        // Generate master keypair
        let (master_secret, master_public) = keypair::<_, MinPk>(&mut rng);

        // Target and namespace
        let namespace = b"example.org";
        let target = 80u64.to_be_bytes();
        let message = b"Message with namespace - 32 byte"; // 32 bytes

        // Generate signature over the namespaced target
        let signature = sign_message::<MinPk>(&master_secret, Some(namespace), &target);

        // Encrypt with namespace
        let ciphertext = encrypt::<_, MinPk>(
            &mut rng,
            master_public,
            (Some(namespace), &target),
            &Block::new(*message),
        );

        // Decrypt
        let decrypted =
            decrypt::<MinPk>(&signature, &ciphertext).expect("Decryption should succeed");

        assert_eq!(message.as_ref(), decrypted.as_ref());
    }

    #[test]
    fn test_namespace_variance() {
        let mut rng = thread_rng();

        // Generate master keypair
        let (master_secret, master_public) = keypair::<_, MinPk>(&mut rng);

        let namespace = b"example.org";
        let target = 100u64.to_be_bytes();
        let message = b"Namespace vs no namespace - 32by"; // 32 bytes

        // Generate signature without namespace
        let signature_no_ns = sign_message::<MinPk>(&master_secret, None, &target);

        // Generate signature with namespace
        let signature_ns = sign_message::<MinPk>(&master_secret, Some(namespace), &target);

        // Encrypt with namespace
        let ciphertext_ns = encrypt::<_, MinPk>(
            &mut rng,
            master_public,
            (Some(namespace), &target),
            &Block::new(*message),
        );

        // Encrypt without namespace
        let ciphertext_no_ns = encrypt::<_, MinPk>(
            &mut rng,
            master_public,
            (None, &target),
            &Block::new(*message),
        );

        // Try to decrypt namespaced ciphertext with non-namespaced signature - should fail
        let result1 = decrypt::<MinPk>(&signature_no_ns, &ciphertext_ns);
        assert!(result1.is_none());

        // Try to decrypt non-namespaced ciphertext with namespaced signature - should fail
        let result2 = decrypt::<MinPk>(&signature_ns, &ciphertext_no_ns);
        assert!(result2.is_none());

        // Correct decryptions should succeed
        let decrypted_ns = decrypt::<MinPk>(&signature_ns, &ciphertext_ns)
            .expect("Decryption with matching namespace should succeed");
        let decrypted_no_ns = decrypt::<MinPk>(&signature_no_ns, &ciphertext_no_ns)
            .expect("Decryption without namespace should succeed");

        assert_eq!(message.as_ref(), decrypted_ns.as_ref());
        assert_eq!(message.as_ref(), decrypted_no_ns.as_ref());
    }

    #[test]
    fn test_cca_modified_v() {
        let mut rng = thread_rng();

        let (master_secret, master_public) = keypair::<_, MinPk>(&mut rng);
        let target = 110u64.to_be_bytes();
        let message = b"Another CCA test message 32bytes"; // 32 bytes

        // Generate signature over the target
        let signature = sign_message::<MinPk>(&master_secret, None, &target);

        // Encrypt
        let ciphertext = encrypt::<_, MinPk>(
            &mut rng,
            master_public,
            (None, &target),
            &Block::new(*message),
        );

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
        let result = decrypt::<MinPk>(&signature, &tampered_ciphertext);
        assert!(result.is_none());
    }

    #[test]
    fn test_cca_modified_u() {
        let mut rng = thread_rng();

        let (master_secret, master_public) = keypair::<_, MinPk>(&mut rng);
        let target = 70u64.to_be_bytes();
        let message = b"CCA security test message 32 byt"; // 32 bytes

        // Generate signature over the target
        let signature = sign_message::<MinPk>(&master_secret, None, &target);

        // Encrypt
        let mut ciphertext = encrypt::<_, MinPk>(
            &mut rng,
            master_public,
            (None, &target),
            &Block::new(*message),
        );

        // Modify U component (this should make decryption fail due to FO transform)
        let mut modified_u = ciphertext.u;
        modified_u.mul(&Scalar::from_rand(&mut rng));
        ciphertext.u = modified_u;

        // Try to decrypt - should fail
        let result = decrypt::<MinPk>(&signature, &ciphertext);
        assert!(result.is_none());
    }
}
