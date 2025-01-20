#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::bls12381::primitives::{group, ops};
    use crate::bls12381::scheme::Bls12381;
    use crate::scheme::Scheme;

    // Test for invalid signature length
    #[test]
    fn test_invalid_signature_length() {
        let invalid_signatures = vec![
            vec![0u8; 95],  // 1 byte shorter
            vec![0u8; 97],  // 1 byte longer
            vec![0u8; 0],   // Empty signature
            vec![0u8; 48],  // Half the correct length
        ];

        let msg = b"test message";
        let (_, public_key) = ops::keypair(&mut rand::thread_rng());

        for sig in invalid_signatures {
            assert!(Bls12381::verify(None, msg, &public_key, &sig).is_err());
        }
    }

    // Test for invalid curve points
    #[test]
    fn test_invalid_curve_points() {
        let msg = b"test message";
        let (private_key, _) = ops::keypair(&mut rand::thread_rng());

        // Point at infinity
        let mut infinity_point = group::G1::zero();
        let invalid_sig = infinity_point.serialize();
        assert!(Bls12381::verify(None, msg, &private_key, &invalid_sig).is_err());

        // Point not on the curve (modifying coordinates)
        let mut sig = ops::sign_message(&private_key, None, msg);
        sig[0] ^= 0xFF; // Corrupt the first byte
        assert!(Bls12381::verify(None, msg, &private_key, &sig).is_err());
    }

    // Test for message substitution attack
    #[test]
    fn test_message_substitution_attack() {
        let (private_key, public_key) = ops::keypair(&mut rand::thread_rng());
        
        let msg1 = b"original message";
        let msg2 = b"substituted message";
        
        let sig = ops::sign_message(&private_key, None, msg1);
        
        // Signature should be valid for the original message
        assert!(Bls12381::verify(None, msg1, &public_key, &sig).is_ok());
        
        // But invalid for the substituted message
        assert!(Bls12381::verify(None, msg2, &public_key, &sig).is_err());
    }

    // Test for signature reuse attack
    #[test]
    fn test_signature_reuse_attack() {
        let (private_key, public_key) = ops::keypair(&mut rand::thread_rng());
        let msg = b"test message";
        
        // Create a signature with one namespace
        let namespace1 = Some(b"namespace1");
        let sig = ops::sign_message(&private_key, namespace1, msg);
        
        // Verify the signature is valid in the original namespace
        assert!(Bls12381::verify(namespace1, msg, &public_key, &sig).is_ok());
        
        // Try reusing the same signature in a different namespace
        let namespace2 = Some(b"namespace2");
        assert!(Bls12381::verify(namespace2, msg, &public_key, &sig).is_err());
    }

    // Test for small subgroup attacks
    #[test]
    fn test_small_subgroup_attack() {
        let msg = b"test message";
        let (private_key, public_key) = ops::keypair(&mut rand::thread_rng());
        
        // Create a valid signature
        let valid_sig = ops::sign_message(&private_key, None, msg);
        
        // Modify the signature to attempt creating a small-order point
        let mut invalid_sig = valid_sig.clone();
        invalid_sig[0] = 0x00;
        invalid_sig[1] = 0x00;
        
        assert!(Bls12381::verify(None, msg, &public_key, &invalid_sig).is_err());
    }
}
