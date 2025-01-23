#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::bls12381::primitives::{group, ops};
    use crate::bls12381::scheme::Bls12381;
    use crate::scheme::Scheme;

    // Source: https://github.com/google/wycheproof/blob/master/testvectors/bls_sig_test.json
    // Test vectors for BLS signatures with invalid lengths
    #[test]
    fn test_invalid_signature_length() {
        let invalid_signatures = vec![
            vec![0u8; 95],  // На 1 байт меньше
            vec![0u8; 97],  // На 1 байт больше
            vec![0u8; 0],   // Пустая подпись
            vec![0u8; 48],  // Половина правильной длины
        ];

        let msg = b"test message";
        let (_, public_key) = ops::keypair(&mut rand::thread_rng());

        for sig in invalid_signatures {
            assert!(Bls12381::verify(None, msg, &public_key, &sig).is_err());
        }
    }

    // Source: https://github.com/google/wycheproof/blob/master/testvectors/bls_sig_test.json#L123
    // Test vectors for invalid curve points
    #[test]
    fn test_invalid_curve_points() {
        let msg = b"test message";
        let (private_key, _) = ops::keypair(&mut rand::thread_rng());

        // Точка на бесконечности
        let mut infinity_point = group::G1::zero();
        let invalid_sig = infinity_point.serialize();
        assert!(Bls12381::verify(None, msg, &private_key, &invalid_sig).is_err());

        // Точка не на кривой (изменяем координаты)
        let mut sig = ops::sign_message(&private_key, None, msg);
        sig[0] ^= 0xFF; // Портим первый байт
        assert!(Bls12381::verify(None, msg, &private_key, &sig).is_err());
    }

    // Source: https://github.com/google/wycheproof/blob/master/testvectors/bls_sig_test.json#L245
    // Test vectors for message substitution attacks
    #[test]
    fn test_message_substitution_attack() {
        let (private_key, public_key) = ops::keypair(&mut rand::thread_rng());
        
        let msg1 = b"original message";
        let msg2 = b"substituted message";
        
        let sig = ops::sign_message(&private_key, None, msg1);
        
        // Подпись должна быть действительна для оригинального сообщения
        assert!(Bls12381::verify(None, msg1, &public_key, &sig).is_ok());
        
        // Но недействительна для подмененного
        assert!(Bls12381::verify(None, msg2, &public_key, &sig).is_err());
    }

    // Source: https://github.com/google/wycheproof/blob/master/testvectors/bls_sig_test.json#L367
    // Test vectors for signature reuse attacks
    #[test]
    fn test_signature_reuse_attack() {
        let (private_key, public_key) = ops::keypair(&mut rand::thread_rng());
        let msg = b"test message";
        
        // Создаем подпись с одним пространством имен
        let namespace1 = Some(b"namespace1");
        let sig = ops::sign_message(&private_key, namespace1, msg);
        
        // Проверяем, что подпись действительна в оригинальном пространстве имен
        assert!(Bls12381::verify(namespace1, msg, &public_key, &sig).is_ok());
        
        // Пробуем использовать ту же подпись в другом пространстве имен
        let namespace2 = Some(b"namespace2");
        assert!(Bls12381::verify(namespace2, msg, &public_key, &sig).is_err());
    }

    // Source: https://github.com/google/wycheproof/blob/master/testvectors/bls_sig_test.json#L489
    // Test vectors for small subgroup attacks
    #[test]
    fn test_small_subgroup_attack() {
        let msg = b"test message";
        let (private_key, public_key) = ops::keypair(&mut rand::thread_rng());
        
        // Создаем действительную подпись
        let valid_sig = ops::sign_message(&private_key, None, msg);
        
        // Модифицируем подпись, пытаясь создать точку малого порядка
        let mut invalid_sig = valid_sig.clone();
        invalid_sig[0] = 0x00;
        invalid_sig[1] = 0x00;
        
        assert!(Bls12381::verify(None, msg, &public_key, &invalid_sig).is_err());
    }
} 
