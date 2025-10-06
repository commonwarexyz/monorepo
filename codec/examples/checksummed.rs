//! Example demonstrating how to use Checksummed with cryptographic hash functions.

use commonware_codec::{
    checksummed::Hasher as CodecHasher, Checksummed, Codec, DecodeExt, Encode, FixedSize,
};
use commonware_cryptography::{Hasher as CryptoHasher, Sha256};

/// Adapter to use commonware_cryptography hashers with Checksummed.
///
/// This wraps a cryptographic hasher to implement the codec Hasher trait.
#[derive(Default, Clone)]
struct CryptoAdapter<H: CryptoHasher>(core::marker::PhantomData<H>);

impl<H: CryptoHasher> CodecHasher for CryptoAdapter<H>
where
    H::Digest: Codec<Cfg = ()> + FixedSize + PartialEq,
{
    type Digest = H::Digest;

    fn update(&mut self, _data: &[u8]) {
        // This adapter uses hash() directly, so update is not needed
    }

    fn finalize(self) -> Self::Digest {
        H::empty()
    }

    fn hash(data: &[u8]) -> Self::Digest {
        H::hash(data)
    }
}

fn main() {
    // Example 1: Using with u64
    println!("Example 1: Checksummed u64");
    let value = 12345u64;
    let checksummed = Checksummed::<_, CryptoAdapter<Sha256>>::from(value);

    let encoded = checksummed.encode();
    println!("  Original: {}", value);
    println!("  Encoded size: {} bytes", encoded.len());

    let decoded = Checksummed::<u64, CryptoAdapter<Sha256>>::decode(encoded.clone()).unwrap();
    let decoded_value = decoded.into_inner();
    println!("  Decoded: {}", decoded_value);
    assert_eq!(decoded_value, value);

    // Example 2: Detecting corruption
    println!("\nExample 2: Detecting data corruption");
    let mut corrupted = encoded.clone();
    corrupted[0] ^= 0xFF; // Corrupt first byte

    match Checksummed::<u64, CryptoAdapter<Sha256>>::decode(corrupted) {
        Ok(_) => println!("  ERROR: Corruption not detected!"),
        Err(e) => println!("  ✓ Corruption detected: {}", e),
    }

    // Example 3: Using with tuples
    println!("\nExample 3: Checksummed tuple");
    let tuple_data = (42u32, 100u64, 255u8);
    let checksummed = Checksummed::<_, CryptoAdapter<Sha256>>::from(tuple_data);

    let encoded = checksummed.encode();
    println!("  Original: {:?}", tuple_data);
    println!("  Encoded size: {} bytes", encoded.len());

    let decoded = Checksummed::<(u32, u64, u8), CryptoAdapter<Sha256>>::decode(encoded).unwrap();
    let decoded_value = decoded.into_inner();
    println!("  Decoded: {:?}", decoded_value);
    assert_eq!(decoded_value, tuple_data);

    // Example 4: Using with Option
    println!("\nExample 4: Checksummed Option");
    let option_data = Some(9999u32);
    let checksummed = Checksummed::<_, CryptoAdapter<Sha256>>::from(option_data);

    let encoded = checksummed.encode();
    println!("  Original: {:?}", option_data);
    println!("  Encoded size: {} bytes", encoded.len());

    let decoded = Checksummed::<Option<u32>, CryptoAdapter<Sha256>>::decode(encoded).unwrap();
    let decoded_value = decoded.into_inner();
    println!("  Decoded: {:?}", decoded_value);
    assert_eq!(decoded_value, option_data);

    println!("\n✓ All examples completed successfully!");
}
