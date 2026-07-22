//! Bridges the crate's public RNG API (rand_core 0.10) into the rand_core 0.6
//! traits that arkworks 0.6 consumes.

use rand_core::{CryptoRng, Rng};

/// Adapter exposing a modern [`Rng`] as an arkworks-compatible RNG.
pub(crate) struct ArkRng<'a, R: ?Sized>(pub(crate) &'a mut R);

impl<R: Rng + ?Sized> ark_std::rand::RngCore for ArkRng<'_, R> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), ark_std::rand::Error> {
        self.0.fill_bytes(dest);
        Ok(())
    }
}

impl<R: CryptoRng + ?Sized> ark_std::rand::CryptoRng for ArkRng<'_, R> {}
