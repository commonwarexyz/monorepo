//! Non-cryptographic backend for tests, simulators, and load generators.
//!
//! This backend implements the [`crate::payments::Backend`] API without proving
//! privacy statements. It is useful when an integrating chain wants to exercise
//! private-payment transaction flow without paying prover cost.

use crate::payments::{Backend, Commitment, Opening};
use rand_core::CryptoRngCore;

/// Non-cryptographic private-payments backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MockBackend;

/// Mock commitment `(value, blinding)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MockCommitment {
    value: u64,
    blind: u64,
}

impl MockCommitment {
    /// Construct a mock commitment.
    pub const fn new(value: u64, blind: u64) -> Self {
        Self { value, blind }
    }

    /// Committed value component.
    pub const fn value(&self) -> u64 {
        self.value
    }

    /// Mock blinding component.
    pub const fn blind(&self) -> u64 {
        self.blind
    }
}

impl core::ops::Add<&Self> for MockCommitment {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        Self {
            value: self.value.wrapping_add(rhs.value),
            blind: self.blind.wrapping_add(rhs.blind),
        }
    }
}

impl core::ops::Sub<&Self> for MockCommitment {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        Self {
            value: self.value.wrapping_sub(rhs.value),
            blind: self.blind.wrapping_sub(rhs.blind),
        }
    }
}

impl Commitment for MockCommitment {
    fn zero() -> Self {
        Self { value: 0, blind: 0 }
    }
}

/// Mock opening `(value, blinding)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MockOpening {
    value: u64,
    blind: u64,
}

impl MockOpening {
    /// Construct a mock opening.
    pub const fn new(value: u64, blind: u64) -> Self {
        Self { value, blind }
    }

    /// Opened value.
    pub const fn value(&self) -> u64 {
        self.value
    }

    /// Mock blinding component.
    pub const fn blind(&self) -> u64 {
        self.blind
    }
}

impl core::ops::Add<&Self> for MockOpening {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        Self {
            value: self.value.wrapping_add(rhs.value),
            blind: self.blind.wrapping_add(rhs.blind),
        }
    }
}

impl core::ops::Sub<&Self> for MockOpening {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        Self {
            value: self.value.wrapping_sub(rhs.value),
            blind: self.blind.wrapping_sub(rhs.blind),
        }
    }
}

impl Opening for MockOpening {
    fn zero() -> Self {
        Self { value: 0, blind: 0 }
    }

    fn value(&self) -> u64 {
        self.value
    }
}

/// Empty mock proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MockProof;

impl Backend for MockBackend {
    type Params = ();
    type Commitment = MockCommitment;
    type Opening = MockOpening;
    type FundProof = MockProof;
    type TransferProof = MockProof;
    type BurnProof = MockCommitment;
    type SetupInput = ();
    type SetupError = core::convert::Infallible;
    #[cfg(feature = "simulator")]
    type Trapdoor = ();

    fn setup(_input: &Self::SetupInput) -> Result<Self::Params, Self::SetupError> {
        Ok(())
    }

    fn commit_public(_params: &Self::Params, value: u64) -> (Self::Commitment, Self::Opening) {
        (MockCommitment::new(value, 0), MockOpening::new(value, 0))
    }

    fn fund(
        _params: &Self::Params,
        value: u64,
        _rng: &mut impl CryptoRngCore,
    ) -> (Self::Commitment, Self::Opening, Self::FundProof) {
        (
            MockCommitment::new(value, 0),
            MockOpening { value, blind: 0 },
            MockProof,
        )
    }

    fn transfer(
        _params: &Self::Params,
        _input_commitment: &Self::Commitment,
        _input_opening: &Self::Opening,
        amount: u64,
        rng: &mut impl CryptoRngCore,
    ) -> (Self::Commitment, Self::Opening, Self::TransferProof) {
        let blind = rng.next_u64();
        (
            MockCommitment::new(amount, blind),
            MockOpening {
                value: amount,
                blind,
            },
            MockProof,
        )
    }

    #[cfg(feature = "simulator")]
    fn simulated_transfer_proof(
        _params: &Self::Params,
        _trapdoor: &Self::Trapdoor,
        _input_commitment: &Self::Commitment,
        _amount_commitment: &Self::Commitment,
        _rng: &mut impl CryptoRngCore,
    ) -> Self::TransferProof {
        MockProof
    }

    fn burn(
        _params: &Self::Params,
        commitment: &Self::Commitment,
        opening: &Self::Opening,
        amount: u64,
        _rng: &mut impl CryptoRngCore,
    ) -> Self::BurnProof {
        assert!(amount <= opening.value());
        assert!(amount <= commitment.value());
        MockCommitment::new(amount, 0)
    }

    fn batch_verify(
        _params: &Self::Params,
        funds: &[(u64, Self::Commitment, Self::FundProof)],
        transfers: &[(Self::Commitment, Self::Commitment, Self::TransferProof)],
        burns: &[(Self::Commitment, u64, Self::BurnProof)],
        _rng: &mut impl CryptoRngCore,
    ) -> bool {
        funds
            .iter()
            .all(|(value, commitment, _)| *commitment == MockCommitment::new(*value, 0))
            && transfers
                .iter()
                .all(|(current, amount, _)| current.value >= amount.value)
            && burns.iter().all(|(current, value, proof)| {
                current.value >= *value && *proof == MockCommitment::new(*value, 0)
            })
    }
}

#[cfg(feature = "codec")]
mod codec {
    use super::{MockCommitment, MockOpening, MockProof};
    use bytes::{Buf, BufMut};
    use commonware_codec::{Error as CodecError, FixedSize, Read, ReadExt, Write};

    impl FixedSize for MockCommitment {
        const SIZE: usize = u64::SIZE + u64::SIZE;
    }

    impl Write for MockCommitment {
        fn write(&self, buf: &mut impl BufMut) {
            self.value().write(buf);
            self.blind().write(buf);
        }
    }

    impl Read for MockCommitment {
        type Cfg = ();

        fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
            Ok(Self::new(u64::read(buf)?, u64::read(buf)?))
        }
    }

    impl FixedSize for MockOpening {
        const SIZE: usize = u64::SIZE + u64::SIZE;
    }

    impl Write for MockOpening {
        fn write(&self, buf: &mut impl BufMut) {
            self.value().write(buf);
            self.blind().write(buf);
        }
    }

    impl Read for MockOpening {
        type Cfg = ();

        fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
            Ok(Self::new(u64::read(buf)?, u64::read(buf)?))
        }
    }

    impl FixedSize for MockProof {
        const SIZE: usize = 0;
    }

    impl Write for MockProof {
        fn write(&self, _buf: &mut impl BufMut) {}
    }

    impl Read for MockProof {
        type Cfg = ();

        fn read_cfg(_buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
            Ok(Self)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MockBackend, MockCommitment, MockProof};
    use crate::payments::Backend;

    struct Rng(u64);

    impl rand_core::RngCore for Rng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }

        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            self.0
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            rand_core::impls::fill_bytes_via_next(self, dest);
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl rand_core::CryptoRng for Rng {}

    #[test]
    fn transfer_pipeline_verifies() {
        MockBackend::setup(&()).expect("mock setup is infallible");
        let mut rng = Rng(1);

        let (fund_commitment, fund_opening, proof) = MockBackend::fund(&(), 10, &mut rng);
        assert!(MockBackend::batch_verify(
            &(),
            &[(10, fund_commitment, proof)],
            &[],
            &[],
            &mut rng
        ));

        let (amount_commitment, _, proof) =
            MockBackend::transfer(&(), &fund_commitment, &fund_opening, 4, &mut rng);
        assert!(MockBackend::batch_verify(
            &(),
            &[],
            &[(fund_commitment, amount_commitment, proof)],
            &[],
            &mut rng
        ));

        let proof = MockBackend::burn(&(), &fund_commitment, &fund_opening, 4, &mut rng);
        assert!(MockBackend::batch_verify(
            &(),
            &[],
            &[],
            &[(fund_commitment, 4, proof)],
            &mut rng
        ));
    }

    #[test]
    fn rejects_invalid_fund_commitment() {
        MockBackend::setup(&()).expect("mock setup is infallible");
        let mut rng = Rng(1);
        assert!(!MockBackend::batch_verify(
            &(),
            &[(10, MockCommitment::new(11, 0), MockProof)],
            &[],
            &[],
            &mut rng
        ));
    }
}
