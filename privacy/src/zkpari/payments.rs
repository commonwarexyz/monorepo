//! Implementation of the private payments backend API using ZK-Pari.
//!
//! This module supplies the concrete commitment and proof machinery for the
//! [`crate::payments::Backend`] trait.

#[cfg(feature = "simulator")]
use crate::zkpari::Trapdoor;
use crate::{
    payments::{Backend, Commitment as PaymentCommitmentTrait, Opening as PaymentOpeningTrait},
    zkpari::{
        data_structures::{CommittedInputOpening, Proof, ProvingKey, VerifyingKey},
        range::RangeProof,
        ZkPari,
    },
};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_std::rand::{rngs::StdRng, RngCore, SeedableRng};
use commonware_parallel::Strategy;
use core::{
    convert::Infallible,
    marker::PhantomData,
    ops::{Add, Neg, Sub},
};
use rand_core::CryptoRngCore;

/// Concrete private payments backend implemented by ZK-Pari.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ZkPariBackend<E: Pairing> {
    _p: PhantomData<E>,
}

/// Proving and verifying keys for the payments range relation.
///
/// Transfers use the standard single-value range relation twice: once for the
/// amount and once for the remaining sender balance.
pub struct PaymentsParams<E: Pairing> {
    pub range_pk: ProvingKey<E>,
    pub range_vk: VerifyingKey<E>,
}

/// A homomorphic balance commitment in the ZK-Pari payment basis.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentCommitment<E: Pairing>(pub E::G1);

impl<E: Pairing> Add<&Self> for PaymentCommitment<E> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl<E: Pairing> Sub<&Self> for PaymentCommitment<E> {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self {
        Self(self.0 - rhs.0)
    }
}

impl<E: Pairing> PaymentCommitmentTrait for PaymentCommitment<E> {
    fn zero() -> Self {
        Self(E::G1Affine::zero().into_group())
    }
}

/// The client-side opening of a payment commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentOpening<E: Pairing> {
    pub value: u64,
    pub opening: CommittedInputOpening<E::ScalarField>,
}

impl<E: Pairing> Add<&Self> for PaymentOpening<E> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self {
        Self {
            value: self
                .value
                .checked_add(rhs.value)
                .expect("payment balance must stay within u64"),
            opening: &self.opening + &rhs.opening,
        }
    }
}

impl<E: Pairing> Sub<&Self> for PaymentOpening<E> {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self {
        Self {
            value: self
                .value
                .checked_sub(rhs.value)
                .expect("payment debit must not underflow"),
            opening: &self.opening - &rhs.opening,
        }
    }
}

impl<E: Pairing> PaymentOpeningTrait for PaymentOpening<E> {
    fn zero() -> Self {
        Self {
            value: 0,
            opening: CommittedInputOpening::zero(),
        }
    }

    fn value(&self) -> u64 {
        self.value
    }
}

/// A transfer proof contains the two range proofs needed for conservation:
/// the transferred amount and the sender's remaining balance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferProof<E: Pairing> {
    pub amount: RangeProof<E>,
    pub remaining: RangeProof<E>,
}

/// A burn proof range-checks the remaining private balance after de-shielding.
pub type BurnProof<E> = RangeProof<E>;

type RangeClaim<E> = (Proof<E>, Vec<<E as Pairing>::ScalarField>);

fn commit_with<E: Pairing>(
    params: &PaymentsParams<E>,
    opening: &PaymentOpening<E>,
) -> PaymentCommitment<E> {
    PaymentCommitment(
        params
            .range_pk
            .pedersen_commit(0, &[E::ScalarField::from(opening.value)], &opening.opening)
            .into_group(),
    )
}

fn slim_proof<E: Pairing>(proof: Proof<E>) -> RangeProof<E> {
    RangeProof {
        t_g: proof.t_g,
        u_g: proof.u_g,
        v_a: proof.v_a,
    }
}

fn proof_with_commitment<E: Pairing>(
    proof: &RangeProof<E>,
    commitment: &PaymentCommitment<E>,
) -> Proof<E> {
    Proof {
        c_ci: vec![commitment.0.into_affine()],
        t_g: proof.t_g,
        u_g: proof.u_g,
        v_a: proof.v_a,
    }
}

fn prove_range<E: Pairing>(
    params: &PaymentsParams<E>,
    opening: &PaymentOpening<E>,
    commitment: &PaymentCommitment<E>,
    rng: &mut impl RngCore,
) -> RangeProof<E> {
    let proof = ZkPari::<E>::prove_with_openings(
        opening.value,
        &params.range_pk,
        core::slice::from_ref(&opening.opening),
        rng,
    );
    debug_assert_eq!(proof.c_ci[0], commitment.0.into_affine());
    slim_proof(proof)
}

impl<E> ZkPariBackend<E>
where
    E: Pairing,
    E::G1Affine: Neg<Output = E::G1Affine>,
{
    fn range_claims(
        params: &PaymentsParams<E>,
        funds: &[(u64, PaymentCommitment<E>, ())],
        transfers: &[(PaymentCommitment<E>, PaymentCommitment<E>, TransferProof<E>)],
        burns: &[(PaymentCommitment<E>, u64, BurnProof<E>)],
    ) -> Option<Vec<RangeClaim<E>>> {
        let mut range_claims = Vec::with_capacity(transfers.len() * 2 + burns.len());

        for (value, fund_commitment, _) in funds {
            if fund_commitment != &Self::commit_public(params, *value).0 {
                return None;
            }
        }

        for (current, amount_commitment, proof) in transfers {
            let remaining_commitment = current.clone() - amount_commitment;
            range_claims.push((
                proof_with_commitment(&proof.amount, amount_commitment),
                Vec::new(),
            ));
            range_claims.push((
                proof_with_commitment(&proof.remaining, &remaining_commitment),
                Vec::new(),
            ));
        }

        for (current, value, proof) in burns {
            let (public_commitment, _) = Self::commit_public(params, *value);
            let remaining_commitment = current.clone() - &public_commitment;
            range_claims.push((
                proof_with_commitment(proof, &remaining_commitment),
                Vec::new(),
            ));
        }

        Some(range_claims)
    }

    fn range_claims_with_strategy(
        strategy: &impl Strategy,
        params: &PaymentsParams<E>,
        funds: &[(u64, PaymentCommitment<E>, ())],
        transfers: &[(PaymentCommitment<E>, PaymentCommitment<E>, TransferProof<E>)],
        burns: &[(PaymentCommitment<E>, u64, BurnProof<E>)],
    ) -> Option<Vec<RangeClaim<E>>>
    where
        E::G1: Send + Sync,
        E::G1Affine: Send + Sync,
        E::ScalarField: Send + Sync,
    {
        if strategy.parallelism_hint() <= 1 || transfers.len() + burns.len() <= 1 {
            return Self::range_claims(params, funds, transfers, burns);
        }

        let funds_valid = strategy.fold(
            funds,
            || true,
            |valid, (value, fund_commitment, _)| {
                valid && fund_commitment == &Self::commit_public(params, *value).0
            },
            |left, right| left && right,
        );
        if !funds_valid {
            return None;
        }

        let transfer_claims = strategy.fold(
            transfers,
            Vec::new,
            |mut claims, (current, amount_commitment, proof)| {
                let remaining_commitment = current.clone() - amount_commitment;
                claims.push((
                    proof_with_commitment(&proof.amount, amount_commitment),
                    Vec::new(),
                ));
                claims.push((
                    proof_with_commitment(&proof.remaining, &remaining_commitment),
                    Vec::new(),
                ));
                claims
            },
            |mut left, right| {
                left.extend(right);
                left
            },
        );
        let burn_claims = strategy.fold(
            burns,
            Vec::new,
            |mut claims, (current, value, proof)| {
                let (public_commitment, _) = Self::commit_public(params, *value);
                let remaining_commitment = current.clone() - &public_commitment;
                claims.push((
                    proof_with_commitment(proof, &remaining_commitment),
                    Vec::new(),
                ));
                claims
            },
            |mut left, right| {
                left.extend(right);
                left
            },
        );

        let mut range_claims = Vec::with_capacity(transfer_claims.len() + burn_claims.len());
        range_claims.extend(transfer_claims);
        range_claims.extend(burn_claims);
        Some(range_claims)
    }

    /// Batch-verify payment proofs using a caller-provided parallel strategy.
    pub fn batch_verify_with_strategy(
        strategy: &impl Strategy,
        params: &PaymentsParams<E>,
        funds: &[(u64, PaymentCommitment<E>, ())],
        transfers: &[(PaymentCommitment<E>, PaymentCommitment<E>, TransferProof<E>)],
        burns: &[(PaymentCommitment<E>, u64, BurnProof<E>)],
        rng: &mut impl CryptoRngCore,
    ) -> bool
    where
        E::ScalarField: Send + Sync,
        E::G1: Send + Sync,
        E::G1Affine: Send + Sync,
        E::G2Affine: Send + Sync,
        E::G2Prepared: Send + Sync,
    {
        Self::batch_verify_with_strategy_impl(strategy, params, funds, transfers, burns, rng)
    }

    fn batch_verify_with_strategy_impl(
        strategy: &impl Strategy,
        params: &PaymentsParams<E>,
        funds: &[(u64, PaymentCommitment<E>, ())],
        transfers: &[(PaymentCommitment<E>, PaymentCommitment<E>, TransferProof<E>)],
        burns: &[(PaymentCommitment<E>, u64, BurnProof<E>)],
        rng: &mut impl CryptoRngCore,
    ) -> bool
    where
        E::ScalarField: Send + Sync,
        E::G1: Send + Sync,
        E::G1Affine: Send + Sync,
        E::G2Affine: Send + Sync,
        E::G2Prepared: Send + Sync,
    {
        let Some(range_claims) =
            Self::range_claims_with_strategy(strategy, params, funds, transfers, burns)
        else {
            return false;
        };
        range_claims.is_empty()
            || ZkPari::<E>::batch_verify_with_strategy(
                strategy,
                &range_claims,
                &params.range_vk,
                rng,
            )
    }
}

impl<E> Backend for ZkPariBackend<E>
where
    E: Pairing,
    E::G1Affine: Neg<Output = E::G1Affine>,
    E::ScalarField: Send + Sync,
    E::G1Affine: Send + Sync,
    E::G2Affine: Send + Sync,
    E::G2Prepared: Send + Sync,
{
    type Params = PaymentsParams<E>;
    type Commitment = PaymentCommitment<E>;
    type Opening = PaymentOpening<E>;
    type FundProof = ();
    type TransferProof = TransferProof<E>;
    type BurnProof = BurnProof<E>;
    type SetupInput = [u8; 32];
    type SetupError = Infallible;
    #[cfg(feature = "simulator")]
    type Trapdoor = Trapdoor<E>;

    fn setup(input: &Self::SetupInput) -> Result<Self::Params, Self::SetupError> {
        let mut rng = StdRng::from_seed(*input);
        let (range_pk, range_vk) = ZkPari::<E>::keygen(&mut rng);
        Ok(PaymentsParams { range_pk, range_vk })
    }

    fn fund(
        params: &Self::Params,
        value: u64,
        _rng: &mut impl CryptoRngCore,
    ) -> (Self::Commitment, Self::Opening, Self::FundProof) {
        let opening = PaymentOpening {
            value,
            opening: CommittedInputOpening::zero(),
        };
        (commit_with(params, &opening), opening, ())
    }

    fn commit_public(params: &Self::Params, value: u64) -> (Self::Commitment, Self::Opening) {
        let opening = PaymentOpening {
            value,
            opening: CommittedInputOpening::zero(),
        };
        (commit_with(params, &opening), opening)
    }

    fn transfer(
        params: &Self::Params,
        input_commitment: &Self::Commitment,
        input_opening: &Self::Opening,
        amount: u64,
        rng: &mut impl CryptoRngCore,
    ) -> (Self::Commitment, Self::Opening, Self::TransferProof) {
        let amount_opening = PaymentOpening {
            value: amount,
            opening: CommittedInputOpening::rand(rng),
        };
        let amount_commitment = commit_with(params, &amount_opening);

        let remaining_opening = input_opening.clone() - &amount_opening;
        let remaining_commitment = input_commitment.clone() - &amount_commitment;
        debug_assert_eq!(
            remaining_commitment,
            commit_with(params, &remaining_opening)
        );

        let proof = TransferProof {
            amount: prove_range(params, &amount_opening, &amount_commitment, rng),
            remaining: prove_range(params, &remaining_opening, &remaining_commitment, rng),
        };
        (amount_commitment, amount_opening, proof)
    }

    #[cfg(feature = "simulator")]
    fn simulated_transfer_proof(
        params: &Self::Params,
        trapdoor: &Self::Trapdoor,
        input_commitment: &Self::Commitment,
        amount_commitment: &Self::Commitment,
        rng: &mut impl CryptoRngCore,
    ) -> Self::TransferProof {
        let remaining_commitment = input_commitment.clone() - amount_commitment;
        TransferProof {
            amount: slim_proof(ZkPari::<E>::simulate(
                trapdoor,
                &params.range_vk,
                &[amount_commitment.0.into_affine()],
                &[],
                rng,
            )),
            remaining: slim_proof(ZkPari::<E>::simulate(
                trapdoor,
                &params.range_vk,
                &[remaining_commitment.0.into_affine()],
                &[],
                rng,
            )),
        }
    }

    fn burn(
        params: &Self::Params,
        commitment: &Self::Commitment,
        opening: &Self::Opening,
        amount: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Self::BurnProof {
        let public_opening = PaymentOpening {
            value: amount,
            opening: CommittedInputOpening::zero(),
        };
        let remaining_opening = opening.clone() - &public_opening;
        let remaining_commitment = commitment.clone() - &commit_with(params, &public_opening);
        debug_assert_eq!(
            remaining_commitment,
            commit_with(params, &remaining_opening)
        );
        prove_range(params, &remaining_opening, &remaining_commitment, rng)
    }

    fn batch_verify(
        params: &Self::Params,
        funds: &[(u64, Self::Commitment, Self::FundProof)],
        transfers: &[(Self::Commitment, Self::Commitment, Self::TransferProof)],
        burns: &[(Self::Commitment, u64, Self::BurnProof)],
        rng: &mut impl CryptoRngCore,
    ) -> bool {
        let Some(range_claims) = Self::range_claims(params, funds, transfers, burns) else {
            return false;
        };
        range_claims.is_empty() || ZkPari::<E>::batch_verify(&range_claims, &params.range_vk, rng)
    }

    fn batch_verify_with_strategy(
        strategy: &impl Strategy,
        params: &Self::Params,
        funds: &[(u64, Self::Commitment, Self::FundProof)],
        transfers: &[(Self::Commitment, Self::Commitment, Self::TransferProof)],
        burns: &[(Self::Commitment, u64, Self::BurnProof)],
        rng: &mut impl CryptoRngCore,
    ) -> bool {
        Self::batch_verify_with_strategy_impl(strategy, params, funds, transfers, burns, rng)
    }
}

#[cfg(feature = "codec")]
pub mod codec {
    use super::{PaymentCommitment, PaymentOpening, PaymentsParams, TransferProof, ZkPariBackend};
    use crate::{
        payments::{Backend, Commitment as PaymentCommitmentTrait},
        zkpari::{range::RangeProof, CommittedInputOpening, ZkPari},
    };
    #[cfg(feature = "simulator")]
    use crate::zkpari::Trapdoor;
    use ark_bn254::{Bn254, Fr};
    use ark_ec::pairing::Pairing;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
    use bytes::{Buf, BufMut};
    use commonware_codec::{Error as CodecError, FixedSize, Read, Write};
    use core::{
        hash::{Hash, Hasher},
        marker::PhantomData,
        ops::{Add, Sub},
    };
    use std::vec::Vec;

    const BN254_G1_COMPRESSED_SIZE: usize = 32;
    const BN254_G1_UNCOMPRESSED_SIZE: usize = 64;
    const BN254_FR_SIZE: usize = 32;
    const COMPRESSED_RANGE_PROOF_SIZE: usize = BN254_G1_COMPRESSED_SIZE * 2 + BN254_FR_SIZE;
    const UNCOMPRESSED_RANGE_PROOF_SIZE: usize = BN254_G1_UNCOMPRESSED_SIZE * 2 + BN254_FR_SIZE;

    /// Validation policy used when decoding ZK-Pari curve and field elements.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum Validation {
        /// Check that decoded values are valid.
        Checked,
        /// Skip validation. Use only for trusted bytes, such as internally written database state.
        Unchecked,
    }

    impl Validation {
        const fn into_ark(self) -> Validate {
            match self {
                Self::Checked => Validate::Yes,
                Self::Unchecked => Validate::No,
            }
        }
    }

    /// Encode values using Arkworks compressed canonical encoding.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Compressed<T>(pub T);

    impl<T> Compressed<T> {
        /// Return the wrapped value.
        pub fn into_inner(self) -> T {
            self.0
        }
    }

    /// Encode values using Arkworks uncompressed canonical encoding.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Uncompressed<T>(pub T);

    impl<T> Uncompressed<T> {
        /// Return the wrapped value.
        pub fn into_inner(self) -> T {
            self.0
        }
    }

    /// Encode values using compressed form and checked decoding.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct CompressedChecked<T>(pub T);

    impl<T> CompressedChecked<T> {
        /// Return the wrapped value.
        pub fn into_inner(self) -> T {
            self.0
        }
    }

    /// Encode values using compressed form and unchecked decoding.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct CompressedUnchecked<T>(pub T);

    impl<T> CompressedUnchecked<T> {
        /// Return the wrapped value.
        pub fn into_inner(self) -> T {
            self.0
        }
    }

    /// Encode values using uncompressed form and checked decoding.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct UncompressedChecked<T>(pub T);

    impl<T> UncompressedChecked<T> {
        /// Return the wrapped value.
        pub fn into_inner(self) -> T {
            self.0
        }
    }

    /// Encode values using uncompressed form and unchecked decoding.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct UncompressedUnchecked<T>(pub T);

    impl<T> UncompressedUnchecked<T> {
        /// Return the wrapped value.
        pub fn into_inner(self) -> T {
            self.0
        }
    }

    /// ZK-Pari BN254 backend with compressed chain-visible types and checked decoding.
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct CompressedCheckedBackend<E>(PhantomData<E>);

    /// ZK-Pari BN254 backend with compressed chain-visible types and unchecked decoding.
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct CompressedUncheckedBackend<E>(PhantomData<E>);

    /// ZK-Pari BN254 backend with uncompressed chain-visible types and checked decoding.
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct UncompressedCheckedBackend<E>(PhantomData<E>);

    /// ZK-Pari BN254 backend with uncompressed chain-visible types and unchecked decoding.
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct UncompressedUncheckedBackend<E>(PhantomData<E>);

    /// BN254 ZK-Pari backend with compressed chain-visible types and checked decoding.
    pub type CompressedCheckedBn254Backend = CompressedCheckedBackend<Bn254>;

    /// BN254 ZK-Pari backend with compressed chain-visible types and unchecked decoding.
    pub type CompressedUncheckedBn254Backend = CompressedUncheckedBackend<Bn254>;

    /// BN254 ZK-Pari backend with uncompressed chain-visible types and checked decoding.
    pub type UncompressedCheckedBn254Backend = UncompressedCheckedBackend<Bn254>;

    /// BN254 ZK-Pari backend with uncompressed chain-visible types and unchecked decoding.
    pub type UncompressedUncheckedBn254Backend = UncompressedUncheckedBackend<Bn254>;

    fn write_canonical<T>(value: &T, buf: &mut impl BufMut, compress: Compress, expected: usize)
    where
        T: CanonicalSerialize,
    {
        let mut bytes = Vec::with_capacity(expected);
        value
            .serialize_with_mode(&mut bytes, compress)
            .expect("canonical serialization to Vec should not fail");
        assert_eq!(
            bytes.len(),
            expected,
            "ZK-Pari canonical encoded size changed"
        );
        buf.put_slice(&bytes);
    }

    fn read_canonical<T>(
        buf: &mut impl Buf,
        compress: Compress,
        validation: Validation,
        expected: usize,
        context: &'static str,
    ) -> Result<T, CodecError>
    where
        T: CanonicalDeserialize,
    {
        if buf.remaining() < expected {
            return Err(CodecError::EndOfBuffer);
        }
        let mut bytes = vec![0; expected];
        buf.copy_to_slice(&mut bytes);
        T::deserialize_with_mode(&bytes[..], compress, validation.into_ark())
            .map_err(|_| CodecError::Invalid(context, "invalid canonical encoding"))
    }

    fn hash_canonical<T, H>(value: &T, state: &mut H, compress: Compress, expected: usize)
    where
        T: CanonicalSerialize,
        H: Hasher,
    {
        let mut bytes = Vec::with_capacity(expected);
        value
            .serialize_with_mode(&mut bytes, compress)
            .expect("canonical serialization to Vec should not fail");
        debug_assert_eq!(bytes.len(), expected);
        state.write(&bytes);
    }

    macro_rules! impl_commitment_wrapper {
        ($wrapper:ident) => {
            impl Add<&Self> for $wrapper<PaymentCommitment<Bn254>> {
                type Output = Self;

                fn add(self, rhs: &Self) -> Self {
                    Self(self.0 + &rhs.0)
                }
            }

            impl Sub<&Self> for $wrapper<PaymentCommitment<Bn254>> {
                type Output = Self;

                fn sub(self, rhs: &Self) -> Self {
                    Self(self.0 - &rhs.0)
                }
            }

            impl PaymentCommitmentTrait for $wrapper<PaymentCommitment<Bn254>> {
                fn zero() -> Self {
                    Self(PaymentCommitment::zero())
                }
            }
        };
    }

    impl_commitment_wrapper!(Compressed);
    impl_commitment_wrapper!(Uncompressed);
    impl_commitment_wrapper!(CompressedChecked);
    impl_commitment_wrapper!(CompressedUnchecked);
    impl_commitment_wrapper!(UncompressedChecked);
    impl_commitment_wrapper!(UncompressedUnchecked);

    macro_rules! impl_payment_commitment_codec {
        ($wrapper:ident, $size:expr, $compress:expr, $context:expr) => {
            impl FixedSize for $wrapper<PaymentCommitment<Bn254>> {
                const SIZE: usize = $size;
            }

            impl FixedSize for $wrapper<&PaymentCommitment<Bn254>> {
                const SIZE: usize = $size;
            }

            impl Write for $wrapper<PaymentCommitment<Bn254>> {
                fn write(&self, buf: &mut impl BufMut) {
                    write_canonical(&self.0 .0, buf, $compress, Self::SIZE);
                }
            }

            impl Write for $wrapper<&PaymentCommitment<Bn254>> {
                fn write(&self, buf: &mut impl BufMut) {
                    write_canonical(&self.0 .0, buf, $compress, Self::SIZE);
                }
            }

            impl Read for $wrapper<PaymentCommitment<Bn254>> {
                type Cfg = Validation;

                fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
                    Ok(Self(PaymentCommitment(read_canonical::<
                        <Bn254 as Pairing>::G1,
                    >(
                        buf,
                        $compress,
                        *cfg,
                        Self::SIZE,
                        $context,
                    )?)))
                }
            }

            impl Hash for $wrapper<PaymentCommitment<Bn254>> {
                fn hash<H: Hasher>(&self, state: &mut H) {
                    hash_canonical(&self.0 .0, state, $compress, Self::SIZE);
                }
            }
        };
    }

    impl_payment_commitment_codec!(
        Compressed,
        BN254_G1_COMPRESSED_SIZE,
        Compress::Yes,
        "zkpari_payment_commitment_compressed"
    );
    impl_payment_commitment_codec!(
        Uncompressed,
        BN254_G1_UNCOMPRESSED_SIZE,
        Compress::No,
        "zkpari_payment_commitment_uncompressed"
    );

    macro_rules! impl_range_proof_codec {
        ($wrapper:ident, $g1_size:expr, $proof_size:expr, $compress:expr, $context:expr) => {
            impl FixedSize for $wrapper<RangeProof<Bn254>> {
                const SIZE: usize = $proof_size;
            }

            impl FixedSize for $wrapper<&RangeProof<Bn254>> {
                const SIZE: usize = $proof_size;
            }

            impl Write for $wrapper<RangeProof<Bn254>> {
                fn write(&self, buf: &mut impl BufMut) {
                    write_canonical(&self.0.t_g, buf, $compress, $g1_size);
                    write_canonical(&self.0.u_g, buf, $compress, $g1_size);
                    write_canonical(&self.0.v_a, buf, $compress, BN254_FR_SIZE);
                }
            }

            impl Write for $wrapper<&RangeProof<Bn254>> {
                fn write(&self, buf: &mut impl BufMut) {
                    write_canonical(&self.0.t_g, buf, $compress, $g1_size);
                    write_canonical(&self.0.u_g, buf, $compress, $g1_size);
                    write_canonical(&self.0.v_a, buf, $compress, BN254_FR_SIZE);
                }
            }

            impl Read for $wrapper<RangeProof<Bn254>> {
                type Cfg = Validation;

                fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
                    Ok(Self(RangeProof {
                        t_g: read_canonical(
                            buf,
                            $compress,
                            *cfg,
                            $g1_size,
                            concat!($context, "_t_g"),
                        )?,
                        u_g: read_canonical(
                            buf,
                            $compress,
                            *cfg,
                            $g1_size,
                            concat!($context, "_u_g"),
                        )?,
                        v_a: read_canonical(
                            buf,
                            $compress,
                            *cfg,
                            BN254_FR_SIZE,
                            concat!($context, "_v_a"),
                        )?,
                    }))
                }
            }

            impl Hash for $wrapper<RangeProof<Bn254>> {
                fn hash<H: Hasher>(&self, state: &mut H) {
                    hash_canonical(&self.0.t_g, state, $compress, $g1_size);
                    hash_canonical(&self.0.u_g, state, $compress, $g1_size);
                    hash_canonical(&self.0.v_a, state, $compress, BN254_FR_SIZE);
                }
            }
        };
    }

    impl_range_proof_codec!(
        Compressed,
        BN254_G1_COMPRESSED_SIZE,
        COMPRESSED_RANGE_PROOF_SIZE,
        Compress::Yes,
        "zkpari_range_compressed"
    );
    impl_range_proof_codec!(
        Uncompressed,
        BN254_G1_UNCOMPRESSED_SIZE,
        UNCOMPRESSED_RANGE_PROOF_SIZE,
        Compress::No,
        "zkpari_range_uncompressed"
    );

    macro_rules! impl_transfer_proof_codec {
        ($wrapper:ident, $range_size:expr) => {
            impl FixedSize for $wrapper<TransferProof<Bn254>> {
                const SIZE: usize = $range_size * 2;
            }

            impl FixedSize for $wrapper<&TransferProof<Bn254>> {
                const SIZE: usize = $range_size * 2;
            }

            impl Write for $wrapper<TransferProof<Bn254>> {
                fn write(&self, buf: &mut impl BufMut) {
                    $wrapper(self.0.amount).write(buf);
                    $wrapper(self.0.remaining).write(buf);
                }
            }

            impl Write for $wrapper<&TransferProof<Bn254>> {
                fn write(&self, buf: &mut impl BufMut) {
                    $wrapper(&self.0.amount).write(buf);
                    $wrapper(&self.0.remaining).write(buf);
                }
            }

            impl Read for $wrapper<TransferProof<Bn254>> {
                type Cfg = Validation;

                fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
                    Ok(Self(TransferProof {
                        amount: <$wrapper<RangeProof<Bn254>> as Read>::read_cfg(buf, cfg)?.0,
                        remaining: <$wrapper<RangeProof<Bn254>> as Read>::read_cfg(buf, cfg)?.0,
                    }))
                }
            }

            impl Hash for $wrapper<TransferProof<Bn254>> {
                fn hash<H: Hasher>(&self, state: &mut H) {
                    $wrapper(self.0.amount).hash(state);
                    $wrapper(self.0.remaining).hash(state);
                }
            }
        };
    }

    impl_transfer_proof_codec!(Compressed, COMPRESSED_RANGE_PROOF_SIZE);
    impl_transfer_proof_codec!(Uncompressed, UNCOMPRESSED_RANGE_PROOF_SIZE);

    macro_rules! impl_opening_codec {
        ($wrapper:ident, $compress:expr, $context:expr) => {
            impl FixedSize for $wrapper<CommittedInputOpening<Fr>> {
                const SIZE: usize = BN254_FR_SIZE;
            }

            impl FixedSize for $wrapper<&CommittedInputOpening<Fr>> {
                const SIZE: usize = BN254_FR_SIZE;
            }

            impl Write for $wrapper<CommittedInputOpening<Fr>> {
                fn write(&self, buf: &mut impl BufMut) {
                    write_canonical(&self.0.rho, buf, $compress, Self::SIZE);
                }
            }

            impl Write for $wrapper<&CommittedInputOpening<Fr>> {
                fn write(&self, buf: &mut impl BufMut) {
                    write_canonical(&self.0.rho, buf, $compress, Self::SIZE);
                }
            }

            impl Read for $wrapper<CommittedInputOpening<Fr>> {
                type Cfg = Validation;

                fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
                    Ok(Self(CommittedInputOpening {
                        rho: read_canonical(buf, $compress, *cfg, Self::SIZE, $context)?,
                    }))
                }
            }

            impl Hash for $wrapper<CommittedInputOpening<Fr>> {
                fn hash<H: Hasher>(&self, state: &mut H) {
                    hash_canonical(&self.0.rho, state, $compress, Self::SIZE);
                }
            }
        };
    }

    impl_opening_codec!(Compressed, Compress::Yes, "zkpari_opening_compressed");
    impl_opening_codec!(Uncompressed, Compress::No, "zkpari_opening_uncompressed");

    macro_rules! impl_fixed_validation_codec {
        ($mode:ident, $form:ident, $validation:expr, $target:ty) => {
            impl FixedSize for $mode<$target> {
                const SIZE: usize = <$form<$target> as FixedSize>::SIZE;
            }

            impl FixedSize for $mode<&$target> {
                const SIZE: usize = <$form<$target> as FixedSize>::SIZE;
            }

            impl Write for $mode<$target> {
                fn write(&self, buf: &mut impl BufMut) {
                    $form(&self.0).write(buf);
                }
            }

            impl Write for $mode<&$target> {
                fn write(&self, buf: &mut impl BufMut) {
                    $form(self.0).write(buf);
                }
            }

            impl Read for $mode<$target> {
                type Cfg = ();

                fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
                    Ok(Self(
                        <$form<$target> as Read>::read_cfg(buf, &$validation)?.0,
                    ))
                }
            }

            impl Hash for $mode<$target> {
                fn hash<H: Hasher>(&self, state: &mut H) {
                    $form(self.0.clone()).hash(state);
                }
            }
        };
    }

    macro_rules! impl_fixed_validation_codecs {
        ($mode:ident, $form:ident, $validation:expr) => {
            impl_fixed_validation_codec!($mode, $form, $validation, PaymentCommitment<Bn254>);
            impl_fixed_validation_codec!($mode, $form, $validation, RangeProof<Bn254>);
            impl_fixed_validation_codec!($mode, $form, $validation, TransferProof<Bn254>);
            impl_fixed_validation_codec!($mode, $form, $validation, CommittedInputOpening<Fr>);
        };
    }

    impl_fixed_validation_codecs!(CompressedChecked, Compressed, Validation::Checked);
    impl_fixed_validation_codecs!(CompressedUnchecked, Compressed, Validation::Unchecked);
    impl_fixed_validation_codecs!(UncompressedChecked, Uncompressed, Validation::Checked);
    impl_fixed_validation_codecs!(UncompressedUnchecked, Uncompressed, Validation::Unchecked);

    macro_rules! impl_backend_wrapper {
        ($backend:ident, $wrapper:ident) => {
            impl Backend for $backend<Bn254> {
                type Params = PaymentsParams<Bn254>;
                type Commitment = $wrapper<PaymentCommitment<Bn254>>;
                type Opening = PaymentOpening<Bn254>;
                type FundProof = ();
                type TransferProof = $wrapper<TransferProof<Bn254>>;
                type BurnProof = $wrapper<RangeProof<Bn254>>;
                type SetupInput = [u8; 32];
                type SetupError = core::convert::Infallible;
                #[cfg(feature = "simulator")]
                type Trapdoor = Trapdoor<Bn254>;

                fn setup(input: &Self::SetupInput) -> Result<Self::Params, Self::SetupError> {
                    ZkPariBackend::<Bn254>::setup(input)
                }

                fn commit_public(
                    params: &Self::Params,
                    value: u64,
                ) -> (Self::Commitment, Self::Opening) {
                    let (commitment, opening) =
                        ZkPariBackend::<Bn254>::commit_public(params, value);
                    ($wrapper(commitment), opening)
                }

                fn fund(
                    params: &Self::Params,
                    value: u64,
                    rng: &mut impl rand_core::CryptoRngCore,
                ) -> (Self::Commitment, Self::Opening, Self::FundProof) {
                    let (commitment, opening, proof) =
                        ZkPariBackend::<Bn254>::fund(params, value, rng);
                    ($wrapper(commitment), opening, proof)
                }

                fn transfer(
                    params: &Self::Params,
                    input_commitment: &Self::Commitment,
                    input_opening: &Self::Opening,
                    amount: u64,
                    rng: &mut impl rand_core::CryptoRngCore,
                ) -> (Self::Commitment, Self::Opening, Self::TransferProof) {
                    let (commitment, opening, proof) = ZkPariBackend::<Bn254>::transfer(
                        params,
                        &input_commitment.0,
                        input_opening,
                        amount,
                        rng,
                    );
                    ($wrapper(commitment), opening, $wrapper(proof))
                }

                #[cfg(feature = "simulator")]
                fn simulated_transfer_proof(
                    params: &Self::Params,
                    trapdoor: &Self::Trapdoor,
                    input_commitment: &Self::Commitment,
                    amount_commitment: &Self::Commitment,
                    rng: &mut impl rand_core::CryptoRngCore,
                ) -> Self::TransferProof {
                    $wrapper(ZkPariBackend::<Bn254>::simulated_transfer_proof(
                        params,
                        trapdoor,
                        &input_commitment.0,
                        &amount_commitment.0,
                        rng,
                    ))
                }

                fn burn(
                    params: &Self::Params,
                    commitment: &Self::Commitment,
                    opening: &Self::Opening,
                    amount: u64,
                    rng: &mut impl rand_core::CryptoRngCore,
                ) -> Self::BurnProof {
                    $wrapper(ZkPariBackend::<Bn254>::burn(
                        params,
                        &commitment.0,
                        opening,
                        amount,
                        rng,
                    ))
                }

                fn batch_verify(
                    params: &Self::Params,
                    funds: &[(u64, Self::Commitment, Self::FundProof)],
                    transfers: &[(Self::Commitment, Self::Commitment, Self::TransferProof)],
                    burns: &[(Self::Commitment, u64, Self::BurnProof)],
                    rng: &mut impl rand_core::CryptoRngCore,
                ) -> bool {
                    let funds = funds
                        .iter()
                        .map(|(value, commitment, proof)| (*value, commitment.0.clone(), *proof))
                        .collect::<Vec<_>>();
                    let transfers = transfers
                        .iter()
                        .map(|(current, amount, proof)| {
                            (current.0.clone(), amount.0.clone(), proof.0)
                        })
                        .collect::<Vec<_>>();
                    let burns = burns
                        .iter()
                        .map(|(current, value, proof)| (current.0.clone(), *value, proof.0))
                        .collect::<Vec<_>>();
                    ZkPariBackend::<Bn254>::batch_verify(params, &funds, &transfers, &burns, rng)
                }

                fn batch_verify_with_strategy(
                    strategy: &impl commonware_parallel::Strategy,
                    params: &Self::Params,
                    funds: &[(u64, Self::Commitment, Self::FundProof)],
                    transfers: &[(Self::Commitment, Self::Commitment, Self::TransferProof)],
                    burns: &[(Self::Commitment, u64, Self::BurnProof)],
                    rng: &mut impl rand_core::CryptoRngCore,
                ) -> bool {
                    let funds_valid = strategy.fold(
                        funds,
                        || true,
                        |valid, (value, commitment, _)| {
                            valid
                                && commitment.0
                                    == ZkPariBackend::<Bn254>::commit_public(params, *value).0
                        },
                        |left, right| left && right,
                    );
                    if !funds_valid {
                        return false;
                    }

                    let transfer_claims = strategy.fold(
                        transfers,
                        Vec::new,
                        |mut claims, (current, amount, proof)| {
                            let remaining_commitment = current.0.clone() - &amount.0;
                            claims.push((
                                super::proof_with_commitment(&proof.0.amount, &amount.0),
                                Vec::new(),
                            ));
                            claims.push((
                                super::proof_with_commitment(
                                    &proof.0.remaining,
                                    &remaining_commitment,
                                ),
                                Vec::new(),
                            ));
                            claims
                        },
                        |mut left, right| {
                            left.extend(right);
                            left
                        },
                    );
                    let burn_claims = strategy.fold(
                        burns,
                        Vec::new,
                        |mut claims, (current, value, proof)| {
                            let (public_commitment, _) =
                                ZkPariBackend::<Bn254>::commit_public(params, *value);
                            let remaining_commitment = current.0.clone() - &public_commitment;
                            claims.push((
                                super::proof_with_commitment(&proof.0, &remaining_commitment),
                                Vec::new(),
                            ));
                            claims
                        },
                        |mut left, right| {
                            left.extend(right);
                            left
                        },
                    );

                    let mut range_claims =
                        Vec::with_capacity(transfer_claims.len() + burn_claims.len());
                    range_claims.extend(transfer_claims);
                    range_claims.extend(burn_claims);

                    range_claims.is_empty()
                        || ZkPari::<Bn254>::batch_verify_with_strategy(
                            strategy,
                            &range_claims,
                            &params.range_vk,
                            rng,
                        )
                }
            }
        };
    }

    impl_backend_wrapper!(CompressedCheckedBackend, CompressedChecked);
    impl_backend_wrapper!(CompressedUncheckedBackend, CompressedUnchecked);
    impl_backend_wrapper!(UncompressedCheckedBackend, UncompressedChecked);
    impl_backend_wrapper!(UncompressedUncheckedBackend, UncompressedUnchecked);

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{payments::Backend, zkpari::payments::ZkPariBackend};
        use ark_std::rand::SeedableRng;
        use commonware_codec::{Decode, Encode};
        use core::hash::Hash;

        fn assert_roundtrip<T>(value: T)
        where
            T: Clone + core::fmt::Debug + Eq,
            Compressed<T>: Decode<Cfg = Validation> + Encode,
            for<'a> Compressed<&'a T>: Encode,
            Uncompressed<T>: Decode<Cfg = Validation> + Encode,
            for<'a> Uncompressed<&'a T>: Encode,
        {
            let compressed = Compressed(&value).encode();
            let uncompressed = Uncompressed(&value).encode();
            assert!(compressed.len() <= uncompressed.len());

            for validation in [Validation::Checked, Validation::Unchecked] {
                assert_eq!(
                    Compressed::<T>::decode_cfg(compressed.clone(), &validation)
                        .expect("compressed decode")
                        .into_inner(),
                    value
                );
                assert_eq!(
                    Uncompressed::<T>::decode_cfg(uncompressed.clone(), &validation)
                        .expect("uncompressed decode")
                        .into_inner(),
                    value
                );
            }
        }

        #[test]
        fn bn254_payment_types_roundtrip_all_codec_modes() {
            let params = ZkPariBackend::<Bn254>::setup(&[7u8; 32]).expect("setup is infallible");
            let mut rng = ark_std::rand::rngs::StdRng::from_seed([3u8; 32]);
            let (commitment, opening, _fund_proof) =
                ZkPariBackend::<Bn254>::fund(&params, 10, &mut rng);
            let (amount, amount_opening, transfer_proof) =
                ZkPariBackend::<Bn254>::transfer(&params, &commitment, &opening, 4, &mut rng);
            let burn_proof =
                ZkPariBackend::<Bn254>::burn(&params, &commitment, &opening, 6, &mut rng);

            assert_roundtrip(commitment);
            assert_roundtrip(amount);
            assert_roundtrip(transfer_proof);
            assert_roundtrip(burn_proof);
            assert_roundtrip(opening.opening);
            assert_roundtrip(amount_opening.opening);
        }

        fn assert_wire_backend<B>()
        where
            B: Backend<
                Params = PaymentsParams<Bn254>,
                Opening = PaymentOpening<Bn254>,
                FundProof = (),
                SetupInput = [u8; 32],
                SetupError = core::convert::Infallible,
            >,
            B::Commitment: Clone + core::fmt::Debug + Eq + Hash + Decode<Cfg = ()> + Encode,
            B::TransferProof: Copy + core::fmt::Debug + Eq + Hash + Decode<Cfg = ()> + Encode,
            B::BurnProof: Copy + core::fmt::Debug + Eq + Hash + Decode<Cfg = ()> + Encode,
        {
            let params = B::setup(&[7u8; 32]).expect("setup is infallible");
            let mut rng = ark_std::rand::rngs::StdRng::from_seed([9u8; 32]);
            let (commitment, opening, proof) = B::fund(&params, 10, &mut rng);
            let decoded_commitment =
                B::Commitment::decode_cfg(commitment.encode(), &()).expect("commitment decode");
            assert_eq!(decoded_commitment, commitment);
            assert!(B::batch_verify(
                &params,
                &[(10, commitment.clone(), proof)],
                &[],
                &[],
                &mut rng
            ));

            let (amount, _amount_opening, proof) =
                B::transfer(&params, &commitment, &opening, 4, &mut rng);
            assert_eq!(
                B::TransferProof::decode_cfg(proof.encode(), &()).expect("transfer proof decode"),
                proof
            );
            assert!(B::batch_verify(
                &params,
                &[],
                &[(commitment.clone(), amount, proof)],
                &[],
                &mut rng
            ));

            let proof = B::burn(&params, &commitment, &opening, 6, &mut rng);
            assert_eq!(
                B::BurnProof::decode_cfg(proof.encode(), &()).expect("burn proof decode"),
                proof
            );
            assert!(B::batch_verify(
                &params,
                &[],
                &[],
                &[(commitment, 6, proof)],
                &mut rng
            ));
        }

        #[test]
        fn bn254_wire_backends_roundtrip_with_fixed_validation() {
            assert_wire_backend::<CompressedCheckedBn254Backend>();
            assert_wire_backend::<CompressedUncheckedBn254Backend>();
            assert_wire_backend::<UncompressedCheckedBn254Backend>();
            assert_wire_backend::<UncompressedUncheckedBn254Backend>();
        }
    }
}
