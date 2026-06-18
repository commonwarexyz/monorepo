//! Traits that a backend proof system for private payments must implement.
//! Must also define a (compatible) commitment scheme for balances and three types of transactions:
//! - fund: move funds from a public account into a private account
//! - transfer: move funds between private accounts
//! - burn: reveal the balance of a private account
//! The commitment scheme is assumed to be homomorphic, supporting addition and subtraction of commitments thereby, allowing in-place updates of the balance.

use core::ops::{Add, Sub};

use rand_core::RngCore;

/// A homomorphic commitment to a balance value.
pub trait Commitment:
    Clone + Eq + for<'a> Add<&'a Self, Output = Self> + for<'a> Sub<&'a Self, Output = Self>
{
    fn zero() -> Self;
}

/// The opening of a commitment
/// 
/// Account balances and hence committed values are assumed to fit in u64
pub trait Opening:
    Clone + for<'a> Add<&'a Self, Output = Self> + for<'a> Sub<&'a Self, Output = Self>
{
    fn zero() -> Self;
    fn value(&self) -> u64;
}

/// A swappable proof backend for private payments.
pub trait Backend: Sized {
    /// Public parameters (e.g. proving/verifying keys).
    type Params;

    /// The homomorphic balance commitment.
    type Commitment: Commitment;

    /// The commitment opening held by the account owner
    type Opening: Opening;

    type FundProof;

    type TransferProof;

    type BurnProof;

    /// Deterministic source material for [`Self::setup`]: for example a seed for a
    /// transparent (hash-derived) setup, or the location on disk of the CRS bytes for a
    /// trusted setup.
    type SetupInput;

    type SetupError: core::fmt::Debug;

    /// Deterministically derive the public parameters from `input`.
    fn setup(input: &Self::SetupInput) -> Result<Self::Params, Self::SetupError>;

    /// mechanism to movefunds from a public account into a private account.
    fn fund(
        params: &Self::Params,
        value: u64,
        rng: &mut impl RngCore,
    ) -> (Self::Commitment, Self::Opening, Self::FundProof);

    /// mechanism to move funds between private accounts.
    /// takes as input the sender's commitment, it's opening and the amount to transfer
    /// returns (amount_commitment, amount_opening, transfer_proof)
    /// note: can be computed before the receipient is even known
    fn transfer(
        params: &Self::Params,
        input_commitment: &Self::Commitment,
        input_opening: &Self::Opening,
        amount: u64,
        rng: &mut impl RngCore,
    ) -> (Self::Commitment, Self::Opening, Self::TransferProof);

    /// mechanism to reveal the balance of a private account
    fn burn(
        params: &Self::Params,
        commitment: &Self::Commitment,
        opening: &Self::Opening,
        rng: &mut impl RngCore,
    ) -> Self::BurnProof;
}
