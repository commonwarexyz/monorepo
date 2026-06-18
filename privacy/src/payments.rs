//! Traits that a backend proof system for private payments must implement.
//! Must also define a (compatible) commitment scheme for balances and three types of transactions:
//! - fund: move funds from a public account into a private account
//! - transfer: move funds between private accounts
//! - burn: reveal the balance of a private account
//!
//! The commitment scheme is assumed to be homomorphic, supporting addition and subtraction of commitments thereby, allowing in-place updates of the balance.

use core::ops::{Add, Sub};

use rand_core::CryptoRngCore;

/// A homomorphic commitment to a balance value.
pub trait Commitment:
    Clone + Eq + for<'a> Add<&'a Self, Output = Self> + for<'a> Sub<&'a Self, Output = Self>
{
    fn zero() -> Self;

    // deterministically commit to a public value
    fn commit_public(value: u64) -> Self;
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

    /// verified using amount and amount_commitment
    type FundProof;

    /// verified using sender_commitment, amount_commitment
    type TransferProof;

    /// verified using sender_commitment, amount
    type BurnProof;

    /// Deterministic source material for [`Self::setup`]: for example a seed for a
    /// transparent (hash-derived) setup, or the location on disk of the CRS bytes for a
    /// trusted setup.
    type SetupInput;

    type SetupError;

    /// Deterministically derive the public parameters from `input`.
    fn setup(input: &Self::SetupInput) -> Result<Self::Params, Self::SetupError>;

    /// mechanism to movefunds from a public account into a private account.
    /// returns (amount_commitment, amount_opening, fund_proof)
    /// to apply:
    /// 1. verify(amount, amount_commitment, fund_proof) == 1
    /// 2. sender_public_balance <- sender_public_balance - amount
    /// 2. sender_commitment <- sender_commitment + amount_commitment
    fn fund(
        params: &Self::Params,
        value: u64,
        rng: &mut impl CryptoRngCore,
    ) -> (Self::Commitment, Self::Opening, Self::FundProof);

    /// mechanism to move funds between private accounts.
    /// takes as input the sender's commitment, it's opening and the amount to transfer
    /// returns (amount_commitment, amount_opening, transfer_proof)
    /// note: can be computed before the receipient is even known
    /// to apply: 
    /// 1. verify(sender_commitment, amount_commitment, transfer_proof) == 1
    /// 2. sender_commitment <- sender_commitment - amount_commitment
    /// 3. recipient_commitment <- recipient_commitment + amount_commitment
    fn transfer(
        params: &Self::Params,
        input_commitment: &Self::Commitment,
        input_opening: &Self::Opening,
        amount: u64,
        rng: &mut impl CryptoRngCore,
    ) -> (Self::Commitment, Self::Opening, Self::TransferProof);

    /// mechanism to move funds from a private account into a public account
    /// takes as input the sender's commitment, it's opening and the amount to burn
    /// returns burn_proof
    /// to apply:
    /// 1. verify(commitment, amount, burn_proof) == 1
    /// 2. sender_public_balance <- sender_public_balance + amount
    /// 3. sender_commitment <- sender_commitment - commit_public(amount)
    fn burn(
        params: &Self::Params,
        commitment: &Self::Commitment,
        opening: &Self::Opening,
        amount: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Self::BurnProof;

    /// batch verify a set of funds, transfers, and burns,
    /// return `true` iff all proofs are valid
    fn batch_verify(
        params: &Self::Params,
        funds: &[(u64, Self::Commitment, Self::FundProof)],
        transfers: &[(
            Self::Commitment,
            Self::Commitment,
            Self::TransferProof,
        )],
        burns: &[(Self::Commitment, u64, Self::BurnProof)],
        rng: &mut impl CryptoRngCore,
    ) -> bool;
}
