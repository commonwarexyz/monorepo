//! Sealed parameter sets for the supported cryptographic fields.

use crate::{
    field::{Modulus, sealed},
    rns,
};

#[cfg_attr(not(target_arch = "x86_64"), path = "parameters/arm/bander_scalar.rs")]
#[cfg_attr(target_arch = "x86_64", path = "parameters/x86/bander_scalar.rs")]
mod bander_scalar;
#[cfg_attr(not(target_arch = "x86_64"), path = "parameters/arm/bls12381.rs")]
#[cfg_attr(target_arch = "x86_64", path = "parameters/x86/bls12381.rs")]
mod bls12381;
#[cfg_attr(not(target_arch = "x86_64"), path = "parameters/arm/bls_scalar.rs")]
#[cfg_attr(target_arch = "x86_64", path = "parameters/x86/bls_scalar.rs")]
mod bls_scalar;
#[cfg_attr(not(target_arch = "x86_64"), path = "parameters/arm/curve25519.rs")]
#[cfg_attr(target_arch = "x86_64", path = "parameters/x86/curve25519.rs")]
mod curve25519;

macro_rules! modulus {
    ($name:ident, $module:ident, $bytes:literal, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl sealed::Sealed for $name {}

        impl Modulus for $name {
            type Encoding = [u8; $bytes];
            const ZERO_ENCODING: Self::Encoding = [0; $bytes];
            const PARAMETERS: &'static rns::Parameters = &$module::PARAMETERS;
        }
    };
}

modulus!(
    Bls12381,
    bls12381,
    48,
    "The 381-bit coordinate field of BLS12-381."
);
modulus!(
    BlsScalar,
    bls_scalar,
    32,
    "The 255-bit BLS12-381 scalar field, also the Bandersnatch coordinate field."
);
modulus!(
    BanderScalar,
    bander_scalar,
    32,
    "The 253-bit prime subgroup order of Bandersnatch and Banderwagon."
);
modulus!(
    Curve25519,
    curve25519,
    32,
    "The Curve25519 coordinate field with modulus 2^255 - 19."
);
