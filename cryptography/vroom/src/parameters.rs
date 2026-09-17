//! Sealed parameter sets for the supported cryptographic fields.

use crate::{
    field::{Modulus, sealed},
    rns,
};

mod bander_scalar;
mod bls12381;
mod bls_scalar;
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
