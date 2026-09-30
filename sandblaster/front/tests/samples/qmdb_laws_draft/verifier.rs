//! A stub verifier: the fixture checks the law rules, not the refinement.
use sandblaster::prelude::*;

pub type Digest = [u8; 32];

#[refines(crate::spec::proof::verify)]
pub fn verify(root: &[u8], key: &[u8], value: &[u8], proof: &[u8]) -> bool {
    root.len() == 32 && key.len() == 32 && value.len() == 32 && proof.len() > 1
}

#[refines(crate::spec::proof::verify)]
pub fn verify_fixed(root: &Digest, key: &Digest, value: &Digest, proof: &[u8]) -> bool {
    verify(root, key, value, proof)
}
