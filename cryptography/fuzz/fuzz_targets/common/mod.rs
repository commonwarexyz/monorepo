#![allow(dead_code)]

use arbitrary::Unstructured;
use commonware_codec::{ReadExt, Write};
use commonware_cryptography::bls12381::{
    primitives::{
        group::{Share, G1, G1_ELEMENT_BYTE_LENGTH, G2, G2_ELEMENT_BYTE_LENGTH},
        variant::{MinPk, MinSig, PartialSignature, Variant},
    },
    tle::{Block, Ciphertext},
};
use commonware_math::algebra::{Additive, CryptoGroup};
use commonware_utils::Participant;

fn encoded_g1(point: G1) -> [u8; G1_ELEMENT_BYTE_LENGTH] {
    let mut bytes = Vec::with_capacity(G1_ELEMENT_BYTE_LENGTH);
    point.write(&mut bytes);
    bytes.try_into().expect("G1 encoding length must be fixed")
}

fn encoded_g2(point: G2) -> [u8; G2_ELEMENT_BYTE_LENGTH] {
    let mut bytes = Vec::with_capacity(G2_ELEMENT_BYTE_LENGTH);
    point.write(&mut bytes);
    bytes.try_into().expect("G2 encoding length must be fixed")
}

pub fn arbitrary_g1(u: &mut Unstructured) -> Result<G1, arbitrary::Error> {
    let bytes = if u.arbitrary()? {
        encoded_g1(G1::generator())
    } else {
        u.arbitrary()?
    };
    match G1::read(&mut bytes.as_slice()) {
        Ok(point) => Ok(point),
        Err(_) => Ok(if u.arbitrary()? {
            G1::zero()
        } else {
            G1::generator()
        }),
    }
}

pub fn arbitrary_g2(u: &mut Unstructured) -> Result<G2, arbitrary::Error> {
    let bytes = if u.arbitrary()? {
        encoded_g2(G2::generator())
    } else {
        u.arbitrary()?
    };
    match G2::read(&mut bytes.as_slice()) {
        Ok(point) => Ok(point),
        Err(_) => Ok(if u.arbitrary()? {
            G2::zero()
        } else {
            G2::generator()
        }),
    }
}

pub fn arbitrary_vec_g1(
    u: &mut Unstructured,
    min: usize,
    max: usize,
) -> Result<Vec<G1>, arbitrary::Error> {
    let len = u.int_in_range(min..=max)?;
    (0..len).map(|_| arbitrary_g1(u)).collect()
}

pub fn arbitrary_vec_g2(
    u: &mut Unstructured,
    min: usize,
    max: usize,
) -> Result<Vec<G2>, arbitrary::Error> {
    let len = u.int_in_range(min..=max)?;
    (0..len).map(|_| arbitrary_g2(u)).collect()
}

pub type Message = (Vec<u8>, Vec<u8>);

pub fn arbitrary_messages(
    u: &mut Unstructured,
    min: usize,
    max: usize,
) -> Result<Vec<Message>, arbitrary::Error> {
    (0..u.int_in_range(min..=max)?)
        .map(|_| Ok((arbitrary_bytes(u, 0, 50)?, arbitrary_bytes(u, 0, 100)?)))
        .collect()
}

pub fn arbitrary_bytes(
    u: &mut Unstructured,
    min: usize,
    max: usize,
) -> Result<Vec<u8>, arbitrary::Error> {
    let len = u.int_in_range(min..=max)?;
    u.bytes(len).map(|b| b.to_vec())
}

pub fn arbitrary_share(u: &mut Unstructured) -> Result<Share, arbitrary::Error> {
    Ok(Share::new(
        Participant::new(u.int_in_range(1..=100)?),
        u.arbitrary()?,
    ))
}

pub fn arbitrary_partial_sig_g1(
    u: &mut Unstructured,
) -> Result<PartialSignature<MinSig>, arbitrary::Error> {
    Ok(PartialSignature {
        index: u.arbitrary()?,
        value: arbitrary_g1(u)?,
    })
}

pub fn arbitrary_partial_sig_g2(
    u: &mut Unstructured,
) -> Result<PartialSignature<MinPk>, arbitrary::Error> {
    Ok(PartialSignature {
        index: u.arbitrary()?,
        value: arbitrary_g2(u)?,
    })
}

pub fn arbitrary_vec_partial_sig_g1(
    u: &mut Unstructured,
    min: usize,
    max: usize,
) -> Result<Vec<PartialSignature<MinSig>>, arbitrary::Error> {
    let len = u.int_in_range(min..=max)?;
    (0..len).map(|_| arbitrary_partial_sig_g1(u)).collect()
}

pub fn arbitrary_vec_partial_sig_g2(
    u: &mut Unstructured,
    min: usize,
    max: usize,
) -> Result<Vec<PartialSignature<MinPk>>, arbitrary::Error> {
    let len = u.int_in_range(min..=max)?;
    (0..len).map(|_| arbitrary_partial_sig_g2(u)).collect()
}

pub fn arbitrary_vec_indexed_g1(
    u: &mut Unstructured,
    min: usize,
    max: usize,
) -> Result<Vec<(u32, G1)>, arbitrary::Error> {
    let len = u.int_in_range(min..=max)?;
    (0..len)
        .map(|_| Ok((u.int_in_range(1..=100)?, arbitrary_g1(u)?)))
        .collect()
}

pub fn arbitrary_vec_indexed_g2(
    u: &mut Unstructured,
    min: usize,
    max: usize,
) -> Result<Vec<(u32, G2)>, arbitrary::Error> {
    let len = u.int_in_range(min..=max)?;
    (0..len)
        .map(|_| Ok((u.int_in_range(1..=100)?, arbitrary_g2(u)?)))
        .collect()
}

pub fn arbitrary_vec_of_vec_partial_sig_g1(
    u: &mut Unstructured,
    outer_min: usize,
    outer_max: usize,
    inner_min: usize,
    inner_max: usize,
) -> Result<Vec<Vec<PartialSignature<MinSig>>>, arbitrary::Error> {
    let outer_len = u.int_in_range(outer_min..=outer_max)?;
    (0..outer_len)
        .map(|_| arbitrary_vec_partial_sig_g1(u, inner_min, inner_max))
        .collect()
}

pub fn arbitrary_vec_of_vec_partial_sig_g2(
    u: &mut Unstructured,
    outer_min: usize,
    outer_max: usize,
    inner_min: usize,
    inner_max: usize,
) -> Result<Vec<Vec<PartialSignature<MinPk>>>, arbitrary::Error> {
    let outer_len = u.int_in_range(outer_min..=outer_max)?;
    (0..outer_len)
        .map(|_| arbitrary_vec_partial_sig_g2(u, inner_min, inner_max))
        .collect()
}

pub fn arbitrary_minpk_signature(
    u: &mut Unstructured,
) -> Result<<MinPk as Variant>::Signature, arbitrary::Error> {
    arbitrary_g2(u)
}

pub fn arbitrary_minsig_signature(
    u: &mut Unstructured,
) -> Result<<MinSig as Variant>::Signature, arbitrary::Error> {
    arbitrary_g1(u)
}

pub fn arbitrary_ciphertext_minpk(
    u: &mut Unstructured,
) -> Result<Ciphertext<MinPk>, arbitrary::Error> {
    Ok(Ciphertext {
        u: arbitrary_g1(u)?,
        v: Block::new(u.arbitrary()?),
        w: Block::new(u.arbitrary()?),
    })
}

pub fn arbitrary_ciphertext_minsig(
    u: &mut Unstructured,
) -> Result<Ciphertext<MinSig>, arbitrary::Error> {
    Ok(Ciphertext {
        u: arbitrary_g2(u)?,
        v: Block::new(u.arbitrary()?),
        w: Block::new(u.arbitrary()?),
    })
}
