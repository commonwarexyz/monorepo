use crate::Message;
use arbitrary::Unstructured;
use commonware_codec::ReadExt;
use commonware_cryptography::bls12381::primitives::{
    group::{
        Element, Scalar, Share, G1, G1_ELEMENT_BYTE_LENGTH, G2, G2_ELEMENT_BYTE_LENGTH,
        SCALAR_LENGTH,
    },
    poly::{compute_weights, Eval, Poly, Weight},
};
use std::collections::BTreeMap;

#[allow(unused)]
pub fn arbitrary_g1(u: &mut Unstructured) -> Result<G1, arbitrary::Error> {
    let bytes: [u8; G1_ELEMENT_BYTE_LENGTH] = u.arbitrary()?;
    match G1::read(&mut bytes.as_slice()) {
        Ok(point) => Ok(point),
        Err(_) => Ok(if u.arbitrary()? {
            G1::zero()
        } else {
            G1::one()
        }),
    }
}

#[allow(unused)]
pub fn arbitrary_g2(u: &mut Unstructured) -> Result<G2, arbitrary::Error> {
    let bytes: [u8; G2_ELEMENT_BYTE_LENGTH] = u.arbitrary()?;
    match G2::read(&mut bytes.as_slice()) {
        Ok(point) => Ok(point),
        Err(_) => Ok(if u.arbitrary()? {
            G2::zero()
        } else {
            G2::one()
        }),
    }
}

#[allow(unused)]
pub fn arbitrary_vec_g1(
    u: &mut Unstructured,
    min: usize,
    max: usize,
) -> Result<Vec<G1>, arbitrary::Error> {
    let len = u.int_in_range(min..=max)?;
    (0..len).map(|_| arbitrary_g1(u)).collect()
}

#[allow(unused)]
pub fn arbitrary_vec_g2(
    u: &mut Unstructured,
    min: usize,
    max: usize,
) -> Result<Vec<G2>, arbitrary::Error> {
    let len = u.int_in_range(min..=max)?;
    (0..len).map(|_| arbitrary_g2(u)).collect()
}

#[allow(unused)]
pub fn arbitrary_messages(
    u: &mut Unstructured,
    min: usize,
    max: usize,
) -> Result<Vec<Message>, arbitrary::Error> {
    (0..u.int_in_range(min..=max)?)
        .map(|_| {
            Ok((
                arbitrary_optional_bytes(u, 50)?,
                arbitrary_bytes(u, 0, 100)?,
            ))
        })
        .collect()
}

#[allow(unused)]
pub fn arbitrary_optional_bytes(
    u: &mut Unstructured,
    max: usize,
) -> Result<Option<Vec<u8>>, arbitrary::Error> {
    if u.arbitrary()? {
        Ok(Some(arbitrary_bytes(u, 0, max)?))
    } else {
        Ok(None)
    }
}

#[allow(unused)]
pub fn arbitrary_bytes(
    u: &mut Unstructured,
    min: usize,
    max: usize,
) -> Result<Vec<u8>, arbitrary::Error> {
    let len = u.int_in_range(min..=max)?;
    u.bytes(len).map(|b| b.to_vec())
}

#[allow(unused)]
pub fn arbitrary_scalar(u: &mut Unstructured) -> Result<Scalar, arbitrary::Error> {
    let bytes: [u8; SCALAR_LENGTH] = u.arbitrary()?;
    match Scalar::read(&mut bytes.as_slice()) {
        Ok(s) => Ok(s),
        Err(_) => Ok(Scalar::from_index(u.int_in_range(0..=u32::MAX)?)),
    }
}

#[allow(unused)]
pub fn arbitrary_share(u: &mut Unstructured) -> Result<Share, arbitrary::Error> {
    Ok(Share {
        index: u.int_in_range(1..=100)?,
        private: arbitrary_scalar(u)?,
    })
}

#[allow(unused)]
pub fn arbitrary_poly_scalar(u: &mut Unstructured) -> Result<Poly<Scalar>, arbitrary::Error> {
    let degree = u.int_in_range(0..=10)?;
    let coeffs = arbitrary_vec_scalar(u, degree as usize + 1, degree as usize + 1)?;
    Ok(Poly::from(coeffs))
}

#[allow(unused)]
pub fn arbitrary_poly_g1(u: &mut Unstructured) -> Result<Poly<G1>, arbitrary::Error> {
    let scalar_poly = arbitrary_poly_scalar(u)?;
    Ok(Poly::<G1>::commit(scalar_poly))
}

#[allow(unused)]
pub fn arbitrary_poly_g2(u: &mut Unstructured) -> Result<Poly<G2>, arbitrary::Error> {
    let scalar_poly = arbitrary_poly_scalar(u)?;
    Ok(Poly::<G2>::commit(scalar_poly))
}

#[allow(unused)]
pub fn arbitrary_eval_g1(u: &mut Unstructured) -> Result<Eval<G1>, arbitrary::Error> {
    Ok(Eval {
        index: u.int_in_range(1..=100)?,
        value: arbitrary_g1(u)?,
    })
}

#[allow(unused)]
pub fn arbitrary_eval_g2(u: &mut Unstructured) -> Result<Eval<G2>, arbitrary::Error> {
    Ok(Eval {
        index: u.int_in_range(1..=100)?,
        value: arbitrary_g2(u)?,
    })
}

#[allow(unused)]
pub fn arbitrary_vec_scalar(
    u: &mut Unstructured,
    min: usize,
    max: usize,
) -> Result<Vec<Scalar>, arbitrary::Error> {
    let len = u.int_in_range(min..=max)?;
    (0..len).map(|_| arbitrary_scalar(u)).collect()
}

#[allow(unused)]
pub fn arbitrary_vec_eval_g1(
    u: &mut Unstructured,
    min: usize,
    max: usize,
) -> Result<Vec<Eval<G1>>, arbitrary::Error> {
    let len = u.int_in_range(min..=max)?;
    (0..len).map(|_| arbitrary_eval_g1(u)).collect()
}

#[allow(unused)]
pub fn arbitrary_vec_eval_g2(
    u: &mut Unstructured,
    min: usize,
    max: usize,
) -> Result<Vec<Eval<G2>>, arbitrary::Error> {
    let len = u.int_in_range(min..=max)?;
    (0..len).map(|_| arbitrary_eval_g2(u)).collect()
}

#[allow(unused)]
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

#[allow(unused)]
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

#[allow(unused)]
pub fn arbitrary_vec_pending_minpk(
    u: &mut Unstructured,
    min: usize,
    max: usize,
) -> Result<Vec<(u32, G1, G2)>, arbitrary::Error> {
    let len = u.int_in_range(min..=max)?;
    (0..len)
        .map(|_| Ok((u.int_in_range(1..=100)?, arbitrary_g1(u)?, arbitrary_g2(u)?)))
        .collect()
}

#[allow(unused)]
pub fn arbitrary_vec_pending_minsig(
    u: &mut Unstructured,
    min: usize,
    max: usize,
) -> Result<Vec<(u32, G2, G1)>, arbitrary::Error> {
    let len = u.int_in_range(min..=max)?;
    (0..len)
        .map(|_| Ok((u.int_in_range(1..=100)?, arbitrary_g2(u)?, arbitrary_g1(u)?)))
        .collect()
}

#[allow(unused)]
pub fn arbitrary_weights(
    u: &mut Unstructured,
    min: usize,
    max: usize,
) -> Result<BTreeMap<u32, Weight>, arbitrary::Error> {
    let len = u.int_in_range(min..=max)?;
    if len == 0 {
        return Ok(BTreeMap::new());
    }

    let mut indices = Vec::new();
    for _ in 0..len {
        let index = u.int_in_range(1..=100)?;
        if !indices.contains(&index) {
            indices.push(index);
        }
    }

    if indices.is_empty() {
        return Ok(BTreeMap::new());
    }

    indices.sort();
    compute_weights(indices).or_else(|_| Ok(BTreeMap::new()))
}

#[allow(unused)]
pub fn arbitrary_vec_of_vec_eval_g1(
    u: &mut Unstructured,
    outer_min: usize,
    outer_max: usize,
    inner_min: usize,
    inner_max: usize,
) -> Result<Vec<Vec<Eval<G1>>>, arbitrary::Error> {
    let outer_len = u.int_in_range(outer_min..=outer_max)?;
    (0..outer_len)
        .map(|_| arbitrary_vec_eval_g1(u, inner_min, inner_max))
        .collect()
}

#[allow(unused)]
pub fn arbitrary_vec_of_vec_eval_g2(
    u: &mut Unstructured,
    outer_min: usize,
    outer_max: usize,
    inner_min: usize,
    inner_max: usize,
) -> Result<Vec<Vec<Eval<G2>>>, arbitrary::Error> {
    let outer_len = u.int_in_range(outer_min..=outer_max)?;
    (0..outer_len)
        .map(|_| arbitrary_vec_eval_g2(u, inner_min, inner_max))
        .collect()
}
