//! One canonical keyed dealing shared by every full validator.
//!
//! The only descriptor field sent is the claimed header. Validators derive the roots and
//! release amounts from the registered context, retained state, and terminal payer vectors.

use crate::bajillion::{
    commitment::MAX_VECTOR_LENGTH,
    payment::PaymentContext,
    state::AccountRow,
    transition::{CloseContext, CloseLimits, Header, OperatorAggregate, TransitionError},
    vector::{OutEntry, OutVector},
};
use alloc::vec::Vec;
use bytes::{Buf, Bytes, BytesMut};
use commonware_codec::{Error as CodecError, RangeCfg, Read, ReadExt, Write, varint::UInt};
use commonware_cryptography::{Digest, PublicKey};

#[derive(Clone, Debug)]
pub(crate) struct Row<P: PublicKey> {
    pub(crate) account: P,
    pub(crate) outgoing: Option<(u64, P::Signature)>,
    pub(crate) vector: OutVector<P>,
}

/// A structurally decoded full dealing. Signature and state validation is still required.
#[derive(Clone, Debug)]
pub struct Dealing<P: PublicKey, D: Digest> {
    pub(crate) header: Header<D>,
    pub(crate) rows: Vec<Row<P>>,
    pub(crate) aggregate: Option<OperatorAggregate>,
    pub(crate) encoded: Bytes,
}
impl<P: PublicKey, D: Digest> Dealing<P, D> {
    /// Returns the claimed proposal header.
    pub const fn header(&self) -> &Header<D> {
        &self.header
    }
    /// Returns the original canonical wire bytes.
    pub const fn encoded(&self) -> &Bytes {
        &self.encoded
    }
}

/// Decodes bounded keyed rows and close-local recipient indices without accessing the database.
pub fn decode<P: PublicKey, D: Digest>(
    encoded: Bytes,
    context: &CloseContext<P, D>,
) -> Result<Dealing<P, D>, CodecError> {
    decode_with(encoded, context.payment(), context.limits())
}
fn decode_with<P: PublicKey, D: Digest>(
    encoded: Bytes,
    context: &PaymentContext<P, D>,
    limits: &CloseLimits,
) -> Result<Dealing<P, D>, CodecError> {
    let invalid = |reason| CodecError::Invalid("clearing::Dealing", reason);
    if P::SIZE != 32 {
        return Err(invalid("account keys must encode exactly 32 bytes"));
    }
    let mut reader = encoded.clone();
    let header = Header::read(&mut reader)?;
    let max_rows = limits
        .max_rows()
        .min(u64::from(MAX_VECTOR_LENGTH))
        .min((reader.remaining() / 33) as u64) as usize;
    let count = usize::read_cfg(&mut reader, &RangeCfg::new(..=max_rows))?;
    let mut skeleton = Vec::<(P, Option<(u64, P::Signature)>)>::with_capacity(count);
    for _ in 0..count {
        let account = P::read(&mut reader)?;
        if skeleton
            .last()
            .is_some_and(|(last, _)| last.as_ref() >= account.as_ref())
        {
            return Err(invalid("account keys are not uniquely sorted"));
        }
        let outgoing = match u8::read(&mut reader)? {
            0 => None,
            1 => Some((
                UInt::<u64>::read(&mut reader)?.into(),
                P::Signature::read(&mut reader)?,
            )),
            tag => return Err(CodecError::InvalidEnum(tag)),
        };
        skeleton.push((account, outgoing));
    }
    let mut budget = limits.max_total_entries();
    let mut vectors = Vec::with_capacity(count);
    for (payer, outgoing) in &skeleton {
        let bound = budget
            .min(limits.max_account_entries())
            .min(u64::from(MAX_VECTOR_LENGTH))
            .min((reader.remaining() / 3) as u64) as usize;
        let length = usize::read_cfg(&mut reader, &RangeCfg::new(..=bound))?;
        budget -= length as u64;
        if outgoing.is_some() != (length != 0) {
            return Err(invalid("outgoing presence does not match vector"));
        }
        let mut entries = Vec::with_capacity(length);
        let mut last = None;
        for _ in 0..length {
            let index = usize::read_cfg(&mut reader, &RangeCfg::new(..count))?;
            if last.is_some_and(|last| last >= index) {
                return Err(invalid("recipient indices are not uniquely sorted"));
            }
            last = Some(index);
            entries.push(OutEntry {
                recipient: skeleton[index].0.clone(),
                cumulative: UInt::<u64>::read(&mut reader)?.into(),
                count: UInt::<u64>::read(&mut reader)?.into(),
            });
        }
        vectors.push(
            OutVector::new(context.epoch(), payer.clone(), entries)
                .map_err(|_| invalid("invalid outgoing vector"))?,
        );
    }
    let aggregate = Option::<OperatorAggregate>::read(&mut reader)?;
    if aggregate.is_some() != skeleton.iter().any(|(_, outgoing)| outgoing.is_some()) {
        return Err(invalid(
            "operator aggregate presence does not match senders",
        ));
    }
    if reader.has_remaining() {
        return Err(invalid("trailing dealing bytes"));
    }
    let rows = skeleton
        .into_iter()
        .zip(vectors)
        .map(|((account, outgoing), vector)| Row {
            account,
            outgoing,
            vector,
        })
        .collect();
    Ok(Dealing {
        header,
        rows,
        aggregate,
        encoded,
    })
}

pub(crate) fn encode<P: PublicKey, D: Digest>(
    header: &Header<D>,
    rows: &[AccountRow<P, D>],
    vectors: &[OutVector<P>],
    aggregate: Option<&OperatorAggregate>,
) -> Result<Bytes, TransitionError> {
    if P::SIZE != 32
        || rows.len() != vectors.len()
        || rows
            .windows(2)
            .any(|pair| pair[0].account.as_ref() >= pair[1].account.as_ref())
    {
        return Err(TransitionError::NonCanonicalRows);
    }
    let mut writer = BytesMut::new();
    header.write(&mut writer);
    rows.len().write(&mut writer);
    for row in rows {
        row.account.write(&mut writer);
        match &row.outgoing {
            None => 0_u8.write(&mut writer),
            Some(send) => {
                1_u8.write(&mut writer);
                UInt(send.body().seq()).write(&mut writer);
                send.payer_signature().write(&mut writer);
            }
        }
    }
    for (row, vector) in rows.iter().zip(vectors) {
        if vector.payer() != &row.account {
            return Err(TransitionError::VectorAlignment);
        }
        vector.entries().len().write(&mut writer);
        for entry in vector.entries() {
            let index = rows
                .binary_search_by(|row| row.account.as_ref().cmp(entry.recipient.as_ref()))
                .map_err(|_| TransitionError::UnknownAccount)?;
            index.write(&mut writer);
            UInt(entry.cumulative).write(&mut writer);
            UInt(entry.count).write(&mut writer);
        }
    }
    match aggregate {
        None => 0_u8.write(&mut writer),
        Some(signature) => {
            1_u8.write(&mut writer);
            signature.write(&mut writer);
        }
    }
    Ok(writer.freeze())
}
