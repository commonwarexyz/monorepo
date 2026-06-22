// Copyright (c) 2023 Espresso Systems (espressosys.com)
// This file is part of the HyperPlonk library.

// You should have received a copy of the MIT License
// along with the HyperPlonk library. If not, see <https://mit-license.org/>.

//! Module for PolyIOP transcript.
//! TODO(ZZ): move this module to HyperPlonk where the transcript will also be
//! useful.
//! TODO(ZZ): decide which APIs need to be public.

mod errors;
use crate::zkpari::utils::to_bytes;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
pub use errors::TranscriptError;
use merlin::Transcript;
use std::marker::PhantomData;
/// An IOP transcript consists of a Merlin transcript and a flag `is_empty` to
/// indicate that if the transcript is empty.
///
/// It is associated with a prime field `F` for which challenges are generated
/// over.
///
/// The `is_empty` flag is useful in the case where a protocol is initiated by
/// the verifier, in which case the prover should start its phase by receiving a
/// `non-empty` transcript.
#[derive(Clone)]
pub struct IOPTranscript<F: PrimeField> {
    transcript: Transcript,
    is_empty: bool,
    #[doc(hidden)]
    phantom: PhantomData<F>,
}

// TODO: Make this into a Trait
impl<F: PrimeField> IOPTranscript<F> {
    /// Create a new IOP transcript.
    pub fn new(label: &'static [u8]) -> Self {
        Self {
            transcript: Transcript::new(label),
            is_empty: true,
            phantom: PhantomData,
        }
    }

    // Append the message to the transcript.
    pub fn append_message(
        &mut self,
        label: &'static [u8],
        msg: &[u8],
    ) -> Result<(), TranscriptError> {
        self.transcript.append_message(label, msg);
        self.is_empty = false;
        Ok(())
    }

    // Append the message to the transcript.
    pub fn append_field_element(
        &mut self,
        label: &'static [u8],
        field_elem: &F,
    ) -> Result<(), TranscriptError> {
        self.append_message(label, &to_bytes!(field_elem)?)
    }

    // Append the message to the transcript.
    pub fn append_serializable_element<S: CanonicalSerialize>(
        &mut self,
        label: &'static [u8],
        group_elem: &S,
    ) -> Result<(), TranscriptError> {
        self.append_message(label, &to_bytes!(group_elem)?)
    }

    // Generate the challenge from the current transcript
    // and append it to the transcript.
    //
    // The output field element is statistical uniform as long
    // as the field has a size less than 2^384.
    pub fn get_and_append_challenge(&mut self, label: &'static [u8]) -> Result<F, TranscriptError> {
        //  we need to reject when transcript is empty
        if self.is_empty {
            return Err(TranscriptError::InvalidTranscript(
                "transcript is empty".to_string(),
            ));
        }

        let mut buf = [0u8; 24];
        self.transcript.challenge_bytes(label, &mut buf);
        let challenge = F::from_le_bytes_mod_order(&buf);
        self.append_serializable_element(label, &challenge)?;
        Ok(challenge)
    }

    // Generate a list of challenges from the current transcript
    // and append them to the transcript.
    //
    // The output field element are statistical uniform as long
    // as the field has a size less than 2^384.
    pub fn get_and_append_challenge_vectors(
        &mut self,
        label: &'static [u8],
        len: usize,
    ) -> Result<Vec<F>, TranscriptError> {
        //  we need to reject when transcript is empty
        if self.is_empty {
            return Err(TranscriptError::InvalidTranscript(
                "transcript is empty".to_string(),
            ));
        }

        let mut res = vec![];
        for _ in 0..len {
            res.push(self.get_and_append_challenge(label)?)
        }
        Ok(res)
    }
}
