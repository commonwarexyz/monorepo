// Copyright (c) 2023 Espresso Systems (espressosys.com)
// This file is part of the HyperPlonk library.

// You should have received a copy of the MIT License
// along with the HyperPlonk library. If not, see <https://mit-license.org/>.

//! Error module.

use ark_std::string::String;

/// A `enum` specifying the possible failure modes of the Transcript.
#[derive(Debug)]
pub enum TranscriptError {
    InvalidTranscript(String),
    SerializationError(ark_serialize::SerializationError),
}

impl core::fmt::Display for TranscriptError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidTranscript(message) => write!(f, "invalid transcript: {message}"),
            Self::SerializationError(error) => {
                write!(f, "serialization error: {error}")
            }
        }
    }
}

impl From<ark_serialize::SerializationError> for TranscriptError {
    fn from(e: ark_serialize::SerializationError) -> Self {
        Self::SerializationError(e)
    }
}
