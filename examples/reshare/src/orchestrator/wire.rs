//! Wire protocol for orchestrator channel communication.

use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use commonware_consensus::{
    simplex::{signing_scheme::Scheme, types::Finalization},
    types::Epoch,
};
use commonware_cryptography::Digest;

/// Messages for requesting and providing epoch-boundary finalizations.
///
/// These messages enable validators to synchronize epoch-boundary finalizations
/// without requiring active consensus engines for old epochs.
#[derive(Clone, Debug, PartialEq)]
pub enum OrchestratorMessage<S: Scheme, D: Digest> {
    /// Request for an epoch's boundary finalization.
    Request(EpochRequest),
    /// Response containing an epoch's boundary finalization.
    Response(EpochResponse<S, D>),
}

/// Request for an epoch's boundary finalization.
#[derive(Clone, Debug, PartialEq)]
pub struct EpochRequest {
    /// The epoch for which the boundary finalization is requested.
    pub epoch: Epoch,
}

/// Response containing an epoch's boundary finalization.
#[derive(Clone, Debug, PartialEq)]
pub struct EpochResponse<S: Scheme, D: Digest> {
    /// The epoch of the boundary finalization.
    pub epoch: Epoch,
    /// The finalization certificate for the last block of the epoch.
    pub finalization: Finalization<S, D>,
}

impl<S: Scheme, D: Digest> Write for OrchestratorMessage<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            OrchestratorMessage::Request(req) => {
                0u8.write(writer);
                req.epoch.write(writer);
            }
            OrchestratorMessage::Response(resp) => {
                1u8.write(writer);
                resp.epoch.write(writer);
                resp.finalization.write(writer);
            }
        }
    }
}

impl<S: Scheme, D: Digest> EncodeSize for OrchestratorMessage<S, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            OrchestratorMessage::Request(req) => req.epoch.encode_size(),
            OrchestratorMessage::Response(resp) => {
                resp.epoch.encode_size() + resp.finalization.encode_size()
            }
        }
    }
}

impl<S: Scheme, D: Digest> Read for OrchestratorMessage<S, D> {
    type Cfg = <S::Certificate as Read>::Cfg;

    fn read_cfg(reader: &mut impl Buf, certificate_cfg: &Self::Cfg) -> Result<Self, Error> {
        let discriminant = <u8>::read(reader)?;
        match discriminant {
            0 => {
                let epoch = Epoch::read(reader)?;
                Ok(OrchestratorMessage::Request(EpochRequest { epoch }))
            }
            1 => {
                let epoch = Epoch::read(reader)?;
                let finalization = Finalization::<S, D>::read_cfg(reader, certificate_cfg)?;
                Ok(OrchestratorMessage::Response(EpochResponse {
                    epoch,
                    finalization,
                }))
            }
            _ => Err(Error::Invalid(
                "reshare::OrchestratorMessage",
                "Invalid discriminant",
            )),
        }
    }
}
