//! Wire protocol for orchestrator communication.

use crate::application::SchemeProvider;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use commonware_consensus::{
    simplex::{signing_scheme::Scheme, types::Finalization},
    types::Epoch,
    Epochable,
};
use commonware_cryptography::{Digest, Signer};

/// Messages for requesting and providing epoch-boundary finalizations.
#[derive(Clone, Debug, PartialEq)]
pub enum Message<S: Scheme, D: Digest> {
    /// Request for an epoch's boundary finalization.
    Request(Epoch),
    /// Response containing the epoch and its boundary finalization.
    ///
    /// The epoch is included separately to enable easier staged decoding.
    Response(Epoch, Finalization<S, D>),
}

impl<S: Scheme, D: Digest> Write for Message<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::Request(epoch) => {
                0u8.write(writer);
                epoch.write(writer);
            }
            Self::Response(epoch, finalization) => {
                1u8.write(writer);
                epoch.write(writer);
                finalization.write(writer);
            }
        }
    }
}

impl<S: Scheme, D: Digest> EncodeSize for Message<S, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Request(epoch) => epoch.encode_size(),
            Self::Response(epoch, finalization) => epoch.encode_size() + finalization.encode_size(),
        }
    }
}

impl<S: Scheme, D: Digest> Message<S, D> {
    /// Reads an orchestrator message using staged decoding.
    ///
    /// Staged decoding is required because response messages contain finalizations that
    /// need epoch-specific certificate codec configuration for decoding. The epoch is
    /// read first to look up the appropriate certificate verifier, then that verifier's
    /// codec config is used to decode the finalization.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(message))` - Successfully decoded message
    /// - `Ok(None)` - Certificate verifier not available for response epoch
    /// - `Err(...)` - Malformed message
    pub fn read_staged<C: Signer>(
        reader: &mut impl Buf,
        scheme_provider: &SchemeProvider<S, C>,
    ) -> Result<Option<Self>, Error> {
        let discriminant = <u8>::read(reader)?;
        let epoch = Epoch::read(reader)?;

        match discriminant {
            0 => Ok(Some(Self::Request(epoch))),
            1 => {
                let Some(scheme) = scheme_provider.get_certificate_verifier(epoch) else {
                    return Ok(None);
                };
                let finalization =
                    Finalization::<S, D>::read_cfg(reader, &scheme.certificate_codec_config())?;

                if finalization.epoch() != epoch {
                    return Err(Error::Invalid(
                        "reshare::orchestrator::wire::Message",
                        "Epoch mismatch in finalization",
                    ));
                }

                Ok(Some(Self::Response(epoch, finalization)))
            }
            _ => Err(Error::Invalid(
                "reshare::orchestrator::wire::Message",
                "Invalid type",
            )),
        }
    }
}
