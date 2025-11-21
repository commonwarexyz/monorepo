//! Wire protocol for orchestrator channel communication.

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
///
/// These messages enable validators to synchronize epoch-boundary finalizations
/// without requiring active consensus engines for old epochs.
#[derive(Clone, Debug, PartialEq)]
pub enum Message<S: Scheme, D: Digest> {
    /// Request for an epoch's boundary finalization.
    Request(Epoch),
    /// Response containing the epoch and its boundary finalization.
    ///
    /// The epoch is included separately to enable staged decoding: the epoch is read first
    /// to determine which certificate verifier to use, then the finalization is decoded.
    Response(Epoch, Finalization<S, D>),
}

impl<S: Scheme, D: Digest> Write for Message<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Message::Request(epoch) => {
                0u8.write(writer);
                epoch.write(writer);
            }
            Message::Response(epoch, finalization) => {
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
            Message::Request(epoch) => epoch.encode_size(),
            Message::Response(epoch, finalization) => {
                epoch.encode_size() + finalization.encode_size()
            }
        }
    }
}

impl<S: Scheme, D: Digest> Message<S, D> {
    /// Reads an orchestrator message using staged decoding with a scheme provider.
    ///
    /// This method performs staged decoding to handle messages efficiently:
    /// - Request messages only require reading the discriminant and epoch
    /// - Response messages additionally require a certificate verifier from the scheme provider
    ///
    /// Returns Ok(Some(message)) if successfully decoded, Ok(None) if a Response cannot be
    /// decoded due to missing certificate verifier, or Err if the message is malformed.
    pub fn read_staged<C: Signer>(
        reader: &mut impl Buf,
        scheme_provider: &SchemeProvider<S, C>,
    ) -> Result<Option<Self>, Error> {
        let discriminant = <u8>::read(reader)?;
        let epoch = Epoch::read(reader)?;

        match discriminant {
            0 => Ok(Some(Message::Request(epoch))),
            1 => {
                let Some(scheme) = scheme_provider.get_certificate_verifier(epoch) else {
                    return Ok(None);
                };

                let certificate_cfg = scheme.certificate_codec_config();
                let finalization = Finalization::<S, D>::read_cfg(reader, &certificate_cfg)?;

                if finalization.epoch() != epoch {
                    return Err(Error::Invalid(
                        "reshare::Message",
                        "Epoch mismatch in finalization",
                    ));
                }

                Ok(Some(Message::Response(epoch, finalization)))
            }
            _ => Err(Error::Invalid("reshare::Message", "Invalid discriminant")),
        }
    }
}
