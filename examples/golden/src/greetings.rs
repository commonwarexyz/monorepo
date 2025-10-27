use commonware_codec::{EncodeSize, Read, Write};
use commonware_cryptography::bls12381::primitives::ops::{sign_message, verify_message};
use commonware_cryptography::bls12381::primitives::variant::MinPk;
use commonware_cryptography::bls12381::primitives::{
    group::{Scalar, G1, G2},
    ops::threshold_signature_recover,
    poly::Eval,
    Error as BlsError,
};
use std::collections::HashMap;
use thiserror::Error as ThisError;
#[derive(Default)]
pub struct PendingGreetings {
    partial_signatures: Vec<Eval<G2>>,
}

impl PendingGreetings {
    pub fn try_apply_greetings(
        &mut self,
        greet: GreetingsMsg,
        pubkey_shares: &HashMap<u32, G1>,
    ) -> Result<(), GreetingsError> {
        let found = self
            .partial_signatures
            .iter()
            .any(|x| &x.index == greet.player_id());

        if found {
            return Ok(());
        }

        greet.verify_partial_signature(pubkey_shares)?;

        self.partial_signatures.push(greet.0);

        Ok(())
    }

    pub fn verify_threshod_signature(&self, t: u32, group: &G1) -> Result<(), GreetingsError> {
        let threshold_sig = threshold_signature_recover::<MinPk, _>(t, &self.partial_signatures)?;

        verify_message::<MinPk>(group, None, GreetingsMsg::MSG, &threshold_sig)?;

        Ok(())
    }

    pub fn len(&self) -> usize {
        self.partial_signatures.len()
    }

    pub fn is_empty(&self) -> bool {
        self.partial_signatures.is_empty()
    }
}

pub struct GreetingsMsg(Eval<G2>);
impl GreetingsMsg {
    const MSG: &[u8] = b"Greetings!";

    pub fn new(player_id: u32, secret_share: &Scalar) -> Self {
        let partial_signature = sign_message::<MinPk>(secret_share, None, Self::MSG);

        let eval = Eval {
            index: player_id,
            value: partial_signature,
        };

        Self(eval)
    }

    pub fn player_id(&self) -> &u32 {
        &self.0.index
    }

    pub fn verify_partial_signature(
        &self,
        pubkey_shares: &HashMap<u32, G1>,
    ) -> Result<(), GreetingsError> {
        let public = pubkey_shares
            .get(&self.0.index)
            .ok_or(GreetingsError::PubkeyShareNotFound(self.0.index))?;
        verify_message::<MinPk>(public, None, Self::MSG, &self.0.value)?;
        Ok(())
    }
}

impl Read for GreetingsMsg {
    type Cfg = <Eval<G2> as Read>::Cfg;
    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let inner = Eval::<G2>::read_cfg(buf, cfg)?;
        Ok(Self(inner))
    }
}

impl Write for GreetingsMsg {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.0.write(buf);
    }
}

impl EncodeSize for GreetingsMsg {
    fn encode_size(&self) -> usize {
        self.0.encode_size()
    }
}

#[derive(Debug, ThisError)]
pub enum GreetingsError {
    #[error("BLS error on greetings message: {0}")]
    BlsError(#[from] BlsError),
    #[error("Player pubkey share not found {0}")]
    PubkeyShareNotFound(u32),
}
