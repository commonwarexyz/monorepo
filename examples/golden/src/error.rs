use thiserror::Error;

use crate::{
    broadcast::BroadcastMsgError, ciphered_share::ShareError, participant::registry::RegistryError,
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("Error in share: {0}")]
    ShareError(#[from] ShareError),
    #[error("Error in broadcasted msg: {0}")]
    BroadcastMsgError(#[from] BroadcastMsgError),
    #[error("Registry error: {0}")]
    RegistryError(#[from] RegistryError),
}
