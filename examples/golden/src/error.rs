use thiserror::Error;

use crate::{broadcast::BroadcastMsgError, share::ShareError};

#[derive(Debug, Error)]
pub enum Error {
    #[error("Error in share: {0}")]
    ShareError(#[from] ShareError),
    #[error("Error in broadcasted msg: {0}")]
    BroadcastMsgError(#[from] BroadcastMsgError),
}
