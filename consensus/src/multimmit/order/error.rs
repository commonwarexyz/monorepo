//! Errors of order extraction.

use crate::multimmit::{algebra, types::FrontierError};

/// A malformed or non-monotone ordering input.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum Error {
    #[error("ordering frontiers are not canonical")]
    Frontier,
    #[error("ordering frontier regresses")]
    Regression,
    #[error("ordering frontiers conflict at one height")]
    Conflict,
    #[error("tip-history opening does not extend the active history")]
    History,
    #[error(transparent)]
    Algebra(#[from] algebra::Error),
}

impl From<FrontierError> for Error {
    fn from(error: FrontierError) -> Self {
        match error {
            FrontierError::Regression(_) => Self::Regression,
            FrontierError::Conflict(_) => Self::Conflict,
            FrontierError::Empty | FrontierError::Chain { .. } | FrontierError::Length => {
                Self::Frontier
            }
        }
    }
}
