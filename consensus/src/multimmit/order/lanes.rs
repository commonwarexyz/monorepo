//! The payment chains whose positions every ordering stream visits first.

use super::Error;
use crate::multimmit::{config::Parameters, types::ChainId};
use std::sync::Arc;

/// The payment chains of an epoch, in chain order.
///
/// Every node must order with the same lanes, so they derive from the epoch's [`Parameters`]
/// alone ([`Parameters::payment_chain`]). Without payment chains the lanes hold nothing, and no
/// ordering stream has a payment pass.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Lanes(Option<Arc<[bool]>>);

impl Lanes {
    /// Returns the lanes without payment chains.
    pub(crate) const fn none() -> Self {
        Self(None)
    }

    /// Returns the lanes whose payment chains are the set entries of `mask`, one per chain.
    pub(crate) fn new(mask: impl IntoIterator<Item = bool>) -> Self {
        let mask = mask.into_iter().collect::<Arc<[bool]>>();
        if mask.iter().any(|payment| *payment) {
            Self(Some(mask))
        } else {
            Self::none()
        }
    }

    /// Returns the lanes of the epoch `parameters` configure.
    pub(crate) fn from_parameters(parameters: &Parameters) -> Self {
        if !parameters.payments() {
            return Self::none();
        }
        Self::new((0..parameters.codec_config().chains()).map(|chain| {
            let chain = u32::try_from(chain).expect("validated chain index fits u32");
            parameters.payment_chain(ChainId::new(chain))
        }))
    }

    /// Returns whether each chain is a payment chain, in chain order, or nothing when none is.
    pub(crate) fn to_mask(&self) -> Vec<bool> {
        self.0.as_deref().map_or_else(Vec::new, <[bool]>::to_vec)
    }

    /// Returns whether `chain` is a payment chain.
    pub(crate) fn payment(&self, chain: usize) -> bool {
        self.0
            .as_ref()
            .is_some_and(|mask| mask.get(chain).copied().unwrap_or(false))
    }

    /// Checks that the lanes describe `chains` chains. Lanes without payment chains describe any
    /// number.
    pub(crate) fn check(&self, chains: usize) -> Result<(), Error> {
        match &self.0 {
            Some(mask) if mask.len() != chains => Err(Error::Frontier),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::types::PathLimits,
        types::{Epoch, Participant},
    };

    #[test]
    fn lanes_without_payment_chains_collapse_to_none() {
        assert_eq!(Lanes::new([false, false]), Lanes::none());
        assert_eq!(Lanes::new([]), Lanes::none());
        assert!(Lanes::none().check(3).is_ok());

        let lanes = Lanes::new([false, true, false]);
        assert_eq!(
            (0..4).map(|chain| lanes.payment(chain)).collect::<Vec<_>>(),
            vec![false, true, false, false]
        );
        assert!(lanes.check(3).is_ok());
        assert_eq!(lanes.check(2), Err(Error::Frontier));
        assert_eq!(lanes.to_mask(), vec![false, true, false]);
        assert!(Lanes::none().to_mask().is_empty());
    }

    #[test]
    fn lanes_follow_the_epoch_parameters() {
        let namespace = b"_COMMONWARE_CONSENSUS_MULTIMMIT_PAYMENT_LANES_TEST";
        let certified = PathLimits::new(0, 0).with_pipeline_window(4).unwrap();
        let parameters = Parameters::new(
            Epoch::new(1),
            namespace,
            6,
            (0..3).map(Participant::new).collect(),
            certified,
        )
        .unwrap()
        .with_chain_limits(vec![PathLimits::new(2, 0), certified, certified])
        .unwrap();
        assert_eq!(Lanes::from_parameters(&parameters), Lanes::none());
        assert_eq!(
            Lanes::from_parameters(&parameters.with_payments(true)),
            Lanes::new([false, true, true])
        );
    }
}
