//! Signature namespaces of one deployment.

use commonware_cryptography::certificate;
use commonware_utils::union_unique;

/// Suffix of the namespace in which senders sign their states.
const STATE: &[u8] = b"_COMMONWARE_CLEARING_BAJILLION_STATE";

/// Suffix of the namespace in which the operator countersigns states.
const ACKNOWLEDGEMENT: &[u8] = b"_COMMONWARE_CLEARING_BAJILLION_ACKNOWLEDGEMENT";

/// Suffix of the namespace in which accounts sign soft withdrawals.
const WITHDRAWAL: &[u8] = b"_COMMONWARE_CLEARING_BAJILLION_WITHDRAWAL";

/// Suffix of the namespace in which the operator signs closes.
const CLOSE: &[u8] = b"_COMMONWARE_CLEARING_BAJILLION_CLOSE";

/// Suffix of the namespace in which validators certify summaries.
const SUMMARY: &[u8] = b"_COMMONWARE_CLEARING_BAJILLION_SUMMARY";

/// Signature namespaces of one deployment.
///
/// Each kind of signed message has its own namespace, so a signature on one kind never verifies as
/// another. All namespaces derive from the deployment's namespace. Deployments must use different
/// namespaces so signatures from one cannot be replayed in another.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Namespace {
    /// Namespace in which senders sign their states.
    pub state: Vec<u8>,
    /// Namespace in which the operator countersigns states.
    pub acknowledgement: Vec<u8>,
    /// Namespace in which accounts sign soft withdrawals.
    pub withdrawal: Vec<u8>,
    /// Namespace in which the operator signs closes.
    pub close: Vec<u8>,
    /// Namespace in which validators certify summaries.
    pub summary: Vec<u8>,
}

impl Namespace {
    /// Derives the signature namespaces of the deployment with namespace `namespace`.
    pub fn new(namespace: &[u8]) -> Self {
        Self {
            state: union_unique(namespace, STATE),
            acknowledgement: union_unique(namespace, ACKNOWLEDGEMENT),
            withdrawal: union_unique(namespace, WITHDRAWAL),
            close: union_unique(namespace, CLOSE),
            summary: union_unique(namespace, SUMMARY),
        }
    }
}

impl certificate::Namespace for Namespace {
    fn derive(namespace: &[u8]) -> Self {
        Self::new(namespace)
    }
}
