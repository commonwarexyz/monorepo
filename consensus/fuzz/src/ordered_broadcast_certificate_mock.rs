//! Mock certificate scheme for the `ordered_broadcast` fuzz harness.

use commonware_consensus::ordered_broadcast::types::{AckNamespace, AckSubject};
use commonware_cryptography::impl_certificate_mock;

impl_certificate_mock!(AckSubject<'a, P, D>, AckNamespace);
