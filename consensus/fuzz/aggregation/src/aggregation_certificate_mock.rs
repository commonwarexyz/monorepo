//! Mock certificate scheme for the `aggregation` fuzz harness.

use commonware_consensus::aggregation::types::{Item, Namespace};
use commonware_cryptography::impl_certificate_mock;
use commonware_utils::N3f1;

impl_certificate_mock!(&'a Item<D>, Namespace, N3f1);
