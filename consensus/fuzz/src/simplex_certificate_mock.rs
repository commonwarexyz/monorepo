use commonware_consensus::simplex::{scheme::Namespace, types::Subject};
use commonware_cryptography::impl_certificate_mock;
use commonware_utils::N3f1;

impl_certificate_mock!(Subject<'a, D>, Namespace, N3f1);
