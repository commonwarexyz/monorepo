use commonware_consensus::simplex::{scheme::Namespace, types::Subject};
use commonware_cryptography::impl_certificate_mock;

impl_certificate_mock!(Subject<'a, D>, Namespace);
