//! Mock implementation of the [`Scheme`] trait for `ordered_broadcast` tests.

use crate::ordered_broadcast::types::{AckNamespace, AckSubject};
use commonware_cryptography::impl_certificate_mock;
use commonware_utils::N3f1;

impl_certificate_mock!(AckSubject<'a, P, D>, AckNamespace, N3f1);
