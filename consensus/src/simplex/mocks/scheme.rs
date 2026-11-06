//! Mock implementation of the [`Scheme`] trait for `simplex` tests.

use crate::{
    simplex::{
        scheme::{Namespace, Seeded},
        types::Subject,
    },
    types::Round,
};
use commonware_cryptography::{PublicKey, impl_certificate_mock};
use commonware_utils::N3f1;

impl_certificate_mock!(Subject<'a, D>, Namespace, N3f1);

impl<P: PublicKey> Seeded for Scheme<P> {
    type Seed = ();

    fn seed(_: Round, _: Option<&Self::Certificate>) {}
}
