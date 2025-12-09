use crate::bls12381::primitives::{
    group::Scalar,
    poly::{eval_msm, Public},
    variant::Variant,
    Error,
};
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use core::{cell::OnceCell, num::NonZeroU32};

/// Configures how participants are assigned shares of a secret.
///
/// More specifically, this configures how evaluation points of a polynomial
/// are assigned to participant identities.
#[derive(Copy, Clone, Default, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum SharingMode {
    #[default]
    NonZeroCounter = 0,
}

impl SharingMode {
    /// Compute the scalar for one participant.
    ///
    /// This will return `None` only if `i >= total`.
    pub(crate) fn scalar(self, total: NonZeroU32, i: u32) -> Option<Scalar> {
        if i >= total.get() {
            return None;
        }
        match self {
            Self::NonZeroCounter => Some(Scalar::from_index(i)),
        }
    }

    /// Compute the scalars for all participants.
    pub(crate) fn all_scalars(self, total: NonZeroU32) -> impl Iterator<Item = Scalar> {
        (0..total.get()).map(move |i| self.scalar(total, i).expect("i < total"))
    }
}

/// Represents the public output of a polynomial secret sharing.
///
/// This does not contain any secret information.
pub struct Sharing<V: Variant> {
    mode: SharingMode,
    total: NonZeroU32,
    poly: Public<V>,
    evals: Vec<OnceCell<V::Public>>,
}

impl<V: Variant> Sharing<V> {
    #[allow(dead_code)]
    pub(crate) fn new(mode: SharingMode, total: NonZeroU32, poly: Public<V>) -> Self {
        Self {
            mode,
            total,
            poly,
            evals: vec![OnceCell::new(); total.get() as usize],
        }
    }

    fn scalar(&self, i: u32) -> Option<Scalar> {
        self.mode.scalar(self.total, i)
    }

    fn all_scalars(&self) -> impl Iterator<Item = Scalar> {
        self.mode.all_scalars(self.total)
    }

    /// Return the total number of participants in this sharing.
    pub const fn total(&self) -> NonZeroU32 {
        self.total
    }

    /// Call this to pre-compute the results of [`Self::partial_public`].
    ///
    /// This should be used if you expect to access many of the partial public
    /// keys, e.g. if verifying several public signatures.
    ///
    /// The first time this method is called can be expensive, but subsequent
    /// calls are idempotent, and cheap.
    pub fn precompute_partial_publics(&self) {
        // NOTE: once we add more interpolation methods, this can be smarter.
        self.evals
            .iter()
            .zip(self.all_scalars())
            .for_each(|(e, s)| {
                e.get_or_init(|| eval_msm::<V>(&self.poly, s));
            })
    }

    /// Get the partial public key associated with a given participant.
    ///
    /// This will return `None` if the index is greater >= [`Self::total`].
    pub fn partial_public(&self, i: u32) -> Result<V::Public, Error> {
        self.evals
            .get(i as usize)
            .map(|e| {
                *e.get_or_init(|| eval_msm::<V>(&self.poly, self.scalar(i).expect("i < total")))
            })
            .ok_or(Error::InvalidIndex)
    }

    /// Get the group public key of this sharing.
    ///
    /// In other words, the public key associated with the shared secret.
    pub fn public(&self) -> V::Public {
        *self.poly.constant()
    }
}
