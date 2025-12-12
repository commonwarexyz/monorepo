use crate::bls12381::primitives::{group::Scalar, variant::Variant, Error};
#[cfg(not(feature = "std"))]
use alloc::sync::Arc;
use cfg_if::cfg_if;
use commonware_codec::{EncodeSize, FixedSize, RangeCfg, Read, ReadExt, Write};
use commonware_math::poly::{Interpolator, Poly};
use commonware_utils::{ordered::Set, quorum, NZU32};
use core::{iter, num::NonZeroU32};
#[cfg(feature = "std")]
use std::sync::{Arc, OnceLock};

/// Configures how participants are assigned shares of a secret.
///
/// More specifically, this configures how evaluation points of a polynomial
/// are assigned to participant identities.
#[derive(Copy, Clone, Default, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Mode {
    // TODO (https://github.com/commonware-xyz/monorepo/issues/1836): Add a mode for sub O(N^2) interpolation
    #[default]
    NonZeroCounter = 0,
}

impl Mode {
    /// Compute the scalar for one participant.
    ///
    /// This will return `None` only if `i >= total`.
    pub(crate) fn scalar(self, total: NonZeroU32, i: u32) -> Option<Scalar> {
        if i >= total.get() {
            return None;
        }
        match self {
            Self::NonZeroCounter => {
                // Adding 1 is critical, because f(0) will contain the secret.
                Some(Scalar::from_u64(i as u64 + 1))
            }
        }
    }

    /// Compute the scalars for all participants.
    pub(crate) fn all_scalars(self, total: NonZeroU32) -> impl Iterator<Item = Scalar> {
        (0..total.get()).map(move |i| self.scalar(total, i).expect("i < total"))
    }

    /// Create an interpolator for this mode, given a set of indices.
    ///
    /// This will return `None` if:
    /// - any `to_index` call on the provided `indices` returns `None`,
    /// - any index returned by `to_index` is >= `total`.
    ///
    /// To be generic over different use cases, we need:
    /// - the total number of participants,
    /// - a set of indices (of any type),
    /// - a means to convert indices to u32 values.
    fn interpolator<I: Clone + Ord>(
        self,
        total: NonZeroU32,
        indices: &Set<I>,
        to_index: impl Fn(&I) -> Option<u32>,
    ) -> Option<Interpolator<I, Scalar>> {
        let mut count = 0;
        let iter = indices
            .iter()
            .filter_map(|i| {
                let scalar = self.scalar(total, to_index(i)?)?;
                Some((i.clone(), scalar))
            })
            .inspect(|_| {
                count += 1;
            });
        let out = Interpolator::new(iter);
        // If any indices failed to produce a scalar, reject.
        if count != indices.len() {
            return None;
        }
        Some(out)
    }

    /// Create an interpolator for this mode, given a set, and a subset.
    ///
    /// The set determines the total number of participants to use for interpolation,
    /// and the indices that will get assigned to the subset.
    ///
    /// This function will return `None` only if `subset` contains elements
    /// not in `set`.
    pub(crate) fn subset_interpolator<I: Clone + Ord>(
        self,
        set: &Set<I>,
        subset: &Set<I>,
    ) -> Option<Interpolator<I, Scalar>> {
        let Ok(total) = NonZeroU32::try_from(set.len() as u32) else {
            return Some(Interpolator::new(iter::empty()));
        };
        self.interpolator(total, subset, |i| set.position(i).map(|x| x as u32))
    }
}

impl FixedSize for Mode {
    const SIZE: usize = 1;
}

impl Write for Mode {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        buf.put_u8(*self as u8);
    }
}

impl Read for Mode {
    type Cfg = ();

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        _cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let tag: u8 = ReadExt::read(buf)?;
        match tag {
            0 => Ok(Self::NonZeroCounter),
            o => Err(commonware_codec::Error::InvalidEnum(o)),
        }
    }
}

/// Represents the public output of a polynomial secret sharing.
///
/// This does not contain any secret information.
#[derive(Clone, Debug)]
pub struct Sharing<V: Variant> {
    mode: Mode,
    total: NonZeroU32,
    poly: Arc<Poly<V::Public>>,
    #[cfg(feature = "std")]
    evals: Arc<Vec<OnceLock<V::Public>>>,
}

impl<V: Variant> PartialEq for Sharing<V> {
    fn eq(&self, other: &Self) -> bool {
        self.mode == other.mode && self.total == other.total && self.poly == other.poly
    }
}

impl<V: Variant> Eq for Sharing<V> {}

impl<V: Variant> Sharing<V> {
    pub(crate) fn new(mode: Mode, total: NonZeroU32, poly: Poly<V::Public>) -> Self {
        Self {
            mode,
            total,
            poly: Arc::new(poly),
            #[cfg(feature = "std")]
            evals: Arc::new(vec![OnceLock::new(); total.get() as usize]),
        }
    }

    /// Get the mode used for this sharing.
    pub(crate) const fn mode(&self) -> Mode {
        self.mode
    }

    pub(crate) fn scalar(&self, i: u32) -> Option<Scalar> {
        self.mode.scalar(self.total, i)
    }

    fn all_scalars(&self) -> impl Iterator<Item = Scalar> {
        self.mode.all_scalars(self.total)
    }

    /// Return the number of participants required to recover the secret.
    pub fn required(&self) -> u32 {
        quorum(self.total.get())
    }

    /// Return the total number of participants in this sharing.
    pub const fn total(&self) -> NonZeroU32 {
        self.total
    }

    /// Create an interpolator over some indices.
    ///
    /// This will return an error if any of the indices are >= [`Self::total`].
    pub(crate) fn interpolator(
        &self,
        indices: &Set<u32>,
    ) -> Result<Interpolator<u32, Scalar>, Error> {
        self.mode
            .interpolator(self.total, indices, |&x| Some(x))
            .ok_or(Error::InvalidIndex)
    }

    /// Call this to pre-compute the results of [`Self::partial_public`].
    ///
    /// This should be used if you expect to access many of the partial public
    /// keys, e.g. if verifying several public signatures.
    ///
    /// The first time this method is called can be expensive, but subsequent
    /// calls are idempotent, and cheap.
    #[cfg(feature = "std")]
    pub fn precompute_partial_publics(&self) {
        // NOTE: once we add more interpolation methods, this can be smarter.
        self.evals
            .iter()
            .zip(self.all_scalars())
            .for_each(|(e, s)| {
                e.get_or_init(|| self.poly.eval_msm(&s));
            })
    }

    /// Get the partial public key associated with a given participant.
    ///
    /// This will return `None` if the index is greater >= [`Self::total`].
    pub fn partial_public(&self, i: u32) -> Result<V::Public, Error> {
        cfg_if! {
            if #[cfg(feature = "std")] {
                self.evals
                    .get(i as usize)
                    .map(|e| {
                        *e.get_or_init(|| self.poly.eval_msm(&self.scalar(i).expect("i < total")))
                    })
                    .ok_or(Error::InvalidIndex)
            } else {
                Ok(self.poly.eval_msm(&self.scalar(i).ok_or(Error::InvalidIndex)?))
            }
        }
    }

    /// Get the group public key of this sharing.
    ///
    /// In other words, the public key associated with the shared secret.
    pub fn public(&self) -> &V::Public {
        self.poly.constant()
    }
}

impl<V: Variant> EncodeSize for Sharing<V> {
    fn encode_size(&self) -> usize {
        self.mode.encode_size() + self.total.get().encode_size() + self.poly.encode_size()
    }
}

impl<V: Variant> Write for Sharing<V> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.mode.write(buf);
        self.total.get().write(buf);
        self.poly.write(buf);
    }
}

impl<V: Variant> Read for Sharing<V> {
    type Cfg = NonZeroU32;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let mode = ReadExt::read(buf)?;
        // We bound total to the config, in order to prevent doing arbitrary
        // computation if we precompute public keys.
        let total = {
            let out: u32 = ReadExt::read(buf)?;
            if out == 0 || out > cfg.get() {
                return Err(commonware_codec::Error::Invalid(
                    "Sharing",
                    "total not in range",
                ));
            }
            // This will not panic, because we checked != 0 above.
            NZU32!(out)
        };
        let poly = Read::read_cfg(buf, &(RangeCfg::from(NZU32!(1)..=*cfg), ()))?;
        Ok(Self::new(mode, total, poly))
    }
}

#[cfg(feature = "arbitrary")]
mod fuzz {
    use super::*;
    use arbitrary::Arbitrary;
    use commonware_utils::NZU32;
    use rand::{rngs::StdRng, SeedableRng};

    impl<'a> Arbitrary<'a> for Mode {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            match u.int_in_range(0u8..=0)? {
                0 => Ok(Self::NonZeroCounter),
                _ => Err(arbitrary::Error::IncorrectFormat),
            }
        }
    }

    impl<'a, V: Variant> Arbitrary<'a> for Sharing<V> {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            let total: u32 = u.int_in_range(1..=100)?;
            let mode: Mode = u.arbitrary()?;
            let seed: u64 = u.arbitrary()?;
            let poly = Poly::new(&mut StdRng::seed_from_u64(seed), quorum(total) - 1);
            Ok(Self::new(
                mode,
                NZU32!(total),
                Poly::<V::Public>::commit(poly),
            ))
        }
    }
}
