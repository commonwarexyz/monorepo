use crate::bls12381::primitives::{group::Scalar, variant::Variant, Error};
#[cfg(not(feature = "std"))]
use alloc::sync::Arc;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use cfg_if::cfg_if;
use commonware_codec::{EncodeSize, FixedSize, RangeCfg, Read, ReadExt, Write};
use commonware_macros::stability;
#[stability(ALPHA)]
use commonware_math::algebra::{FieldNTT, Ring};
use commonware_math::poly::{Interpolator, Poly};
use commonware_parallel::Sequential;
#[stability(ALPHA)]
use commonware_utils::{ordered::BiMap, TryFromIterator};
use commonware_utils::{ordered::Set, Faults, Participant, NZU32};
#[cfg(feature = "std")]
use core::iter;
use core::num::NonZeroU32;
#[cfg(feature = "std")]
use std::sync::{Arc, OnceLock};
#[cfg(feature = "std")]
use std::vec::Vec;

/// Configures how participants are assigned shares of a secret.
///
/// More specifically, this configures how evaluation points of a polynomial
/// are assigned to participant identities.
#[derive(Copy, Clone, Default, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Mode {
    #[default]
    NonZeroCounter = 0,

    /// Assigns participants to powers of a root of unity.
    ///
    /// This mode enables sub-quadratic interpolation using NTT-based algorithms.
    #[cfg(not(any(
        commonware_stability_BETA,
        commonware_stability_GAMMA,
        commonware_stability_DELTA,
        commonware_stability_EPSILON,
        commonware_stability_RESERVED
    )))]
    RootsOfUnity = 1,
}

impl Mode {
    /// Compute the scalar for one participant.
    ///
    /// This will return `None` only if `i >= total`.
    pub(crate) fn scalar(self, total: NonZeroU32, i: Participant) -> Option<Scalar> {
        if i.get() >= total.get() {
            return None;
        }
        match self {
            Self::NonZeroCounter => {
                // Adding 1 is critical, because f(0) will contain the secret.
                Some(Scalar::from_u64(i.get() as u64 + 1))
            }
            #[cfg(not(any(
                commonware_stability_BETA,
                commonware_stability_GAMMA,
                commonware_stability_DELTA,
                commonware_stability_EPSILON,
                commonware_stability_RESERVED
            )))]
            Self::RootsOfUnity => {
                // Participant i gets w^i. Since w^i != 0 for any i, this never
                // collides with the secret at f(0).
                let size = (total.get() as u64).next_power_of_two();
                let lg_size = size.ilog2() as u8;
                let w = Scalar::root_of_unity(lg_size).expect("domain too large for NTT");
                Some(w.exp(&[i.get() as u64]))
            }
        }
    }

    /// Compute the scalars for all participants.
    #[cfg(feature = "std")]
    pub(crate) fn all_scalars(self, total: NonZeroU32) -> Vec<Scalar> {
        match self {
            Self::NonZeroCounter => (0..total.get())
                .map(|i| Scalar::from_u64(i as u64 + 1))
                .collect(),
            #[cfg(not(any(
                commonware_stability_BETA,
                commonware_stability_GAMMA,
                commonware_stability_DELTA,
                commonware_stability_EPSILON,
                commonware_stability_RESERVED
            )))]
            Self::RootsOfUnity => {
                let size = (total.get() as u64).next_power_of_two();
                let lg_size = size.ilog2() as u8;
                let w = Scalar::root_of_unity(lg_size).expect("domain too large for NTT");
                (0..total.get())
                    .scan(Scalar::one(), |state, _| {
                        let val = state.clone();
                        *state *= &w;
                        Some(val)
                    })
                    .collect()
            }
        }
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
    /// - a means to convert indices to Participant values.
    fn interpolator<I: Clone + Ord>(
        self,
        total: NonZeroU32,
        indices: &Set<I>,
        to_index: impl Fn(&I) -> Option<Participant>,
    ) -> Option<Interpolator<I, Scalar>> {
        match self {
            Self::NonZeroCounter => {
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
                // If any indices fail to produce a scalar, reject.
                if count != indices.len() {
                    return None;
                }
                Some(out)
            }
            #[cfg(not(any(
                commonware_stability_BETA,
                commonware_stability_GAMMA,
                commonware_stability_DELTA,
                commonware_stability_EPSILON,
                commonware_stability_RESERVED
            )))]
            Self::RootsOfUnity => {
                // For roots of unity mode, we use the fast O(n log n) interpolation.
                // Participant i maps to exponent i, so the evaluation point is w^i.
                let size = (total.get() as u64).next_power_of_two();
                let ntt_total = NonZeroU32::new(u32::try_from(size).ok()?)?;

                let mut count = 0;
                let points: Vec<(I, u32)> = indices
                    .iter()
                    .filter_map(|i| {
                        let participant = to_index(i)?;
                        if participant.get() >= total.get() {
                            return None;
                        }
                        count += 1;
                        Some((i.clone(), participant.get()))
                    })
                    .collect();

                // If any indices fail to produce a scalar, reject.
                if count != indices.len() {
                    return None;
                }

                let points = BiMap::try_from_iter(points).ok()?;
                Some(Interpolator::roots_of_unity(ntt_total, points))
            }
        }
    }

    /// Create an interpolator for this mode, given a set, and a subset.
    ///
    /// The set determines the total number of participants to use for interpolation,
    /// and the indices that will get assigned to the subset.
    ///
    /// This function will return `None` only if `subset` contains elements
    /// not in `set`.
    #[cfg(feature = "std")]
    pub(crate) fn subset_interpolator<I: Clone + Ord>(
        self,
        set: &Set<I>,
        subset: &Set<I>,
    ) -> Option<Interpolator<I, Scalar>> {
        let Ok(total) = NonZeroU32::try_from(set.len() as u32) else {
            return Some(Interpolator::new(iter::empty()));
        };
        self.interpolator(total, subset, |i| {
            set.position(i).map(Participant::from_usize)
        })
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

/// Determines which modes can be parsed.
///
/// As modes have been added over time, this versioning mechanism helps with
/// supporting compatibility.
///
/// This allows upgrading to a new version of the library, including more modes,
/// while using this version to determine which modes are supported at runtime.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ModeVersion(u8);

impl ModeVersion {
    /// Version 0, supporting:
    ///
    /// - [`Mode::NonZeroCounter`]
    pub const fn v0() -> Self {
        Self(0)
    }

    /// Version 1, supporting v0, and:
    ///
    /// - [`Mode::RootsOfUnity`]
    #[stability(ALPHA)]
    pub const fn v1() -> Self {
        Self(1)
    }

    const fn supports(&self, mode: &Mode) -> bool {
        match mode {
            Mode::NonZeroCounter => true,
            #[cfg(not(any(
                commonware_stability_BETA,
                commonware_stability_GAMMA,
                commonware_stability_DELTA,
                commonware_stability_EPSILON,
                commonware_stability_RESERVED
            )))]
            Mode::RootsOfUnity => self.0 >= 1,
        }
    }
}

impl Read for Mode {
    type Cfg = ModeVersion;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        version: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let tag: u8 = ReadExt::read(buf)?;
        let mode = match tag {
            0 => Self::NonZeroCounter,
            #[cfg(not(any(
                commonware_stability_BETA,
                commonware_stability_GAMMA,
                commonware_stability_DELTA,
                commonware_stability_EPSILON,
                commonware_stability_RESERVED
            )))]
            1 => Self::RootsOfUnity,
            o => return Err(commonware_codec::Error::InvalidEnum(o)),
        };
        if !version.supports(&mode) {
            return Err(commonware_codec::Error::Invalid(
                "Mode",
                "unsupported mode for version",
            ));
        }
        Ok(mode)
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
    #[cfg(feature = "std")]
    pub(crate) const fn mode(&self) -> Mode {
        self.mode
    }

    pub(crate) fn scalar(&self, i: Participant) -> Option<Scalar> {
        self.mode.scalar(self.total, i)
    }

    #[cfg(feature = "std")]
    fn all_scalars(&self) -> Vec<Scalar> {
        self.mode.all_scalars(self.total)
    }

    /// Return the number of participants required to recover the secret
    /// using the given fault model.
    pub fn required<M: Faults>(&self) -> u32 {
        M::quorum(self.total.get())
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
        indices: &Set<Participant>,
    ) -> Result<Interpolator<Participant, Scalar>, Error> {
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
                e.get_or_init(|| self.poly.eval_msm(&s, &Sequential));
            })
    }

    /// Get the partial public key associated with a given participant.
    ///
    /// This will return `None` if the index is greater >= [`Self::total`].
    pub fn partial_public(&self, i: Participant) -> Result<V::Public, Error> {
        cfg_if! {
            if #[cfg(feature = "std")] {
                self.evals
                    .get(usize::from(i))
                    .map(|e| {
                        *e.get_or_init(|| {
                            self.poly
                                .eval_msm(&self.scalar(i).expect("i < total"), &Sequential)
                        })
                    })
                    .ok_or(Error::InvalidIndex)
            } else {
                Ok(self
                    .poly
                    .eval_msm(&self.scalar(i).ok_or(Error::InvalidIndex)?, &Sequential))
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
    type Cfg = (NonZeroU32, ModeVersion);

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        (max_participants, max_supported_mode): &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let mode = Read::read_cfg(buf, max_supported_mode)?;
        // We bound total to the config, in order to prevent doing arbitrary
        // computation if we precompute public keys.
        let total = {
            let out: u32 = ReadExt::read(buf)?;
            if out == 0 || out > max_participants.get() {
                return Err(commonware_codec::Error::Invalid(
                    "Sharing",
                    "total not in range",
                ));
            }
            // This will not panic, because we checked != 0 above.
            NZU32!(out)
        };
        let poly = Read::read_cfg(buf, &(RangeCfg::from(NZU32!(1)..=*max_participants), ()))?;
        Ok(Self::new(mode, total, poly))
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use commonware_invariants::minifuzz;
    use commonware_utils::ordered::Map;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_roots_of_unity_interpolator_large_total_returns_none() {
        let total = NonZeroU32::new(u32::MAX).expect("u32::MAX is non-zero");
        let indices = Set::from_iter_dedup([Participant::new(0)]);
        let interpolator =
            Mode::RootsOfUnity.interpolator(total, &indices, |participant| Some(*participant));
        assert!(
            interpolator.is_none(),
            "domain > u32::MAX should be rejected instead of panicking"
        );
    }

    #[test]
    fn test_mode_read_rejects_mode_above_max_supported_mode() {
        let encoded = [Mode::RootsOfUnity as u8];
        Mode::read_cfg(&mut &encoded[..], &ModeVersion::v0())
            .expect_err("roots mode must be rejected when max mode is counter");
    }

    #[test]
    fn test_all_scalars_matches_scalar() {
        minifuzz::test(|u| {
            let mode = match u.int_in_range(0u8..=1)? {
                0 => Mode::NonZeroCounter,
                1 => Mode::RootsOfUnity,
                _ => unreachable!("range is 0..=1"),
            };
            let total = NonZeroU32::new(u.int_in_range(1u32..=512u32)?).expect("range is non-zero");
            let index = u.int_in_range(0u32..=total.get() - 1)?;
            let participant = Participant::new(index);

            let scalars = mode.all_scalars(total);
            assert_eq!(
                scalars[usize::from(participant)].clone(),
                mode.scalar(total, participant).expect("index is in range")
            );
            Ok(())
        });
    }

    #[test]
    fn test_subset_interpolation_recovers_constant() {
        minifuzz::test(|u| {
            let mode = match u.int_in_range(0u8..=1)? {
                0 => Mode::NonZeroCounter,
                1 => Mode::RootsOfUnity,
                _ => unreachable!("range is 0..=1"),
            };
            let total = NonZeroU32::new(u.int_in_range(1u32..=64u32)?).expect("range is non-zero");

            let mut subset_vec = Vec::new();
            for i in 0..total.get() {
                if u.arbitrary::<bool>()? {
                    subset_vec.push(Participant::new(i));
                }
            }
            if subset_vec.is_empty() {
                let i = u.int_in_range(0u32..=total.get() - 1)?;
                subset_vec.push(Participant::new(i));
            }
            let subset = Set::from_iter_dedup(subset_vec);

            let max_degree = u32::try_from(subset.len() - 1).expect("subset len fits in u32");
            let degree = u.int_in_range(0u32..=max_degree)?;
            let seed: u64 = u.arbitrary()?;
            let poly: Poly<Scalar> = Poly::new(&mut StdRng::seed_from_u64(seed), degree);

            let all_shares = Map::from_iter_dedup((0..total.get()).map(|i| {
                let participant = Participant::new(i);
                let scalar = mode.scalar(total, participant).expect("in range");
                let share = poly.eval(&scalar);
                (participant, share)
            }));

            let subset_evals = Map::from_iter_dedup(subset.iter().map(|participant| {
                (
                    *participant,
                    all_shares
                        .get_value(participant)
                        .expect("participant exists")
                        .clone(),
                )
            }));

            let interpolator = mode
                .interpolator(total, &subset, |participant| Some(*participant))
                .expect("subset indices are valid");
            let recovered = interpolator
                .interpolate(&subset_evals, &Sequential)
                .expect("subset should match interpolator domain");

            assert_eq!(recovered, poly.constant().clone());
            Ok(())
        });
    }
}

#[cfg(feature = "arbitrary")]
mod fuzz {
    use super::*;
    use arbitrary::Arbitrary;
    use commonware_utils::{N3f1, NZU32};
    use rand::{rngs::StdRng, SeedableRng};

    impl<'a> Arbitrary<'a> for Mode {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            match u.int_in_range(0u8..=1)? {
                0 => Ok(Self::NonZeroCounter),
                1 => Ok(Self::RootsOfUnity),
                _ => Err(arbitrary::Error::IncorrectFormat),
            }
        }
    }

    impl<'a, V: Variant> Arbitrary<'a> for Sharing<V> {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            let total: u32 = u.int_in_range(1..=100)?;
            let mode: Mode = u.arbitrary()?;
            let seed: u64 = u.arbitrary()?;
            let poly = Poly::new(&mut StdRng::seed_from_u64(seed), N3f1::quorum(total) - 1);
            Ok(Self::new(
                mode,
                NZU32!(total),
                Poly::<V::Public>::commit(poly),
            ))
        }
    }
}
