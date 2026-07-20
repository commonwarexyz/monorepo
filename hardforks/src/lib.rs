#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]
#![no_std]

commonware_macros::stability_scope!(BETA {
    extern crate alloc;

    use alloc::vec::Vec;
    use core::hash::{Hash, Hasher};
    use rapidhash::quality::RapidHasher;
    use thiserror::Error;

    const COMMITMENT_NAMESPACE: &[u8] = b"_COMMONWARE_HARDFORKS_SCHEDULE_COMMITMENT";

    macro_rules! hardforks {
        (
            $(#[$enum_meta:meta])*
            $visibility:vis enum $name:ident {
                $(
                    $(#[$variant_meta:meta])*
                    $variant:ident
                ),+ $(,)?
            }
        ) => {
            $(#[$enum_meta])*
            #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, strum::IntoStaticStr)]
            #[non_exhaustive]
            #[strum(serialize_all = "title_case")]
            $visibility enum $name {
                $(
                    $(#[$variant_meta])*
                    $variant,
                )+
            }

            impl $name {
                /// All hardforks in hierarchy order.
                pub const VARIANTS: &'static [Self] = &[$(Self::$variant),+];

                /// Returns the human-readable hardfork name.
                pub fn name(self) -> &'static str {
                    self.into()
                }
            }
        };
    }

    hardforks! {
        /// A Commonware protocol hardfork.
        ///
        /// Declaration order defines the hardfork hierarchy.
        pub enum Hardfork {
            /// The Alameda hardfork.
            Alameda,
        }
    }

    /// An invalid hardfork schedule.
    #[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
    pub enum Error {
        /// A hardfork has more than one configured activation epoch.
        #[error("hardfork has more than one configured activation epoch")]
        Duplicate,

        /// A descendant is configured to activate before an explicitly configured ancestor.
        #[error("hardfork activation epochs are not monotonic")]
        NonMonotonic,
    }

    /// Hardfork activation epochs for a chain.
    ///
    /// The schedule is ordered by [`Hardfork`]. Activating a hardfork implicitly activates every
    /// ancestor, including ancestors omitted from the schedule.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct Schedule<E> {
        activations: Vec<(Hardfork, E)>,
    }

    impl<E> Schedule<E> {
        /// Creates a builder for configuring hardfork activation epochs.
        pub const fn builder() -> ScheduleBuilder<E> {
            ScheduleBuilder::new()
        }
    }

    impl<E> Default for Schedule<E> {
        fn default() -> Self {
            Self {
                activations: Vec::new(),
            }
        }
    }

    impl<E: Ord> Schedule<E> {
        fn new(activations: impl IntoIterator<Item = (Hardfork, E)>) -> Result<Self, Error> {
            let mut activations: Vec<_> = activations.into_iter().collect();
            activations.sort_unstable_by_key(|(hardfork, _)| *hardfork);

            for pair in activations.windows(2) {
                let [(earlier, earlier_epoch), (later, later_epoch)] = pair else {
                    unreachable!("windows of two always contain two items");
                };

                if earlier == later {
                    return Err(Error::Duplicate);
                }
                if earlier_epoch > later_epoch {
                    return Err(Error::NonMonotonic);
                }
            }

            Ok(Self { activations })
        }
    }

    impl<E: Copy + Ord> Schedule<E> {
        /// Returns the effective activation epoch for `hardfork`.
        ///
        /// If `hardfork` is omitted, the first configured descendant determines its activation
        /// epoch. Returns `None` when neither it nor a descendant is configured.
        pub fn activation_epoch(&self, hardfork: Hardfork) -> Option<E> {
            let index = self
                .activations
                .partition_point(|(candidate, _)| *candidate < hardfork);
            self.activations.get(index).map(|(_, epoch)| *epoch)
        }

        /// Returns whether `hardfork` is active at `epoch`.
        pub fn is_active(&self, hardfork: Hardfork, epoch: E) -> bool {
            self.activation_epoch(hardfork)
                .is_some_and(|activation| epoch >= activation)
        }

        /// Returns the latest hardfork active at `epoch`.
        pub fn latest(&self, epoch: E) -> Option<Hardfork> {
            let index = self
                .activations
                .partition_point(|(_, activation)| *activation <= epoch);
            index
                .checked_sub(1)
                .map(|index| self.activations[index].0)
        }
    }

    impl<E: Hash> Schedule<E> {
        /// Returns a deterministic commitment to the configured activations.
        ///
        /// The epoch type's [`Hash`] implementation defines how epochs contribute to the
        /// commitment. This commitment is intended for comparing schedules, not for
        /// cryptographic authentication.
        pub fn commitment(&self) -> u64 {
            let mut hasher = RapidHasher::default();
            hasher.write(COMMITMENT_NAMESPACE);
            hasher.write_u64(self.activations.len() as u64);

            for (hardfork, epoch) in &self.activations {
                let ordinal = Hardfork::VARIANTS.partition_point(|candidate| candidate < hardfork);
                hasher.write_u64(ordinal as u64);
                epoch.hash(&mut hasher);
            }

            hasher.finish()
        }
    }

    /// Builds a [`Schedule`] from user-defined activation epochs.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct ScheduleBuilder<E> {
        activations: Vec<(Hardfork, E)>,
    }

    impl<E> ScheduleBuilder<E> {
        const fn new() -> Self {
            Self {
                activations: Vec::new(),
            }
        }

        /// Configures `hardfork` to activate at `epoch`.
        pub fn activate(mut self, hardfork: Hardfork, epoch: E) -> Self {
            self.activations.push((hardfork, epoch));
            self
        }
    }

    impl<E: Ord> ScheduleBuilder<E> {
        /// Builds and validates the schedule.
        ///
        /// Input order does not matter. Equal activation epochs are allowed, but each hardfork
        /// may appear only once and descendants cannot activate before explicitly configured
        /// ancestors.
        pub fn build(self) -> Result<Schedule<E>, Error> {
            Schedule::new(self.activations)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        hardforks! {
            enum TestHardfork {
                First,
                SecondVariant,
                Third,
            }
        }

        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        struct Epoch(u64);

        #[test]
        fn hardfork_metadata() {
            assert_eq!(Hardfork::VARIANTS, &[Hardfork::Alameda]);
            assert_eq!(Hardfork::Alameda.name(), "Alameda");
            assert_eq!(
                TestHardfork::VARIANTS,
                &[
                    TestHardfork::First,
                    TestHardfork::SecondVariant,
                    TestHardfork::Third,
                ]
            );
            assert_eq!(TestHardfork::SecondVariant.name(), "Second Variant");
        }

        #[test]
        fn activation_boundary() {
            let schedule = Schedule::builder()
                .activate(Hardfork::Alameda, Epoch(10))
                .build()
                .unwrap();

            assert_eq!(
                schedule.activation_epoch(Hardfork::Alameda),
                Some(Epoch(10))
            );
            assert!(!schedule.is_active(Hardfork::Alameda, Epoch(9)));
            assert!(schedule.is_active(Hardfork::Alameda, Epoch(10)));
            assert_eq!(schedule.latest(Epoch(9)), None);
            assert_eq!(schedule.latest(Epoch(10)), Some(Hardfork::Alameda));
        }

        #[test]
        fn empty_schedule() {
            let schedule = Schedule::<Epoch>::builder().build().unwrap();

            assert_eq!(schedule.activation_epoch(Hardfork::Alameda), None);
            assert!(!schedule.is_active(Hardfork::Alameda, Epoch(u64::MAX)));
            assert_eq!(schedule.latest(Epoch(u64::MAX)), None);
        }

        #[test]
        fn builder_rejects_duplicate_hardforks() {
            let error = Schedule::builder()
                .activate(Hardfork::Alameda, Epoch(5))
                .activate(Hardfork::Alameda, Epoch(10))
                .build()
                .unwrap_err();

            assert_eq!(error, Error::Duplicate);
        }

        #[test]
        fn schedule_commitment() {
            let schedule = Schedule::builder()
                .activate(Hardfork::Alameda, 10u64)
                .build()
                .unwrap();
            let same = Schedule::builder()
                .activate(Hardfork::Alameda, 10u64)
                .build()
                .unwrap();
            let different = Schedule::builder()
                .activate(Hardfork::Alameda, 11u64)
                .build()
                .unwrap();

            assert_eq!(schedule.commitment(), 0x6ec3_14dd_d98a_3e00);
            assert_eq!(schedule.commitment(), same.commitment());
            assert_ne!(schedule.commitment(), different.commitment());
            assert_ne!(schedule.commitment(), Schedule::<u64>::default().commitment());
        }
    }
});
