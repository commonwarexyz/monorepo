//! Dispatch-selected native instruction and composition checks.

use crate::{
    ArmV9, IceLake, Neon, Operation, Simd, dispatch,
    emulated::{EmulatedArmV9, EmulatedIceLake, EmulatedNeon},
    native::fuzz as differential,
};
use arbitrary::{Arbitrary, Unstructured};

/// A dispatched native instruction or composition check.
#[derive(Clone, Copy, Debug, Arbitrary)]
pub enum Plan {
    /// Checks all common instructions against the selected profile's emulator.
    #[cfg(not(miri))]
    Common,
    /// Checks the selected profile's additional instructions.
    #[cfg(not(miri))]
    Profile,
    /// Checks unaligned loads against the selected profile's emulator.
    Load,
    /// Checks stores and their surrounding memory.
    Store,
    /// Checks broadcasts of arbitrary and boundary words.
    Splat,
    /// Checks wrapping addition of arbitrary and boundary words.
    Add,
    /// Checks rejection of short slices without modifying failed stores.
    #[cfg(test)]
    ShortMemory,
    /// Checks direct and nested execution, including writes by a portable leaf.
    Execute,
}

struct Instructions<'a, 'b>(Plan, &'a mut Unstructured<'b>);

impl<S: Simd> Operation<S> for Instructions<'_, '_> {
    type Output = arbitrary::Result<()>;

    // Portable execution does not validate native instructions or consume their inputs.
    fn portable(self, _: S) -> Self::Output {
        Ok(())
    }

    fn neon(self, simd: S) -> Self::Output
    where
        S: Neon,
    {
        match self.0 {
            #[cfg(not(miri))]
            Plan::Common => differential::common(simd, EmulatedNeon, self.1),
            #[cfg(not(miri))]
            Plan::Profile => differential::neon(simd, EmulatedNeon, self.1),
            plan => memory(plan, simd, EmulatedNeon, self.1),
        }
    }

    fn ice_lake(self, simd: S) -> Self::Output
    where
        S: IceLake,
    {
        match self.0 {
            #[cfg(not(miri))]
            Plan::Common => differential::common(simd, EmulatedIceLake, self.1),
            #[cfg(not(miri))]
            Plan::Profile => differential::ice_lake(simd, EmulatedIceLake, self.1),
            plan => memory(plan, simd, EmulatedIceLake, self.1),
        }
    }

    fn arm_v9(self, simd: S) -> Self::Output
    where
        S: ArmV9,
    {
        match self.0 {
            #[cfg(not(miri))]
            Plan::Common => differential::common(simd, EmulatedArmV9, self.1),
            #[cfg(not(miri))]
            Plan::Profile => {
                differential::neon(simd, EmulatedArmV9, self.1)?;
                differential::arm_v9(simd, EmulatedArmV9, self.1)
            }
            plan => memory(plan, simd, EmulatedArmV9, self.1),
        }
    }
}

const BOUNDARIES: [u64; 8] = [
    0,
    1,
    u64::MAX,
    u64::MAX - 1,
    1 << 63,
    (1 << 63) - 1,
    0xaaaa_aaaa_aaaa_aaaa,
    0x5555_5555_5555_5555,
];

fn word(u: &mut Unstructured<'_>) -> arbitrary::Result<u64> {
    if u.arbitrary()? {
        u.arbitrary()
    } else {
        Ok(BOUNDARIES[u.int_in_range(0..=BOUNDARIES.len() - 1)?])
    }
}

fn memory<N: Simd, E: Simd>(
    plan: Plan,
    n: N,
    e: E,
    u: &mut Unstructured<'_>,
) -> arbitrary::Result<()> {
    assert_eq!(N::U64_LANES, E::U64_LANES);
    let mut a = [0; 9];
    let mut b = [0; 9];
    for value in a.iter_mut().chain(b.iter_mut()) {
        *value = word(u)?;
    }
    match plan {
        Plan::Load => assert_eq!(
            differential::longs(n, n.u64_load(&a[1..])),
            differential::longs(e, e.u64_load(&a[1..]))
        ),
        Plan::Store => assert_eq!(
            differential::longs(n, n.u64_insert::<1>(n.u64_splat(a[0]), a[1])),
            differential::longs(e, e.u64_insert::<1>(e.u64_splat(a[0]), a[1]))
        ),
        Plan::Splat => assert_eq!(
            differential::longs(n, n.u64_splat(a[0])),
            differential::longs(e, e.u64_splat(a[0]))
        ),
        Plan::Add => assert_eq!(
            differential::longs(n, n.u64_add(n.u64_load(&a[1..]), n.u64_load(&b[1..]))),
            differential::longs(e, e.u64_add(e.u64_load(&a[1..]), e.u64_load(&b[1..])))
        ),
        #[cfg(test)]
        Plan::ShortMemory => {
            let len = u.int_in_range(0..=N::U64_LANES - 1)?;
            check_short(n, a[0], len);
            check_short(e, a[0], len);
        }
        _ => unreachable!("instruction check must select its differential helper"),
    }
    Ok(())
}

#[cfg(test)]
fn check_short<S: Simd>(simd: S, value: u64, len: usize) {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    let mut memory = [value; 10];
    assert!(catch_unwind(AssertUnwindSafe(|| simd.u64_load(&memory[1..1 + len]))).is_err());
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            simd.u64_store(simd.u64_splat(!value), &mut memory[1..1 + len]);
        }))
        .is_err()
    );
    assert_eq!(memory, [value; 10]);
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Path {
    Portable,
    IceLake,
    ArmV9,
    Neon,
}

struct Leaf<'a>(&'a mut [u64; 8]);

impl<S: Simd> Operation<S> for Leaf<'_> {
    type Output = ();

    // Associated constants cannot be used as const generic chunk sizes.
    #[allow(unknown_lints, clippy::chunks_exact_to_as_chunks)]
    fn portable(self, simd: S) {
        for chunk in self.0.chunks_exact_mut(S::U64_LANES) {
            simd.u64_store(simd.u64_add(simd.u64_load(chunk), simd.u64_splat(1)), chunk);
        }
    }
}

struct Child<'a>(&'a mut [u64; 8]);

impl<S: Simd> Operation<S> for Child<'_> {
    type Output = (Path, usize);

    fn portable(self, simd: S) -> Self::Output {
        simd.execute(Leaf(self.0));
        (Path::Portable, S::U64_LANES)
    }

    fn neon(self, simd: S) -> Self::Output
    where
        S: Neon,
    {
        simd.execute(Leaf(self.0));
        (Path::Neon, S::U64_LANES)
    }

    fn ice_lake(self, simd: S) -> Self::Output
    where
        S: IceLake,
    {
        simd.execute(Leaf(self.0));
        (Path::IceLake, S::U64_LANES)
    }

    fn arm_v9(self, simd: S) -> Self::Output
    where
        S: ArmV9,
    {
        simd.execute(Leaf(self.0));
        (Path::ArmV9, S::U64_LANES)
    }
}

struct Parent<O>(O);

impl<S: Simd, O: Operation<S>> Operation<S> for Parent<O> {
    type Output = O::Output;

    fn portable(self, simd: S) -> Self::Output {
        execute_child(simd, self.0)
    }
}

// Keep a consumer frame outlined to test feature-scope reentry through execute.
#[inline(never)]
fn execute_child<S: Simd, O: Operation<S>>(simd: S, child: O) -> O::Output {
    simd.execute(child)
}

fn expected_backend() -> (Path, usize) {
    #[cfg(target_arch = "x86_64")]
    if crate::native::NativeIceLake::new().is_some() {
        return (Path::IceLake, 8);
    }
    #[cfg(target_arch = "aarch64")]
    if crate::native::NativeArmV9::new().is_some() {
        return (Path::ArmV9, 2);
    }
    #[cfg(target_arch = "aarch64")]
    if crate::native::NativeNeon::new().is_some() {
        return (Path::Neon, 2);
    }
    (Path::Portable, 1)
}

impl Plan {
    /// Runs the selected check through runtime dispatch.
    ///
    /// Instruction checks compare native results with the matching emulator.
    /// Portable selection skips those checks without consuming inputs.
    pub fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
        match self {
            Self::Execute => {
                let input: [u64; 8] = u.arbitrary()?;
                let expected = input.map(|v| v.wrapping_add(1));
                let backend = expected_backend();

                let mut direct = input;
                assert_eq!(dispatch(Child(&mut direct)), backend);
                assert_eq!(direct, expected);

                let mut nested = input;
                assert_eq!(dispatch(Parent(Parent(Child(&mut nested)))), backend);
                assert_eq!(nested, expected);

                let mut leaf = input;
                dispatch(Leaf(&mut leaf));
                assert_eq!(leaf, expected);
            }
            plan => dispatch(Instructions(plan, u))?,
        }
        Ok(())
    }
}

#[test]
fn test_execute() {
    commonware_invariants::minifuzz::test(|u| Plan::Execute.run(u));
}

#[test]
fn test_memory() {
    for plan in [
        Plan::Load,
        Plan::Store,
        Plan::Splat,
        Plan::Add,
        Plan::ShortMemory,
    ] {
        commonware_invariants::minifuzz::test(|u| plan.run(u));
    }
}

#[cfg(not(miri))]
#[test]
fn test_common() {
    commonware_invariants::minifuzz::test(|u| Plan::Common.run(u));
}

#[cfg(not(miri))]
#[test]
fn test_profile() {
    commonware_invariants::minifuzz::test(|u| Plan::Profile.run(u));
}

#[test]
fn test_selected_profile() {
    let selected = expected_backend();
    std::eprintln!("instruction differential backend: {selected:?}");
    #[cfg(target_arch = "aarch64")]
    if std::arch::is_aarch64_feature_detected!("neon")
        && std::arch::is_aarch64_feature_detected!("sha2")
    {
        assert!(matches!(selected.0, Path::Neon | Path::ArmV9));
    }
    if selected.0 == Path::Portable {
        let mut u = Unstructured::new(&[1; 32]);
        let len = u.len();
        Plan::Load.run(&mut u).unwrap();
        assert_eq!(u.len(), len);
    }
}
