#![allow(dead_code)] // UI fixtures intentionally declare aliases without constructing them.

use commonware_utils::{Bounded, Bounded as Limit, vec};
use core::num::NonZeroU32;

const POSITIVE: u32 = 1;

type Primitive = Bounded<u32, 1, 100>;
type IndependentNonZero = Bounded<NonZeroU32, 0, 100>;
type BoundedVec = vec::Bounded<NonZeroU32>;
type GenericMinimum<const MIN: u32> = Bounded<NonZeroU32, MIN, 100>;

type Redundant = Bounded<NonZeroU32, 1, 100>;
type Qualified = commonware_utils::Bounded<core::num::NonZeroU64, 1, 100>;
type Direct = Bounded<core::num::NonZero<u32>, 1, 100>;
type Renamed = Limit<NonZeroU32, POSITIVE, 100>;
type Positive = NonZeroU32;
type Aliased = Bounded<Positive, { 1 + 1 }, 100>;

fn accepts_valid(_: Primitive, _: IndependentNonZero, _: BoundedVec) {}
fn rejects_redundant(_: Redundant, _: Qualified, _: Direct, _: Renamed, _: Aliased) {}

#[deny(unfulfilled_lint_expectations)]
mod coverage {
    use super::*;

    type Wrapper<T, const MIN: u32, const MAX: u32> = Bounded<T, MIN, MAX>;
    type Positive<T> = Bounded<T, 1, 100>;
    type PositiveExpression<T> = Bounded<T, { 1 + 1 }, 100>;
    type PositiveConstant<T> = Bounded<T, POSITIVE, 100>;
    type PositiveWrapped<T> = Wrapper<T, { 1 + 1 }, 100>;
    type NonzeroRange<const MIN: u32> = Bounded<NonZeroU32, MIN, 100>;
    type PrimitiveAlias = u32;
    type GenericNonZero<T> = core::num::NonZero<T>;
    type WrappedNonZero<T> = Bounded<core::num::NonZero<T>, 1, 100>;
    type WrappedGenericNonZero<T> = Bounded<GenericNonZero<T>, 1, 100>;
    type OptionalGenericNonZero<T> = Bounded<GenericNonZero<T>, 0, 100>;
    type Optional<T> = Bounded<T, 0, 100>;
    trait HasInteger {
        type Integer;
    }
    struct Source;
    impl HasInteger for Source {
        type Integer = NonZeroU32;
    }
    type Associated = <Source as HasInteger>::Integer;
    type PositivePrimitive = Positive<u32>;
    type ZeroMinimum = NonzeroRange<0>;
    type IndependentAlias = Optional<NonZeroU32>;
    type IndependentPrimitiveAlias = Bounded<core::num::NonZero<PrimitiveAlias>, 0, 100>;
    type IndependentGenericAlias = OptionalGenericNonZero<PrimitiveAlias>;
    type IndependentAssociated = Bounded<Associated, 0, 100>;
    type IndependentDirectAssociated = Bounded<<Source as HasInteger>::Integer, 0, 100>;

    struct AssociatedFields {
        #[expect(redundant_bounded_nonzero)]
        redundant: Bounded<<Source as HasInteger>::Integer, 1, 100>,
        independent: Bounded<<Source as HasInteger>::Integer, 0, 100>,
    }

    #[expect(redundant_bounded_nonzero)]
    type ViaWrapper = Wrapper<NonZeroU32, 1, 100>;

    #[expect(redundant_bounded_nonzero)]
    type ViaPositive = Positive<NonZeroU32>;

    #[expect(redundant_bounded_nonzero)]
    type ViaPositiveExpression = PositiveExpression<NonZeroU32>;

    #[expect(redundant_bounded_nonzero)]
    type ViaPositiveConstant = PositiveConstant<NonZeroU32>;

    #[expect(redundant_bounded_nonzero)]
    type ViaPositiveWrapped = PositiveWrapped<NonZeroU32>;

    #[expect(redundant_bounded_nonzero)]
    type ViaNonzeroRange = NonzeroRange<1>;

    #[expect(redundant_bounded_nonzero)]
    type ViaGenericNonZeroAlias = Bounded<GenericNonZero<u32>, 1, 100>;

    #[expect(redundant_bounded_nonzero)]
    type ViaPrimitiveAlias = Bounded<core::num::NonZero<PrimitiveAlias>, 1, 100>;

    #[expect(redundant_bounded_nonzero)]
    type ViaNestedGenericAlias = Bounded<GenericNonZero<PrimitiveAlias>, 1, 100>;

    #[expect(redundant_bounded_nonzero)]
    type ViaWrappedNonZero = WrappedNonZero<u32>;

    #[expect(redundant_bounded_nonzero)]
    type ViaWrappedGenericNonZero = WrappedGenericNonZero<u32>;

    #[expect(redundant_bounded_nonzero)]
    type ViaAssociated = Bounded<Associated, 1, 100>;

    #[expect(redundant_bounded_nonzero)]
    type ViaDirectAssociated = Bounded<<Source as HasInteger>::Integer, 1, 100>;

    #[expect(redundant_bounded_nonzero)]
    fn rejects_expression() {
        let _ = Bounded::<NonZeroU32, 1, 100>::try_from(1u32);

        #[expect(redundant_bounded_nonzero)]
        let _: Option<Bounded<<Source as HasInteger>::Integer, 1, 100>> = None;
        let _: Option<Bounded<<Source as HasInteger>::Integer, 0, 100>> = None;
    }
}

fn main() {}
