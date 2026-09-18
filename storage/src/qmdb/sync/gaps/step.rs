//! Scalar transition for sync gap scanning.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

/// Result of processing one coverage range.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Step {
    /// The first uncovered interval ends at this location.
    Gap(u64),
    /// Continue scanning from this first uncovered location.
    Advance(u64),
    /// The target interval is fully covered.
    Complete,
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(
    verus_keep_ghost,
    verus_spec(result: Step =>
        requires
            frontier < target_end,
        ensures
            local_laws(
                result,
                frontier as int,
                target_end as int,
                covered_start as int,
                covered_end as int,
            ),
            history_laws(
                result,
                frontier as int,
                target_end as int,
                covered_start as int,
                covered_end as int,
            ),
    )
)]
#[inline]
pub(crate) const fn scan_step(
    frontier: u64,
    target_end: u64,
    covered_start: u64,
    covered_end: u64,
) -> Step {
    if covered_end <= covered_start {
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_advance_histories(
                frontier as int,
                covered_start as int,
                covered_end as int,
                frontier as int,
            );
        }
        return Step::Advance(frontier);
    }

    if frontier < covered_start {
        let gap_end = if covered_start < target_end {
            covered_start
        } else {
            target_end
        };
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_gap_histories(
                frontier as int,
                target_end as int,
                covered_start as int,
                covered_end as int,
                gap_end as int,
            );
        }
        return Step::Gap(gap_end);
    }

    let next_frontier = if frontier < covered_end {
        covered_end
    } else {
        frontier
    };
    if next_frontier >= target_end {
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_complete_histories(
                frontier as int,
                target_end as int,
                covered_start as int,
                covered_end as int,
            );
        }
        Step::Complete
    } else {
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_advance_histories(
                frontier as int,
                covered_start as int,
                covered_end as int,
                next_frontier as int,
            );
        }
        Step::Advance(next_frontier)
    }
}

#[cfg(verus_keep_ghost)]
verus! {

spec fn interval_covers(range: (int, int), point: int) -> bool {
    range.0 < range.1 && range.0 <= point < range.1
}

spec fn covered(ranges: Seq<(int, int)>, point: int) -> bool {
    exists|i: int| 0 <= i < ranges.len() && interval_covers(ranges[i], point)
}

spec fn prefix_covered(ranges: Seq<(int, int)>, start: int, end: int) -> bool {
    forall|point: int| start <= point < end ==> #[trigger] covered(ranges, point)
}

spec fn nonempty_ends_at_most(ranges: Seq<(int, int)>, end: int) -> bool {
    forall|i: int| 0 <= i < ranges.len() && ranges[i].0 < ranges[i].1
        ==> #[trigger] ranges[i].1 <= end
}

spec fn starts_at_least(ranges: Seq<(int, int)>, start: int) -> bool {
    forall|i: int| 0 <= i < ranges.len() ==> start <= #[trigger] ranges[i].0
}

spec fn covered_with_current(
    processed: Seq<(int, int)>,
    current: (int, int),
    remaining: Seq<(int, int)>,
    point: int,
) -> bool {
    covered(processed, point)
        || interval_covers(current, point)
        || covered(remaining, point)
}

spec fn gap_history_law(
    frontier: int,
    target_end: int,
    current: (int, int),
    gap_end: int,
) -> bool {
    forall|processed: Seq<(int, int)>, remaining: Seq<(int, int)>, target_start: int|
        target_start <= frontier
            && prefix_covered(processed, target_start, frontier)
            && nonempty_ends_at_most(processed, frontier)
            && starts_at_least(remaining, current.0)
        ==> prefix_covered(processed, target_start, frontier)
            && (forall|point: int| frontier <= point < gap_end ==>
                !#[trigger] covered_with_current(processed, current, remaining, point))
            && (gap_end == target_end
                || covered_with_current(processed, current, remaining, gap_end))
}

spec fn advance_history_law(frontier: int, current: (int, int), next: int) -> bool {
    forall|processed: Seq<(int, int)>, target_start: int|
        target_start <= frontier
            && prefix_covered(processed, target_start, frontier)
            && nonempty_ends_at_most(processed, frontier)
        ==> prefix_covered(processed.push(current), target_start, next)
            && nonempty_ends_at_most(processed.push(current), next)
}

spec fn complete_history_law(
    frontier: int,
    target_end: int,
    current: (int, int),
) -> bool {
    forall|processed: Seq<(int, int)>, target_start: int|
        target_start <= frontier
            && prefix_covered(processed, target_start, frontier)
            && nonempty_ends_at_most(processed, frontier)
        ==> prefix_covered(processed.push(current), target_start, target_end)
}

spec fn local_laws(
    result: Step,
    frontier: int,
    target_end: int,
    covered_start: int,
    covered_end: int,
) -> bool {
    match result {
        Step::Gap(gap_end) => {
            &&& covered_start < covered_end
            &&& frontier < covered_start
            &&& frontier < gap_end <= target_end
            &&& gap_end == if covered_start < target_end {
                covered_start
            } else {
                target_end
            }
        }
        Step::Advance(next) => {
            &&& frontier <= next < target_end
            &&& if covered_start < covered_end {
                covered_start <= frontier
                    && next == if frontier < covered_end { covered_end } else { frontier }
            } else {
                next == frontier
            }
        }
        Step::Complete => {
            &&& covered_start < covered_end
            &&& covered_start <= frontier
            &&& target_end <= covered_end
        }
    }
}

spec fn history_laws(
    result: Step,
    frontier: int,
    target_end: int,
    covered_start: int,
    covered_end: int,
) -> bool {
    match result {
        Step::Gap(gap_end) => gap_history_law(
            frontier,
            target_end,
            (covered_start, covered_end),
            gap_end as int,
        ),
        Step::Advance(next) => advance_history_law(
            frontier,
            (covered_start, covered_end),
            next as int,
        ),
        Step::Complete => complete_history_law(
            frontier,
            target_end,
            (covered_start, covered_end),
        ),
    }
}

proof fn lemma_push_covers_old(ranges: Seq<(int, int)>, current: (int, int), point: int)
    requires
        covered(ranges, point),
    ensures
        covered(ranges.push(current), point),
{
    let i = choose|i: int| 0 <= i < ranges.len() && interval_covers(ranges[i], point);
    assert(ranges.push(current)[i] == ranges[i]);
}

proof fn lemma_push_covers_current(ranges: Seq<(int, int)>, current: (int, int), point: int)
    requires
        interval_covers(current, point),
    ensures
        covered(ranges.push(current), point),
{
    let i = ranges.len() as int;
    assert(ranges.push(current)[i] == current);
}

proof fn lemma_push_ends_at_most(
    processed: Seq<(int, int)>,
    current: (int, int),
    frontier: int,
    next: int,
)
    requires
        nonempty_ends_at_most(processed, frontier),
        frontier <= next,
        current.0 < current.1 ==> current.1 <= next,
    ensures
        nonempty_ends_at_most(processed.push(current), next),
{
    assert forall|i: int|
        0 <= i < processed.push(current).len()
            && processed.push(current)[i].0 < processed.push(current)[i].1
        implies #[trigger] processed.push(current)[i].1 <= next by {
        if i < processed.len() {
            assert(processed.push(current)[i] == processed[i]);
            assert(processed[i].1 <= frontier);
        } else {
            assert(i == processed.len());
            assert(processed.push(current)[i] == current);
        }
    }
}

proof fn lemma_extend_prefix(
    processed: Seq<(int, int)>,
    target_start: int,
    frontier: int,
    current: (int, int),
    next: int,
)
    requires
        target_start <= frontier,
        prefix_covered(processed, target_start, frontier),
        current.0 < current.1 ==> current.0 <= frontier,
        next == if current.0 < current.1 {
            if frontier < current.1 { current.1 } else { frontier }
        } else {
            frontier
        },
    ensures
        prefix_covered(processed.push(current), target_start, next),
{
    assert forall|point: int| target_start <= point < next implies
        #[trigger] covered(processed.push(current), point) by {
        if point < frontier {
            assert(covered(processed, point));
            lemma_push_covers_old(processed, current, point);
        } else {
            assert(current.0 < current.1);
            assert(frontier < current.1);
            assert(interval_covers(current, point));
            lemma_push_covers_current(processed, current, point);
        }
    }
}

proof fn lemma_advance_histories(
    frontier: int,
    covered_start: int,
    covered_end: int,
    next: int,
)
    requires
        covered_start < covered_end ==> covered_start <= frontier,
        next == if covered_start < covered_end {
            if frontier < covered_end { covered_end } else { frontier }
        } else {
            frontier
        },
    ensures
        advance_history_law(frontier, (covered_start, covered_end), next),
{
    assert forall|processed: Seq<(int, int)>, target_start: int|
        target_start <= frontier
            && prefix_covered(processed, target_start, frontier)
            && nonempty_ends_at_most(processed, frontier)
        implies prefix_covered(
                processed.push((covered_start, covered_end)),
                target_start,
                next,
            )
            && nonempty_ends_at_most(
                processed.push((covered_start, covered_end)),
                next,
            ) by {
        lemma_extend_prefix(
            processed,
            target_start,
            frontier,
            (covered_start, covered_end),
            next,
        );
        lemma_push_ends_at_most(
            processed,
            (covered_start, covered_end),
            frontier,
            next,
        );
    }
}

proof fn lemma_complete_histories(
    frontier: int,
    target_end: int,
    covered_start: int,
    covered_end: int,
)
    requires
        frontier < target_end,
        covered_start < covered_end,
        covered_start <= frontier,
        target_end <= covered_end,
    ensures
        complete_history_law(
            frontier,
            target_end,
            (covered_start, covered_end),
        ),
{
    assert forall|processed: Seq<(int, int)>, target_start: int|
        target_start <= frontier
            && prefix_covered(processed, target_start, frontier)
            && nonempty_ends_at_most(processed, frontier)
        implies prefix_covered(
            processed.push((covered_start, covered_end)),
            target_start,
            target_end,
        ) by {
        lemma_extend_prefix(
            processed,
            target_start,
            frontier,
            (covered_start, covered_end),
            covered_end,
        );
        assert forall|point: int| target_start <= point < target_end implies
            #[trigger] covered(
                processed.push((covered_start, covered_end)),
                point,
            ) by {
            assert(point < covered_end);
        }
    }
}

proof fn lemma_processed_does_not_cover_gap(
    processed: Seq<(int, int)>,
    frontier: int,
    point: int,
)
    requires
        nonempty_ends_at_most(processed, frontier),
        frontier <= point,
    ensures
        !covered(processed, point),
{
    if covered(processed, point) {
        let i = choose|i: int|
            0 <= i < processed.len() && interval_covers(processed[i], point);
        assert(processed[i].1 <= frontier);
        assert(false);
    }
}

proof fn lemma_remaining_does_not_cover_gap(
    remaining: Seq<(int, int)>,
    current_start: int,
    point: int,
)
    requires
        starts_at_least(remaining, current_start),
        point < current_start,
    ensures
        !covered(remaining, point),
{
    if covered(remaining, point) {
        let i = choose|i: int|
            0 <= i < remaining.len() && interval_covers(remaining[i], point);
        assert(current_start <= remaining[i].0);
        assert(false);
    }
}

proof fn lemma_gap_histories(
    frontier: int,
    target_end: int,
    covered_start: int,
    covered_end: int,
    gap_end: int,
)
    requires
        frontier < target_end,
        covered_start < covered_end,
        frontier < covered_start,
        gap_end == if covered_start < target_end { covered_start } else { target_end },
    ensures
        gap_history_law(
            frontier,
            target_end,
            (covered_start, covered_end),
            gap_end,
        ),
{
    assert(frontier < gap_end <= target_end);
    assert(gap_end <= covered_start);
    assert forall|processed: Seq<(int, int)>, remaining: Seq<(int, int)>, target_start: int|
        target_start <= frontier
            && prefix_covered(processed, target_start, frontier)
            && nonempty_ends_at_most(processed, frontier)
            && starts_at_least(remaining, covered_start)
        implies prefix_covered(processed, target_start, frontier)
            && (forall|point: int| frontier <= point < gap_end ==>
                !#[trigger] covered_with_current(
                    processed,
                    (covered_start, covered_end),
                    remaining,
                    point,
                ))
            && (gap_end == target_end
                || covered_with_current(
                    processed,
                    (covered_start, covered_end),
                    remaining,
                    gap_end,
                )) by {
        assert forall|point: int| frontier <= point < gap_end implies
            !#[trigger] covered_with_current(
                processed,
                (covered_start, covered_end),
                remaining,
                point,
            ) by {
            lemma_processed_does_not_cover_gap(processed, frontier, point);
            lemma_remaining_does_not_cover_gap(remaining, covered_start, point);
            assert(!interval_covers((covered_start, covered_end), point));
        }
        if gap_end != target_end {
            assert(gap_end == covered_start);
            assert(interval_covers((covered_start, covered_end), gap_end));
        }
    }
}

}
