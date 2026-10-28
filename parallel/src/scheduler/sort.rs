//! **Parallel** stable slice sorting.
//!
//! This implementation is mostly copied from the `core::slice::sort` module, with minimal changes
//! to support stable Rust and parallel `is_less` (e.g. `Fn` rather than `FnMut`).
//!
//! It contains the core logic of the stable sort used by `slice::sort` based on TimSort, which
//! merge sorts chunks of the slice in parallel and then merges the chunks in parallel.

use super::{SendPtr, join};
use core::{cmp, mem, ptr, slice};

// When dropped, copies from `src` into `dest`.
struct InsertionHole<T> {
    src: *const T,
    dest: *mut T,
}

impl<T> Drop for InsertionHole<T> {
    fn drop(&mut self) {
        // SAFETY: This is a helper class. Please refer to its usage for correctness. Namely, one
        // must be sure that `src` and `dst` does not overlap as required by
        // `ptr::copy_nonoverlapping` and are both valid for writes.
        unsafe {
            ptr::copy_nonoverlapping(self.src, self.dest, 1);
        }
    }
}

/// Inserts `v[v.len() - 1]` into pre-sorted sequence `v[..v.len() - 1]` so that whole `v[..]`
/// becomes sorted.
unsafe fn insert_tail<T, F>(v: &mut [T], is_less: &F)
where
    F: Fn(&T, &T) -> bool,
{
    debug_assert!(v.len() >= 2);

    let arr_ptr = v.as_mut_ptr();
    let i = v.len() - 1;

    // SAFETY: caller must ensure v is at least len 2.
    unsafe {
        // See insert_head which talks about why this approach is beneficial.
        let i_ptr = arr_ptr.add(i);

        // It's important that we use i_ptr here. If this check is positive and we continue,
        // We want to make sure that no other copy of the value was seen by is_less.
        // Otherwise we would have to copy it back.
        if is_less(&*i_ptr, &*i_ptr.sub(1)) {
            // It's important, that we use tmp for comparison from now on. As it is the value that
            // will be copied back. And notionally we could have created a divergence if we copy
            // back the wrong value.
            let tmp = mem::ManuallyDrop::new(ptr::read(i_ptr));
            // Intermediate state of the insertion process is always tracked by `hole`, which
            // serves two purposes:
            // 1. Protects integrity of `v` from panics in `is_less`.
            // 2. Fills the remaining hole in `v` in the end.
            //
            // Panic safety:
            //
            // If `is_less` panics at any point during the process, `hole` will get dropped and
            // fill the hole in `v` with `tmp`, thus ensuring that `v` still holds every object it
            // initially held exactly once.
            let mut hole = InsertionHole {
                src: &*tmp,
                dest: i_ptr.sub(1),
            };
            ptr::copy_nonoverlapping(hole.dest, i_ptr, 1);

            // SAFETY: We know i is at least 1.
            for j in (0..(i - 1)).rev() {
                let j_ptr = arr_ptr.add(j);
                if !is_less(&*tmp, &*j_ptr) {
                    break;
                }

                ptr::copy_nonoverlapping(j_ptr, hole.dest, 1);
                hole.dest = j_ptr;
            }
            // `hole` gets dropped and thus copies `tmp` into the remaining hole in `v`.
        }
    }
}

/// Sort `v` assuming `v[..offset]` is already sorted.
///
/// Never inline this function to avoid code bloat. It still optimizes nicely and has practically no
/// performance impact. Even improving performance in some cases.
#[inline(never)]
fn insertion_sort_shift_left<T, F>(v: &mut [T], offset: usize, is_less: &F)
where
    F: Fn(&T, &T) -> bool,
{
    let len = v.len();

    // Using assert here improves performance.
    assert!(offset != 0 && offset <= len);

    // Shift each element of the unsorted region v[i..] as far left as is needed to make v sorted.
    for i in offset..len {
        // SAFETY: we tested that `offset` must be at least 1, so this loop is only entered if len
        // >= 2. The range is exclusive and we know `i` must be at least 1 so this slice has at
        // >least len 2.
        unsafe {
            insert_tail(&mut v[..=i], is_less);
        }
    }
}

/// Merges non-decreasing runs `v[..mid]` and `v[mid..]` using `buf` as temporary storage, and
/// stores the result into `v[..]`.
///
/// # Safety
///
/// The two slices must be non-empty and `mid` must be in bounds. Buffer `buf` must be long enough
/// to hold a copy of the shorter slice. Also, `T` must not be a zero-sized type.
unsafe fn merge<T, F>(v: &mut [T], mid: usize, buf: *mut T, is_less: &F)
where
    F: Fn(&T, &T) -> bool,
{
    let len = v.len();
    let v = v.as_mut_ptr();

    // SAFETY: mid and len must be in-bounds of v.
    let (v_mid, v_end) = unsafe { (v.add(mid), v.add(len)) };

    // The merge process first copies the shorter run into `buf`. Then it traces the newly copied
    // run and the longer run forwards (or backwards), comparing their next unconsumed elements and
    // copying the lesser (or greater) one into `v`.
    //
    // As soon as the shorter run is fully consumed, the process is done. If the longer run gets
    // consumed first, then we must copy whatever is left of the shorter run into the remaining
    // hole in `v`.
    //
    // Intermediate state of the process is always tracked by `hole`, which serves two purposes:
    // 1. Protects integrity of `v` from panics in `is_less`.
    // 2. Fills the remaining hole in `v` if the longer run gets consumed first.
    //
    // Panic safety:
    //
    // If `is_less` panics at any point during the process, `hole` will get dropped and fill the
    // hole in `v` with the unconsumed range in `buf`, thus ensuring that `v` still holds every
    // object it initially held exactly once.
    let mut hole;

    if mid <= len - mid {
        // The left run is shorter.

        // SAFETY: buf must have enough capacity for `v[..mid]`.
        unsafe {
            ptr::copy_nonoverlapping(v, buf, mid);
            hole = MergeHole {
                start: buf,
                end: buf.add(mid),
                dest: v,
            };
        }

        // Initially, these pointers point to the beginnings of their arrays.
        let left = &mut hole.start;
        let mut right = v_mid;
        let out = &mut hole.dest;

        while *left < hole.end && right < v_end {
            // Consume the lesser side.
            // If equal, prefer the left run to maintain stability.

            // SAFETY: left and right must be valid and part of v same for out.
            unsafe {
                let is_l = is_less(&*right, &**left);
                let to_copy = if is_l { right } else { *left };
                ptr::copy_nonoverlapping(to_copy, *out, 1);
                *out = out.add(1);
                right = right.add(is_l as usize);
                *left = left.add(!is_l as usize);
            }
        }
    } else {
        // The right run is shorter.

        // SAFETY: buf must have enough capacity for `v[mid..]`.
        unsafe {
            ptr::copy_nonoverlapping(v_mid, buf, len - mid);
            hole = MergeHole {
                start: buf,
                end: buf.add(len - mid),
                dest: v_mid,
            };
        }

        // Initially, these pointers point past the ends of their arrays.
        let left = &mut hole.dest;
        let right = &mut hole.end;
        let mut out = v_end;

        while v < *left && buf < *right {
            // Consume the greater side.
            // If equal, prefer the right run to maintain stability.

            // SAFETY: left and right must be valid and part of v same for out.
            unsafe {
                let is_l = is_less(&*right.sub(1), &*left.sub(1));
                *left = left.sub(is_l as usize);
                *right = right.sub(!is_l as usize);
                let to_copy = if is_l { *left } else { *right };
                out = out.sub(1);
                ptr::copy_nonoverlapping(to_copy, out, 1);
            }
        }
    }
    // Finally, `hole` gets dropped. If the shorter run was not fully consumed, whatever remains of
    // it will now be copied into the hole in `v`.
}

// When dropped, copies the range `start..end` into `dest..`.
struct MergeHole<T> {
    start: *mut T,
    end: *mut T,
    dest: *mut T,
}

impl<T> Drop for MergeHole<T> {
    fn drop(&mut self) {
        // SAFETY: `T` is not a zero-sized type, and these are pointers into a slice's elements.
        unsafe {
            let len = self.end.offset_from(self.start) as usize;
            ptr::copy_nonoverlapping(self.start, self.dest, len);
        }
    }
}

/// The result of merge sort.
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq)]
enum MergeSortResult {
    /// The slice has already been sorted.
    NonDescending,
    /// The slice has been descending and therefore it was left intact.
    Descending,
    /// The slice was sorted.
    Sorted,
}

/// This merge sort borrows some (but not all) ideas from TimSort, which used to be described in
/// detail [here](https://github.com/python/cpython/blob/main/Objects/listsort.txt). However Python
/// has switched to a Powersort based implementation.
///
/// The algorithm identifies strictly descending and non-descending subsequences, which are called
/// natural runs. There is a stack of pending runs yet to be merged. Each newly found run is pushed
/// onto the stack, and then some pairs of adjacent runs are merged until these two invariants are
/// satisfied:
///
/// 1. for every `i` in `1..runs.len()`: `runs[i - 1].len > runs[i].len`
/// 2. for every `i` in `2..runs.len()`: `runs[i - 2].len > runs[i - 1].len + runs[i].len`
///
/// The invariants ensure that the total running time is *O*(*n* \* log(*n*)) worst-case.
///
/// # Safety
///
/// The argument `buf` is used as a temporary buffer and must hold at least `v.len() / 2`.
unsafe fn merge_sort<T, CmpF>(v: &mut [T], buf_ptr: *mut T, is_less: &CmpF) -> MergeSortResult
where
    CmpF: Fn(&T, &T) -> bool,
{
    // The caller should have already checked that.
    debug_assert_ne!(size_of::<T>(), 0);

    let len = v.len();

    let mut runs = Vec::new();

    let mut end = 0;
    let mut start = 0;

    // Scan forward. Memory pre-fetching prefers forward scanning vs backwards scanning, and the
    // code-gen is usually better. For the most sensitive types such as integers, these are merged
    // bidirectionally at once. So there is no benefit in scanning backwards.
    while end < len {
        let (streak_end, was_reversed) = find_streak(&v[start..], is_less);
        end += streak_end;
        if start == 0 && end == len {
            return if was_reversed {
                MergeSortResult::Descending
            } else {
                MergeSortResult::NonDescending
            };
        }
        if was_reversed {
            v[start..end].reverse();
        }

        // Insert some more elements into the run if it's too short. Insertion sort is faster than
        // merge sort on short sequences, so this significantly improves performance.
        end = provide_sorted_batch(v, start, end, is_less);

        // Push this run onto the stack.
        runs.push(TimSortRun {
            start,
            len: end - start,
        });
        start = end;

        // Merge some pairs of adjacent runs to satisfy the invariants.
        while let Some(r) = collapse(runs.as_slice(), len) {
            let left = runs[r];
            let right = runs[r + 1];
            let merge_slice = &mut v[left.start..right.start + right.len];
            // SAFETY: `buf_ptr` must hold enough capacity for the shorter of the two sides, and
            // neither side may be on length 0.
            unsafe {
                merge(merge_slice, left.len, buf_ptr, is_less);
            }
            runs[r + 1] = TimSortRun {
                start: left.start,
                len: left.len + right.len,
            };
            runs.remove(r);
        }
    }

    // Finally, exactly one run must remain in the stack.
    debug_assert!(runs.len() == 1 && runs[0].start == 0 && runs[0].len == len);

    // The original order of the slice was neither non-descending nor descending.
    return MergeSortResult::Sorted;

    // Examines the stack of runs and identifies the next pair of runs to merge. More specifically,
    // if `Some(r)` is returned, that means `runs[r]` and `runs[r + 1]` must be merged next. If the
    // algorithm should continue building a new run instead, `None` is returned.
    //
    // TimSort is infamous for its buggy implementations, as described here:
    // http://envisage-project.eu/timsort-specification-and-verification/
    //
    // The gist of the story is: we must enforce the invariants on the top four runs on the stack.
    // Enforcing them on just top three is not sufficient to ensure that the invariants will still
    // hold for *all* runs in the stack.
    //
    // This function correctly checks invariants for the top four runs. Additionally, if the top
    // run starts at index 0, it will always demand a merge operation until the stack is fully
    // collapsed, in order to complete the sort.
    #[inline]
    const fn collapse(runs: &[TimSortRun], stop: usize) -> Option<usize> {
        let n = runs.len();
        if n >= 2
            && (runs[n - 1].start + runs[n - 1].len == stop
                || runs[n - 2].len <= runs[n - 1].len
                || (n >= 3 && runs[n - 3].len <= runs[n - 2].len + runs[n - 1].len)
                || (n >= 4 && runs[n - 4].len <= runs[n - 3].len + runs[n - 2].len))
        {
            if n >= 3 && runs[n - 3].len < runs[n - 1].len {
                Some(n - 3)
            } else {
                Some(n - 2)
            }
        } else {
            None
        }
    }
}

/// Internal type used by merge_sort.
#[derive(Clone, Copy, Debug)]
struct TimSortRun {
    len: usize,
    start: usize,
}

/// Takes a range as denoted by start and end, that is already sorted and extends it to the right if
/// necessary with sorts optimized for smaller ranges such as insertion sort.
fn provide_sorted_batch<T, F>(v: &mut [T], start: usize, mut end: usize, is_less: &F) -> usize
where
    F: Fn(&T, &T) -> bool,
{
    let len = v.len();
    assert!(end >= start && end <= len);

    // This value is a balance between least comparisons and best performance, as
    // influenced by for example cache locality.
    const MIN_INSERTION_RUN: usize = 10;

    // Insert some more elements into the run if it's too short. Insertion sort is faster than
    // merge sort on short sequences, so this significantly improves performance.
    let start_end_diff = end - start;

    if start_end_diff < MIN_INSERTION_RUN && end < len {
        // v[start_found..end] are elements that are already sorted in the input. We want to extend
        // the sorted region to the left, so we push up MIN_INSERTION_RUN - 1 to the right. Which is
        // more efficient that trying to push those already sorted elements to the left.
        end = cmp::min(start + MIN_INSERTION_RUN, len);
        let presorted_start = cmp::max(start_end_diff, 1);

        insertion_sort_shift_left(&mut v[start..end], presorted_start, is_less);
    }

    end
}

/// Finds a streak of presorted elements starting at the beginning of the slice. Returns the first
/// value that is not part of said streak, and a bool denoting whether the streak was reversed.
/// Streaks can be increasing or decreasing.
fn find_streak<T, F>(v: &[T], is_less: &F) -> (usize, bool)
where
    F: Fn(&T, &T) -> bool,
{
    let len = v.len();

    if len < 2 {
        return (len, false);
    }

    let mut end = 2;

    // SAFETY: See below specific.
    unsafe {
        // SAFETY: We checked that len >= 2, so 0 and 1 are valid indices.
        let assume_reverse = is_less(v.get_unchecked(1), v.get_unchecked(0));

        // SAFETY: We know end >= 2 and check end < len.
        // From that follows that accessing v at end and end - 1 is safe.
        if assume_reverse {
            while end < len && is_less(v.get_unchecked(end), v.get_unchecked(end - 1)) {
                end += 1;
            }

            (end, true)
        } else {
            while end < len && !is_less(v.get_unchecked(end), v.get_unchecked(end - 1)) {
                end += 1;
            }
            (end, false)
        }
    }
}

// Everything above is copied from `core::slice::sort` (with very minor tweaks). Everything below
// parallelizes the sort on the scheduler.

/// Splits two sorted slices so that they can be merged in parallel.
///
/// Returns two indices `(a, b)` so that slices `left[..a]` and `right[..b]` come before
/// `left[a..]` and `right[b..]`.
fn split_for_merge<T, F>(left: &[T], right: &[T], is_less: &F) -> (usize, usize)
where
    F: Fn(&T, &T) -> bool,
{
    let left_len = left.len();
    let right_len = right.len();

    if left_len >= right_len {
        let left_mid = left_len / 2;

        // Find the first element in `right` that is greater than or equal to `left[left_mid]`.
        let mut a = 0;
        let mut b = right_len;
        while a < b {
            let m = a + (b - a) / 2;
            if is_less(&right[m], &left[left_mid]) {
                a = m + 1;
            } else {
                b = m;
            }
        }

        (left_mid, a)
    } else {
        let right_mid = right_len / 2;

        // Find the first element in `left` that is greater than `right[right_mid]`.
        let mut a = 0;
        let mut b = left_len;
        while a < b {
            let m = a + (b - a) / 2;
            if is_less(&right[right_mid], &left[m]) {
                b = m;
            } else {
                a = m + 1;
            }
        }

        (a, right_mid)
    }
}

/// Merges slices `left` and `right` in parallel and stores the result into `dest`.
///
/// # Safety
///
/// The `dest` pointer must have enough space to store the result.
///
/// Even if `is_less` panics at any point during the merge process, this function will fully copy
/// all elements from `left` and `right` into `dest` (not necessarily in sorted order).
unsafe fn par_merge<T, F>(left: &mut [T], right: &mut [T], dest: *mut T, is_less: &F)
where
    T: Send,
    F: Fn(&T, &T) -> bool + Sync,
{
    // Slices whose lengths sum up to this value are merged sequentially. This number is slightly
    // larger than `CHUNK_LENGTH`, and the reason is that merging is faster than merge sorting, so
    // merging needs a bit coarser granularity in order to hide the overhead of the scheduler's task
    // scheduling.
    const MAX_SEQUENTIAL: usize = 5000;

    let left_len = left.len();
    let right_len = right.len();

    // Intermediate state of the merge process, which serves two purposes:
    // 1. Protects integrity of `dest` from panics in `is_less`.
    // 2. Copies the remaining elements as soon as one of the two sides is exhausted.
    //
    // Panic safety:
    //
    // If `is_less` panics at any point during the merge process, `s` will get dropped and copy the
    // remaining parts of `left` and `right` into `dest`.
    let mut s = State {
        left_start: left.as_mut_ptr(),
        // SAFETY: one past the end of a slice is in bounds of its allocation.
        left_end: unsafe { left.as_mut_ptr().add(left_len) },
        right_start: right.as_mut_ptr(),
        // SAFETY: one past the end of a slice is in bounds of its allocation.
        right_end: unsafe { right.as_mut_ptr().add(right_len) },
        dest,
    };

    if left_len == 0 || right_len == 0 || left_len + right_len < MAX_SEQUENTIAL {
        while s.left_start < s.left_end && s.right_start < s.right_end {
            // Consume the lesser side.
            // If equal, prefer the left run to maintain stability.

            // SAFETY: both cursors point at unconsumed elements of their slices, and `dest` has
            // room for every element not yet copied, as the caller guarantees.
            unsafe {
                let is_l = is_less(&*s.right_start, &*s.left_start);
                let to_copy = if is_l { s.right_start } else { s.left_start };
                ptr::copy_nonoverlapping(to_copy, s.dest, 1);
                s.dest = s.dest.add(1);
                s.right_start = s.right_start.add(is_l as usize);
                s.left_start = s.left_start.add(!is_l as usize);
            }
        }
    } else {
        // Function `split_for_merge` might panic. If that happens, `s` will get destructed and copy
        // the whole `left` and `right` into `dest`.
        let (left_mid, right_mid) = split_for_merge(left, right, is_less);
        let (left_l, left_r) = left.split_at_mut(left_mid);
        let (right_l, right_r) = right.split_at_mut(right_mid);

        // Prevent the destructor of `s` from running. The scheduler will ensure that both calls to
        // `par_merge` happen. If one of the two calls panics, they will ensure that elements still
        // get copied into `dest_left` and `dest_right``.
        mem::forget(s);

        // Wrap pointers in SendPtr so that they can be sent to another thread
        // See the documentation of SendPtr for a full explanation
        let dest_l = SendPtr(dest);
        // SAFETY: the left halves fill the start of `dest`, which has room for both halves.
        let dest_r = SendPtr(unsafe { dest.add(left_l.len() + right_l.len()) });
        join(
            // SAFETY: each half merges into its own disjoint part of `dest`.
            move || unsafe { par_merge(left_l, right_l, dest_l.get(), is_less) },
            // SAFETY: each half merges into its own disjoint part of `dest`.
            move || unsafe { par_merge(left_r, right_r, dest_r.get(), is_less) },
        );
    }
    // Finally, `s` gets dropped if we used sequential merge, thus copying the remaining elements
    // all at once.

    // When dropped, copies arrays `left_start..left_end` and `right_start..right_end` into `dest`,
    // in that order.
    struct State<T> {
        left_start: *mut T,
        left_end: *mut T,
        right_start: *mut T,
        right_end: *mut T,
        dest: *mut T,
    }

    impl<T> Drop for State<T> {
        fn drop(&mut self) {
            // Copy array `left`, followed by `right`.

            // SAFETY: the cursors bound the unconsumed parts of both slices, and `dest` has room
            // for exactly those elements.
            unsafe {
                let left_len = self.left_end.offset_from(self.left_start) as usize;
                ptr::copy_nonoverlapping(self.left_start, self.dest, left_len);
                self.dest = self.dest.add(left_len);

                let right_len = self.right_end.offset_from(self.right_start) as usize;
                ptr::copy_nonoverlapping(self.right_start, self.dest, right_len);
            }
        }
    }
}

/// Recursively merges pre-sorted chunks inside `v`.
///
/// Chunks of `v` are stored in `chunks` as intervals (inclusive left and exclusive right bound).
/// Argument `buf` is an auxiliary buffer that will be used during the procedure.
/// If `into_buf` is true, the result will be stored into `buf`, otherwise it will be in `v`.
///
/// # Safety
///
/// The number of chunks must be positive and they must be adjacent: the right bound of each chunk
/// must equal the left bound of the following chunk.
///
/// The buffer must be at least as long as `v`.
unsafe fn merge_recurse<T, F>(
    v: *mut T,
    buf: *mut T,
    chunks: &[(usize, usize)],
    into_buf: bool,
    is_less: &F,
) where
    T: Send,
    F: Fn(&T, &T) -> bool + Sync,
{
    let len = chunks.len();
    debug_assert!(len > 0);

    // Base case of the algorithm.
    // If only one chunk is remaining, there's no more work to split and merge.
    if len == 1 {
        if into_buf {
            // Copy the chunk from `v` into `buf`.
            let (start, end) = chunks[0];
            // SAFETY: the chunk lies within `v`, and `buf` is at least as long as `v`.
            unsafe {
                let src = v.add(start);
                let dest = buf.add(start);
                ptr::copy_nonoverlapping(src, dest, end - start);
            }
        }
        return;
    }

    // Split the chunks into two halves.
    let (start, _) = chunks[0];
    let (mid, _) = chunks[len / 2];
    let (_, end) = chunks[len - 1];
    let (left, right) = chunks.split_at(len / 2);

    // After recursive calls finish we'll have to merge chunks `(start, mid)` and `(mid, end)` from
    // `src` into `dest`. If the current invocation has to store the result into `buf`, we'll
    // merge chunks from `v` into `buf`, and vice versa.
    //
    // Recursive calls flip `into_buf` at each level of recursion. More concretely, `par_merge`
    // merges chunks from `buf` into `v` at the first level, from `v` into `buf` at the second
    // level etc.
    let (src, dest) = if into_buf { (v, buf) } else { (buf, v) };

    // Panic safety:
    //
    // If `is_less` panics at any point during the recursive calls, the destructor of `guard` will
    // be executed, thus copying everything from `src` into `dest`. This way we ensure that all
    // chunks are in fact copied into `dest`, even if the merge process doesn't finish.

    // SAFETY: the chunks lie within `v`, and `buf` is at least as long as `v`.
    let guard = unsafe {
        MergeHole {
            start: src.add(start),
            end: src.add(end),
            dest: dest.add(start),
        }
    };

    // Wrap pointers in SendPtr so that they can be sent to another thread
    // See the documentation of SendPtr for a full explanation
    let v = SendPtr(v);
    let buf = SendPtr(buf);
    join(
        // SAFETY: each half of the chunks is adjacent and covers its own part of `v` and `buf`.
        move || unsafe { merge_recurse(v.get(), buf.get(), left, !into_buf, is_less) },
        // SAFETY: each half of the chunks is adjacent and covers its own part of `v` and `buf`.
        move || unsafe { merge_recurse(v.get(), buf.get(), right, !into_buf, is_less) },
    );

    // Everything went all right - recursive calls didn't panic.
    // Forget the guard in order to prevent its destructor from running.
    mem::forget(guard);

    // Merge chunks `(start, mid)` and `(mid, end)` from `src` into `dest`.

    // SAFETY: the recursive calls left both sorted halves in `src`, and `dest` has room for both.
    unsafe {
        let src_left = slice::from_raw_parts_mut(src.add(start), mid - start);
        let src_right = slice::from_raw_parts_mut(src.add(mid), end - mid);
        par_merge(src_left, src_right, dest.add(start), is_less);
    }
}

/// Merge sorts each chunk of `v` in parallel, recording each chunk's bounds and result in
/// `results`, one entry per chunk in order. Every chunk but the last has `chunk_length` elements.
///
/// # Safety
///
/// `buf` must point at the element of the scratch buffer that matches `v[0]`, with room for
/// `v.len()` elements, and `start` must be the index of `v[0]` in the slice being sorted.
unsafe fn sort_chunks<T, F>(
    v: &mut [T],
    start: usize,
    chunk_length: usize,
    buf: SendPtr<T>,
    results: &mut [(usize, usize, MergeSortResult)],
    is_less: &F,
) where
    T: Send,
    F: Fn(&T, &T) -> bool + Sync,
{
    if let [result] = results {
        // SAFETY: the chunk has its own part of the buffer, which holds at least half its length.
        *result = (start, start + v.len(), unsafe {
            merge_sort(v, buf.get(), is_less)
        });
        return;
    }

    // Split the chunks into two halves.
    let (left_results, right_results) = results.split_at_mut(results.len() / 2);
    let split = left_results.len() * chunk_length;
    let (left, right) = v.split_at_mut(split);
    // SAFETY: the right half starts `split` elements into `v`, so its buffer does too.
    let right_buf = SendPtr(unsafe { buf.get().add(split) });
    join(
        // SAFETY: each half sorts its own part of `v` in its own part of the buffer.
        move || unsafe { sort_chunks(left, start, chunk_length, buf, left_results, is_less) },
        // SAFETY: each half sorts its own part of `v` in its own part of the buffer.
        move || unsafe {
            sort_chunks(
                right,
                start + split,
                chunk_length,
                right_buf,
                right_results,
                is_less,
            )
        },
    );
}

/// Sorts `v` using merge sort in parallel.
///
/// The algorithm is stable, allocates memory, and `O(n log n)` worst-case.
/// The allocated temporary buffer is of the same length as is `v`.
///
/// It must run on a worker of a thread pool, since it splits its work with [`join()`].
pub(crate) fn par_mergesort<T, F>(v: &mut [T], is_less: F)
where
    T: Send,
    F: Fn(&T, &T) -> bool + Sync,
{
    // Slices of up to this length get sorted using insertion sort in order to avoid the cost of
    // buffer allocation.
    const MAX_INSERTION: usize = 20;

    // The length of initial chunks. This number is as small as possible but so that the overhead
    // of the scheduler's task scheduling is still negligible.
    const CHUNK_LENGTH: usize = 2000;

    // Sorting has no meaningful behavior on zero-sized types.
    if size_of::<T>() == 0 {
        return;
    }

    let len = v.len();

    // Short slices get sorted in-place via insertion sort to avoid allocations.
    if len <= MAX_INSERTION {
        if len >= 2 {
            insertion_sort_shift_left(v, 1, &is_less);
        }
        return;
    }

    // Allocate a buffer to use as scratch memory. We keep the length 0 so we can keep in it
    // shallow copies of the contents of `v` without risking the dtors running on copies if
    // `is_less` panics.
    let mut buf = Vec::<T>::with_capacity(len);
    let buf = buf.as_mut_ptr();

    // If the slice is not longer than one chunk would be, do sequential merge sort and return.
    if len <= CHUNK_LENGTH {
        // SAFETY: the buffer holds `len` elements, at least half the slice.
        let res = unsafe { merge_sort(v, buf, &is_less) };
        if res == MergeSortResult::Descending {
            v.reverse();
        }
        return;
    }

    // Split the slice into chunks and merge sort them in parallel.
    // However, descending chunks will not be sorted - they will be simply left intact.
    let mut results = vec![(0, 0, MergeSortResult::Sorted); len.div_ceil(CHUNK_LENGTH)];
    // SAFETY: the buffer holds `len` elements and starts at the element matching `v[0]`.
    unsafe {
        sort_chunks(v, 0, CHUNK_LENGTH, SendPtr(buf), &mut results, &is_less);
    }
    let mut iter = results.into_iter().peekable();

    // Now attempt to concatenate adjacent chunks that were left intact.
    let mut chunks = Vec::with_capacity(iter.len());

    while let Some((a, mut b, res)) = iter.next() {
        // If this chunk was not modified by the sort procedure...
        if res != MergeSortResult::Sorted {
            while let Some(&(x, y, r)) = iter.peek() {
                // If the following chunk is of the same type and can be concatenated...
                if r == res && (r == MergeSortResult::Descending) == is_less(&v[x], &v[x - 1]) {
                    // Concatenate them.
                    b = y;
                    iter.next();
                } else {
                    break;
                }
            }
        }

        // Descending chunks must be reversed.
        if res == MergeSortResult::Descending {
            v[a..b].reverse();
        }

        chunks.push((a, b));
    }

    // All chunks are properly sorted.
    // Now we just have to merge them together.

    // SAFETY: the chunks are adjacent and cover `v`, and the buffer is as long as `v`.
    unsafe {
        merge_recurse(v.as_mut_ptr(), buf, &chunks, false, &is_less);
    }
}

#[cfg(test)]
mod tests {
    use super::{par_mergesort, split_for_merge};
    use crate::scheduler::{Placement, ThreadPoolBuilder};
    use commonware_utils::test_rng;
    use rand::RngExt as _;
    use std::{
        panic::{self, AssertUnwindSafe},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    /// Sorts `v` on a worker of a new pool, as the strategy does.
    fn sort_in_pool<T: Send>(v: &mut [T], is_less: impl Fn(&T, &T) -> bool + Send + Sync) {
        ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap()
            .install_in(Placement::Wide { near: 0 }, || par_mergesort(v, is_less));
    }

    #[test]
    fn test_split_for_merge() {
        fn check(left: &[u32], right: &[u32]) {
            let (l, r) = split_for_merge(left, right, &|&a, &b| a < b);
            assert!(
                left[..l]
                    .iter()
                    .all(|&x| right[r..].iter().all(|&y| x <= y))
            );
            assert!(right[..r].iter().all(|&x| left[l..].iter().all(|&y| x < y)));
        }

        check(&[1, 2, 2, 2, 2, 3], &[1, 2, 2, 2, 2, 3]);
        check(&[1, 2, 2, 2, 2, 3], &[]);
        check(&[], &[1, 2, 2, 2, 2, 3]);

        let rng = &mut test_rng();

        for _ in 0..100 {
            let limit: u32 = rng.random_range(1..21);
            let left_len: usize = rng.random_range(0..20);
            let right_len: usize = rng.random_range(0..20);

            let mut left = (0..left_len)
                .map(|_| rng.random_range(0..limit))
                .collect::<Vec<_>>();
            let mut right = (0..right_len)
                .map(|_| rng.random_range(0..limit))
                .collect::<Vec<_>>();

            left.sort();
            right.sort();
            check(&left, &right);
        }
    }

    /// The sort matches the standard stable sort at insertion, single-chunk, and multi-chunk
    /// lengths, keeping equal keys in input order.
    #[test]
    fn sorts_stably_at_every_length() {
        let mut rng = test_rng();
        for len in [
            0, 1, 2, 20, 21, 1999, 2000, 2001, 4000, 4001, 10_007, 50_000,
        ] {
            for modulus in [4u32, 1_000_000] {
                let input: Vec<(u32, usize)> = (0..len)
                    .map(|index| (rng.random_range(0..modulus), index))
                    .collect();
                let mut expected = input.clone();
                expected.sort_by_key(|&(key, _)| key);
                let mut sorted = input;
                sort_in_pool(&mut sorted, |a, b| a.0 < b.0);
                assert_eq!(sorted, expected, "len={len} modulus={modulus}");
            }
        }
    }

    /// Ascending and descending inputs, whole or one chunk at a time, take the paths that leave
    /// chunks intact, reverse descending ones, and concatenate neighbors before merging.
    #[test]
    fn sorts_presorted_runs() {
        let len = 10_000u32;
        let ascending: Vec<u32> = (0..len).collect();
        let descending: Vec<u32> = (0..len).rev().collect();
        let descending_chunks: Vec<u32> = (0..len)
            .map(|i| (i / 2000) * 2000 + (1999 - i % 2000))
            .collect();
        let descending_pairs: Vec<(u32, u32)> = (0..len).map(|i| ((len - i) / 2, i)).collect();
        for input in [ascending, descending, descending_chunks] {
            let mut expected = input.clone();
            expected.sort();
            let mut sorted = input;
            sort_in_pool(&mut sorted, |a, b| a < b);
            assert_eq!(sorted, expected);
        }
        let mut expected = descending_pairs.clone();
        expected.sort_by_key(|&(key, _)| key);
        let mut sorted = descending_pairs;
        sort_in_pool(&mut sorted, |a, b| a.0 < b.0);
        assert_eq!(sorted, expected);
    }

    /// Sorting zero-sized values does nothing.
    #[test]
    fn sorts_zero_sized_values() {
        let mut values = vec![(); 5000];
        sort_in_pool(&mut values, |_, _| {
            panic!("zero-sized values are never compared")
        });
        assert_eq!(values.len(), 5000);
    }

    /// A comparator that panics partway leaves every element in the slice exactly once.
    #[test]
    fn a_panicking_comparator_keeps_every_element() {
        // Each element counts its drops, so an element lost or duplicated by the sort changes the
        // count.
        struct Tracked {
            value: u32,
            drops: Arc<AtomicUsize>,
        }
        impl Drop for Tracked {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::SeqCst);
            }
        }

        let len = 10_000;
        let drops = Arc::new(AtomicUsize::new(0));
        let mut rng = test_rng();
        let mut tracked: Vec<Tracked> = (0..len)
            .map(|_| Tracked {
                value: rng.random(),
                drops: Arc::clone(&drops),
            })
            .collect();
        let mut expected: Vec<u32> = tracked.iter().map(|element| element.value).collect();
        let comparisons = AtomicUsize::new(0);
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            sort_in_pool(&mut tracked, |a, b| {
                assert_ne!(
                    comparisons.fetch_add(1, Ordering::Relaxed),
                    50_000,
                    "comparator failed"
                );
                a.value < b.value
            })
        }));
        assert!(result.is_err());
        assert_eq!(drops.load(Ordering::SeqCst), 0);

        let mut values: Vec<u32> = tracked.iter().map(|element| element.value).collect();
        values.sort_unstable();
        expected.sort_unstable();
        assert_eq!(values, expected);
        drop(tracked);
        assert_eq!(drops.load(Ordering::SeqCst), len);
    }
}
