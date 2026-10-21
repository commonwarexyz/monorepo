//! Planning and progress of direct (`O_DIRECT`) positioned reads.
//!
//! A direct read covers the [DIRECT_ALIGN]-aligned superset of its range with one exact-size
//! aligned buffer, submits it in chunks of at most [CHUNK_CAP] bytes and hands out only the
//! requested bytes, which a completion reported. A range without a representable superset, or a
//! direct read the kernel rejects or completes short, is served by a buffered read instead.
//!
//! Nothing here touches a ring, socket or file.

use super::waiter::WaiterState;
use crate::{Error, IoBufMut};
use bytes::Buf as _;
use commonware_utils::Widen;
use std::{alloc::Layout, num::NonZeroUsize};

/// Alignment of the file offset, length and destination address of every direct read.
pub const DIRECT_ALIGN: usize = 4096;

/// Largest length of one direct read: `i32::MAX` rounded down to [DIRECT_ALIGN].
///
/// The kernel returns at most `MAX_RW_COUNT` (`INT_MAX` rounded down to the page size) bytes from
/// one read. On pages larger than [DIRECT_ALIGN] that is a short read whose length is still a
/// multiple of [DIRECT_ALIGN], so the read continues from an aligned cursor.
pub const CHUNK_CAP: usize = i32::MAX as usize / DIRECT_ALIGN * DIRECT_ALIGN;

// Submitted lengths are SQE lengths.
const _: () = assert!(CHUNK_CAP <= u32::MAX as usize);

/// The aligned superset a direct read covers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Geometry {
    /// Physical file offset of the superset.
    pub aligned_offset: u64,
    /// Bytes of the superset before the requested range.
    pub skip: usize,
    /// Length of the superset.
    pub aligned_len: usize,
}

/// One validated range of a batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Plan {
    /// Physical file offset of the range.
    pub offset: u64,
    /// Length of the range.
    pub len: usize,
    /// Superset of a direct read of the range, or `None` when only a buffered read can serve it.
    pub direct: Option<Geometry>,
}

/// Validate every range of a batch before any is admitted.
///
/// `ranges` are logical `(offset, len)` pairs and `data_offset` is the physical offset of logical
/// offset 0. A range whose physical offset or end overflows, or whose buffered destination has no
/// allocation layout, fails the whole batch with [Error::OffsetOverflow]. A logically valid range
/// whose superset is not representable is planned without a [Geometry] and served buffered.
pub fn plan(ranges: &[(u64, usize)], data_offset: u64) -> Result<Vec<Plan>, Error> {
    ranges
        .iter()
        .map(|&(offset, len)| {
            let offset = offset
                .checked_add(data_offset)
                .ok_or(Error::OffsetOverflow)?;
            offset
                .checked_add(Widen::widen(len))
                .ok_or(Error::OffsetOverflow)?;
            Layout::array::<u8>(len).map_err(|_| Error::OffsetOverflow)?;
            Ok(Plan {
                offset,
                len,
                direct: geometry(offset, len, isize::MAX as usize),
            })
        })
        .collect()
}

/// Return the superset a direct read of `len` bytes at physical `offset` covers.
///
/// `None` for an empty range, a superset whose length overflows, a superset ending beyond the
/// largest signed file offset (which the kernel rejects), or a superset longer than
/// `layout_limit` rounded down to [DIRECT_ALIGN]. With `layout_limit` set to `isize::MAX`, the
/// last case is exactly the superset having no allocation layout at [DIRECT_ALIGN].
pub fn geometry(offset: u64, len: usize, layout_limit: usize) -> Option<Geometry> {
    if len == 0 {
        return None;
    }
    let align: u64 = Widen::widen(DIRECT_ALIGN);
    let aligned_offset = offset - offset % align;
    let skip = (offset % align) as usize;
    let aligned_len = skip
        .checked_add(len)?
        .checked_next_multiple_of(DIRECT_ALIGN)?;
    let aligned_end = aligned_offset.checked_add(Widen::widen(aligned_len))?;
    if aligned_end > i64::MAX as u64 || aligned_len > layout_limit / DIRECT_ALIGN * DIRECT_ALIGN {
        return None;
    }
    Some(Geometry {
        aligned_offset,
        skip,
        aligned_len,
    })
}

/// Allocate the aligned buffer of a direct read, with its length set to the superset's.
///
/// `None` when no allocation layout holds the superset, which leaves the range to a buffered
/// read. Every direct read buffer comes from here.
pub fn allocate(geometry: &Geometry) -> Option<IoBufMut> {
    let align = NonZeroUsize::new(DIRECT_ALIGN).expect("alignment is nonzero");
    let mut buf = IoBufMut::try_with_alignment(geometry.aligned_len, align)?;
    // SAFETY: Only the kernel writes this buffer, and nothing reads it before a completion.
    // [Direct::on_cqe] hands it on in one of three ways. Success narrows it to bytes completions
    // reported. A fallback narrows it for the buffered read loop, which fills every byte before
    // it reports success. A failure returns it in an error output, which carries it unread with
    // its length cleared.
    unsafe { buf.set_len(geometry.aligned_len) };
    Some(buf)
}

/// Return the length of the next direct read of an `aligned_len` superset whose first `read`
/// bytes are complete.
pub const fn next_len(aligned_len: usize, read: usize) -> usize {
    let remaining = aligned_len - read;
    if remaining < CHUNK_CAP {
        remaining
    } else {
        CHUNK_CAP
    }
}

/// Return the destination and length of the next direct read into `buf`, the unadvanced aligned
/// buffer of a read whose first `read` bytes are complete.
pub fn chunk(buf: &mut IoBufMut, read: usize) -> (*mut u8, u32) {
    let aligned_len = buf.len();
    assert!(
        read < aligned_len,
        "direct read progress exceeds its buffer"
    );
    let len = next_len(aligned_len, read);

    // SAFETY: `read < buf.len() <= capacity`, so the destination lies within the buffer.
    let ptr = unsafe { buf.as_mut_ptr().add(read) };
    debug_assert!(
        ptr.addr().is_multiple_of(DIRECT_ALIGN) && len.is_multiple_of(DIRECT_ALIGN) && len > 0,
        "direct read destination or length is not aligned"
    );
    (ptr, len as u32)
}

/// Why a direct read is served buffered instead.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reason {
    /// The kernel rejected the read as invalid (`EINVAL`).
    Invalid,
    /// The read ended before the range at an unaligned length, or read nothing.
    Short,
    /// The kernel does not support the read (`EOPNOTSUPP`).
    Unsupported,
    /// Any other error.
    Error,
}

/// How one completion advances a direct read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Step {
    /// The completion covers the range. Advance the cursor by the count and hand out the range.
    Done(usize),
    /// Advance the cursor by the count and continue: requeue while active, or time out under a
    /// cancellation request.
    Continue(usize),
    /// Serve the range with a buffered read.
    Fallback(Reason),
    /// Fail the read.
    Fail,
}

/// Terminal or next state of a direct read after one completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// The buffer holds exactly the range.
    Done,
    /// Another direct read is needed, or the read times out under a cancellation request.
    Continue,
    /// The buffer is narrowed to the range and the cursor reset for a buffered read.
    Fallback(Reason),
    /// The read failed.
    Fail,
}

/// The requested range inside the aligned buffer of a direct read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Direct {
    /// Bytes of the buffer before the range.
    pub skip: usize,
    /// Length of the range.
    pub len: usize,
}

impl Direct {
    /// Classify the completion `result` of a direct read whose first `read` bytes of an
    /// `aligned_len` superset were complete when it was submitted.
    ///
    /// A completion covering the range succeeds even under a cancellation request. Otherwise,
    /// under a cancellation request every completion but `ECANCELED` continues, so no further
    /// read is submitted. `ECANCELED` fails the read in either state.
    pub fn classify(
        self,
        state: WaiterState,
        result: i32,
        read: usize,
        aligned_len: usize,
    ) -> Step {
        let active = matches!(state, WaiterState::Active { .. });
        let reason = match result {
            n if n > 0 => {
                let n = n as usize;
                let submitted = next_len(aligned_len, read);
                assert!(
                    n <= submitted,
                    "direct read CQE exceeds submitted length: n={n} submitted={submitted}"
                );
                if read + n >= self.skip + self.len {
                    return Step::Done(n);
                }
                if !active || n.is_multiple_of(DIRECT_ALIGN) {
                    return Step::Continue(n);
                }
                Reason::Short
            }
            0 => Reason::Short,
            code if code == -libc::EAGAIN || code == -libc::EWOULDBLOCK || code == -libc::EINTR => {
                return Step::Continue(0);
            }
            code if code == -libc::ECANCELED => return Step::Fail,
            code if code == -libc::EINVAL => Reason::Invalid,
            code if code == -libc::EOPNOTSUPP => Reason::Unsupported,
            _ => Reason::Error,
        };
        if active {
            Step::Fallback(reason)
        } else {
            Step::Continue(0)
        }
    }

    /// Apply the completion `result` to `buf`, the aligned buffer of the read, and its cursor
    /// `read`.
    ///
    /// On success and on fallback `buf` is narrowed to the range. Success exposes exactly the
    /// range, which the completed reads cover. A fallback resets `read` for a buffered read of
    /// the range into the narrowed buffer, which must fill it before exposing it.
    pub fn on_cqe(
        self,
        state: WaiterState,
        result: i32,
        buf: &mut IoBufMut,
        read: &mut usize,
    ) -> Outcome {
        match self.classify(state, result, *read, buf.len()) {
            Step::Done(n) => {
                *read += n;
                self.narrow(buf);
                Outcome::Done
            }
            Step::Continue(n) => {
                *read += n;
                Outcome::Continue
            }
            Step::Fallback(reason) => {
                *read = 0;
                self.narrow(buf);
                Outcome::Fallback(reason)
            }
            Step::Fail => Outcome::Fail,
        }
    }

    /// Narrow the aligned buffer to the range, leaving the bytes around it unreachable.
    fn narrow(self, buf: &mut IoBufMut) {
        buf.truncate(self.skip + self.len);
        buf.advance(self.skip);
    }
}

#[cfg(test)]
#[commonware_macros::test_group("miri")]
mod tests {
    use super::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    /// Waiter state before any cancellation.
    const ACTIVE: WaiterState = WaiterState::Active { target_tick: None };

    /// Waiter state after a cancellation request.
    const CANCELLING: WaiterState = WaiterState::CancelRequested;

    /// Byte at physical offset `offset` of the simulated file.
    const fn byte(offset: u64) -> u8 {
        (offset % 251) as u8
    }

    /// Simulate the kernel completing `n` bytes of the next direct read of `buf` at physical
    /// `aligned_offset + read`, writing exactly those bytes.
    fn kernel_read(buf: &mut IoBufMut, aligned_offset: u64, read: usize, n: usize) {
        let (ptr, len) = chunk(buf, read);
        assert!(n <= len as usize);
        for i in 0..n {
            // SAFETY: `i < n <= len` and `chunk` returns a destination of `len` bytes.
            unsafe {
                ptr.add(i)
                    .write(byte(aligned_offset + Widen::widen(read + i)))
            };
        }
    }

    /// Simulate a buffered read filling the narrowed buffer of the range at physical `offset`.
    fn buffered_read(buf: &mut IoBufMut, offset: u64) {
        let len = buf.len();
        let ptr = buf.as_mut_ptr();
        for i in 0..len {
            // SAFETY: The narrowed buffer has `len` bytes of capacity.
            unsafe { ptr.add(i).write(byte(offset + Widen::widen(i))) };
        }
    }

    #[test]
    fn test_plan_rejects_logically_invalid_ranges() {
        // The physical offset, the physical end and the buffered layout are each checked, and
        // one invalid range fails the whole batch.
        for ranges in [
            vec![(0, 1), (u64::MAX - 7, 1)],
            vec![(0, 1), (u64::MAX - 100, 100)],
            vec![(0, isize::MAX as usize + 1)],
            vec![(0, 0), (1 << 40, usize::MAX)],
        ] {
            assert!(
                matches!(plan(&ranges, 8), Err(Error::OffsetOverflow)),
                "{ranges:?}"
            );
        }

        // The largest representable end is valid.
        let plans = plan(&[(u64::MAX - 9, 1)], 8).unwrap();
        assert_eq!(plans[0].offset, u64::MAX - 1);
        assert_eq!(plans[0].direct, None);
    }

    #[test]
    fn test_plan_maps_ranges_to_supersets() {
        let plans = plan(&[(0, 4096), (7, 10), (4093, 6), (100, 0), (4096, 1)], 4096).unwrap();
        let expected = [
            (4096, 4096, Some((4096, 0, 4096))),
            (4103, 10, Some((4096, 7, 4096))),
            (8189, 6, Some((4096, 4093, 8192))),
            (4196, 0, None),
            (8192, 1, Some((8192, 0, 4096))),
        ];
        for (plan, (offset, len, direct)) in plans.into_iter().zip(expected) {
            assert_eq!(plan.offset, offset);
            assert_eq!(plan.len, len);
            assert_eq!(
                plan.direct,
                direct.map(|(aligned_offset, skip, aligned_len)| Geometry {
                    aligned_offset,
                    skip,
                    aligned_len,
                })
            );
        }

        // A V0 data offset leaves every superset unaligned with the logical range.
        let plans = plan(&[(0, 4096)], 8).unwrap();
        assert_eq!(
            plans[0].direct,
            Some(Geometry {
                aligned_offset: 0,
                skip: 8,
                aligned_len: 8192,
            })
        );
    }

    #[test]
    fn test_unrepresentable_supersets_are_served_buffered() {
        let limit = isize::MAX as usize;

        // Empty ranges and supersets whose length overflows.
        assert_eq!(geometry(0, 0, limit), None);
        assert_eq!(geometry(4095, usize::MAX - 4094, limit), None);
        assert_eq!(geometry(0, usize::MAX - 100, limit), None);

        // A superset crossing the largest signed file offset, while the range itself does not.
        let offset = (1u64 << 63) - 4096;
        assert_eq!(geometry(offset, 1, limit), None);
        assert_eq!(
            geometry(offset - 4096, 4096, limit),
            Some(Geometry {
                aligned_offset: offset - 4096,
                skip: 0,
                aligned_len: 4096,
            })
        );
        let plans = plan(&[(offset - 8, 1)], 8).unwrap();
        assert_eq!(plans[0].offset, offset);
        assert_eq!(plans[0].direct, None);

        // On a 32-bit target, a range whose own layout is valid can have a superset without one.
        let limit = i32::MAX as usize;
        let len = i32::MAX as usize - 100;
        assert!(Layout::from_size_align(len, 1).is_ok());
        assert_eq!(geometry(0, len, limit), None);
        assert_eq!(
            geometry(4000, CHUNK_CAP - 4000, limit),
            Some(Geometry {
                aligned_offset: 0,
                skip: 4000,
                aligned_len: CHUNK_CAP,
            })
        );
        assert_eq!(geometry(4000, CHUNK_CAP - 3999, limit), None);
        assert!(geometry(0, len, isize::MAX as usize).is_some());
    }

    #[test]
    fn test_chunks_progress_under_every_page_cap() {
        assert_eq!(CHUNK_CAP % DIRECT_ALIGN, 0);
        assert!(CHUNK_CAP <= i32::MAX as usize);
        assert_eq!(next_len(CHUNK_CAP, 0), CHUNK_CAP);
        assert_eq!(next_len(CHUNK_CAP + DIRECT_ALIGN, 0), CHUNK_CAP);
        assert_eq!(next_len(CHUNK_CAP + DIRECT_ALIGN, CHUNK_CAP), DIRECT_ALIGN);
        assert_eq!(next_len(3 * DIRECT_ALIGN, DIRECT_ALIGN), 2 * DIRECT_ALIGN);

        // Model the kernel's cap on one read for 4, 16 and 64 KiB pages. Every capped chunk is
        // aligned progress, and the read covers its range without a fallback.
        for page in [4096usize, 16 << 10, 64 << 10] {
            let kernel_cap = i32::MAX as usize & !(page - 1);
            for aligned_len in [
                CHUNK_CAP,
                CHUNK_CAP + DIRECT_ALIGN,
                3 * CHUNK_CAP + 5 * DIRECT_ALIGN,
            ] {
                for skip in [0, 100] {
                    let direct = Direct {
                        skip,
                        len: aligned_len - skip - 1,
                    };
                    let mut read = 0;
                    let mut steps = 0;
                    loop {
                        let len = next_len(aligned_len, read);
                        assert!(len > 0 && len <= CHUNK_CAP && len.is_multiple_of(DIRECT_ALIGN));
                        let n = len.min(kernel_cap);
                        steps += 1;
                        let result = i32::try_from(n).unwrap();
                        match direct.classify(ACTIVE, result, read, aligned_len) {
                            Step::Continue(n) => {
                                assert_eq!(n % DIRECT_ALIGN, 0);
                                read += n;
                            }
                            Step::Done(n) => {
                                read += n;
                                break;
                            }
                            step => panic!("unexpected {step:?}"),
                        }
                    }
                    assert!(read >= direct.skip + direct.len);
                    assert!(steps <= aligned_len.div_ceil(kernel_cap) + 1);
                }
            }
        }
    }

    #[test]
    fn test_classifier_rows() {
        // A two-page superset of a range starting 100 bytes in and ending 100 bytes short.
        let direct = Direct {
            skip: 100,
            len: 2 * DIRECT_ALIGN - 200,
        };
        let aligned = 2 * DIRECT_ALIGN;
        let page = DIRECT_ALIGN as i32;
        let covering = aligned as i32 - 100;
        let classify = |state, result, read| direct.classify(state, result, read, aligned);

        for state in [ACTIVE, CANCELLING] {
            // Retries keep the read and never stage under a cancellation request.
            for code in [libc::EAGAIN, libc::EWOULDBLOCK, libc::EINTR] {
                assert_eq!(classify(state, -code, 0), Step::Continue(0));
            }

            // Cancellation by the kernel or by a request fails the read.
            assert_eq!(classify(state, -libc::ECANCELED, 0), Step::Fail);

            // A covering completion wins, including a short one at the end of the file and one
            // completing an aligned prefix.
            assert_eq!(classify(state, covering, 0), Step::Done(covering as usize));
            assert_eq!(classify(state, 2 * page, 0), Step::Done(2 * DIRECT_ALIGN));
            assert_eq!(
                classify(state, page - 100, DIRECT_ALIGN),
                Step::Done(DIRECT_ALIGN - 100)
            );
        }

        // Aligned progress short of the range continues.
        assert_eq!(classify(ACTIVE, page, 0), Step::Continue(DIRECT_ALIGN));

        // Everything else switches to a buffered read while active.
        for (result, reason) in [
            (0, Reason::Short),
            (1, Reason::Short),
            (page - 1, Reason::Short),
            (page + 1, Reason::Short),
            (covering - 1, Reason::Short),
            (-libc::EINVAL, Reason::Invalid),
            (-libc::EOPNOTSUPP, Reason::Unsupported),
            (-libc::EIO, Reason::Error),
            (-libc::ENOMEM, Reason::Error),
            (-libc::EFAULT, Reason::Error),
        ] {
            assert_eq!(
                classify(ACTIVE, result, 0),
                Step::Fallback(reason),
                "{result}"
            );

            // A cancellation request never switches: the read times out instead.
            let step = classify(CANCELLING, result, 0);
            assert!(
                matches!(step, Step::Continue(n) if n == result.max(0) as usize),
                "{result}: {step:?}"
            );
        }
        assert_eq!(classify(CANCELLING, page, 0), Step::Continue(DIRECT_ALIGN));
        assert_eq!(
            classify(ACTIVE, 0, DIRECT_ALIGN),
            Step::Fallback(Reason::Short)
        );

        // A completion longer than its submission is an invariant failure.
        let overflow = catch_unwind(AssertUnwindSafe(|| classify(ACTIVE, 2 * page + 1, 0)));
        assert!(overflow.is_err());
        let overflow = catch_unwind(AssertUnwindSafe(|| {
            classify(ACTIVE, page + 1, DIRECT_ALIGN)
        }));
        assert!(overflow.is_err());
    }

    /// The outcome of a synthetic completion sequence and the range it exposes.
    #[derive(Debug, Eq, PartialEq)]
    enum Served {
        /// Served by direct reads.
        Direct,
        /// Served by a buffered read after a fallback.
        Buffered(Reason),
        /// Failed.
        Failed,
        /// Timed out under a cancellation request, without output.
        TimedOut,
        /// Still needs another completion.
        Pending,
    }

    /// Apply `completions` to a direct read of `len` bytes at physical `offset`, simulating the
    /// kernel for each positive count, and return the outcome with the exposed bytes.
    ///
    /// Completions from index `cancel_from` on arrive under a cancellation request, where a
    /// completion that does not finish the read times it out, as the waiter table does.
    fn serve(
        offset: u64,
        len: usize,
        seed: Option<u8>,
        completions: &[i32],
        cancel_from: usize,
    ) -> (Served, Option<Vec<u8>>) {
        let geometry = geometry(offset, len, isize::MAX as usize).unwrap();
        let mut buf = allocate(&geometry).unwrap();
        assert_eq!(buf.len(), geometry.aligned_len);
        assert_eq!(buf.as_mut_ptr().addr() % DIRECT_ALIGN, 0);
        if let Some(seed) = seed {
            // SAFETY: The buffer has `aligned_len` bytes of capacity.
            unsafe { std::ptr::write_bytes(buf.as_mut_ptr(), seed, geometry.aligned_len) };
        }
        let direct = Direct {
            skip: geometry.skip,
            len,
        };
        let mut read = 0;
        for (index, &result) in completions.iter().enumerate() {
            if result > 0 {
                kernel_read(&mut buf, geometry.aligned_offset, read, result as usize);
            }
            let state = if index < cancel_from {
                ACTIVE
            } else {
                CANCELLING
            };
            match direct.on_cqe(state, result, &mut buf, &mut read) {
                Outcome::Done => {
                    assert_eq!(buf.len(), len);
                    // The prefix stays unreachable through every conversion.
                    let buf = buf.freeze().try_into_mut().unwrap();
                    assert_eq!(buf.len(), len);
                    return (Served::Direct, Some(buf.as_ref().to_vec()));
                }
                // The cursor may be unaligned, but no further read is submitted.
                Outcome::Continue if state == CANCELLING => return (Served::TimedOut, None),
                Outcome::Continue => assert_eq!(read % DIRECT_ALIGN, 0),
                Outcome::Fallback(reason) => {
                    assert_eq!(read, 0);
                    assert_eq!(buf.len(), len);
                    buffered_read(&mut buf, offset);
                    return (Served::Buffered(reason), Some(buf.as_ref().to_vec()));
                }
                Outcome::Fail => return (Served::Failed, None),
            }
        }
        (Served::Pending, None)
    }

    #[test]
    fn test_completion_sequences_expose_only_reported_bytes() {
        const NEVER: usize = usize::MAX;
        let page = DIRECT_ALIGN as i32;
        let long = 3 * DIRECT_ALIGN - 200;

        // (offset, len, completions, index of the first completion under a cancellation
        // request, outcome)
        let cases: &[(u64, usize, &[i32], usize, Served)] = &[
            // One covering read, aligned or not.
            (0, DIRECT_ALIGN, &[page], NEVER, Served::Direct),
            (4196, 50, &[page], NEVER, Served::Direct),
            (4093, 6, &[2 * page], NEVER, Served::Direct),
            // A short read at the end of the file that still covers the range, and one that
            // ends a byte short of it.
            (8192 + 10, 100, &[200], NEVER, Served::Direct),
            (8192 + 10, 100, &[110], NEVER, Served::Direct),
            (
                8192 + 10,
                100,
                &[109],
                NEVER,
                Served::Buffered(Reason::Short),
            ),
            // Retries, then aligned progress, then a covering read.
            (
                100,
                long,
                &[-libc::EAGAIN, page, -libc::EINTR, 2 * page],
                NEVER,
                Served::Direct,
            ),
            (100, long, &[page, page, page - 100], NEVER, Served::Direct),
            (
                100,
                long,
                &[page, page, page - 101],
                NEVER,
                Served::Buffered(Reason::Short),
            ),
            // Fallbacks after a direct prefix or none.
            (
                100,
                long,
                &[page, 10],
                NEVER,
                Served::Buffered(Reason::Short),
            ),
            (
                100,
                long,
                &[page, 0],
                NEVER,
                Served::Buffered(Reason::Short),
            ),
            (
                7,
                10,
                &[-libc::EINVAL],
                NEVER,
                Served::Buffered(Reason::Invalid),
            ),
            (
                7,
                10,
                &[-libc::EOPNOTSUPP],
                NEVER,
                Served::Buffered(Reason::Unsupported),
            ),
            (
                4096,
                4096,
                &[-libc::EIO],
                NEVER,
                Served::Buffered(Reason::Error),
            ),
            // Kernel cancellation and unfinished reads expose nothing.
            (7, 10, &[-libc::ECANCELED], NEVER, Served::Failed),
            (100, long, &[page, -libc::EAGAIN], NEVER, Served::Pending),
            // Under a cancellation request a covering completion still exposes exactly the
            // reported bytes, including after an aligned prefix read before the request.
            (4196, 50, &[page], 0, Served::Direct),
            (8192 + 10, 100, &[110], 0, Served::Direct),
            (100, long, &[page, 2 * page], 1, Served::Direct),
            (100, long, &[page, page, page - 100], 2, Served::Direct),
            // Anything else under a cancellation request ends the read without output, even
            // a short completion that leaves the cursor unaligned.
            (100, long, &[page, page - 1], 1, Served::TimedOut),
            (100, long, &[page, page, page - 101], 2, Served::TimedOut),
            (8192 + 10, 100, &[109], 0, Served::TimedOut),
            (100, long, &[page, 0], 1, Served::TimedOut),
            (100, long, &[page, -libc::EAGAIN], 1, Served::TimedOut),
            (7, 10, &[-libc::EINVAL], 0, Served::TimedOut),
            (7, 10, &[-libc::ECANCELED], 0, Served::Failed),
        ];

        // Fresh buffers expose any unwritten byte to Miri. Seeded buffers expose a stale byte to
        // the comparison. Bytes are compared before outcomes, so an early success reaches both.
        for seed in [None, Some(0xEE), Some(0x00)] {
            for (offset, len, completions, cancel_from, outcome) in cases {
                let (served, bytes) = serve(*offset, *len, seed, completions, *cancel_from);
                if let Some(bytes) = bytes {
                    let expected: Vec<u8> =
                        (*offset..*offset + Widen::widen(*len)).map(byte).collect();
                    assert_eq!(bytes, expected, "{offset} {len} {completions:?} {seed:?}");
                }
                assert_eq!(
                    &served, outcome,
                    "{offset} {len} {completions:?} {cancel_from}"
                );
            }
        }
    }

    #[test]
    fn test_unsubmittable_cursor_is_rejected() {
        let geometry = geometry(0, 10, isize::MAX as usize).unwrap();
        let mut buf = allocate(&geometry).unwrap();
        let (_, len) = chunk(&mut buf, 0);
        assert_eq!(len as usize, DIRECT_ALIGN);
        let past = catch_unwind(AssertUnwindSafe(|| chunk(&mut buf, DIRECT_ALIGN)));
        assert!(past.is_err());
    }
}
