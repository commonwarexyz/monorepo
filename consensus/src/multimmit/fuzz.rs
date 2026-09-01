//! Input decoding shared by the module-local fuzz exercises.
//!
//! Each campaign keeps its entry point next to the code it checks, as an `exercise(input)` function
//! in that module's `fuzz.rs`. This module only turns raw input into schedule decisions.

/// Reads fuzz input as a stream of schedule decisions.
///
/// A cycling schedule repeats the input once it is exhausted, while a padded schedule reads zeros.
/// Empty input always reads zeros. Each campaign keeps one mode so saved inputs keep their meaning.
pub(crate) struct ByteSchedule<'a> {
    bytes: &'a [u8],
    cursor: usize,
    cycle: bool,
}

impl<'a> ByteSchedule<'a> {
    /// Returns a schedule that repeats `bytes` once exhausted.
    pub(crate) const fn cycling(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            cursor: 0,
            cycle: true,
        }
    }

    /// Returns a schedule that reads zeros once `bytes` is exhausted.
    pub(crate) const fn padded(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            cursor: 0,
            cycle: false,
        }
    }

    /// Returns the next byte.
    pub(crate) const fn byte(&mut self) -> u8 {
        let len = self.bytes.len();
        let byte = if self.cursor < len {
            self.bytes[self.cursor]
        } else if self.cycle && len > 0 {
            self.bytes[self.cursor % len]
        } else {
            0
        };
        self.cursor += 1;
        byte
    }

    /// Returns the next byte as an index or count.
    pub(crate) fn index(&mut self) -> usize {
        usize::from(self.byte())
    }

    /// Returns the next two bytes as a little-endian word.
    pub(crate) const fn word(&mut self) -> u16 {
        u16::from_le_bytes([self.byte(), self.byte()])
    }

    /// Returns the next `N` bytes.
    pub(crate) fn take<const N: usize>(&mut self) -> [u8; N] {
        core::array::from_fn(|_| self.byte())
    }

    /// Permutes `values` with a Fisher-Yates pass that reads one byte per swap.
    pub(crate) fn shuffle<T>(&mut self, values: &mut [T]) {
        for upper in (1..values.len()).rev() {
            let other = self.index() % (upper + 1);
            values.swap(upper, other);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ByteSchedule;

    #[test]
    fn cycling_repeats_input() {
        let mut schedule = ByteSchedule::cycling(&[1, 2, 3]);
        assert_eq!(schedule.take::<7>(), [1, 2, 3, 1, 2, 3, 1]);
    }

    #[test]
    fn padded_reads_zeros_after_input() {
        let mut schedule = ByteSchedule::padded(&[1, 2]);
        assert_eq!(schedule.take::<4>(), [1, 2, 0, 0]);
    }

    #[test]
    fn empty_input_reads_zeros() {
        assert_eq!(ByteSchedule::cycling(&[]).take::<3>(), [0; 3]);
        assert_eq!(ByteSchedule::padded(&[]).take::<3>(), [0; 3]);
    }

    #[test]
    fn word_is_little_endian() {
        assert_eq!(ByteSchedule::padded(&[0x34, 0x12]).word(), 0x1234);
    }
}
