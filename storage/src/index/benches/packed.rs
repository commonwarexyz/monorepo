//! Experimental five-byte locations interpreted within a shared absolute location window.

pub(super) const WINDOW_SIZE: u64 = 1 << 40;
pub(super) const MASK: u64 = WINDOW_SIZE - 1;

/// The low 40 bits of an absolute location, without per-value alignment padding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub(super) struct PackedLocation(pub(super) [u8; 5]);

/// The caller must keep every stored location within this window, including during updates.
/// Advancing the floor past a surviving value can alias it to a different absolute location.
#[derive(Clone, Copy, Debug)]
pub(super) struct Window {
    floor: u64,
    end: u64,
}

/// Invalid bounds or a location that cannot be represented by the supplied window.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub(super) enum Error {
    #[error("location window is reversed or exceeds 40 bits")]
    InvalidWindow,
    #[error("location is outside the window")]
    OutsideWindow,
}

impl Window {
    pub(super) fn new(floor: u64, end: u64) -> Result<Self, Error> {
        if end.checked_sub(floor).is_none_or(|len| len > WINDOW_SIZE) {
            return Err(Error::InvalidWindow);
        }
        Ok(Self { floor, end })
    }

    #[inline]
    pub(super) fn encode(self, location: u64) -> Result<PackedLocation, Error> {
        if location < self.floor || location >= self.end {
            return Err(Error::OutsideWindow);
        }
        let bytes = location.to_le_bytes();
        Ok(PackedLocation(bytes[..5].try_into().unwrap()))
    }

    #[inline]
    pub(super) fn decode(self, location: PackedLocation) -> Result<u64, Error> {
        let mut bytes = [0; 8];
        bytes[..5].copy_from_slice(&location.0);
        let offset = u64::from_le_bytes(bytes).wrapping_sub(self.floor) & MASK;
        self.floor
            .checked_add(offset)
            .filter(|&location| location < self.end)
            .ok_or(Error::OutsideWindow)
    }
}
