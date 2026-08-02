//! Signer-attributed consensus values.

use super::Participant;

/// Provides access to the participant that signed a value.
pub trait Attributable {
    /// Returns the index of the participant that produced this value.
    fn signer(&self) -> Participant;
}

/// A map of [`Attributable`] values keyed by signer.
///
/// The key for each value is inferred from [`Attributable::signer`]. Each signer can insert at most one
/// value, and iteration follows participant order.
pub struct AttributableMap<T: Attributable> {
    participants: usize,
    data: Vec<Option<T>>,
    added: usize,
}

impl<T: Attributable> AttributableMap<T> {
    /// Creates an empty map for `participants` possible signers.
    pub const fn new(participants: usize) -> Self {
        Self {
            participants,
            data: Vec::new(),
            added: 0,
        }
    }

    /// Removes every value and releases their storage.
    pub fn clear(&mut self) {
        self.data = Vec::new();
        self.added = 0;
    }

    /// Inserts `item` unless its signer is out of bounds or already present.
    ///
    /// Returns `true` when the value was inserted.
    pub fn insert(&mut self, item: T) -> bool {
        let index: usize = item.signer().into();
        if index >= self.participants {
            return false;
        }
        if self.data.is_empty() {
            // `resize_with` avoids requiring `T: Clone` while pre-filling with `None`.
            self.data.reserve_exact(self.participants);
            self.data.resize_with(self.participants, || None);
        }
        if self.data[index].is_some() {
            return false;
        }

        self.data[index] = Some(item);
        self.added += 1;
        true
    }

    /// Returns the number of stored values.
    pub const fn len(&self) -> usize {
        self.added
    }

    /// Returns `true` when the map contains no values.
    pub const fn is_empty(&self) -> bool {
        self.added == 0
    }

    /// Returns the value attributed to `signer`, if present.
    pub fn get(&self, signer: Participant) -> Option<&T> {
        self.data.get(<usize>::from(signer))?.as_ref()
    }

    /// Iterates over values in ascending signer order.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.data.iter().filter_map(|item| item.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Value(Participant);

    impl Attributable for Value {
        fn signer(&self) -> Participant {
            self.0
        }
    }

    #[test]
    fn operations_preserve_attribution_and_signer_order() {
        let mut map = AttributableMap::new(5);
        assert_eq!(map.len(), 0);
        assert!(map.is_empty());
        assert_eq!(map.data.capacity(), 0, "empty maps should allocate lazily");

        for signer in 0..5 {
            assert!(map.get(Participant::new(signer)).is_none());
        }

        assert!(map.insert(Value(Participant::new(3))));
        assert!(map.data.capacity() >= 5);
        assert!(map.insert(Value(Participant::new(1))));
        assert_eq!(map.len(), 2);
        assert!(!map.is_empty());
        assert_eq!(
            map.iter().map(Attributable::signer).collect::<Vec<_>>(),
            [Participant::new(1), Participant::new(3)]
        );
        assert_eq!(
            map.get(Participant::new(1)).map(Attributable::signer),
            Some(Participant::new(1))
        );
        assert_eq!(
            map.get(Participant::new(3)).map(Attributable::signer),
            Some(Participant::new(3))
        );

        assert!(map.get(Participant::new(0)).is_none());
        assert!(map.get(Participant::new(2)).is_none());
        assert!(map.get(Participant::new(4)).is_none());
        assert!(!map.insert(Value(Participant::new(3))));
        assert!(!map.insert(Value(Participant::new(5))));
        assert!(!map.insert(Value(Participant::new(100))));
        assert_eq!(map.len(), 2);

        map.clear();
        assert!(map.is_empty());
        assert_eq!(map.len(), 0);
        assert_eq!(map.iter().count(), 0);
        assert_eq!(map.data.capacity(), 0, "clear should release vote storage");

        assert!(map.insert(Value(Participant::new(2))));
        assert_eq!(map.len(), 1);
        assert_eq!(
            map.iter().map(Attributable::signer).collect::<Vec<_>>(),
            [Participant::new(2)]
        );
    }
}
