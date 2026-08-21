use arbitrary::Unstructured;
use commonware_runtime::deterministic::{PartialWriteMode, WriteConfig};
use commonware_utils::Probability;
use std::collections::BTreeSet;

const RATE_BUCKETS: u32 = 101;
const WRITE_CONFIGS: u32 = RATE_BUCKETS * RATE_BUCKETS * 2;

/// Decode the write-fault configuration shared by storage recovery fuzzers from exactly two
/// bytes. The decoder covers both modes and every pair of whole-percent rates in `[0, 100]`.
pub fn write_config(u: &mut Unstructured<'_>) -> arbitrary::Result<WriteConfig> {
    Ok(write_config_from_code(u.arbitrary()?))
}

fn write_config_from_code(code: u16) -> WriteConfig {
    let mut code = u32::from(code) % WRITE_CONFIGS;
    let failure_rate = code % RATE_BUCKETS;
    code /= RATE_BUCKETS;
    let retention_rate = code % RATE_BUCKETS;
    code /= RATE_BUCKETS;
    let mode = if code == 0 {
        PartialWriteMode::Prefix
    } else {
        PartialWriteMode::Subset
    };

    WriteConfig {
        failure_rate: Probability::new(u64::from(failure_rate), 100).unwrap(),
        retention_rate: Probability::new(u64::from(retention_rate), 100).unwrap(),
        mode,
    }
}

/// Tracks the byte-producing index mutation allowed for each section and whether any retained
/// mutation overwrote bytes belonging to an existing authenticated page.
#[derive(Debug, Default)]
pub struct IndexMutations {
    modified: BTreeSet<u64>,
    overwrites: BTreeSet<u64>,
}

impl IndexMutations {
    /// Return whether `section` can receive its one byte-producing mutation.
    pub fn can_modify(&self, section: u64) -> bool {
        !self.modified.contains(&section)
    }

    /// Record an append-only extension.
    pub fn record_extension(&mut self, section: u64) {
        self.modified.insert(section);
    }

    /// Record a mutation overlapping bytes that existed before the write.
    pub fn record_overwrite(&mut self, section: u64) {
        self.modified.insert(section);
        self.overwrites.insert(section);
    }

    /// Remove all mutation provenance for `section` after its blob is deleted.
    pub fn remove(&mut self, section: u64) {
        self.modified.remove(&section);
        self.overwrites.remove(&section);
    }

    /// Return whether a retained overwrite can explain an index-page checksum error.
    pub fn may_accept_invalid_checksum(&self) -> bool {
        !self.overwrites.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{IndexMutations, PartialWriteMode, write_config, write_config_from_code};
    use arbitrary::Unstructured;
    use commonware_utils::Probability;
    use std::collections::BTreeMap;

    #[test]
    fn write_config_leaves_an_operation_discriminant() {
        let bytes = [0u8; 6];
        let mut input = Unstructured::new(&bytes);
        write_config(&mut input).expect("write config must fit in two bytes");
        assert_eq!(input.len(), 4);
    }

    #[test]
    fn write_config_covers_the_percent_grid_uniformly() {
        let mut counts = BTreeMap::new();
        for code in 0..=u16::MAX {
            let config = write_config_from_code(code);
            let mode = match config.mode {
                PartialWriteMode::Prefix => 0,
                PartialWriteMode::Subset => 1,
            };
            *counts
                .entry((config.failure_rate, config.retention_rate, mode))
                .or_insert(0usize) += 1;
        }

        assert_eq!(counts.len(), 101 * 101 * 2);
        assert!(counts.values().all(|count| matches!(count, 3 | 4)));
        for mode in 0..=1 {
            assert!(counts.contains_key(&(
                Probability::new(0, 100).unwrap(),
                Probability::new(0, 100).unwrap(),
                mode
            )));
            assert!(counts.contains_key(&(
                Probability::new(100, 100).unwrap(),
                Probability::new(100, 100).unwrap(),
                mode
            )));
        }
    }

    #[test]
    fn invalid_checksum_requires_a_retained_existing_byte_overwrite() {
        let mut mutations = IndexMutations::default();

        mutations.record_extension(1);
        assert!(!mutations.can_modify(1));
        assert!(
            !mutations.may_accept_invalid_checksum(),
            "an append-only extension must not suppress the recovery oracle"
        );

        mutations.remove(1);
        assert!(mutations.can_modify(1));
        mutations.record_overwrite(1);
        assert!(mutations.may_accept_invalid_checksum());

        mutations.remove(1);
        assert!(!mutations.may_accept_invalid_checksum());
    }
}
