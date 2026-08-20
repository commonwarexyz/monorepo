use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest};
use commonware_parallel::Rayon;
use commonware_storage::bmt::{Builder, Tree};
use std::{num::NonZeroUsize, ops::Range};

pub(crate) const WORKERS: usize = 8;

#[derive(Clone, Copy)]
enum Layout {
    EvenlySpaced,
    Clustered,
    Dense,
    Edges,
}

#[derive(Clone, Copy)]
pub(crate) struct Profile {
    pub(crate) shape: &'static str,
    pub(crate) leaves: u32,
    pub(crate) changes: u32,
    pub(crate) ranges: u32,
    layout: Layout,
}

impl Profile {
    const fn new(
        shape: &'static str,
        leaves: u32,
        changes: u32,
        ranges: u32,
        layout: Layout,
    ) -> Self {
        Self {
            shape,
            leaves,
            changes,
            ranges,
            layout,
        }
    }

    fn positions(self) -> Vec<u32> {
        match self.layout {
            Layout::EvenlySpaced => (0..self.changes)
                .map(|index| {
                    u32::try_from(
                        u64::from(index) * u64::from(self.leaves) / u64::from(self.changes),
                    )
                    .expect("benchmark position fits in u32")
                })
                .collect(),
            Layout::Clustered => {
                let start = (self.leaves - self.changes) / 2;
                (start..start + self.changes).collect()
            }
            Layout::Dense => (0..self.leaves).collect(),
            Layout::Edges => vec![0, self.leaves - 1],
        }
    }

    fn boundaries(self) -> Vec<u32> {
        (0..=self.ranges)
            .map(|index| {
                u32::try_from(u64::from(index) * u64::from(self.leaves) / u64::from(self.ranges))
                    .expect("benchmark boundary fits in u32")
            })
            .collect()
    }
}

pub(crate) const UPDATE_PROFILES: &[Profile] = &[
    Profile::new("sparse", 65_536, 64, 256, Layout::EvenlySpaced),
    Profile::new("clustered", 65_536, 64, 256, Layout::Clustered),
    Profile::new("dense", 8_192, 8_192, 256, Layout::Dense),
    Profile::new("odd", 65_537, 65, 256, Layout::EvenlySpaced),
    Profile::new("boundary", 65_536, 2, 256, Layout::Edges),
];

pub(crate) const RANGE_PROFILES: &[Profile] = &[
    Profile::new("sparse", 65_536, 64, 1, Layout::EvenlySpaced),
    Profile::new("sparse", 65_536, 64, 256, Layout::EvenlySpaced),
    Profile::new("clustered", 65_536, 64, 256, Layout::Clustered),
    Profile::new("dense", 8_192, 8_192, 256, Layout::Dense),
    Profile::new("odd", 65_537, 65, 256, Layout::EvenlySpaced),
    Profile::new("boundary", 65_536, 2, 256, Layout::Edges),
];

pub(crate) struct Disclosure {
    pub(crate) range: Range<u32>,
    pub(crate) positions: Vec<u32>,
    pub(crate) opening: Vec<Digest>,
    pub(crate) closing: Vec<Digest>,
}

pub(crate) struct Fixture {
    pub(crate) tree: Tree<Digest>,
    pub(crate) changes: Vec<(u32, Digest)>,
    pub(crate) boundaries: Vec<u32>,
    pub(crate) disclosures: Vec<Disclosure>,
}

impl Fixture {
    pub(crate) fn new(profile: Profile) -> Self {
        assert!(profile.leaves > 1);
        assert!(profile.changes > 0 && profile.changes <= profile.leaves);
        assert!(profile.ranges > 0 && profile.ranges <= profile.leaves);

        let opening = (0..profile.leaves)
            .map(|position| digest(b"opening", position))
            .collect::<Vec<_>>();
        let mut builder = Builder::<Sha256>::new(opening.len());
        for leaf in &opening {
            builder.add(leaf);
        }
        let tree = builder.build();

        let positions = profile.positions();
        assert_eq!(positions.len(), profile.changes as usize);
        assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
        let changes = positions
            .iter()
            .map(|&position| (position, digest(b"closing", position)))
            .collect::<Vec<_>>();
        assert!(
            changes
                .iter()
                .all(|(position, closing)| opening[*position as usize] != *closing)
        );

        let boundaries = profile.boundaries();
        assert_eq!(boundaries.len(), profile.ranges as usize + 1);
        assert_eq!(boundaries.first(), Some(&0));
        assert_eq!(boundaries.last(), Some(&profile.leaves));
        assert!(boundaries.windows(2).all(|pair| pair[0] < pair[1]));

        let disclosures = boundaries
            .windows(2)
            .map(|pair| {
                let start = positions.partition_point(|position| *position < pair[0]);
                let end = positions.partition_point(|position| *position < pair[1]);
                let positions = positions[start..end].to_vec();
                let opening = positions
                    .iter()
                    .map(|position| opening[*position as usize])
                    .collect();
                let closing = changes[start..end]
                    .iter()
                    .map(|(_, closing)| *closing)
                    .collect();
                Disclosure {
                    range: pair[0]..pair[1],
                    positions,
                    opening,
                    closing,
                }
            })
            .collect();

        Self {
            tree,
            changes,
            boundaries,
            disclosures,
        }
    }
}

pub(crate) fn strategy() -> Rayon {
    Rayon::new(NonZeroUsize::new(WORKERS).expect("worker count is nonzero"))
        .expect("benchmark worker pool must initialize")
}

fn digest(domain: &[u8], position: u32) -> Digest {
    Sha256::hash(&[domain, &position.to_be_bytes()])
}
