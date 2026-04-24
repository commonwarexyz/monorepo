#[derive(Clone, Copy)]
pub(crate) enum ShardSelection {
    Best,
    Exception,
    Worst,
    Interleaved,
}

impl ShardSelection {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Best => "best",
            Self::Exception => "exception",
            Self::Worst => "worst",
            Self::Interleaved => "interleaved",
        }
    }

    pub(crate) fn indices(self, min: u16) -> Vec<u16> {
        match self {
            Self::Best => (0..min).collect(),
            Self::Exception => (1..=min).collect(),
            Self::Worst => (min..min + min).collect(),
            Self::Interleaved => (0..min)
                .map(|i| {
                    let k = i / 2;
                    if i % 2 == 0 {
                        k
                    } else {
                        min + k
                    }
                })
                .collect(),
        }
    }
}

pub(crate) const SELECTIONS: [ShardSelection; 4] = [
    ShardSelection::Best,
    ShardSelection::Exception,
    ShardSelection::Worst,
    ShardSelection::Interleaved,
];
