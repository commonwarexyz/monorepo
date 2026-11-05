//! Openings of one key in a sorted list committed with a binary Merkle tree.

use super::Error;
use bytes::BufMut;
use commonware_codec::{Buf, EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_cryptography::{Digest, Hasher};
use commonware_storage::bmt::{Proof, Tree};

/// Tag of [Lookup::Member] in the encoding.
const MEMBER: u8 = 0;

/// Tag of [Lookup::NonMember] in the encoding.
const NON_MEMBER: u8 = 1;

/// Opens the value bound to one key in a list that is strictly increasing by key and committed
/// with a binary Merkle tree.
///
/// The tree's root binds the number of entries, so an opening also proves whether an entry is the
/// first or last. Whoever certifies a root must check that the list behind it is sorted, because
/// an unsorted list can prove a present key absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lookup<K, V, D: Digest> {
    /// The key is present.
    Member {
        /// Position of the key's entry.
        position: u32,
        /// Value bound to the key.
        value: V,
        /// Opening of the entry.
        proof: Proof<D>,
    },
    /// The key is absent.
    NonMember {
        /// Position at which the key would be inserted.
        position: u32,
        /// Entry preceding `position`, unless the key precedes every entry.
        lower: Option<(K, V)>,
        /// Entry at `position`, unless the key follows every entry.
        upper: Option<(K, V)>,
        /// Opening of the neighbors present, or of the empty list.
        proof: Proof<D>,
    },
}

impl<K: Ord + Clone, V: Clone, D: Digest> Lookup<K, V, D> {
    /// Opens `key` in `entries`. The entries must be strictly increasing by key and committed by
    /// `tree`.
    pub(crate) fn new(entries: &[(K, V)], tree: &Tree<D>, key: &K) -> Self {
        let proof = |start: usize, end: usize| {
            tree.range_proof(start as u32, end as u32)
                .expect("entries must be committed by the tree")
        };
        match entries.binary_search_by(|(candidate, _)| candidate.cmp(key)) {
            Ok(position) => Self::Member {
                position: position as u32,
                value: entries[position].1.clone(),
                proof: proof(position, position),
            },
            Err(position) => {
                let lower = position.checked_sub(1).map(|index| entries[index].clone());
                let upper = entries.get(position).cloned();
                let proof = match (&lower, &upper) {
                    (None, None) => Proof::default(),
                    (Some(_), Some(_)) => proof(position - 1, position),
                    (Some(_), None) => proof(position - 1, position - 1),
                    (None, Some(_)) => proof(position, position),
                };
                Self::NonMember {
                    position: position as u32,
                    lower,
                    upper,
                    proof,
                }
            }
        }
    }

    /// Verifies the opening of `key` under `root`, where `leaf` computes an entry's leaf.
    ///
    /// Returns the value bound to `key`, or `None` if the opening proves it absent.
    pub(crate) fn verify<H: Hasher<Digest = D>>(
        &self,
        key: &K,
        root: &D,
        leaf: impl Fn(&K, &V) -> D,
    ) -> Result<Option<&V>, Error> {
        match self {
            Self::Member {
                position,
                value,
                proof,
            } => {
                proof
                    .verify_element_inclusion::<H>(*position, &leaf(key, value), root)
                    .map_err(|_| Error::InvalidOpening)?;
                Ok(Some(value))
            }
            Self::NonMember {
                position,
                lower,
                upper,
                proof,
            } => {
                // An empty list has no neighbors, and only the empty proof opens its root.
                let count = proof.leaf_count;
                if count == 0 {
                    if *position != 0 || lower.is_some() || upper.is_some() {
                        return Err(Error::InvalidOpening);
                    }
                    proof
                        .verify_multi_inclusion::<H>(&[], root)
                        .map_err(|_| Error::InvalidOpening)?;
                    return Ok(None);
                }

                // Otherwise the key lies strictly between its neighbors, and an entry is missing
                // only because the key precedes the first entry or follows the last one.
                if *position > count
                    || lower.is_some() != (*position > 0)
                    || upper.is_some() != (*position < count)
                    || lower.as_ref().is_some_and(|(lower, _)| lower >= key)
                    || upper.as_ref().is_some_and(|(upper, _)| upper <= key)
                {
                    return Err(Error::InvalidOpening);
                }
                let mut elements = Vec::with_capacity(2);
                if let Some((lower, value)) = lower {
                    elements.push((*position - 1, leaf(lower, value)));
                }
                if let Some((upper, value)) = upper {
                    elements.push((*position, leaf(upper, value)));
                }
                proof
                    .verify_multi_inclusion::<H>(&elements, root)
                    .map_err(|_| Error::InvalidOpening)?;
                Ok(None)
            }
        }
    }
}

impl<K: Write, V: Write, D: Digest> Write for Lookup<K, V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Member {
                position,
                value,
                proof,
            } => {
                MEMBER.write(buf);
                position.write(buf);
                value.write(buf);
                proof.write(buf);
            }
            Self::NonMember {
                position,
                lower,
                upper,
                proof,
            } => {
                NON_MEMBER.write(buf);
                position.write(buf);
                lower.write(buf);
                upper.write(buf);
                proof.write(buf);
            }
        }
    }
}

impl<K: EncodeSize, V: EncodeSize, D: Digest> EncodeSize for Lookup<K, V, D> {
    fn encode_size(&self) -> usize {
        MEMBER.encode_size()
            + match self {
                Self::Member {
                    position,
                    value,
                    proof,
                } => position.encode_size() + value.encode_size() + proof.encode_size(),
                Self::NonMember {
                    position,
                    lower,
                    upper,
                    proof,
                } => {
                    position.encode_size()
                        + lower.encode_size()
                        + upper.encode_size()
                        + proof.encode_size()
                }
            }
    }
}

impl<K: Read<Cfg = ()>, V: Read<Cfg = ()>, D: Digest> Read for Lookup<K, V, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            MEMBER => Ok(Self::Member {
                position: u32::read(buf)?,
                value: V::read(buf)?,
                proof: Proof::read_cfg(buf, &1)?,
            }),
            NON_MEMBER => Ok(Self::NonMember {
                position: u32::read(buf)?,
                lower: Option::<(K, V)>::read_cfg(buf, &((), ()))?,
                upper: Option::<(K, V)>::read_cfg(buf, &((), ()))?,
                proof: Proof::read_cfg(buf, &2)?,
            }),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, K, V, D> arbitrary::Arbitrary<'a> for Lookup<K, V, D>
where
    K: arbitrary::Arbitrary<'a>,
    V: arbitrary::Arbitrary<'a>,
    D: Digest + arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let position = u.arbitrary()?;
        let siblings = u.int_in_range(0..=4)?;
        let proof = Proof {
            leaf_count: u.arbitrary()?,
            siblings: (0..siblings)
                .map(|_| u.arbitrary())
                .collect::<arbitrary::Result<_>>()?,
        };
        if u.arbitrary()? {
            Ok(Self::Member {
                position,
                value: u.arbitrary()?,
                proof,
            })
        } else {
            Ok(Self::NonMember {
                position,
                lower: u.arbitrary()?,
                upper: u.arbitrary()?,
                proof,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt as _, Encode as _};
    use commonware_cryptography::{Sha256, sha256::Digest};
    use commonware_storage::bmt::Builder;

    type TestLookup = Lookup<u64, u64, Digest>;

    fn leaf(key: &u64, value: &u64) -> Digest {
        Sha256::hash(&[&key.to_be_bytes(), &value.to_be_bytes()])
    }

    /// Returns `count` entries with keys 10, 20, ... and their tree.
    fn list(count: u64) -> (Vec<(u64, u64)>, Tree<Digest>) {
        let entries: Vec<_> = (1..=count).map(|i| (10 * i, i)).collect();
        let mut builder = Builder::<Sha256>::new(entries.len());
        for (key, value) in &entries {
            builder.add(&leaf(key, value));
        }
        (entries, builder.build())
    }

    fn verify(lookup: &TestLookup, key: u64, root: &Digest) -> Result<Option<u64>, Error> {
        lookup
            .verify::<Sha256>(&key, root, leaf)
            .map(|value| value.copied())
    }

    #[test]
    fn test_opens_every_key() {
        for count in 0..=6 {
            let (entries, tree) = list(count);
            let root = tree.root();
            for (key, value) in &entries {
                let lookup = TestLookup::new(&entries, &tree, key);
                assert!(matches!(lookup, Lookup::Member { .. }));
                assert_eq!(verify(&lookup, *key, &root).unwrap(), Some(*value));
            }
            for key in (0..=count).map(|i| 10 * i + 5) {
                let lookup = TestLookup::new(&entries, &tree, &key);
                assert!(matches!(lookup, Lookup::NonMember { .. }));
                assert_eq!(verify(&lookup, key, &root).unwrap(), None);
            }
        }
    }

    #[test]
    fn test_rejects_tampered_members() {
        let (entries, tree) = list(4);
        let root = tree.root();
        let lookup = TestLookup::new(&entries, &tree, &20);
        let Lookup::Member {
            position,
            value,
            proof,
        } = lookup.clone()
        else {
            panic!("key must be present");
        };
        for tampered in [
            Lookup::Member {
                position,
                value: value + 1,
                proof: proof.clone(),
            },
            Lookup::Member {
                position: position + 1,
                value,
                proof,
            },
        ] {
            assert!(matches!(
                verify(&tampered, 20, &root),
                Err(Error::InvalidOpening)
            ));
        }
        assert!(matches!(
            verify(&lookup, 30, &root),
            Err(Error::InvalidOpening)
        ));
        assert!(matches!(
            verify(&lookup, 20, &list(5).1.root()),
            Err(Error::InvalidOpening)
        ));
    }

    #[test]
    fn test_rejects_tampered_non_members() {
        let (entries, tree) = list(4);
        let root = tree.root();

        // An opening between two neighbors only proves keys strictly between them absent.
        let lookup = TestLookup::new(&entries, &tree, &25);
        for key in [20, 30, 15, 35] {
            assert!(matches!(
                verify(&lookup, key, &root),
                Err(Error::InvalidOpening)
            ));
        }
        let Lookup::NonMember {
            position,
            lower,
            upper,
            proof,
        } = lookup
        else {
            panic!("key must be absent");
        };

        // Neighbors must be present unless the key precedes or follows every entry, and must sit
        // at the claimed position.
        for tampered in [
            Lookup::NonMember {
                position,
                lower,
                upper: None,
                proof: proof.clone(),
            },
            Lookup::NonMember {
                position,
                lower: None,
                upper,
                proof: proof.clone(),
            },
            Lookup::NonMember {
                position: position + 1,
                lower,
                upper,
                proof: proof.clone(),
            },
            Lookup::NonMember {
                position,
                lower: upper,
                upper: lower,
                proof,
            },
            Lookup::NonMember {
                position: 0,
                lower: None,
                upper: None,
                proof: Proof::default(),
            },
        ] {
            assert!(matches!(
                verify(&tampered, 25, &root),
                Err(Error::InvalidOpening)
            ));
        }

        // A present key cannot be proven absent with the neighbors of a nearby absent key.
        let (lower_key, upper_key) = (lower.unwrap().0, upper.unwrap().0);
        assert_eq!((lower_key, upper_key), (20, 30));
        let lookup = TestLookup::new(&entries, &tree, &5);
        assert!(matches!(
            verify(&lookup, 10, &root),
            Err(Error::InvalidOpening)
        ));
        let lookup = TestLookup::new(&entries, &tree, &45);
        assert!(matches!(
            verify(&lookup, 40, &root),
            Err(Error::InvalidOpening)
        ));
    }

    #[test]
    fn test_empty_list() {
        let (entries, tree) = list(0);
        let lookup = TestLookup::new(&entries, &tree, &5);
        assert_eq!(verify(&lookup, 5, &tree.root()).unwrap(), None);
        assert!(matches!(
            verify(&lookup, 5, &list(1).1.root()),
            Err(Error::InvalidOpening)
        ));
    }

    #[test]
    fn test_codec() {
        let (entries, tree) = list(3);
        for key in [5, 10, 25, 30, 35] {
            let lookup = TestLookup::new(&entries, &tree, &key);
            let decoded = TestLookup::decode(lookup.encode()).unwrap();
            assert_eq!(decoded, lookup);
        }
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Lookup<u64, u64, Digest>>,
        }
    }
}
