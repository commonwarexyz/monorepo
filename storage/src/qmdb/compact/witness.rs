//! The persisted witness of a compact-db state and its verification.
//!
//! A [`Witness`] records one applied state: the commit operation, the committed size, and the
//! pinned nodes one operation below it. The journal stores it as a [`StoredWitness`], whose commit
//! stays encoded, so selecting a witness by size never decodes a commit. The commit's inclusion
//! proof is not stored. [`restore`] rebuilds the Merkle by appending the commit operation to the
//! pinned nodes and derives the root and proof from it. [`rebuild`] decodes a journaled witness's
//! commit and maps an entry that cannot be restored to [`Error::DataCorrupted`].

use super::operation::Operation;
use crate::{
    Context,
    journal::{
        self,
        authenticated::{Backing as _, BackingRecovery as _},
        contiguous::variable,
    },
    merkle::{Family, Location, MAX_PINNED_NODES, Proof, compact},
    qmdb::{self, Error, sync::CompactTarget},
};
use bytes::Bytes;
use commonware_codec::{Buf, EncodeSize, Read, Write};
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;

/// An applied state: the last commit operation, the committed size, and the pinned nodes.
#[derive(Clone)]
pub(super) struct Witness<F: Family, D: Digest, O: Operation<F>> {
    /// The last commit operation, at `size - 1`.
    pub(super) commit: O,
    /// The committed database size.
    pub(super) size: Location<F>,
    /// Pinned nodes one operation below the commit, in the order returned by
    /// [`Family::nodes_to_pin`].
    pub(super) pinned_nodes: Vec<D>,
}

impl<F: Family, D: Digest, O: Operation<F>> Witness<F, D, O> {
    /// The journal form of this witness.
    pub(super) fn stored(&self) -> StoredWitness<F, D> {
        StoredWitness {
            commit: self.commit.encode(),
            size: self.size,
            pinned_nodes: self.pinned_nodes.clone(),
        }
    }
}

/// A [`Witness`] as the witness journal stores it, with its commit still encoded.
#[derive(Clone)]
pub(super) struct StoredWitness<F: Family, D: Digest> {
    /// The encoded last commit operation, at `size - 1`.
    pub(super) commit: Bytes,
    /// The committed database size.
    pub(super) size: Location<F>,
    /// Pinned nodes one operation below the commit, in the order returned by
    /// [`Family::nodes_to_pin`].
    pub(super) pinned_nodes: Vec<D>,
}

impl<F: Family, D: Digest> StoredWitness<F, D> {
    /// Decode the commit with `cfg`.
    pub(super) fn decode<O: Operation<F>>(
        self,
        cfg: &O::Cfg,
    ) -> Result<Witness<F, D, O>, commonware_codec::Error> {
        Ok(Witness {
            commit: O::decode_cfg(self.commit, cfg)?,
            size: self.size,
            pinned_nodes: self.pinned_nodes,
        })
    }
}

impl<F: Family, D: Digest> EncodeSize for StoredWitness<F, D> {
    fn encode_size(&self) -> usize {
        self.commit.encode_size() + self.size.encode_size() + self.pinned_nodes.encode_size()
    }
}

impl<F: Family, D: Digest> Write for StoredWitness<F, D> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.commit.write(buf);
        self.size.write(buf);
        self.pinned_nodes.write(buf);
    }
}

impl<F: Family, D: Digest> Read for StoredWitness<F, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, commonware_codec::Error> {
        let commit = Bytes::read_cfg(buf, &(..).into())?;
        let size = Location::<F>::read_cfg(buf, &())?;
        let pinned_nodes = Vec::<D>::read_cfg(buf, &((..=MAX_PINNED_NODES).into(), ()))?;
        Ok(Self {
            commit,
            size,
            pinned_nodes,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<F: Family, D: Digest> arbitrary::Arbitrary<'_> for StoredWitness<F, D>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            commit: u.arbitrary::<Vec<u8>>()?.into(),
            size: Location::new(u.int_in_range(1..=*F::MAX_LEAVES)?),
            pinned_nodes: u.arbitrary()?,
        })
    }
}

/// A witness whose commit has been checked and whose root and commit proof are derived from it.
#[derive(Clone)]
pub(super) struct VerifiedWitness<F: Family, D: Digest, O: Operation<F>> {
    pub(super) witness: Witness<F, D, O>,
    /// Inactivity floor declared by the commit.
    pub(super) inactivity_floor_loc: Location<F>,
    /// Root committed by `witness`.
    pub(super) root: D,
    /// Inclusion proof for the commit at `size - 1` against `root`, derived from the
    /// witness when it was built or loaded.
    pub(super) proof: Proof<F, D>,
}

impl<F: Family, D: Digest, O: Operation<F>> VerifiedWitness<F, D, O> {
    /// The committed size, which also identifies the last commit's location.
    pub(super) const fn size(&self) -> Location<F> {
        self.witness.size
    }

    /// The metadata carried by the commit.
    pub(super) fn metadata(&self) -> Option<&O::Metadata> {
        self.witness.commit.metadata()
    }

    /// The compact-sync target (root and size) this witness can serve.
    pub(super) const fn target(&self) -> CompactTarget<F, D> {
        CompactTarget {
            root: self.root,
            size: self.size(),
        }
    }
}

/// The contiguous variable journal of a compact db's witnesses.
pub(super) type Journal<E, F, D> = variable::Journal<E, StoredWitness<F, D>>;

/// Split a witness journal config into the journal's own config and the codec config that
/// decodes its commits.
pub(super) fn split_config<C>(cfg: variable::Config<C>) -> (variable::Config<()>, C) {
    let variable::Config {
        partition,
        items_per_section,
        compression,
        codec_config,
        page_cache,
        write_buffer,
        replay_buffer,
    } = cfg;
    let journal = variable::Config {
        partition,
        items_per_section,
        compression,
        codec_config: (),
        page_cache,
        write_buffer,
        replay_buffer,
    };
    (journal, codec_config)
}

/// Recover the witness journal bounded at `max_size` when that view can settle selection, and
/// unbounded otherwise.
///
/// Witness position `p` has size at least `p + 1` in an append-only journal, so positions below
/// the cap hold every witness no larger than the cap. A compact-sync import resets the journal to
/// position 1, so an imported state of size 1 leaves position `p` with size at least `p`. A
/// retained start at or above the cap therefore opens unbounded, and a bounded view that ends at
/// the cap with a tip size below the cap widens.
pub(super) async fn recover<E, F, D>(
    context: E,
    config: variable::Config<()>,
    max_size: Option<Location<F>>,
) -> Result<variable::Recovery<E, StoredWitness<F, D>>, Error<F>>
where
    E: Context,
    F: Family,
    D: Digest,
{
    let Some(cap) = max_size else {
        return Ok(Journal::<E, F, D>::recover(context, config, None).await?);
    };
    if variable::Recovery::<E, StoredWitness<F, D>>::span(context.child("span"), &config)
        .await?
        .start
        >= *cap
    {
        return Ok(Journal::<E, F, D>::recover(context, config, None).await?);
    }
    let bounded = Journal::<E, F, D>::recover(context, config, Some(*cap)).await?;
    let bounds = bounded.bounds();

    // The bounded view starts at the span start, below the cap, so a view that ends at the cap
    // is non-empty.
    if bounds.end < *cap || bounded.read(bounds.end - 1).await?.size >= cap {
        return Ok(bounded);
    }
    Ok(bounded.unbounded().await?)
}

/// A Merkle materialized from a witness, with the witness verified against it.
pub(super) struct Rebuilt<F: Family, D: Digest, O: Operation<F>, S: Strategy> {
    pub(super) merkle: compact::Merkle<F, D, S>,
    pub(super) tip: VerifiedWitness<F, D, O>,
}

/// Build a witness for `commit`, the last operation in `merkle`.
///
/// The tip operation's inclusion proof is only computable before the Merkle is pruned to its
/// frontier.
pub(super) fn build_witness<F, O, H, S>(
    merkle: &compact::Merkle<F, H::Digest, S>,
    commit: O,
    inactivity_floor_loc: Location<F>,
) -> Result<VerifiedWitness<F, H::Digest, O>, Error<F>>
where
    F: Family,
    O: Operation<F>,
    H: Hasher,
    S: Strategy,
{
    let hasher = qmdb::hasher::<H>();
    let mem = merkle.mem();
    let size = mem.leaves();
    let last_commit_loc = size - 1;
    let inactive_peaks = F::inactive_peaks(size, inactivity_floor_loc);
    let root = mem.root(&hasher, inactive_peaks)?;
    let pinned_nodes = F::nodes_to_pin(last_commit_loc)
        .map(|pos| *mem.get_node_unchecked(pos))
        .collect::<Vec<_>>();
    let proof = mem.proof(&hasher, last_commit_loc, inactive_peaks)?;
    Ok(VerifiedWitness {
        witness: Witness {
            commit,
            size,
            pinned_nodes,
        },
        inactivity_floor_loc,
        root,
        proof,
    })
}

/// Validate `witness`, materialize its Merkle, and derive its root and commit proof.
///
/// The Merkle is built from the pinned nodes one operation below the commit plus the commit
/// itself, then pruned back to its frontier. A zero size returns [`Error::DataCorrupted`], a
/// non-commit operation returns [`Error::UnexpectedData`], and a floor beyond the commit returns
/// [`Error::FloorBeyondSize`]. Merkle errors propagate unchanged.
pub(super) fn restore<F, O, H, S>(
    strategy: S,
    witness: Witness<F, H::Digest, O>,
) -> Result<Rebuilt<F, H::Digest, O, S>, Error<F>>
where
    F: Family,
    O: Operation<F>,
    H: Hasher,
    S: Strategy,
{
    let Witness {
        commit,
        size,
        pinned_nodes,
    } = witness;
    let Some(last_commit_loc) = size.checked_sub(1) else {
        return Err(Error::DataCorrupted("invalid compact witness"));
    };
    let Some(inactivity_floor_loc) = commit.has_floor() else {
        return Err(Error::UnexpectedData(last_commit_loc));
    };
    if inactivity_floor_loc > last_commit_loc {
        return Err(Error::FloorBeyondSize(
            inactivity_floor_loc,
            last_commit_loc,
        ));
    }
    let mut merkle = compact::Merkle::from_compact_state(strategy, last_commit_loc, pinned_nodes)?;
    merkle.append_leaf(&qmdb::hasher::<H>(), &commit.encode())?;
    let tip = build_witness::<F, O, H, S>(&merkle, commit, inactivity_floor_loc)?;
    merkle.prune_to_frontier();
    Ok(Rebuilt { merkle, tip })
}

/// Decode a journaled witness's commit with `cfg`, then restore it.
///
/// A commit that fails to decode returns [`Error::Journal`], like any undecodable journal entry.
/// Any restore failure is [`Error::DataCorrupted`]: the entry came from this db's own journal.
pub(super) fn rebuild<F, O, H, S>(
    strategy: S,
    stored: StoredWitness<F, H::Digest>,
    cfg: &O::Cfg,
) -> Result<Rebuilt<F, H::Digest, O, S>, Error<F>>
where
    F: Family,
    O: Operation<F>,
    H: Hasher,
    S: Strategy,
{
    let witness = stored
        .decode::<O>(cfg)
        .map_err(|err| Error::Journal(journal::Error::Codec(err)))?;
    restore::<F, O, H, S>(strategy, witness).map_err(|err| match err {
        Error::UnexpectedData(_) => Error::DataCorrupted("last operation was not a commit"),
        _ => Error::DataCorrupted("invalid compact witness"),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        journal::contiguous::Contiguous,
        merkle::{mmb, mmr},
        qmdb::{
            compact::{Config, Db},
            immutable, keyless,
            keyless::fixed::Operation as TestOp,
        },
    };
    use commonware_codec::Error as CodecError;
    use commonware_cryptography::Sha256;
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize, sequence::U64};

    type Sha256Digest = <Sha256 as Hasher>::Digest;

    fn journal_config<C>(
        context: &deterministic::Context,
        partition: &str,
        codec_config: C,
    ) -> variable::Config<C> {
        variable::Config {
            partition: partition.into(),
            items_per_section: NZU64!(4),
            compression: None,
            codec_config,
            page_cache: CacheRef::from_pooler(context, NZU16!(77), NZUsize!(9)),
            write_buffer: NZUsize!(1024),
            replay_buffer: NZUsize!(1024),
        }
    }

    /// Write `entries` to a fresh witness journal in `partition`.
    async fn write_entries<F: Family>(
        context: deterministic::Context,
        partition: &str,
        entries: &[StoredWitness<F, Sha256Digest>],
    ) {
        let cfg = journal_config(&context, partition, ());
        let mut journal = Journal::<_, F, Sha256Digest>::init(context, cfg)
            .await
            .unwrap();
        for entry in entries {
            (journal, _) = journal.append(entry).await.unwrap();
        }
        drop(journal.sync().await.unwrap());
    }

    fn assert_decode_errors<F, O>(valid_cfg: O::Cfg, restrictive_cfg: O::Cfg)
    where
        F: Family,
        O: Operation<F, Metadata = Vec<u8>>,
    {
        deterministic::Runner::default().start(|context| async move {
            let witness = Witness::<F, Sha256Digest, O> {
                commit: O::commit(Some(vec![1, 2, 3]), Location::new(0)),
                size: Location::new(1),
                pinned_nodes: Vec::new(),
            };
            let stored = witness.stored();
            let decoded = stored.clone().decode::<O>(&valid_cfg).unwrap();
            assert_eq!(decoded.commit.metadata(), Some(&vec![1, 2, 3]));
            assert!(matches!(
                stored.clone().decode::<O>(&restrictive_cfg),
                Err(CodecError::InvalidLength(3))
            ));
            let mut invalid_tag = stored.clone();
            invalid_tag.commit = vec![0xff].into();
            assert!(matches!(
                invalid_tag.clone().decode::<O>(&valid_cfg),
                Err(CodecError::InvalidEnum(0xff))
            ));

            // The metadata is valid at the configured limit, then rejected on reopen with a
            // smaller limit. The failed open must preserve the persisted witness.
            write_entries(context.child("write"), "witness-metadata-limit", &[stored]).await;
            let cfg = Config {
                strategy: Sequential,
                witness: journal_config(&context, "witness-metadata-limit", valid_cfg.clone()),
            };
            let mut restrictive = cfg.clone();
            restrictive.witness.codec_config = restrictive_cfg;
            assert!(matches!(
                Db::<F, _, O, Sha256, _>::init(
                    context.child("reject_metadata"),
                    restrictive.clone(),
                    None
                )
                .await,
                Err(Error::Journal(crate::journal::Error::Codec(
                    CodecError::InvalidLength(3)
                )))
            ));
            // An import whose commit the restrictive config rejects fails before it can replace
            // the partition's contents.
            assert!(matches!(
                Db::<F, _, O, Sha256, _>::init_from_sync(
                    context.child("reject_import"),
                    restrictive.clone(),
                    Location::new(0),
                    Vec::new(),
                    O::commit(Some(vec![1, 2, 3]), Location::new(0)),
                ),
                Err(Error::Journal(crate::journal::Error::Codec(
                    CodecError::InvalidLength(3)
                )))
            ));
            let db = Db::<F, _, O, Sha256, _>::init(context.child("reopen"), cfg, None)
                .await
                .unwrap();
            assert_eq!(db.get_metadata(), Some(vec![1, 2, 3]));
            db.destroy().await.unwrap();

            // The invalid operation tag sits inside a valid journal frame.
            write_entries(
                context.child("write_invalid_tag"),
                "witness-invalid-tag",
                &[invalid_tag],
            )
            .await;
            assert!(matches!(
                Db::<F, _, O, Sha256, _>::init(
                    context.child("reject_tag"),
                    Config {
                        strategy: Sequential,
                        witness: journal_config(&context, "witness-invalid-tag", valid_cfg),
                    },
                    None,
                )
                .await,
                Err(Error::Journal(crate::journal::Error::Codec(
                    CodecError::InvalidEnum(0xff)
                )))
            ));
        });
    }

    #[test]
    fn test_decode_errors_keyless_mmr() {
        assert_decode_errors::<mmr::Family, keyless::variable::Operation<mmr::Family, Vec<u8>>>(
            ((..=3).into(), ()),
            ((..=2).into(), ()),
        );
    }

    #[test]
    fn test_decode_errors_keyless_mmb() {
        assert_decode_errors::<mmb::Family, keyless::variable::Operation<mmb::Family, Vec<u8>>>(
            ((..=3).into(), ()),
            ((..=2).into(), ()),
        );
    }

    #[test]
    fn test_decode_errors_immutable_mmr() {
        assert_decode_errors::<
            mmr::Family,
            immutable::variable::Operation<mmr::Family, U64, Vec<u8>>,
        >(((), ((..=3).into(), ())), ((), ((..=2).into(), ())));
    }

    #[test]
    fn test_decode_errors_immutable_mmb() {
        assert_decode_errors::<
            mmb::Family,
            immutable::variable::Operation<mmb::Family, U64, Vec<u8>>,
        >(((), ((..=3).into(), ())), ((), ((..=2).into(), ())));
    }

    /// Bounded initialization selects by size without decoding the commits it discards, so a
    /// newer witness whose commit no longer decodes does not hide an older state that does.
    ///
    /// Each case builds the selected state from `imported` genesis or fresh storage, commits
    /// once more, then appends a witness of `discarded_size` whose metadata the restrictive
    /// config rejects, and reopens bounded below it.
    fn assert_bounded_selection_ignores_discarded_commits<F, O>(
        valid_cfg: O::Cfg,
        restrictive_cfg: O::Cfg,
    ) where
        F: Family,
        O: Operation<F, Metadata = Vec<u8>>,
    {
        for (index, (imported, discarded_size)) in
            [(false, 5), (true, 3), (true, 5)].into_iter().enumerate()
        {
            let valid_cfg = valid_cfg.clone();
            let restrictive_cfg = restrictive_cfg.clone();
            deterministic::Runner::default().start(|context| async move {
                let partition = format!("witness-bounded-selection-{index}");
                let cfg = Config {
                    strategy: Sequential,
                    witness: journal_config(&context, &partition, valid_cfg),
                };
                let db = if imported {
                    // Seed an older history for the genesis import to replace.
                    let seeded =
                        Db::<F, _, O, Sha256, _>::init(context.child("seed"), cfg.clone(), None)
                            .await
                            .unwrap();
                    let floor = seeded.inactivity_floor_loc();
                    let batch = seeded
                        .new_batch()
                        .merkleize(&seeded, None, floor)
                        .await
                        .unwrap();
                    let (seeded, _) = seeded.apply_batch(batch).await.unwrap();
                    drop(seeded.sync().await.unwrap());
                    let db = Db::<F, _, O, Sha256, _>::init_from_sync(
                        context.child("import"),
                        cfg.clone(),
                        Location::new(0),
                        Vec::new(),
                        O::commit(None, Location::new(0)),
                    )
                    .unwrap();
                    db.commit().await.unwrap()
                } else {
                    Db::<F, _, O, Sha256, _>::init(context.child("fresh"), cfg.clone(), None)
                        .await
                        .unwrap()
                };
                let floor = db.inactivity_floor_loc();
                let batch = db.new_batch().merkleize(&db, None, floor).await.unwrap();
                let (db, _) = db.apply_batch(batch).await.unwrap();
                let db = db.sync().await.unwrap();
                let selected = db.target();
                assert_eq!(selected.size, Location::new(2));
                drop(db);

                // Append a newer witness whose commit only the valid config decodes.
                let (journal_cfg, _) = split_config(cfg.witness.clone());
                let journal =
                    Journal::<_, F, Sha256Digest>::init(context.child("append"), journal_cfg)
                        .await
                        .unwrap();
                let discarded = Witness::<F, Sha256Digest, O> {
                    commit: O::commit(Some(vec![1, 2, 3]), Location::new(0)),
                    size: Location::new(discarded_size),
                    pinned_nodes: Vec::new(),
                };
                let (journal, _) = journal.append(&discarded.stored()).await.unwrap();
                drop(journal.sync().await.unwrap());

                let mut restrictive = cfg;
                restrictive.witness.codec_config = restrictive_cfg;
                let db = Db::<F, _, O, Sha256, _>::init(
                    context.child("bounded"),
                    restrictive,
                    Some(Location::new(discarded_size - 1)),
                )
                .await
                .unwrap();
                assert_eq!(db.target(), selected);
                db.destroy().await.unwrap();
            });
        }
    }

    #[test]
    fn test_bounded_selection_ignores_discarded_commits_keyless_mmr() {
        assert_bounded_selection_ignores_discarded_commits::<
            mmr::Family,
            keyless::variable::Operation<mmr::Family, Vec<u8>>,
        >(((..=3).into(), ()), ((..=2).into(), ()));
    }

    #[test]
    fn test_bounded_selection_ignores_discarded_commits_keyless_mmb() {
        assert_bounded_selection_ignores_discarded_commits::<
            mmb::Family,
            keyless::variable::Operation<mmb::Family, Vec<u8>>,
        >(((..=3).into(), ()), ((..=2).into(), ()));
    }

    #[test]
    fn test_bounded_selection_ignores_discarded_commits_immutable_mmr() {
        assert_bounded_selection_ignores_discarded_commits::<
            mmr::Family,
            immutable::variable::Operation<mmr::Family, U64, Vec<u8>>,
        >(((), ((..=3).into(), ())), ((), ((..=2).into(), ())));
    }

    #[test]
    fn test_bounded_selection_ignores_discarded_commits_immutable_mmb() {
        assert_bounded_selection_ignores_discarded_commits::<
            mmb::Family,
            immutable::variable::Operation<mmb::Family, U64, Vec<u8>>,
        >(((), ((..=3).into(), ())), ((), ((..=2).into(), ())));
    }

    fn assert_restore_rejects_invalid_witness<F: Family>() {
        let genesis = Witness {
            commit: TestOp::<F, U64>::Commit(None, Location::new(0)),
            size: Location::new(1),
            pinned_nodes: Vec::new(),
        };

        let mut empty = genesis.clone();
        empty.size = Location::new(0);
        assert!(matches!(
            restore::<F, _, Sha256, _>(Sequential, empty),
            Err(Error::DataCorrupted("invalid compact witness"))
        ));

        let mut non_commit = genesis.clone();
        non_commit.commit = TestOp::Append(U64::new(7));
        assert!(matches!(
            restore::<F, _, Sha256, _>(Sequential, non_commit),
            Err(Error::UnexpectedData(loc)) if loc == 0
        ));

        let mut invalid_floor = genesis.clone();
        invalid_floor.commit = TestOp::Commit(None, Location::new(1));
        assert!(matches!(
            restore::<F, _, Sha256, _>(Sequential, invalid_floor),
            Err(Error::FloorBeyondSize(floor, loc)) if floor == 1 && loc == 0
        ));

        let mut invalid_pins = genesis;
        invalid_pins.pinned_nodes.push(Sha256::fill(0xff));
        assert!(matches!(
            restore::<F, _, Sha256, _>(Sequential, invalid_pins),
            Err(Error::Merkle(crate::merkle::Error::InvalidPinnedNodes))
        ));
    }

    #[test]
    fn test_restore_rejects_invalid_witness_mmr() {
        assert_restore_rejects_invalid_witness::<mmr::Family>();
    }

    #[test]
    fn test_restore_rejects_invalid_witness_mmb() {
        assert_restore_rejects_invalid_witness::<mmb::Family>();
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;
        use commonware_cryptography::sha256;

        commonware_conformance::conformance_tests! {
            CodecConformance<StoredWitness<mmr::Family, sha256::Digest>>,
            CodecConformance<StoredWitness<mmb::Family, sha256::Digest>>,
        }
    }

    /// Corrupt the entry at `pos` with `f`, preserving the entries above it.
    pub(crate) async fn corrupt_entry<E, F, D>(
        journal: Journal<E, F, D>,
        pos: u64,
        f: impl FnOnce(&mut StoredWitness<F, D>),
    ) -> Journal<E, F, D>
    where
        E: Context,
        F: Family,
        D: Digest,
    {
        let mut entries = Vec::new();
        for p in pos..journal.bounds().end {
            entries.push(journal.read(p).await.unwrap());
        }
        f(&mut entries[0]);
        let mut journal = journal.test_truncate(pos).await.unwrap();
        for entry in &entries {
            (journal, _) = journal.append(entry).await.unwrap();
        }
        journal.sync().await.unwrap()
    }

    /// Read the tip witness entry.
    pub(crate) async fn tip<E, F, D>(journal: &Journal<E, F, D>) -> StoredWitness<F, D>
    where
        E: Context,
        F: Family,
        D: Digest,
    {
        let size = journal.size();
        journal.read(size - 1).await.unwrap()
    }

    /// Append a witness entry without syncing it.
    pub(crate) async fn append_unsynced<E, F, D>(
        journal: Journal<E, F, D>,
        entry: StoredWitness<F, D>,
    ) -> Journal<E, F, D>
    where
        E: Context,
        F: Family,
        D: Digest,
    {
        let (journal, _) = journal.append(&entry).await.unwrap();
        journal
    }

    /// Replace the tip witness entry.
    pub(crate) async fn overwrite_tip<E, F, D>(
        journal: Journal<E, F, D>,
        entry: StoredWitness<F, D>,
    ) -> Journal<E, F, D>
    where
        E: Context,
        F: Family,
        D: Digest,
    {
        let entries = journal.size();
        let journal = journal.test_truncate(entries - 1).await.unwrap();
        let (journal, _) = journal.append(&entry).await.unwrap();
        journal.sync().await.unwrap()
    }
}
