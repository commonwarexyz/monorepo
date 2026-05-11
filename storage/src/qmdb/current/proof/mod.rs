//! Proof types for [crate::qmdb::current] authenticated databases.
//!
//! This module provides:
//! - [OpsRootWitness]: Authenticates an ops root against a canonical `current` root.
//! - [RangeProof]: Proves a range of operations exist in the database.
//! - [OperationProof]: Proves a specific operation is active in the database.

mod geometry;

use self::geometry::RangeProofGeometry;
use crate::{
    journal::contiguous::{Contiguous, Reader as _},
    merkle::{
        self,
        hasher::{Hasher, Standard as StandardHasher},
        storage::Storage,
        Family, Graftable, Location, Position, Proof,
    },
    qmdb::{
        self,
        current::{db::combine_roots, grafting},
        Error,
    },
};
use bytes::{Buf, BufMut};
use commonware_codec::{
    varint::UInt, Codec, EncodeSize, Read, ReadExt as _, ReadRangeExt as _, Write,
};
use commonware_cryptography::{Digest, Hasher as CHasher};
use commonware_utils::bitmap::{Prunable as BitMap, Readable as BitmapReadable};
use core::ops::Range;
use futures::future::try_join_all;
use std::{collections::BTreeMap, num::NonZeroU64};
use tracing::debug;

/// Witness that a particular `ops_root` is committed by a `current` canonical root.
///
/// `canonical_root = hash(ops_root || grafted_root [|| next_bit || partial_chunk_digest])`
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct OpsRootWitness<D: Digest> {
    /// The grafted-tree root committed by the canonical root.
    pub grafted_root: D,

    /// The trailing partial chunk contribution, if the bitmap length is not chunk-aligned:
    /// `(next_bit, partial_chunk_digest)`.
    pub partial_chunk: Option<(u64, D)>,
}

impl<D: Digest> OpsRootWitness<D> {
    /// Return true if this witness proves that `canonical_root` commits to `ops_root`.
    pub fn verify<H: CHasher<Digest = D>>(
        &self,
        hasher: &StandardHasher<H>,
        ops_root: &D,
        canonical_root: &D,
    ) -> bool {
        let partial = self.partial_chunk.as_ref().map(|(nb, d)| (*nb, d));
        combine_roots(hasher, ops_root, &self.grafted_root, partial) == *canonical_root
    }
}

impl<D: Digest> Write for OpsRootWitness<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.grafted_root.write(buf);
        self.partial_chunk.is_some().write(buf);
        if let Some((next_bit, digest)) = &self.partial_chunk {
            UInt(*next_bit).write(buf);
            digest.write(buf);
        }
    }
}

impl<D: Digest> EncodeSize for OpsRootWitness<D> {
    fn encode_size(&self) -> usize {
        self.grafted_root.encode_size()
            + self
                .partial_chunk
                .as_ref()
                .map_or(1, |(nb, d)| 1 + UInt(*nb).encode_size() + d.encode_size())
    }
}

impl<D: Digest> Read for OpsRootWitness<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let grafted_root = D::read(buf)?;
        let partial_chunk = if bool::read(buf)? {
            let next_bit = UInt::<u64>::read(buf)?.into();
            let digest = D::read(buf)?;
            Some((next_bit, digest))
        } else {
            None
        };
        Ok(Self {
            grafted_root,
            partial_chunk,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<D: Digest> arbitrary::Arbitrary<'_> for OpsRootWitness<D>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            grafted_root: u.arbitrary()?,
            partial_chunk: u.arbitrary()?,
        })
    }
}

// Provides complete bitmap chunks by index for grafted reconstruction. Pruned chunks are returned
// as zero chunks because their bits are already folded into the inactive prefix.
struct BitmapGrafting<'a, B, const N: usize> {
    status: &'a B,
    grafting_height: u32,
    complete_chunks: u64,
    pruned_chunks: u64,
}

impl<'a, B: BitmapReadable<N>, const N: usize> BitmapGrafting<'a, B, N> {
    fn new(status: &'a B) -> Self {
        Self {
            status,
            grafting_height: grafting::height::<N>(),
            complete_chunks: status.complete_chunks() as u64,
            pruned_chunks: status.pruned_chunks() as u64,
        }
    }

    fn chunk(&self, idx: u64) -> Option<[u8; N]> {
        if idx >= self.complete_chunks {
            None
        } else if idx < self.pruned_chunks {
            Some([0u8; N])
        } else {
            Some(self.status.get_chunk(idx as usize))
        }
    }
}

// Reconstructs the canonical grafted root from the ops-tree range proof, operation elements, and
// the prefix/suffix witnesses described by the five-segment geometry.
fn reconstruct_grafted_root<F: Graftable, H: CHasher, C: AsRef<[u8]>>(
    verifier: &grafting::Verifier<'_, F, H>,
    proof: &RangeProof<F, H::Digest>,
    geometry: &RangeProofGeometry<F>,
    collected: &BTreeMap<Position<F>, H::Digest>,
    get_chunk: impl Fn(u64) -> Option<C>,
) -> Option<H::Digest> {
    let prefix_boundary = geometry.prefix_boundary();
    let range_peaks = geometry.range_peaks();
    let suffix_boundary = geometry.suffix_boundary();
    let (prefix_counts, prefix_bitmap_witnesses, prefix_boundary_digests) =
        geometry.split_prefix_witnesses(&proof.prefix_witnesses)?;
    let (suffix_boundary_digests, suffix_bitmap_witnesses, suffix_counts) =
        geometry.split_suffix_witnesses(&proof.suffix_witnesses)?;

    let mut peak_entries = Vec::with_capacity(
        proof.prefix_witnesses.len() + range_peaks.len() + proof.suffix_witnesses.len(),
    );
    peak_entries.extend(prefix_bitmap_witnesses.iter().copied().zip(prefix_counts));
    let mut range_digests = Vec::with_capacity(range_peaks.len());
    for pos in range_peaks.positions() {
        range_digests.push(*collected.get(&pos)?);
    }

    // `root_with_folded_peaks` needs one ordered peak entry per reconstructed grafted peak. The
    // pure prefix/suffix witnesses already contain grafted digests; the range-adjacent ops-tree
    // digests must be transformed with their bitmap chunks first.
    let middle_iter = prefix_boundary
        .heights_with_digests(prefix_boundary_digests)
        .chain(range_peaks.heights_with_digests(&range_digests))
        .chain(suffix_boundary.heights_with_digests(suffix_boundary_digests));
    peak_entries.extend(grafting::transform_peak_digests::<F, _, _, _>(
        verifier,
        middle_iter,
        prefix_boundary.start_leaf(),
        geometry.grafting_height(),
        get_chunk,
    ));
    peak_entries.extend(suffix_bitmap_witnesses.iter().copied().zip(suffix_counts));

    let inactive_peaks = proof.proof.inactive_peaks;
    let inactive_to_fold = grafting::transformed_inactive_peaks::<F, _>(
        &peak_entries,
        inactive_peaks,
        geometry.total_peaks(),
    )
    .ok()?;
    let digests = peak_entries.iter().map(|(digest, _count)| digest);
    verifier.root_with_folded_peaks(geometry.leaves(), inactive_to_fold, inactive_peaks, digests)
}

struct GraftedProofParts<F: Family, D: Digest> {
    proof: Proof<F, D>,
    prefix_witnesses: Vec<D>,
    suffix_witnesses: Vec<D>,
}

fn peak_digests<F: Family, D: Digest>(
    peaks: impl IntoIterator<Item = Position<F>>,
    fetched: &BTreeMap<Position<F>, D>,
) -> Result<Vec<D>, Error<F>> {
    peaks
        .into_iter()
        .map(|pos| {
            fetched
                .get(&pos)
                .copied()
                .ok_or_else(|| Error::from(merkle::Error::<F>::MissingNode(pos)))
        })
        .collect()
}

fn prefix_witness<
    F: Graftable,
    D: Digest,
    H: CHasher<Digest = D>,
    B: BitmapReadable<N>,
    const N: usize,
>(
    hasher: &StandardHasher<H>,
    bitmap: &BitmapGrafting<'_, B, N>,
    geometry: &RangeProofGeometry<F>,
    ops_peak_digests: &[D],
) -> Vec<D> {
    let pure_prefix = geometry.pure_prefix();
    let prefix_boundary = geometry.prefix_boundary();
    let (pure_prefix_digests, boundary_digests) = ops_peak_digests.split_at(pure_prefix.len());
    debug_assert_eq!(boundary_digests.len(), prefix_boundary.len());
    let mut witness = grafting::transform_peak_digests::<F, _, _, _>(
        hasher,
        pure_prefix.heights_with_digests(pure_prefix_digests),
        pure_prefix.start_leaf(),
        bitmap.grafting_height,
        |idx| bitmap.chunk(idx),
    )
    .into_iter()
    .map(|(digest, _count)| digest)
    .collect::<Vec<_>>();
    witness.extend_from_slice(boundary_digests);
    witness
}

fn suffix_witness<
    F: Graftable,
    D: Digest,
    H: CHasher<Digest = D>,
    B: BitmapReadable<N>,
    const N: usize,
>(
    hasher: &StandardHasher<H>,
    bitmap: &BitmapGrafting<'_, B, N>,
    geometry: &RangeProofGeometry<F>,
    ops_peak_digests: &[D],
) -> Vec<D> {
    let suffix_boundary = geometry.suffix_boundary();
    let pure_suffix = geometry.pure_suffix();
    let (boundary_digests, pure_suffix_digests) = ops_peak_digests.split_at(suffix_boundary.len());
    debug_assert_eq!(pure_suffix_digests.len(), pure_suffix.len());
    let mut witness = boundary_digests.to_vec();
    witness.extend(
        grafting::transform_peak_digests::<F, _, _, _>(
            hasher,
            pure_suffix.heights_with_digests(pure_suffix_digests),
            pure_suffix.start_leaf(),
            bitmap.grafting_height,
            |idx| bitmap.chunk(idx),
        )
        .into_iter()
        .map(|(digest, _count)| digest),
    );
    witness
}

async fn build_grafted_range_proof<
    F: Graftable,
    D: Digest,
    H: CHasher<Digest = D>,
    S: Storage<F, Digest = D>,
    B: BitmapReadable<N>,
    const N: usize,
>(
    hasher: &StandardHasher<H>,
    bitmap: &BitmapGrafting<'_, B, N>,
    storage: &S,
    geometry: &RangeProofGeometry<F>,
) -> Result<GraftedProofParts<F, D>, Error<F>> {
    let proof_positions = merkle::range_collection_nodes(
        geometry.leaves(),
        geometry.inactive_peaks(),
        geometry.range(),
    )?;
    let mut fetch_positions = proof_positions.clone();
    fetch_positions.extend(geometry.prefix_positions());
    fetch_positions.extend(geometry.after_positions());
    fetch_positions.sort_unstable();
    debug_assert!(
        fetch_positions
            .windows(2)
            .all(|window| window[0] != window[1]),
        "grafted proof fetch positions should be unique"
    );

    let node_futures = fetch_positions
        .into_iter()
        .map(|pos| async move { storage.get_node(pos).await.map(|digest| (pos, digest)) })
        .collect::<Vec<_>>();
    let fetched: BTreeMap<Position<F>, D> = try_join_all(node_futures)
        .await?
        .into_iter()
        .map(|(pos, digest)| {
            digest
                .ok_or_else(|| Error::from(merkle::Error::<F>::MissingNode(pos)))
                .map(|d| (pos, d))
        })
        .collect::<Result<_, Error<F>>>()?;

    let proof = merkle::build_range_collection_proof::<F, D, Error<F>>(
        geometry.leaves(),
        geometry.inactive_peaks(),
        &proof_positions,
        |pos| fetched.get(&pos).copied(),
        |pos| Error::from(merkle::Error::<F>::MissingNode(pos)),
    )?;

    let prefix_ops_peak_digests = peak_digests(geometry.prefix_positions(), &fetched)?;
    let prefix_witnesses =
        prefix_witness::<F, D, H, B, N>(hasher, bitmap, geometry, &prefix_ops_peak_digests);

    let suffix_ops_peak_digests = peak_digests(geometry.after_positions(), &fetched)?;
    let suffix_witnesses =
        suffix_witness::<F, D, H, B, N>(hasher, bitmap, geometry, &suffix_ops_peak_digests);

    Ok(GraftedProofParts {
        proof,
        prefix_witnesses,
        suffix_witnesses,
    })
}

/// A proof that a range of operations exist in the database.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct RangeProof<F: Family, D: Digest> {
    /// The Merkle digest material required to verify the proof.
    pub proof: Proof<F, D>,

    /// Extra prefix witnesses needed when grafted reconstruction must inspect peaks that ops-tree
    /// proof collection could otherwise hide behind a prefix accumulator.
    ///
    /// This vector follows the geometry's prefix segment order: bitmap witness digests for
    /// `pure_prefix`, then ops-tree peak digests for `prefix_boundary`.
    pub prefix_witnesses: Vec<D>,

    /// Extra suffix witnesses needed when grafted reconstruction must inspect peaks that ops-tree
    /// proof collection could otherwise hide behind a suffix accumulator.
    ///
    /// This vector follows the geometry's suffix segment order: ops-tree peak digests for
    /// `suffix_boundary`, then bitmap witness digests for `pure_suffix`.
    pub suffix_witnesses: Vec<D>,

    /// The partial chunk digest from the status bitmap at the time of proof generation, if any.
    pub partial_chunk_digest: Option<D>,

    /// The ops-tree root at the time of proof generation.
    /// Needed by the verifier to reconstruct the canonical root.
    pub ops_root: D,
}

/// Parameters that identify the operation span and snapshot used to build a range proof.
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct RangeProofSpec<F: Family, D: Digest> {
    /// First operation location to prove.
    pub start_loc: Location<F>,

    /// Maximum number of operations to include.
    pub max_ops: NonZeroU64,

    /// Inactivity floor used to fold old inactive peaks.
    pub inactivity_floor: Location<F>,

    /// The ops-tree root at the time of proof generation.
    pub ops_root: D,
}

impl<F: Graftable, D: Digest> RangeProof<F, D> {
    /// Create a new range proof for the provided `range` of operations.
    pub async fn new<H: CHasher<Digest = D>, S: Storage<F, Digest = D>, const N: usize>(
        hasher: &StandardHasher<H>,
        status: &impl BitmapReadable<N>,
        storage: &S,
        inactivity_floor: Location<F>,
        range: Range<Location<F>>,
        ops_root: D,
    ) -> Result<Self, Error<F>> {
        let bitmap = BitmapGrafting::new(status);
        let leaves = Location::try_from(storage.size().await)?;
        let inactive_peaks = grafting::chunk_aligned_inactive_peaks::<F>(
            leaves,
            inactivity_floor,
            bitmap.grafting_height,
        )?;
        let geometry = RangeProofGeometry::new(
            leaves,
            range,
            inactive_peaks,
            bitmap.grafting_height,
            bitmap.complete_chunks,
        )?;

        let requires_grafted_reconstruction = geometry.requires_grafted_reconstruction()?;
        let GraftedProofParts {
            proof,
            prefix_witnesses,
            suffix_witnesses,
        } = if requires_grafted_reconstruction {
            build_grafted_range_proof(hasher, &bitmap, storage, &geometry).await?
        } else {
            GraftedProofParts {
                proof: merkle::verification::historical_range_proof(
                    hasher,
                    storage,
                    geometry.leaves(),
                    geometry.range(),
                    geometry.inactive_peaks(),
                )
                .await?,
                prefix_witnesses: Vec::new(),
                suffix_witnesses: Vec::new(),
            }
        };

        let (last_chunk, next_bit) = status.last_chunk();
        let partial_chunk_digest = if next_bit != BitMap::<N>::CHUNK_SIZE_BITS {
            // Last chunk is incomplete, meaning it is not yet committed by the grafted bitmap root
            // and needs to be included in the proof.
            Some(hasher.digest(&last_chunk))
        } else {
            None
        };

        Ok(Self {
            proof,
            prefix_witnesses,
            suffix_witnesses,
            partial_chunk_digest,
            ops_root,
        })
    }

    /// Returns a proof that the specified range of operations are part of the database, along with
    /// the operations from the range and their activity status chunks. A truncated range (from
    /// hitting the max) can be detected by looking at the length of the returned operations vector.
    ///
    /// # Errors
    ///
    /// Returns [Error::OperationPruned] if `start_loc` falls in a pruned bitmap chunk.
    /// Returns [`merkle::Error::LocationOverflow`] if `start_loc` > [merkle::Family::MAX_LEAVES].
    /// Returns [`merkle::Error::RangeOutOfBounds`] if `start_loc` >= number of leaves in the tree.
    pub async fn new_with_ops<
        H: CHasher<Digest = D>,
        C: Contiguous,
        S: Storage<F, Digest = D>,
        const N: usize,
    >(
        hasher: &StandardHasher<H>,
        status: &impl BitmapReadable<N>,
        storage: &S,
        log: &C,
        request: RangeProofSpec<F, D>,
    ) -> Result<(Self, Vec<C::Item>, Vec<[u8; N]>), Error<F>> {
        // Compute the end location of the range.
        let leaves = Location::new(status.len());
        if request.start_loc >= leaves {
            return Err(merkle::Error::RangeOutOfBounds(request.start_loc).into());
        }

        // Reject ranges that start in pruned bitmap chunks.
        let chunk_bits = BitMap::<N>::CHUNK_SIZE_BITS;
        let start = *request.start_loc / chunk_bits;
        if (start as usize) < status.pruned_chunks() {
            return Err(Error::OperationPruned(request.start_loc));
        }

        let max_loc = request.start_loc.saturating_add(request.max_ops.get());
        let end_loc = core::cmp::min(max_loc, leaves);

        // Generate the proof from the grafted storage.
        let proof = Self::new(
            hasher,
            status,
            storage,
            request.inactivity_floor,
            request.start_loc..end_loc,
            request.ops_root,
        )
        .await?;

        // Collect the operations necessary to verify the proof.
        let reader = log.reader().await;
        let futures = (*request.start_loc..*end_loc)
            .map(|i| reader.read(i))
            .collect::<Vec<_>>();
        let ops = try_join_all(futures).await?;

        // Gather the chunks necessary to verify the proof.
        let end = (*end_loc - 1) / chunk_bits; // chunk that contains the last bit
        let chunks = (start..=end)
            .map(|i| status.get_chunk(i as usize))
            .collect::<Vec<_>>();

        Ok((proof, ops, chunks))
    }

    /// Return true if the given sequence of `ops` were applied starting at location `start_loc` in
    /// the db with the provided root, and having the activity status described by `chunks`.
    pub fn verify<H: CHasher<Digest = D>, O: Codec, const N: usize>(
        &self,
        root_hasher: &StandardHasher<H>,
        start_loc: Location<F>,
        ops: &[O],
        chunks: &[[u8; N]],
        root: &H::Digest,
    ) -> bool {
        if ops.is_empty() || chunks.is_empty() {
            debug!("verification failed, empty input");
            return false;
        }
        // Compute the (non-inclusive) end location of the range.
        let Some(end_loc) = start_loc.checked_add(ops.len() as u64) else {
            debug!("verification failed, end_loc overflow");
            return false;
        };

        let leaves = self.proof.leaves;
        if end_loc > leaves {
            debug!(
                loc = ?end_loc,
                ?leaves, "verification failed, invalid range"
            );
            return false;
        }

        // Validate the number of input chunks.
        let chunk_bits = BitMap::<N>::CHUNK_SIZE_BITS;
        let start_chunk = *start_loc / chunk_bits;
        let end_chunk = (*end_loc - 1) / chunk_bits;
        let complete_chunks = *leaves / chunk_bits;

        if (end_chunk - start_chunk + 1) != chunks.len() as u64 {
            debug!("verification failed, chunk metadata length mismatch");
            return false;
        }

        let next_bit = *leaves % chunk_bits;
        let has_partial_chunk = next_bit != 0;

        let elements = ops.iter().map(|op| op.encode()).collect::<Vec<_>>();
        let chunk_vec = chunks.iter().map(|c| c.as_ref()).collect::<Vec<_>>();
        let grafting_height = grafting::height::<N>();
        let grafting_verifier = grafting::Verifier::<F, H>::new(
            grafting_height,
            start_chunk,
            chunk_vec,
            qmdb::ROOT_BAGGING,
        );

        // For partial chunks, validate the last chunk digest from the proof.
        if has_partial_chunk {
            let Some(last_chunk_digest) = self.partial_chunk_digest else {
                debug!("proof has no partial chunk digest");
                return false;
            };

            // If the proof covers an operation in the partial chunk, verify that the
            // chunk provided by the caller matches the digest embedded in the proof.
            if end_chunk == complete_chunks {
                let last_chunk = chunks.last().expect("chunks non-empty");
                if last_chunk_digest != grafting_verifier.digest(last_chunk) {
                    debug!("last chunk digest does not match expected value");
                    return false;
                }
            }
        } else if self.partial_chunk_digest.is_some() {
            debug!("proof has unexpected partial chunk digest");
            return false;
        }

        let geometry = match RangeProofGeometry::new(
            leaves,
            start_loc..end_loc,
            self.proof.inactive_peaks,
            grafting_height,
            complete_chunks,
        ) {
            Ok(geometry) => geometry,
            Err(error) => {
                debug!(?error, "verification failed, invalid proof geometry");
                return false;
            }
        };
        let requires_grafted_reconstruction = match geometry.requires_grafted_reconstruction() {
            Ok(requires_grafted_reconstruction) => requires_grafted_reconstruction,
            Err(error) => {
                debug!(?error, "verification failed, invalid size");
                return false;
            }
        };
        let merkle_root = if !requires_grafted_reconstruction {
            if !self.prefix_witnesses.is_empty() || !self.suffix_witnesses.is_empty() {
                debug!("verification failed, unexpected prefix/suffix witnesses");
                return false;
            }
            match self
                .proof
                .reconstruct_root(&grafting_verifier, &elements, start_loc)
            {
                Ok(root) => root,
                Err(error) => {
                    debug!(?error, "invalid proof input");
                    return false;
                }
            }
        } else {
            let mut collected = Vec::new();
            if let Err(error) = self.proof.reconstruct_range_collecting(
                &grafting_verifier,
                &elements,
                start_loc,
                &mut collected,
            ) {
                debug!(?error, "invalid proof input");
                return false;
            };

            let collected: BTreeMap<Position<F>, D> = collected.into_iter().collect();
            let get_chunk = |chunk_idx: u64| -> Option<&[u8]> {
                if chunk_idx >= complete_chunks {
                    return None;
                }
                chunk_idx
                    .checked_sub(start_chunk)
                    .filter(|&idx| idx < chunks.len() as u64)
                    .map(|idx| chunks[idx as usize].as_ref())
            };
            let Some(root) = reconstruct_grafted_root(
                &grafting_verifier,
                self,
                &geometry,
                &collected,
                get_chunk,
            ) else {
                debug!("verification failed, could not reconstruct grafted root");
                return false;
            };
            root
        };

        let partial =
            has_partial_chunk.then(|| (next_bit, self.partial_chunk_digest.as_ref().unwrap()));
        combine_roots(root_hasher, &self.ops_root, &merkle_root, partial) == *root
    }
}

impl<F: Family, D: Digest> Write for RangeProof<F, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.proof.write(buf);
        self.prefix_witnesses.write(buf);
        self.suffix_witnesses.write(buf);
        self.partial_chunk_digest.write(buf);
        self.ops_root.write(buf);
    }
}

impl<F: Family, D: Digest> EncodeSize for RangeProof<F, D> {
    fn encode_size(&self) -> usize {
        self.proof.encode_size()
            + self.prefix_witnesses.encode_size()
            + self.suffix_witnesses.encode_size()
            + self.partial_chunk_digest.encode_size()
            + self.ops_root.encode_size()
    }
}

impl<F: Family, D: Digest> Read for RangeProof<F, D> {
    /// The maximum number of digests allowed across all digest vectors in the range proof.
    type Cfg = usize;

    fn read_cfg(
        buf: &mut impl Buf,
        max_digests: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let proof = Proof::<F, D>::read_cfg(buf, max_digests)?;
        let remaining = max_digests - proof.digests.len();
        let prefix_witnesses = Vec::<D>::read_range(buf, ..=remaining)?;
        let remaining = remaining - prefix_witnesses.len();
        let suffix_witnesses = Vec::<D>::read_range(buf, ..=remaining)?;
        let partial_chunk_digest = Option::<D>::read(buf)?;
        let ops_root = D::read(buf)?;
        Ok(Self {
            proof,
            prefix_witnesses,
            suffix_witnesses,
            partial_chunk_digest,
            ops_root,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<F: Family, D: Digest> arbitrary::Arbitrary<'_> for RangeProof<F, D>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            proof: u.arbitrary()?,
            prefix_witnesses: u.arbitrary()?,
            suffix_witnesses: u.arbitrary()?,
            partial_chunk_digest: u.arbitrary()?,
            ops_root: u.arbitrary()?,
        })
    }
}

/// A proof that a specific operation is currently active in the database.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct OperationProof<F: Family, D: Digest, const N: usize> {
    /// The location of the operation in the db.
    pub loc: Location<F>,

    /// The status bitmap chunk that contains the bit corresponding the operation's location.
    pub chunk: [u8; N],

    /// The range proof that incorporates activity status for the operation designated by `loc`.
    pub range_proof: RangeProof<F, D>,
}

impl<F: Graftable, D: Digest, const N: usize> OperationProof<F, D, N> {
    /// Return an inclusion proof that incorporates activity status for the operation designated by
    /// `loc`.
    ///
    /// # Errors
    ///
    /// Returns [Error::OperationPruned] if `loc` falls in a pruned bitmap chunk.
    pub async fn new<H: CHasher<Digest = D>, S: Storage<F, Digest = D>>(
        hasher: &StandardHasher<H>,
        status: &impl BitmapReadable<N>,
        storage: &S,
        inactivity_floor: Location<F>,
        loc: Location<F>,
        ops_root: D,
    ) -> Result<Self, Error<F>> {
        // Reject locations in pruned bitmap chunks.
        if BitMap::<N>::to_chunk_index(*loc) < status.pruned_chunks() {
            return Err(Error::OperationPruned(loc));
        }
        let range_proof = RangeProof::new(
            hasher,
            status,
            storage,
            inactivity_floor,
            loc..loc + 1,
            ops_root,
        )
        .await?;
        let chunk = status.get_chunk(BitMap::<N>::to_chunk_index(*loc));
        Ok(Self {
            loc,
            chunk,
            range_proof,
        })
    }
}

impl<F: Graftable, D: Digest, const N: usize> OperationProof<F, D, N> {
    /// Verify that the proof proves that `operation` is active in the database with the given
    /// `root`.
    pub fn verify<H: CHasher<Digest = D>, O: Codec>(
        &self,
        hasher: &StandardHasher<H>,
        operation: O,
        root: &D,
    ) -> bool {
        // Make sure that the bit for the operation in the bitmap chunk is actually a 1 (indicating
        // the operation is indeed active).
        if !BitMap::<N>::get_bit_from_chunk(&self.chunk, *self.loc) {
            debug!(
                ?self.loc,
                "proof verification failed, operation is inactive"
            );
            return false;
        }

        self.range_proof
            .verify(hasher, self.loc, &[operation], &[self.chunk], root)
    }
}

impl<F: Family, D: Digest, const N: usize> Write for OperationProof<F, D, N> {
    fn write(&self, buf: &mut impl BufMut) {
        self.loc.write(buf);
        self.chunk.write(buf);
        self.range_proof.write(buf);
    }
}

impl<F: Family, D: Digest, const N: usize> EncodeSize for OperationProof<F, D, N> {
    fn encode_size(&self) -> usize {
        self.loc.encode_size() + self.chunk.encode_size() + self.range_proof.encode_size()
    }
}

impl<F: Family, D: Digest, const N: usize> Read for OperationProof<F, D, N> {
    /// The total digest cap forwarded to the embedded range proof.
    type Cfg = usize;

    fn read_cfg(
        buf: &mut impl Buf,
        max_digests: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let loc = Location::<F>::read(buf)?;
        let chunk = <[u8; N]>::read(buf)?;
        let range_proof = RangeProof::<F, D>::read_cfg(buf, max_digests)?;
        Ok(Self {
            loc,
            chunk,
            range_proof,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<F: Family, D: Digest, const N: usize> arbitrary::Arbitrary<'_> for OperationProof<F, D, N>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            loc: u.arbitrary()?,
            chunk: u.arbitrary()?,
            range_proof: u.arbitrary()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        merkle::{conformance::build_test_mem, mem::Mem},
        mmb,
        qmdb::current::{db, grafting},
    };
    use commonware_codec::{Decode as _, DecodeExt as _, Encode as _};
    use commonware_cryptography::{sha256, Sha256};
    use commonware_macros::test_traced;
    use commonware_parallel::Sequential;
    use commonware_runtime::{deterministic, Runner};
    use commonware_utils::bitmap::{Prunable as BitMap, Readable as BitmapReadable};

    #[test]
    fn test_ops_root_witness_codec_roundtrip() {
        for partial_chunk in [
            None,
            Some((0u64, Sha256::hash(b"partial-zero"))),
            Some((123u64, Sha256::hash(b"partial-nonzero"))),
        ] {
            let witness = OpsRootWitness {
                grafted_root: Sha256::hash(b"grafted"),
                partial_chunk,
            };
            let encoded = witness.encode();
            assert_eq!(encoded.len(), witness.encode_size());
            let decoded = OpsRootWitness::<sha256::Digest>::decode(encoded).unwrap();
            assert_eq!(decoded, witness);
        }
    }

    fn range_proof_digest_count<F: Family, D: Digest>(proof: &RangeProof<F, D>) -> usize {
        proof.proof.digests.len() + proof.prefix_witnesses.len() + proof.suffix_witnesses.len()
    }

    #[test]
    fn test_range_proof_codec_roundtrip() {
        type F = mmb::Family;
        const MAX_DIGESTS: usize = 64;

        let proof = Proof::<F, sha256::Digest> {
            leaves: mmb::Location::new(42),
            inactive_peaks: 0,
            digests: vec![
                Sha256::hash(b"d0"),
                Sha256::hash(b"d1"),
                Sha256::hash(b"d2"),
            ],
        };
        let ops_root = Sha256::hash(b"ops-root");

        let cases = [
            // Minimal: no optional fields or prefix/suffix witnesses.
            RangeProof {
                proof: proof.clone(),
                prefix_witnesses: vec![],
                suffix_witnesses: vec![],
                partial_chunk_digest: None,
                ops_root,
            },
            // All optional fields populated, with prefix/suffix witnesses on both sides.
            RangeProof {
                proof,
                prefix_witnesses: vec![Sha256::hash(b"u0"), Sha256::hash(b"u1")],
                suffix_witnesses: vec![Sha256::hash(b"s0"), Sha256::hash(b"s1")],
                partial_chunk_digest: Some(Sha256::hash(b"partial")),
                ops_root,
            },
            // Default proof with only partial chunk digest.
            RangeProof {
                proof: Proof::<F, sha256::Digest>::default(),
                prefix_witnesses: vec![],
                suffix_witnesses: vec![],
                partial_chunk_digest: Some(Sha256::hash(b"only-partial")),
                ops_root,
            },
        ];

        for proof in cases {
            let encoded = proof.encode();
            assert_eq!(encoded.len(), proof.encode_size());
            let decoded =
                RangeProof::<F, sha256::Digest>::decode_cfg(encoded, &MAX_DIGESTS).unwrap();
            assert_eq!(decoded, proof);
        }
    }

    #[test]
    fn test_range_proof_codec_enforces_total_digest_budget() {
        type F = mmb::Family;

        let proof = RangeProof {
            proof: Proof::<F, sha256::Digest> {
                leaves: mmb::Location::new(42),
                inactive_peaks: 0,
                digests: vec![Sha256::hash(b"d0")],
            },
            prefix_witnesses: vec![Sha256::hash(b"u0")],
            suffix_witnesses: vec![Sha256::hash(b"s0")],
            partial_chunk_digest: None,
            ops_root: Sha256::hash(b"ops-root"),
        };

        let encoded = proof.encode();
        let total_digests = range_proof_digest_count(&proof);

        let decoded =
            RangeProof::<F, sha256::Digest>::decode_cfg(encoded.clone(), &total_digests).unwrap();
        assert_eq!(decoded, proof);
        assert!(
            RangeProof::<F, sha256::Digest>::decode_cfg(encoded, &(total_digests - 1)).is_err()
        );
    }

    #[test]
    fn test_operation_proof_codec_roundtrip() {
        type F = mmb::Family;
        const N: usize = 32;
        const MAX_DIGESTS: usize = 64;

        let range_proof = RangeProof {
            proof: Proof::<F, sha256::Digest> {
                leaves: mmb::Location::new(7),
                inactive_peaks: 0,
                digests: vec![Sha256::hash(b"sib")],
            },
            prefix_witnesses: vec![Sha256::hash(b"peak")],
            suffix_witnesses: vec![Sha256::hash(b"suf")],
            partial_chunk_digest: None,
            ops_root: Sha256::hash(b"ops"),
        };

        let chunk: [u8; N] = core::array::from_fn(|i| i as u8);

        let proof = OperationProof::<F, sha256::Digest, N> {
            loc: mmb::Location::new(5),
            chunk,
            range_proof,
        };

        let encoded = proof.encode();
        assert_eq!(encoded.len(), proof.encode_size());
        let decoded =
            OperationProof::<F, sha256::Digest, N>::decode_cfg(encoded, &MAX_DIGESTS).unwrap();
        assert_eq!(decoded, proof);
    }

    #[test]
    fn test_operation_proof_codec_enforces_total_digest_budget() {
        type F = mmb::Family;
        const N: usize = 32;

        let range_proof = RangeProof {
            proof: Proof::<F, sha256::Digest> {
                leaves: mmb::Location::new(7),
                inactive_peaks: 0,
                digests: vec![Sha256::hash(b"sib")],
            },
            prefix_witnesses: vec![Sha256::hash(b"peak")],
            suffix_witnesses: vec![Sha256::hash(b"suf")],
            partial_chunk_digest: None,
            ops_root: Sha256::hash(b"ops"),
        };
        let total_digests = range_proof_digest_count(&range_proof);
        let proof = OperationProof::<F, sha256::Digest, N> {
            loc: mmb::Location::new(5),
            chunk: core::array::from_fn(|i| i as u8),
            range_proof,
        };

        let encoded = proof.encode();
        let decoded =
            OperationProof::<F, sha256::Digest, N>::decode_cfg(encoded.clone(), &total_digests)
                .unwrap();
        assert_eq!(decoded, proof);
        assert!(
            OperationProof::<F, sha256::Digest, N>::decode_cfg(encoded, &(total_digests - 1))
                .is_err()
        );
    }

    #[test_traced]
    fn test_range_proof_verifies_for_mmb_multi_peak_chunk() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            type F = mmb::Family;
            const N: usize = 1;

            let hasher = qmdb::hasher::<Sha256>();
            let grafting_height = grafting::height::<N>();

            let leaf_count = (16..=64u64)
                .find(|&leaves| {
                    let size = F::location_to_position(mmb::Location::new(leaves));
                    F::chunk_peaks(size, 1, grafting_height).nth(1).is_some()
                })
                .expect("expected an MMB size whose second chunk spans multiple peaks");

            let mut status = BitMap::<N>::new();
            for _ in 0..leaf_count {
                status.push(true);
            }
            let ops = build_test_mem(&hasher, mmb::mem::Mmb::new(), leaf_count);
            let ops_root = ops.root(&hasher, 0).unwrap();

            let chunk_inputs: Vec<_> =
                (0..<BitMap<N> as BitmapReadable<N>>::complete_chunks(&status))
                    .map(|chunk_idx| {
                        (
                            chunk_idx,
                            <BitMap<N> as BitmapReadable<N>>::get_chunk(&status, chunk_idx),
                        )
                    })
                    .collect();
            let mut leaf_digests = db::compute_grafted_leaves::<F, Sha256, Sequential, N>(
                &hasher,
                &ops,
                chunk_inputs,
                &Sequential,
            )
            .await
            .unwrap();
            leaf_digests.sort_by_key(|(chunk_idx, _)| *chunk_idx);

            let grafted_hasher =
                grafting::GraftedHasher::<F, _>::new(hasher.clone(), grafting_height);
            let mut grafted = Mem::<F, sha256::Digest>::new();
            let merkleized = {
                let mut batch = grafted.new_batch();
                for (_, digest) in leaf_digests {
                    batch = batch.add_leaf_digest(digest);
                }
                batch.merkleize(&grafted, &grafted_hasher)
            };
            grafted.apply_batch(&merkleized).unwrap();

            let storage = grafting::Storage::new(&grafted, grafting_height, &ops, hasher.clone());
            let root = db::compute_db_root::<F, Sha256, _, _, N>(
                &hasher,
                &status,
                &storage,
                None,
                Location::new(0),
                &ops_root,
            )
            .await
            .unwrap();

            let loc = mmb::Location::new(BitMap::<N>::CHUNK_SIZE_BITS + 4);
            let proof = RangeProof::new(
                &hasher,
                &status,
                &storage,
                Location::new(0),
                loc..loc + 1,
                ops_root,
            )
            .await
            .unwrap();

            let element = hasher.digest(&(*loc).to_be_bytes());
            assert!(proof.verify(
                &hasher,
                loc,
                &[element],
                &[<BitMap<N> as BitmapReadable<N>>::get_chunk(&status, 1)],
                &root,
            ));
        });
    }

    #[test_traced]
    fn test_range_proof_verifies_with_partial_suffix_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            type F = mmb::Family;
            const N: usize = 1;

            let hasher = qmdb::hasher::<Sha256>();
            let grafting_height = grafting::height::<N>();
            let chunk_bits = BitMap::<N>::CHUNK_SIZE_BITS;

            let (leaf_count, loc) = (chunk_bits * 2 + 1..=64u64)
                .find_map(|leaves| {
                    let complete_chunks = leaves / chunk_bits;
                    if complete_chunks < 2 || leaves % chunk_bits == 0 {
                        return None;
                    }

                    let size = F::location_to_position(mmb::Location::new(leaves));
                    F::chunk_peaks(size, 1, grafting_height).nth(1)?;
                    Some((leaves, mmb::Location::new(chunk_bits + 1)))
                })
                .expect("expected an MMB proof with a partial trailing suffix chunk");

            let mut status = BitMap::<N>::new();
            for _ in 0..leaf_count {
                status.push(true);
            }
            let ops = build_test_mem(&hasher, mmb::mem::Mmb::new(), leaf_count);
            let ops_root = ops.root(&hasher, 0).unwrap();

            let chunk_inputs: Vec<_> =
                (0..<BitMap<N> as BitmapReadable<N>>::complete_chunks(&status))
                    .map(|chunk_idx| {
                        (
                            chunk_idx,
                            <BitMap<N> as BitmapReadable<N>>::get_chunk(&status, chunk_idx),
                        )
                    })
                    .collect();
            let mut leaf_digests = db::compute_grafted_leaves::<F, Sha256, Sequential, N>(
                &hasher,
                &ops,
                chunk_inputs,
                &Sequential,
            )
            .await
            .unwrap();
            leaf_digests.sort_by_key(|(chunk_idx, _)| *chunk_idx);

            let grafted_hasher =
                grafting::GraftedHasher::<F, _>::new(hasher.clone(), grafting_height);
            let mut grafted = Mem::<F, sha256::Digest>::new();
            let merkleized = {
                let mut batch = grafted.new_batch();
                for (_, digest) in leaf_digests {
                    batch = batch.add_leaf_digest(digest);
                }
                batch.merkleize(&grafted, &grafted_hasher)
            };
            grafted.apply_batch(&merkleized).unwrap();

            let storage = grafting::Storage::new(&grafted, grafting_height, &ops, hasher.clone());
            let partial = {
                let (chunk, next_bit) = status.last_chunk();
                Some((*chunk, next_bit))
            };
            let root = db::compute_db_root::<F, Sha256, _, _, N>(
                &hasher,
                &status,
                &storage,
                partial,
                Location::new(0),
                &ops_root,
            )
            .await
            .unwrap();
            let proof = RangeProof::new(
                &hasher,
                &status,
                &storage,
                Location::new(0),
                loc..loc + 1,
                ops_root,
            )
            .await
            .unwrap();

            let element = hasher.digest(&(*loc).to_be_bytes());
            let chunk_idx = (*loc / BitMap::<N>::CHUNK_SIZE_BITS) as usize;
            assert!(proof.verify(
                &hasher,
                loc,
                &[element],
                &[<BitMap<N> as BitmapReadable<N>>::get_chunk(
                    &status, chunk_idx
                )],
                &root,
            ));
        });
    }

    #[test_traced]
    fn test_range_proof_verifies_when_range_reaches_partial_chunk_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            type F = mmb::Family;
            const N: usize = 1;

            let hasher = qmdb::hasher::<Sha256>();
            let grafting_height = grafting::height::<N>();
            let chunk_bits = BitMap::<N>::CHUNK_SIZE_BITS;

            let (leaf_count, start_loc, complete_chunks) = (17..=128u64)
                .find_map(|leaves| {
                    let complete_chunks = leaves / chunk_bits;
                    if complete_chunks < 2 || leaves % chunk_bits == 0 {
                        return None;
                    }

                    let leaves_loc = mmb::Location::new(leaves);
                    let size = F::location_to_position(leaves_loc);
                    F::chunk_peaks(size, 1, grafting_height).nth(1)?;

                    (0..chunk_bits).find_map(|offset| {
                        let start_loc = mmb::Location::new(chunk_bits + offset);
                        if *start_loc >= complete_chunks * chunk_bits {
                            return None;
                        }
                        let geometry = RangeProofGeometry::<F>::new(
                            leaves_loc,
                            start_loc..leaves_loc,
                            0,
                            grafting_height,
                            complete_chunks,
                        )
                        .ok()?;
                        geometry.requires_grafted_reconstruction().ok()?.then_some((
                            leaves,
                            start_loc,
                            complete_chunks,
                        ))
                    })
                })
                .expect("expected an MMB proof into the trailing partial chunk");

            let mut status = BitMap::<N>::new();
            for _ in 0..leaf_count {
                status.push(true);
            }
            let ops = build_test_mem(&hasher, mmb::mem::Mmb::new(), leaf_count);
            let ops_root = ops.root(&hasher, 0).unwrap();

            let chunk_inputs: Vec<_> =
                (0..<BitMap<N> as BitmapReadable<N>>::complete_chunks(&status))
                    .map(|chunk_idx| {
                        (
                            chunk_idx,
                            <BitMap<N> as BitmapReadable<N>>::get_chunk(&status, chunk_idx),
                        )
                    })
                    .collect();
            let mut leaf_digests = db::compute_grafted_leaves::<F, Sha256, Sequential, N>(
                &hasher,
                &ops,
                chunk_inputs,
                &Sequential,
            )
            .await
            .unwrap();
            leaf_digests.sort_by_key(|(chunk_idx, _)| *chunk_idx);

            let grafted_hasher =
                grafting::GraftedHasher::<F, _>::new(hasher.clone(), grafting_height);
            let mut grafted = Mem::<F, sha256::Digest>::new();
            let merkleized = {
                let mut batch = grafted.new_batch();
                for (_, digest) in leaf_digests {
                    batch = batch.add_leaf_digest(digest);
                }
                batch.merkleize(&grafted, &grafted_hasher)
            };
            grafted.apply_batch(&merkleized).unwrap();

            let storage = grafting::Storage::new(&grafted, grafting_height, &ops, hasher.clone());
            let partial = {
                let (chunk, next_bit) = status.last_chunk();
                Some((*chunk, next_bit))
            };
            let root = db::compute_db_root::<F, Sha256, _, _, N>(
                &hasher,
                &status,
                &storage,
                partial,
                Location::new(0),
                &ops_root,
            )
            .await
            .unwrap();

            let leaves_loc = mmb::Location::new(leaf_count);
            let proof = RangeProof::new(
                &hasher,
                &status,
                &storage,
                Location::new(0),
                start_loc..leaves_loc,
                ops_root,
            )
            .await
            .unwrap();

            let elements = (*start_loc..leaf_count)
                .map(|idx| hasher.digest(&idx.to_be_bytes()))
                .collect::<Vec<_>>();
            let start_chunk_idx = (*start_loc / chunk_bits) as usize;
            let end_chunk_idx = complete_chunks as usize;
            let chunks = (start_chunk_idx..=end_chunk_idx)
                .map(|chunk_idx| <BitMap<N> as BitmapReadable<N>>::get_chunk(&status, chunk_idx))
                .collect::<Vec<_>>();
            assert!(proof.verify(&hasher, start_loc, &elements, &chunks, &root,));
        });
    }
    #[test_traced]
    fn test_range_proof_rejects_unexpected_partial_chunk_digest() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            type F = mmb::Family;
            const N: usize = 1;

            let hasher = qmdb::hasher::<Sha256>();
            let grafting_height = grafting::height::<N>();
            let chunk_bits = BitMap::<N>::CHUNK_SIZE_BITS;

            let leaf_count = chunk_bits * 2; // Perfect chunks, NO partial trailing bits
            let mut status = BitMap::<N>::new();
            for _ in 0..leaf_count {
                status.push(true);
            }
            let ops = build_test_mem(&hasher, mmb::mem::Mmb::new(), leaf_count);
            let ops_root = ops.root(&hasher, 0).unwrap();

            let chunk_inputs: Vec<_> =
                (0..<BitMap<N> as BitmapReadable<N>>::complete_chunks(&status))
                    .map(|chunk_idx| {
                        (
                            chunk_idx,
                            <BitMap<N> as BitmapReadable<N>>::get_chunk(&status, chunk_idx),
                        )
                    })
                    .collect();
            let mut leaf_digests = db::compute_grafted_leaves::<F, Sha256, Sequential, N>(
                &hasher,
                &ops,
                chunk_inputs,
                &Sequential,
            )
            .await
            .unwrap();
            leaf_digests.sort_by_key(|(chunk_idx, _)| *chunk_idx);

            let grafted_hasher =
                grafting::GraftedHasher::<F, _>::new(hasher.clone(), grafting_height);
            let mut grafted = Mem::<F, sha256::Digest>::new();
            let merkleized = {
                let mut batch = grafted.new_batch();
                for (_, digest) in leaf_digests {
                    batch = batch.add_leaf_digest(digest);
                }
                batch.merkleize(&grafted, &grafted_hasher)
            };
            grafted.apply_batch(&merkleized).unwrap();

            let storage = grafting::Storage::new(&grafted, grafting_height, &ops, hasher.clone());
            let root = db::compute_db_root::<F, Sha256, _, _, N>(
                &hasher,
                &status,
                &storage,
                None,
                Location::new(0),
                &ops_root,
            )
            .await
            .unwrap();

            let loc = mmb::Location::new(0);
            let mut proof = RangeProof::new(
                &hasher,
                &status,
                &storage,
                Location::new(0),
                loc..loc + 1,
                ops_root,
            )
            .await
            .unwrap();

            let element = hasher.digest(&(*loc).to_be_bytes());
            let chunk = <BitMap<N> as BitmapReadable<N>>::get_chunk(&status, 0);

            let mut tampered = proof.clone();
            tampered
                .prefix_witnesses
                .push(hasher.digest(b"fake prefix witness"));
            assert!(!tampered.verify(&hasher, loc, &[element], &[chunk], &root,));

            // Tamper with the proof by injecting a fake partial chunk digest
            proof.partial_chunk_digest = Some(hasher.digest(b"fake partial chunk"));
            assert!(!proof.verify(&hasher, loc, &[element], &[chunk], &root,));
        });
    }

    #[test_traced]
    fn test_range_proof_unfolds_mmb_peaks_for_grafted_reconstruction() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            type F = mmb::Family;
            const N: usize = 1;

            let hasher = qmdb::hasher::<Sha256>();
            let grafting_height = grafting::height::<N>();
            let chunk_bits = BitMap::<N>::CHUNK_SIZE_BITS;

            let (leaf_count, loc, geometry) = (chunk_bits * 3..=128u64)
                .filter(|leaves| leaves % chunk_bits == 0)
                .find_map(|leaves| {
                    let leaves_loc = mmb::Location::new(leaves);
                    let complete_chunks = leaves / chunk_bits;
                    (0..leaves).find_map(|idx| {
                        let loc = mmb::Location::new(idx);
                        let geometry = RangeProofGeometry::<F>::new(
                            leaves_loc,
                            loc..loc + 1,
                            0,
                            grafting_height,
                            complete_chunks,
                        )
                        .ok()?;
                        geometry
                            .requires_grafted_reconstruction()
                            .ok()?
                            .then_some((leaves, loc, geometry))
                    })
                })
                .expect("expected an MMB proof requiring grafted reconstruction");

            let mut status = BitMap::<N>::new();
            for _ in 0..leaf_count {
                status.push(true);
            }
            let ops = build_test_mem(&hasher, mmb::mem::Mmb::new(), leaf_count);
            let ops_root = ops.root(&hasher, 0).unwrap();

            let chunk_inputs: Vec<_> =
                (0..<BitMap<N> as BitmapReadable<N>>::complete_chunks(&status))
                    .map(|chunk_idx| {
                        (
                            chunk_idx,
                            <BitMap<N> as BitmapReadable<N>>::get_chunk(&status, chunk_idx),
                        )
                    })
                    .collect();
            let mut leaf_digests = db::compute_grafted_leaves::<F, Sha256, Sequential, N>(
                &hasher,
                &ops,
                chunk_inputs,
                &Sequential,
            )
            .await
            .unwrap();
            leaf_digests.sort_by_key(|(chunk_idx, _)| *chunk_idx);

            let grafted_hasher =
                grafting::GraftedHasher::<F, _>::new(hasher.clone(), grafting_height);
            let mut grafted = Mem::<F, sha256::Digest>::new();
            let merkleized = {
                let mut batch = grafted.new_batch();
                for (_, digest) in leaf_digests {
                    batch = batch.add_leaf_digest(digest);
                }
                batch.merkleize(&grafted, &grafted_hasher)
            };
            grafted.apply_batch(&merkleized).unwrap();

            let storage = grafting::Storage::new(&grafted, grafting_height, &ops, hasher.clone());
            let root = db::compute_db_root::<F, Sha256, _, _, N>(
                &hasher,
                &status,
                &storage,
                None,
                Location::new(0),
                &ops_root,
            )
            .await
            .unwrap();
            let proof = RangeProof::new(
                &hasher,
                &status,
                &storage,
                Location::new(0),
                loc..loc + 1,
                ops_root,
            )
            .await
            .unwrap();

            // The prefix/suffix witnesses follow the five-segment geometry: bitmap witness
            // digests for pure segments and individual ops-tree digests for boundary segments.
            assert_eq!(proof.prefix_witnesses.len(), geometry.prefix_witness_len());
            assert_eq!(proof.suffix_witnesses.len(), geometry.suffix_witness_len());

            let element = hasher.digest(&(*loc).to_be_bytes());
            let chunk_idx = (*loc / chunk_bits) as usize;
            assert!(proof.verify(
                &hasher,
                loc,
                &[element],
                &[<BitMap<N> as BitmapReadable<N>>::get_chunk(
                    &status, chunk_idx
                )],
                &root,
            ));

            let mut tampered = proof.clone();
            tampered.proof.inactive_peaks = 1;
            assert!(!tampered.verify(
                &hasher,
                loc,
                &[element],
                &[<BitMap<N> as BitmapReadable<N>>::get_chunk(
                    &status, chunk_idx
                )],
                &root,
            ));

            let mut tampered = proof.clone();
            tampered.proof.inactive_peaks = usize::MAX;
            assert!(!tampered.verify(
                &hasher,
                loc,
                &[element],
                &[<BitMap<N> as BitmapReadable<N>>::get_chunk(
                    &status, chunk_idx
                )],
                &root,
            ));

            let mut tampered = proof;
            assert!(!tampered.proof.digests.is_empty());
            tampered.proof.digests[0] = hasher.digest(b"fake generic sibling");
            assert!(!tampered.verify(
                &hasher,
                loc,
                &[element],
                &[<BitMap<N> as BitmapReadable<N>>::get_chunk(
                    &status, chunk_idx
                )],
                &root,
            ));
        });
    }

    #[test_traced]
    fn test_range_proof_allows_ops_and_grafted_inactive_counts_to_differ() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            type F = mmb::Family;
            const N: usize = 1;

            let hasher = qmdb::hasher::<Sha256>();
            let grafting_height = grafting::height::<N>();
            let chunk_bits = BitMap::<N>::CHUNK_SIZE_BITS;
            let leaf_count = chunk_bits;
            let leaves = mmb::Location::new(leaf_count);
            let inactivity_floor = mmb::Location::new(chunk_bits - 2);

            let ops_inactive_peaks =
                F::inactive_peaks(F::location_to_position(leaves), inactivity_floor);
            let aligned_inactive = grafting::chunk_aligned_inactive_peaks::<F>(
                leaves,
                inactivity_floor,
                grafting_height,
            )
            .unwrap();
            assert_ne!(ops_inactive_peaks, aligned_inactive);

            let mut status = BitMap::<N>::new();
            for _ in 0..leaf_count {
                status.push(true);
            }
            let ops = build_test_mem(&hasher, mmb::mem::Mmb::new(), leaf_count);

            // The ops root is the inner QMDB log root and commits the ops-tree inactive peak count.
            // The grafted bitmap root commits the chunk-aligned count, since bitmap chunks are
            // the atomic inactive-prefix boundary for the current root.
            let ops_root = ops.root(&hasher, ops_inactive_peaks).unwrap();

            let chunk_inputs: Vec<_> =
                (0..<BitMap<N> as BitmapReadable<N>>::complete_chunks(&status))
                    .map(|chunk_idx| {
                        (
                            chunk_idx,
                            <BitMap<N> as BitmapReadable<N>>::get_chunk(&status, chunk_idx),
                        )
                    })
                    .collect();
            let mut leaf_digests = db::compute_grafted_leaves::<F, Sha256, Sequential, N>(
                &hasher,
                &ops,
                chunk_inputs,
                &Sequential,
            )
            .await
            .unwrap();
            leaf_digests.sort_by_key(|(chunk_idx, _)| *chunk_idx);

            let grafted_hasher =
                grafting::GraftedHasher::<F, _>::new(hasher.clone(), grafting_height);
            let mut grafted = Mem::<F, sha256::Digest>::new();
            let merkleized = {
                let mut batch = grafted.new_batch();
                for (_, digest) in leaf_digests {
                    batch = batch.add_leaf_digest(digest);
                }
                batch.merkleize(&grafted, &grafted_hasher)
            };
            grafted.apply_batch(&merkleized).unwrap();

            let storage = grafting::Storage::new(&grafted, grafting_height, &ops, hasher.clone());
            let root = db::compute_db_root::<F, Sha256, _, _, N>(
                &hasher,
                &status,
                &storage,
                None,
                inactivity_floor,
                &ops_root,
            )
            .await
            .unwrap();

            let loc = mmb::Location::new(chunk_bits - 1);
            let proof = RangeProof::new(
                &hasher,
                &status,
                &storage,
                inactivity_floor,
                loc..loc + 1,
                ops_root,
            )
            .await
            .unwrap();
            assert_eq!(proof.proof.inactive_peaks, aligned_inactive);

            let element = hasher.digest(&(*loc).to_be_bytes());
            let chunk = <BitMap<N> as BitmapReadable<N>>::get_chunk(&status, 0);
            assert!(proof.verify(&hasher, loc, &[element], &[chunk], &root));
        });
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::super::{OperationProof, OpsRootWitness, RangeProof};
        use crate::merkle::{mmb, mmr};
        use commonware_codec::conformance::CodecConformance;
        use commonware_cryptography::sha256::Digest as Sha256Digest;

        commonware_conformance::conformance_tests! {
            CodecConformance<OpsRootWitness<Sha256Digest>>,
            CodecConformance<RangeProof<mmr::Family, Sha256Digest>>,
            CodecConformance<RangeProof<mmb::Family, Sha256Digest>>,
            CodecConformance<OperationProof<mmr::Family, Sha256Digest, 32>>,
            CodecConformance<OperationProof<mmb::Family, Sha256Digest, 32>>,
        }
    }
}
