use super::*;
use crate::Scheme;

/// A ZODA shard that has been checked for integrity already.
#[derive(Clone)]
pub struct CheckedShard<D: Digest> {
    pub(crate) index: usize,
    pub(crate) shard: Arc<Matrix<F>>,
    pub(crate) data_bytes: usize,
    pub(crate) root: D,
    pub(crate) checksum: Arc<Matrix<F>>,
    pub(crate) commitment: Summary,
}

/// Precomputed checking state derived from a shard's metadata and commitment.
#[derive(Clone)]
pub struct CheckingData<D: Digest> {
    pub(crate) core: CheckingCore<D>,
    pub(crate) checksum: Arc<Matrix<F>>,
}

impl<D: Digest> CheckingData<D> {
    pub(crate) fn reckon(
        config: &Config,
        commitment: &Summary,
        data_bytes: usize,
        root: D,
        checksum: Arc<Matrix<F>>,
    ) -> Result<Self, Error> {
        let core = CheckingCore::reckon(config, commitment, data_bytes, root, checksum.as_ref())?;
        Ok(Self { core, checksum })
    }

    fn metadata_matches(&self, shard: &Shard<D>) -> bool {
        shard.data_bytes == self.core.topology.data_bytes
            && shard.root == self.core.root
            && shard.checksum.as_ref() == self.checksum.as_ref()
    }

    fn matches_checked_shard(&self, shard: &CheckedShard<D>) -> bool {
        shard.data_bytes == self.core.topology.data_bytes
            && shard.root == self.core.root
            && shard.checksum.as_ref() == self.checksum.as_ref()
    }

    fn check<H: Hasher<Digest = D>>(
        &self,
        index: u16,
        shard: &Shard<D>,
    ) -> Result<CheckedShard<D>, Error> {
        if !self.metadata_matches(shard) {
            return Err(Error::InvalidShard);
        }
        let shard_idx =
            self.core
                .check_rows::<H>(index, &shard.inclusion_proof, shard.rows.as_ref())?;
        Ok(CheckedShard {
            index: shard_idx,
            shard: shard.rows.clone(),
            data_bytes: self.core.topology.data_bytes,
            root: self.core.root,
            checksum: self.checksum.clone(),
            commitment: self.core.commitment,
        })
    }
}

impl<D: Digest> CheckedShard<D> {
    fn checking_data(&self, config: &Config) -> Result<CheckingData<D>, Error> {
        CheckingData::reckon(
            config,
            &self.commitment,
            self.data_bytes,
            self.root,
            self.checksum.clone(),
        )
    }

    fn metadata_matches(&self, other: &Self) -> bool {
        self.data_bytes == other.data_bytes
            && self.root == other.root
            && self.checksum.as_ref() == other.checksum.as_ref()
    }
}

impl<D: Digest> CheckedShardView for CheckedShard<D> {
    fn index(&self) -> usize {
        self.index
    }

    fn shard(&self) -> &Matrix<F> {
        self.shard.as_ref()
    }
}

impl<H: Hasher> Scheme for Zoda<H> {
    type Commitment = Summary;
    type Shard = Shard<H::Digest>;
    type CheckedShard = CheckedShard<H::Digest>;
    type Error = Error;

    fn encode(
        config: &Config,
        data: impl bytes::Buf,
        strategy: &impl Strategy,
    ) -> Result<(Self::Commitment, Vec<Self::Shard>), Self::Error> {
        let data_bytes = data.remaining();
        let topology = Topology::reckon(config, data_bytes);
        let data = Matrix::init(
            topology.data_rows,
            topology.data_cols,
            F::stream_from_u64s(iter_u64_le(data)),
        );

        let encoded_data = data
            .as_polynomials(topology.encoded_rows)
            .expect("data has too many rows")
            .evaluate()
            .data();

        let row_hashes: Vec<H::Digest> = strategy.map_collect_vec(0..encoded_data.rows(), |i| {
            row_digest::<H>(&encoded_data[i])
        });
        let mut bmt_builder = BmtBuilder::<H>::new(row_hashes.len());
        for hash in &row_hashes {
            bmt_builder.add(hash);
        }
        let bmt = bmt_builder.build();
        let root = bmt.root();

        let mut transcript = Transcript::new(NAMESPACE);
        transcript.commit((topology.data_bytes as u64).encode());
        transcript.commit(root.encode());
        let commitment = transcript.summarize();

        let mut transcript = Transcript::resume(commitment);
        let checking_matrix = checking_matrix(&transcript, &topology);
        let checksum = Arc::new(data.mul(&checking_matrix));
        transcript.commit(checksum.encode());
        let shuffled_indices = shuffle_indices(&transcript, encoded_data.rows());

        let shard_results: Vec<Result<Shard<H::Digest>, Error>> =
            strategy.map_collect_vec(0..topology.total_shards, |shard_idx| {
                let indices = &shuffled_indices
                    [shard_idx * topology.samples..(shard_idx + 1) * topology.samples];
                let rows = Matrix::init(
                    indices.len(),
                    topology.data_cols,
                    indices
                        .iter()
                        .flat_map(|&i| encoded_data[i as usize].iter().copied()),
                );
                let inclusion_proof = bmt
                    .multi_proof(indices)
                    .map_err(Error::FailedToCreateInclusionProof)?;
                Ok(Shard {
                    data_bytes,
                    root,
                    inclusion_proof,
                    rows: Arc::new(rows),
                    checksum: checksum.clone(),
                })
            });
        let shards = shard_results
            .into_iter()
            .collect::<Result<Vec<_>, Error>>()?;
        Ok((commitment, shards))
    }

    fn check(
        config: &Config,
        commitment: &Self::Commitment,
        index: u16,
        shard: &Self::Shard,
    ) -> Result<Self::CheckedShard, Self::Error> {
        let checking_data = CheckingData::reckon(
            config,
            commitment,
            shard.data_bytes,
            shard.root,
            shard.checksum.clone(),
        )?;
        checking_data.check::<H>(index, shard)
    }

    fn decode(
        config: &Config,
        commitment: &Self::Commitment,
        shards: &[Self::CheckedShard],
        _strategy: &impl Strategy,
    ) -> Result<Vec<u8>, Self::Error> {
        let first = shards.first().ok_or(Error::InsufficientShards(
            shards.len(),
            usize::from(config.minimum_shards.get()),
        ))?;
        if &first.commitment != commitment {
            return Err(Error::InconsistentCheckedShard);
        }
        if !shards
            .iter()
            .all(|shard| &shard.commitment == commitment && shard.metadata_matches(first))
        {
            return Err(Error::InconsistentCheckedShard);
        }
        let checking_data = first.checking_data(config)?;
        if checking_data.core.commitment != *commitment {
            return Err(Error::InconsistentCheckedShard);
        }
        if !shards
            .iter()
            .all(|shard| checking_data.matches_checked_shard(shard))
        {
            return Err(Error::InconsistentCheckedShard);
        }
        decode_checked_shards(&checking_data.core, shards)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::{Error, Zoda},
        *,
    };
    use crate::{Config, Scheme};
    use commonware_cryptography::{Hasher, Sha256};
    use commonware_math::{
        algebra::{FieldNTT as _, Ring},
        fields::goldilocks::F,
        ntt::{EvaluationVector, PolynomialVector},
    };
    use commonware_parallel::Sequential;
    use commonware_utils::NZU16;
    use std::sync::Arc;

    const STRATEGY: Sequential = Sequential;

    fn config_2_1() -> Config {
        Config {
            minimum_shards: NZU16!(2),
            extra_shards: NZU16!(1),
        }
    }

    #[test]
    fn checksum_malleability() {
        fn vanishing(lg_domain: u8, vanish_indices: &[u32]) -> PolynomialVector<F> {
            let w = F::root_of_unity(lg_domain).expect("domain too large for Goldilocks");
            let mut domain = Vec::with_capacity(1usize << lg_domain);
            let mut x = F::one();
            for _ in 0..(1usize << lg_domain) {
                domain.push(x);
                x *= &w;
            }
            let roots: Vec<F> = vanish_indices.iter().map(|&i| domain[i as usize]).collect();
            let mut out = EvaluationVector::empty(lg_domain as usize, 1);
            domain.into_iter().enumerate().for_each(|(i, x)| {
                let mut acc = F::one();
                for root in &roots {
                    acc *= &(x - root);
                }
                out.fill_row(i, &[acc]);
            });
            out.recover()
        }

        let config = config_2_1();
        let data = vec![0x5Au8; 256 * 1024];
        let (commitment, mut shards) =
            <Zoda<Sha256> as Scheme>::encode(&config, &data[..], &STRATEGY).unwrap();

        let a_i = 1usize;
        let b_i = 2usize;

        let checking_data = CheckingData::reckon(
            &config,
            &commitment,
            shards[0].data_bytes,
            shards[0].root,
            shards[0].checksum.clone(),
        )
        .unwrap();

        let samples = checking_data.core.topology.samples;
        let a_indices =
            checking_data.core.shuffled_indices[a_i * samples..(a_i + 1) * samples].to_vec();
        let lg_rows = checking_data.core.topology.encoded_rows.ilog2() as usize;
        let shift = vanishing(lg_rows as u8, &a_indices);
        let mut checksum = (*shards[1].checksum).clone();
        for (i, shift_i) in shift.coefficients_up_to(checksum.rows()).enumerate() {
            for j in 0..checksum.cols() {
                checksum[(i, j)] += &shift_i[0];
            }
        }
        shards[1].checksum = Arc::new(checksum);
        shards[2].checksum = shards[1].checksum.clone();

        assert!(matches!(
            <Zoda<Sha256> as Scheme>::check(&config, &commitment, b_i as u16, &shards[b_i]),
            Err(Error::InvalidShard)
        ));

        assert!(matches!(
            <Zoda<Sha256> as Scheme>::check(&config, &commitment, a_i as u16, &shards[a_i]),
            Err(Error::InvalidShard)
        ));
    }

    #[test]
    fn decode_rejects_duplicate_indices() {
        let config = config_2_1();
        let data = b"duplicate shard coverage";
        let (commitment, shards) = Zoda::<Sha256>::encode(&config, &data[..], &STRATEGY).unwrap();
        let checked_shard0 = Zoda::<Sha256>::check(&config, &commitment, 0, &shards[0]).unwrap();
        let duplicate = checked_shard0.clone();
        let shards = vec![checked_shard0, duplicate];
        let result = Zoda::<Sha256>::decode(&config, &commitment, &shards, &STRATEGY);
        match result {
            Err(Error::InsufficientUniqueRows(actual, expected)) => assert!(actual < expected),
            other => panic!("expected insufficient unique rows error, got {other:?}"),
        }
    }

    #[test]
    fn check_rejects_mutated_metadata() {
        let config = config_2_1();
        let data = b"metadata coverage";
        let (commitment, mut shards) =
            Zoda::<Sha256>::encode(&config, &data[..], &STRATEGY).unwrap();
        shards[1].data_bytes += 1;

        assert!(matches!(
            Zoda::<Sha256>::check(&config, &commitment, 1, &shards[1]),
            Err(Error::InvalidShard)
        ));
    }

    #[test]
    fn check_rejects_mutated_root() {
        let config = config_2_1();
        let data = b"root coverage";
        let (commitment, mut shards) =
            Zoda::<Sha256>::encode(&config, &data[..], &STRATEGY).unwrap();
        shards[1].root = Sha256::hash(b"mutated root");

        assert!(matches!(
            Zoda::<Sha256>::check(&config, &commitment, 1, &shards[1]),
            Err(Error::InvalidShard)
        ));
    }

    #[test]
    fn check_rejects_mutated_checksum() {
        let config = config_2_1();
        let data = vec![0x5Au8; 256 * 1024];
        let (commitment, mut shards) =
            Zoda::<Sha256>::encode(&config, &data[..], &STRATEGY).unwrap();

        let mut checksum = (*shards[1].checksum).clone();
        checksum[(0, 0)] += &F::one();
        shards[1].checksum = Arc::new(checksum);

        assert!(matches!(
            Zoda::<Sha256>::check(&config, &commitment, 1, &shards[1]),
            Err(Error::InvalidShard)
        ));
    }

    #[test]
    fn decode_rejects_mixed_checked_shard_metadata() {
        let config = config_2_1();
        let data = b"metadata mismatch";
        let (commitment, shards) = Zoda::<Sha256>::encode(&config, &data[..], &STRATEGY).unwrap();
        let checked_a = Zoda::<Sha256>::check(&config, &commitment, 0, &shards[0]).unwrap();
        let mut checked_b = Zoda::<Sha256>::check(&config, &commitment, 1, &shards[1]).unwrap();
        checked_b.root = Sha256::hash(b"mutated root");

        assert!(matches!(
            Zoda::<Sha256>::decode(&config, &commitment, &[checked_a, checked_b], &STRATEGY),
            Err(Error::InconsistentCheckedShard)
        ));
    }
}
