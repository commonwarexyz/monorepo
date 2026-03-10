use super::*;
use crate::PhasedScheme;

/// A compact shard forwarded after deriving checking data from a full shard.
#[derive(Clone, Debug)]
pub struct WeakShard<D: Digest> {
    inclusion_proof: Proof<D>,
    shard: Arc<Matrix<F>>,
}

impl<D: Digest> PartialEq for WeakShard<D> {
    fn eq(&self, other: &Self) -> bool {
        self.inclusion_proof == other.inclusion_proof && self.shard == other.shard
    }
}

impl<D: Digest> Eq for WeakShard<D> {}

impl<D: Digest> EncodeSize for WeakShard<D> {
    fn encode_size(&self) -> usize {
        self.inclusion_proof.encode_size() + self.shard.as_ref().encode_size()
    }
}

impl<D: Digest> Write for WeakShard<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.inclusion_proof.write(buf);
        self.shard.as_ref().write(buf);
    }
}

impl<D: Digest> Read for WeakShard<D> {
    type Cfg = crate::CodecConfig;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let max_data_bits = cfg.maximum_shard_size.saturating_mul(8);
        let max_data_els = F::bits_to_elements(max_data_bits).max(1);
        Ok(Self {
            inclusion_proof: Read::read_cfg(buf, &max_data_els)?,
            shard: Arc::new(Read::read_cfg(buf, &(max_data_els, ()))?),
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<D: Digest> arbitrary::Arbitrary<'_> for WeakShard<D>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            inclusion_proof: u.arbitrary()?,
            shard: Arc::new(u.arbitrary()?),
        })
    }
}

/// A weak ZODA shard that has been checked for integrity already.
#[derive(Clone)]
pub struct CheckedShard {
    index: usize,
    shard: Arc<Matrix<F>>,
    commitment: Summary,
}

/// Precomputed checking state derived from a strong shard.
#[derive(Clone)]
pub struct CheckingData<D: Digest> {
    core: CheckingCore<D>,
}

impl<D: Digest> CheckingData<D> {
    fn reckon(
        config: &Config,
        commitment: &Summary,
        data_bytes: usize,
        root: D,
        checksum: Arc<Matrix<F>>,
    ) -> Result<Self, Error> {
        let core = CheckingCore::reckon(config, commitment, data_bytes, root, checksum.as_ref())?;
        Ok(Self { core })
    }

    fn check<H: Hasher<Digest = D>>(
        &self,
        commitment: &Summary,
        index: u16,
        weak_shard: &WeakShard<D>,
    ) -> Result<CheckedShard, Error> {
        if self.core.commitment != *commitment {
            return Err(Error::InvalidShard);
        }
        let shard_idx = self.core.check_rows::<H>(
            index,
            &weak_shard.inclusion_proof,
            weak_shard.shard.as_ref(),
        )?;
        Ok(CheckedShard {
            index: shard_idx,
            shard: weak_shard.shard.clone(),
            commitment: *commitment,
        })
    }
}

impl CheckedShardView for CheckedShard {
    fn index(&self) -> usize {
        self.index
    }

    fn shard(&self) -> &Matrix<F> {
        self.shard.as_ref()
    }
}

impl<H: Hasher> PhasedScheme for Zoda<H> {
    type Commitment = Summary;
    type StrongShard = Shard<H::Digest>;
    type WeakShard = WeakShard<H::Digest>;
    type CheckingData = CheckingData<H::Digest>;
    type CheckedShard = CheckedShard;
    type Error = Error;

    fn encode(
        config: &Config,
        data: impl bytes::Buf,
        strategy: &impl Strategy,
    ) -> Result<(Self::Commitment, Vec<Self::StrongShard>), Self::Error> {
        <Self as crate::Scheme>::encode(config, data, strategy)
    }

    fn weaken(
        config: &Config,
        commitment: &Self::Commitment,
        index: u16,
        shard: Self::StrongShard,
    ) -> Result<(Self::CheckingData, Self::CheckedShard, Self::WeakShard), Self::Error> {
        let Shard {
            data_bytes,
            root,
            inclusion_proof,
            rows,
            checksum,
        } = shard;
        let weak_shard = WeakShard {
            inclusion_proof,
            shard: rows,
        };
        let checking_data = CheckingData::reckon(config, commitment, data_bytes, root, checksum)?;
        let checked = checking_data.check::<H>(commitment, index, &weak_shard)?;
        Ok((checking_data, checked, weak_shard))
    }

    fn check(
        _config: &Config,
        commitment: &Self::Commitment,
        checking_data: &Self::CheckingData,
        index: u16,
        weak_shard: Self::WeakShard,
    ) -> Result<Self::CheckedShard, Self::Error> {
        checking_data.check::<H>(commitment, index, &weak_shard)
    }

    fn decode(
        _config: &Config,
        commitment: &Self::Commitment,
        checking_data: Self::CheckingData,
        shards: &[Self::CheckedShard],
        _strategy: &impl Strategy,
    ) -> Result<Vec<u8>, Self::Error> {
        if checking_data.core.commitment != *commitment {
            return Err(Error::InvalidShard);
        }
        if !shards.iter().all(|shard| &shard.commitment == commitment) {
            return Err(Error::InvalidShard);
        }
        decode_checked_shards(&checking_data.core, shards)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Error, Zoda};
    use crate::{Config, PhasedScheme};
    use commonware_cryptography::Sha256;
    use commonware_math::{algebra::Ring, fields::goldilocks::F};
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
    fn roundtrip() {
        let config = config_2_1();
        let data = b"strong scheme roundtrip";
        let (commitment, mut shards) =
            Zoda::<Sha256>::encode(&config, &data[..], &STRATEGY).unwrap();

        let (checking_data, checked_0, _) =
            Zoda::<Sha256>::weaken(&config, &commitment, 0, shards.remove(0)).unwrap();
        let (_, _, weak_1) =
            Zoda::<Sha256>::weaken(&config, &commitment, 1, shards.remove(0)).unwrap();
        let checked_1 =
            Zoda::<Sha256>::check(&config, &commitment, &checking_data, 1, weak_1).unwrap();

        let decoded = Zoda::<Sha256>::decode(
            &config,
            &commitment,
            checking_data,
            &[checked_0, checked_1],
            &STRATEGY,
        )
        .unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn decode_rejects_duplicate_indices() {
        let config = config_2_1();
        let data = b"duplicate weak shard coverage";
        let (commitment, mut shards) =
            Zoda::<Sha256>::encode(&config, &data[..], &STRATEGY).unwrap();
        let (checking_data, checked_0, _) =
            Zoda::<Sha256>::weaken(&config, &commitment, 0, shards.remove(0)).unwrap();
        let duplicate = checked_0.clone();
        let result = Zoda::<Sha256>::decode(
            &config,
            &commitment,
            checking_data,
            &[checked_0, duplicate],
            &STRATEGY,
        );
        match result {
            Err(Error::InsufficientUniqueRows(actual, expected)) => assert!(actual < expected),
            other => panic!("expected insufficient unique rows error, got {other:?}"),
        }
    }

    #[test]
    fn check_rejects_mutated_weak_shard() {
        let config = config_2_1();
        let data = b"mutated weak shard";
        let (commitment, mut shards) =
            Zoda::<Sha256>::encode(&config, &data[..], &STRATEGY).unwrap();

        let (checking_data, _, _) =
            Zoda::<Sha256>::weaken(&config, &commitment, 0, shards.remove(0)).unwrap();
        let (_, _, mut weak_1) =
            Zoda::<Sha256>::weaken(&config, &commitment, 1, shards.remove(0)).unwrap();
        Arc::make_mut(&mut weak_1.shard)[(0, 0)] += &F::one();

        assert!(matches!(
            Zoda::<Sha256>::check(&config, &commitment, &checking_data, 1, weak_1),
            Err(Error::InvalidShard)
        ));
    }

    #[test]
    fn check_rejects_wrong_checking_data() {
        let config = config_2_1();
        let (commitment_a, mut shards_a) =
            Zoda::<Sha256>::encode(&config, &b"alpha"[..], &STRATEGY).unwrap();
        let (commitment_b, mut shards_b) =
            Zoda::<Sha256>::encode(&config, &b"bravo"[..], &STRATEGY).unwrap();

        let (checking_data_a, _, _) =
            Zoda::<Sha256>::weaken(&config, &commitment_a, 0, shards_a.remove(0)).unwrap();
        let (_, _, weak_b) =
            Zoda::<Sha256>::weaken(&config, &commitment_b, 1, shards_b.remove(1)).unwrap();

        assert!(matches!(
            Zoda::<Sha256>::check(&config, &commitment_a, &checking_data_a, 1, weak_b),
            Err(Error::InvalidShard)
        ));
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::super::WeakShard;
        use commonware_codec::conformance::CodecConformance;
        use commonware_cryptography::sha256::Digest as Sha256Digest;

        commonware_conformance::conformance_tests! {
            CodecConformance<WeakShard<Sha256Digest>>,
        }
    }
}
