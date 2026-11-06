//! Epochs cut by the operator's shards, and the closes assembled from their cuts.

use super::{
    Amount, Close, Epoch, Error, Flow, Limits, Namespace, Queue, Row, Withdrawal, matrix,
    settlement::{Flows, Total},
};
use bytes::BufMut;
use commonware_codec::{
    Buf, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt, Write,
};
use commonware_cryptography::{Digest, Hasher, PublicKey, Signer};
use std::{
    collections::{HashMap, HashSet},
    iter::once,
};

/// One shard's part of an epoch, frozen when the shard opens the next epoch.
///
/// [Operator::cut](super::Operator::cut) returns it. It holds the payment map of every sender the
/// shard admitted in the epoch, with the sender's signature and the map's root, and the soft
/// withdrawals the shard collected. It also records how many queued requests the close processes,
/// the same in every shard's cut, and the floor deductions the shard holds until the epoch settles.
/// [Close::assemble] merges the cuts of every shard into the epoch's close.
///
/// A cut is the operator's own state, so decoding checks its shape but trusts its roots and
/// deductions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cut<P: PublicKey, D: Digest, A: Amount> {
    /// The epoch cut.
    pub(crate) epoch: Epoch,
    /// Epoch of the last cut the operator settled before this one, or zero if it knew of none.
    pub(crate) settled: Epoch,
    /// Rows of distinct accounts, in no particular order, each with the root of its payment map.
    pub(crate) rows: Vec<(Row<P, A>, D)>,
    /// Soft withdrawals in request order.
    pub(crate) withdrawals: Vec<Withdrawal<P, A>>,
    /// Number of queued deposits the close processes.
    pub(crate) deposits: u64,
    /// Number of queued forced withdrawals the close processes.
    pub(crate) forced_withdrawals: u64,
    /// What the close may take from each account active in the cut.
    pub(crate) deductions: Vec<(P, Total<A>)>,
}

impl<P: PublicKey, D: Digest, A: Amount> Cut<P, D, A> {
    /// Returns the epoch cut.
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }
}

impl<P: PublicKey, D: Digest, A: Amount> Write for Cut<P, D, A> {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.settled.write(buf);
        self.rows.write(buf);
        self.withdrawals.write(buf);
        self.deposits.write(buf);
        self.forced_withdrawals.write(buf);
        self.deductions.write(buf);
    }
}

impl<P: PublicKey, D: Digest, A: Amount> EncodeSize for Cut<P, D, A> {
    fn encode_size(&self) -> usize {
        2 * Epoch::SIZE
            + self.rows.encode_size()
            + self.withdrawals.encode_size()
            + 2 * u64::SIZE
            + self.deductions.encode_size()
    }
}

impl<P: PublicKey, D: Digest, A: Amount> Read for Cut<P, D, A> {
    /// The limits of the close, and the maximum number of forced withdrawals it processes.
    type Cfg = (Limits, usize);

    fn read_cfg(
        buf: &mut impl Buf,
        (limits, forced): &(Limits, usize),
    ) -> Result<Self, CodecError> {
        let epoch = Epoch::read(buf)?;
        let settled = Epoch::read(buf)?;
        let rows = Vec::<(Row<P, A>, D)>::read_cfg(
            buf,
            &(RangeCfg::new(..=limits.rows), (limits.receivers, ())),
        )?;
        let withdrawals =
            Vec::<Withdrawal<P, A>>::read_cfg(buf, &(RangeCfg::new(..=limits.withdrawals), ()))?;
        let deposits = u64::read(buf)?;
        let forced_withdrawals = u64::read(buf)?;
        let accounts = limits
            .rows
            .saturating_add(limits.withdrawals)
            .saturating_add(*forced);
        let deductions =
            Vec::<(P, Total<A>)>::read_cfg(buf, &(RangeCfg::new(..=accounts), ((), ())))?;
        let mut senders = HashSet::with_capacity(rows.len());
        let mut deducted = HashSet::with_capacity(deductions.len());
        if !rows
            .iter()
            .all(|(row, _)| !row.payments.is_empty() && senders.insert(&row.account))
            || !withdrawals
                .windows(2)
                .all(|pair| pair[0].request() < pair[1].request())
            || !deductions
                .iter()
                .all(|(account, _)| deducted.insert(account))
        {
            return Err(CodecError::Invalid(
                "clearing::bajillion::Cut",
                "rows, withdrawals, and deductions must not repeat",
            ));
        }
        Ok(Self {
            epoch,
            settled,
            rows,
            withdrawals,
            deposits,
            forced_withdrawals,
            deductions,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<P: PublicKey, D: Digest, A: Amount> arbitrary::Arbitrary<'_> for Cut<P, D, A>
where
    P: for<'a> arbitrary::Arbitrary<'a>,
    P::Signature: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
    A: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let mut rows: Vec<(Row<P, A>, D)> = u.arbitrary()?;
        rows.sort_by(|(a, _), (b, _)| a.account.cmp(&b.account));
        rows.dedup_by(|(a, _), (b, _)| a.account == b.account);
        let mut withdrawals: Vec<Withdrawal<P, A>> = u.arbitrary()?;
        withdrawals.sort_by(|a, b| a.request().cmp(&b.request()));
        withdrawals.dedup_by(|a, b| a.request() == b.request());
        let mut deductions: Vec<(P, Total<A>)> = u.arbitrary()?;
        deductions.sort_by(|(a, _), (b, _)| a.cmp(b));
        deductions.dedup_by(|(a, _), (b, _)| a == b);
        Ok(Self {
            epoch: u.arbitrary()?,
            settled: u.arbitrary()?,
            rows,
            withdrawals,
            deposits: u.arbitrary()?,
            forced_withdrawals: u.arbitrary()?,
            deductions,
        })
    }
}

impl<P: PublicKey, O: PublicKey, A: Amount> Close<P, O, A> {
    /// Assembles the close of an epoch from the cuts of the shards that take part in it, and
    /// returns it with the flow of every account it touches, in account order.
    ///
    /// The close is the one a single operator serving every account would build. It processes the
    /// oldest `deposits` deposits and `forced_withdrawals` forced withdrawals in `queue`, the
    /// ledger's queues while it expects this close, and every cut must record the same counts.
    ///
    /// An epoch in which no shard admitted anything has no cuts, and its close only processes the
    /// queue. Assembly reads no operator state, so it runs on any thread or machine while the
    /// shards admit the next epoch. The deployment routes each flow to the shard serving its
    /// account in the next epoch, and that shard settles it with
    /// [Operator::settle](super::Operator::settle).
    ///
    /// ```text
    ///   Cut(e) of shard 1 --+                   +--> Close(e) --------------> validators
    ///   Cut(e) of shard 2 --+--> assemble(e) ---+
    ///   Cut(e) of shard 3 --+                   +--> flows, in account order
    ///                                                      | by shard in e+1
    ///                                     +----------------+----------------+
    ///                                     v                v                v
    ///                                  shard 1          shard 2          shard 3     settle(e)
    /// ```
    ///
    /// Returns an error if a count is out of bounds, a cut or one of its soft withdrawals is for
    /// another epoch than the queue, a cut records other counts, or an account pays or withdraws in
    /// two cuts.
    #[allow(clippy::type_complexity)]
    pub fn assemble<H, S>(
        signer: &S,
        namespace: &Namespace,
        queue: &Queue<P, A>,
        deposits: u64,
        forced_withdrawals: u64,
        cuts: impl IntoIterator<Item = Cut<P, H::Digest, A>>,
    ) -> Result<(Self, Vec<(P, Flow<H::Digest, A>)>), Error>
    where
        H: Hasher,
        S: Signer<PublicKey = O, Signature = O::Signature>,
    {
        let cuts: Vec<_> = cuts.into_iter().collect();
        let epoch = queue.epoch;
        let (queued_deposits, queued_forced_withdrawals) =
            queue.prefix(deposits, forced_withdrawals)?;

        // Every cut must process the same queued requests in the expected epoch, and every
        // account must pay and withdraw in a single cut.
        let mut owners = HashMap::new();
        for (index, cut) in cuts.iter().enumerate() {
            let found = once(cut.epoch)
                .chain(cut.withdrawals.iter().map(|withdrawal| withdrawal.epoch))
                .find(|found| *found != epoch);
            if let Some(found) = found {
                return Err(Error::WrongEpoch {
                    expected: epoch,
                    found,
                });
            }
            if (cut.deposits, cut.forced_withdrawals) != (deposits, forced_withdrawals) {
                return Err(Error::InvalidCut);
            }
            let accounts = cut
                .rows
                .iter()
                .map(|(row, _)| &row.account)
                .chain(cut.withdrawals.iter().map(|withdrawal| &withdrawal.account));
            for account in accounts {
                if *owners.entry(account).or_insert(index) != index {
                    return Err(Error::DuplicateAccount);
                }
            }
        }
        drop(owners);

        let mut rows = Vec::with_capacity(cuts.iter().map(|cut| cut.rows.len()).sum());
        let mut withdrawals = Vec::new();
        for cut in cuts {
            rows.extend(cut.rows);
            withdrawals.extend(cut.withdrawals);
        }
        rows.sort_unstable_by(|(a, _), (b, _)| a.account.cmp(&b.account));
        withdrawals.sort_unstable_by(|a, b| a.request().cmp(&b.request()));

        let flows = Flows::new(
            epoch,
            rows.iter()
                .map(|(row, root)| (&row.account, &row.payments, root)),
            &withdrawals,
            queued_deposits,
            queued_forced_withdrawals,
        )?;
        let root = matrix::root::<H, P>(rows.iter().map(|(row, root)| (&row.account, root)));
        let signature = signer.sign(
            &namespace.close,
            &Self::message(epoch, &root, &withdrawals, deposits, forced_withdrawals),
        );
        let close = Self::new(
            epoch,
            rows.into_iter().map(|(row, _)| row).collect(),
            withdrawals,
            deposits,
            forced_withdrawals,
            signature,
        );
        Ok((close, flows.into_flows()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bajillion::Amounts;
    use commonware_codec::{Decode as _, Encode as _};
    use commonware_cryptography::{
        Sha256,
        ed25519::{PrivateKey, PublicKey},
        sha256::Digest,
    };

    const LIMITS: Limits = Limits {
        rows: 4,
        receivers: 4,
        withdrawals: 4,
    };

    type TestCut = Cut<PublicKey, Digest, u64>;

    /// Returns a cut whose rows pay the last of `count` signers.
    fn cut(count: u64) -> TestCut {
        let signers: Vec<_> = (0..count).map(PrivateKey::from_seed).collect();
        let receiver = signers[signers.len() - 1].public_key();
        let rows = signers[..signers.len() - 1]
            .iter()
            .map(|signer| {
                let payments = Amounts::new([(receiver.clone(), 1)]).unwrap();
                let root = payments.root::<Sha256>();
                let row = Row {
                    account: signer.public_key(),
                    payments,
                    signature: signer.sign(b"row", b"row"),
                };
                (row, root)
            })
            .collect();
        let namespace = Namespace::new(b"_COMMONWARE_CLEARING_CUT_TEST");
        Cut {
            epoch: 3,
            settled: 2,
            rows,
            withdrawals: vec![Withdrawal::sign(&signers[0], &namespace, 3, 5, 0)],
            deposits: 2,
            forced_withdrawals: 1,
            deductions: vec![
                (signers[0].public_key(), Total::new(6)),
                (receiver, Total::new(7)),
            ],
        }
    }

    #[test]
    fn test_cut_round_trips() {
        let cut = cut(3);
        let decoded = TestCut::decode_cfg(cut.encode(), &(LIMITS, 1)).unwrap();
        assert_eq!(decoded, cut);
        assert_eq!(decoded.epoch(), 3);
    }

    #[test]
    fn test_decode_rejects_repeats_and_oversized_cuts() {
        // Rows, withdrawals, and deductions must not repeat, and every row pays someone.
        let canonical = cut(3);
        let mut repeated_row = canonical.clone();
        repeated_row.rows.push(canonical.rows[0].clone());
        let mut empty = canonical.clone();
        empty.rows[0].0.payments = Amounts::empty();
        let mut repeated_withdrawal = canonical.clone();
        repeated_withdrawal
            .withdrawals
            .push(canonical.withdrawals[0].clone());
        let mut repeated_deduction = canonical.clone();
        repeated_deduction
            .deductions
            .push(canonical.deductions[0].clone());
        for cut in [repeated_row, empty, repeated_withdrawal, repeated_deduction] {
            assert!(TestCut::decode_cfg(cut.encode(), &(LIMITS, 1)).is_err());
        }

        // Sizes are bounded.
        let limits = Limits { rows: 1, ..LIMITS };
        assert!(TestCut::decode_cfg(canonical.encode(), &(limits, 1)).is_err());
        let limits = Limits {
            rows: 0,
            withdrawals: 1,
            ..LIMITS
        };
        let mut rowless = canonical;
        rowless.rows.clear();
        assert!(TestCut::decode_cfg(rowless.encode(), &(limits, 1)).is_ok());
        assert!(TestCut::decode_cfg(rowless.encode(), &(limits, 0)).is_err());
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::super::*;
        use commonware_codec::conformance::CodecConformance;
        use commonware_cryptography::{ed25519::PublicKey, sha256::Digest};

        commonware_conformance::conformance_tests! {
            CodecConformance<Cut<PublicKey, Digest, u64>>,
        }
    }
}
